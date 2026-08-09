"""Phase 5 — maintainer / behavioral trust signals (offline).

Pure reducers are driven with canned JSON and the fail-open, cost-capped
orchestrator is exercised with an ``httpx.MockTransport``, so no network is hit.
Covers: health normalization, the bounded penalty, absent-signal = no-penalty,
the archived-repo case, the API-call budget cap, and fail-open.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from src.scanner.maintainer import (
    MAINTAINER_PENALTY_CAP,
    NEG_ABANDONED,
    NEG_ARCHIVED,
    NEG_SOLE_MAINTAINER,
    SIG_ACTIVE,
    SIG_DIVERSITY,
    SIG_ORG_2FA,
    SIG_PROTECTED_BRANCH,
    SIG_SIGNED_COMMITS,
    analyze_maintainer_signals,
    build_signals,
    contributor_concentration,
    days_since,
    maintainer_penalty,
)


def _iso_days_ago(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_days_since_and_bad_input():
    assert days_since(_iso_days_ago(10)) in (9, 10, 11)
    assert days_since(None) is None
    assert days_since("not-a-date") is None


def test_contributor_concentration():
    contribs = [
        {"login": "a", "contributions": 90},
        {"login": "b", "contributions": 10},
    ]
    count, share = contributor_concentration(contribs)
    assert count == 2
    assert share == 0.9
    assert contributor_concentration([]) == (None, None)
    assert contributor_concentration(None) == (None, None)


# ── normalization / labels (build_signals) ───────────────────────────────────

def test_healthy_active_diverse_org_repo_scores_high_no_penalty():
    repo_meta = {
        "archived": False, "disabled": False,
        "pushed_at": _iso_days_ago(5), "open_issues_count": 3,
        "default_branch": "main",
        "owner": {"type": "Organization", "login": "acme"},
    }
    contributors = [
        {"login": "a", "contributions": 40},
        {"login": "b", "contributions": 35},
        {"login": "c", "contributions": 30},
        {"login": "d", "contributions": 25},
        {"login": "e", "contributions": 20},
    ]
    sig = build_signals(
        repo_meta=repo_meta,
        contributors=contributors,
        releases=[{"published_at": _iso_days_ago(30)}],
        branch={"protected": True},
        org={"two_factor_requirement_enabled": True},
        commits=[
            {"commit": {"verification": {"verified": True}}},
            {"commit": {"verification": {"verified": True}}},
        ],
    )
    assert sig.ok and sig.present
    # Strong positives all present.
    assert SIG_ACTIVE in sig.positive_signals
    assert SIG_DIVERSITY in sig.positive_signals
    assert SIG_PROTECTED_BRANCH in sig.positive_signals
    assert SIG_ORG_2FA in sig.positive_signals
    assert SIG_SIGNED_COMMITS in sig.positive_signals
    assert not sig.negative_signals
    assert sig.maintainer_health >= 85
    # A healthy repo is never score-penalized.
    assert maintainer_penalty(sig) == 0


def test_absent_signals_are_neutral_no_penalty():
    # Only the minimal repo metadata is readable (a fresh/small repo). No archived
    # flag and a recent push → absence must NOT create a penalty or false-F.
    repo_meta = {
        "archived": False, "pushed_at": _iso_days_ago(20),
        "default_branch": "main", "owner": {"type": "User", "login": "solo"},
    }
    sig = build_signals(repo_meta=repo_meta)
    assert sig.ok
    assert maintainer_penalty(sig) == 0
    # Health stays neutral-ish (active bonus only), never floored by absence.
    assert sig.maintainer_health >= 50
    # No contributor data → no bus-factor label.
    assert NEG_SOLE_MAINTAINER not in sig.negative_signals


def test_sole_maintainer_labeled_but_not_penalized():
    repo_meta = {
        "archived": False, "pushed_at": _iso_days_ago(10),
        "default_branch": "main", "owner": {"type": "User", "login": "solo"},
    }
    sig = build_signals(
        repo_meta=repo_meta,
        contributors=[{"login": "solo", "contributions": 100}],
    )
    assert NEG_SOLE_MAINTAINER in sig.negative_signals
    # Bus factor is a surfaced label only — it must not score-penalize (anti-false-F).
    assert maintainer_penalty(sig) == 0


def test_archived_repo_bounded_penalty():
    repo_meta = {
        "archived": True, "disabled": False,
        "pushed_at": _iso_days_ago(400), "open_issues_count": 5,
        "default_branch": "main", "owner": {"type": "User", "login": "x"},
    }
    sig = build_signals(repo_meta=repo_meta)
    assert sig.archived
    assert NEG_ARCHIVED in sig.negative_signals
    assert SIG_ACTIVE not in sig.positive_signals
    pen = maintainer_penalty(sig)
    assert pen > 0
    assert pen <= MAINTAINER_PENALTY_CAP  # bounded — never an unbounded F
    assert sig.maintainer_health < 50


def test_abandoned_repo_penalized_and_capped():
    repo_meta = {
        "archived": False, "disabled": True,
        "pushed_at": _iso_days_ago(1200),  # >2y abandoned
        "open_issues_count": 120, "default_branch": "main",
        "owner": {"type": "User", "login": "x"},
    }
    sig = build_signals(repo_meta=repo_meta)
    assert NEG_ABANDONED in sig.negative_signals
    assert sig.stale_issue_tracker is True  # many open issues + very stale
    # disabled(12) + abandoned(8) = 20 → capped at MAINTAINER_PENALTY_CAP.
    assert maintainer_penalty(sig) == MAINTAINER_PENALTY_CAP


def test_no_repo_meta_returns_empty():
    sig = build_signals(repo_meta=None)
    assert sig.ok is False
    assert sig.present is False
    assert maintainer_penalty(sig) == 0


# ── async orchestrator (mock transport) ──────────────────────────────────────

def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_analyze_happy_path_org_repo():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/acme/tool":
            return httpx.Response(200, json={
                "archived": False, "disabled": False,
                "pushed_at": _iso_days_ago(3), "open_issues_count": 2,
                "default_branch": "main",
                "owner": {"type": "Organization", "login": "acme"},
            })
        if path == "/repos/acme/tool/contributors":
            return httpx.Response(200, json=[
                {"login": "a", "contributions": 50},
                {"login": "b", "contributions": 40},
                {"login": "c", "contributions": 30},
                {"login": "d", "contributions": 20},
                {"login": "e", "contributions": 15},
            ])
        if path == "/repos/acme/tool/releases":
            return httpx.Response(200, json=[{"published_at": _iso_days_ago(20)}])
        if path == "/repos/acme/tool/branches/main":
            return httpx.Response(200, json={"protected": True})
        if path == "/orgs/acme":
            return httpx.Response(200, json={"two_factor_requirement_enabled": True})
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "acme", "tool", token="t", max_calls=5, client=client,
        )
    assert sig.ok and sig.present
    assert SIG_ACTIVE in sig.positive_signals
    assert SIG_PROTECTED_BRANCH in sig.positive_signals
    assert SIG_ORG_2FA in sig.positive_signals
    assert SIG_DIVERSITY in sig.positive_signals
    assert maintainer_penalty(sig) == 0
    assert sig.api_calls_used == 5


@pytest.mark.asyncio
async def test_analyze_user_repo_fetches_commits_for_signed_ratio():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/solo/tool":
            return httpx.Response(200, json={
                "archived": False, "pushed_at": _iso_days_ago(10),
                "default_branch": "main",
                "owner": {"type": "User", "login": "solo"},
            })
        if path == "/repos/solo/tool/commits":
            return httpx.Response(200, json=[
                {"commit": {"verification": {"verified": True}}},
                {"commit": {"verification": {"verified": True}}},
                {"commit": {"verification": {"verified": False}}},
            ])
        # everything else empty/absent
        if path in ("/repos/solo/tool/contributors", "/repos/solo/tool/releases"):
            return httpx.Response(200, json=[])
        if path == "/repos/solo/tool/branches/main":
            return httpx.Response(404)
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "solo", "tool", token=None, max_calls=5, client=client,
        )
    # A user-owned repo takes the commits branch (not org 2FA).
    assert sig.signed_commit_ratio is not None
    assert SIG_SIGNED_COMMITS in sig.positive_signals  # 2/3 verified ≥ 0.5
    assert sig.org_2fa_required is None  # never fetched for a user repo


@pytest.mark.asyncio
async def test_analyze_archived_repo_end_to_end():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/dead/tool":
            return httpx.Response(200, json={
                "archived": True, "pushed_at": _iso_days_ago(900),
                "default_branch": "main",
                "owner": {"type": "User", "login": "dead"},
            })
        return httpx.Response(404)  # everything else unreadable

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "dead", "tool", token=None, max_calls=5, client=client,
        )
    assert sig.archived is True
    assert NEG_ARCHIVED in sig.negative_signals
    pen = maintainer_penalty(sig)
    assert 0 < pen <= MAINTAINER_PENALTY_CAP


@pytest.mark.asyncio
async def test_budget_cap_limits_calls():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request.url.path == "/repos/o/r":
            return httpx.Response(200, json={
                "archived": False, "pushed_at": _iso_days_ago(5),
                "default_branch": "main",
                "owner": {"type": "Organization", "login": "o"},
            })
        return httpx.Response(200, json=[])

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "o", "r", token=None, max_calls=2, client=client,
        )
    # Only repo-meta + contributors are allowed by the budget of 2.
    assert calls["n"] == 2
    assert sig.api_calls_used == 2
    # Releases/branch/org were skipped → those signals stay absent (no penalty).
    assert sig.branch_protected is None
    assert sig.org_2fa_required is None


@pytest.mark.asyncio
async def test_analyze_fails_open_on_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "o", "r", token=None, max_calls=5, client=client,
        )
    # No metadata could be read → empty, ok=False, never raises.
    assert sig.ok is False
    assert maintainer_penalty(sig) == 0


@pytest.mark.asyncio
async def test_analyze_missing_repo_returns_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)  # repo gone / private

    async with _mock_client(handler) as client:
        sig = await analyze_maintainer_signals(
            "o", "r", token=None, max_calls=5, client=client,
        )
    assert sig.ok is False
    assert sig.present is False
