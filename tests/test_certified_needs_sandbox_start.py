"""The Certified mark needs a sandbox run that started the tool (Kenne, 2026-11-07).

When the sandbox was meant to start a tool (an MCP server plan or a skill's hooks and
scripts) and the tool never started, for ANY start reason, the mark is withheld. An
attacker can crash on purpose under the sandbox; the mark promises a finished, clean
run. The decision (safe / review / do_not_connect) and the trust score do not move.
A plain library on an install-only plan (``not_applicable``) is not affected.

Every surface reads the same applied data: the API response (and the /mcp
structuredContent built from it), badges and cards (``_badge_view``), the OG previews
and the repo preflight.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import src.api.public_scan_router as psr
from src.database import get_db
from src.main import app

URL = "/api/v1/public/scan/package/npm/left-pad"
CERT = {"eligible": True, "checks": {"no_critical_or_high": True}}

START_REASONS = ("crashed", "no_entrypoint", "install_failed", "timeout", "resource_limit",
                 "needs_credentials", "needs_arguments", "missing_binary", "unknown")
EXEC_PLANS = ("npm-mcp", "pypi-mcp", "npm-git-mcp", "pypi-git-mcp", "skill")


def _scan(score: int = 92) -> dict:
    return {
        "trust_score": score, "trust_tier": "verified", "scan_result": "clean",
        "grade": "A+",
        "recommended_limits": psr.recommended_limits(score),
        "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0, "categories": {},
                     "items": [], "suppressed_lines": 0},
        "positive_signals": [], "category_scores": {}, "certified": CERT,
        "metadata": {"files_scanned": 120, "primary_language": "javascript",
                     "has_readme": True, "has_license": True, "has_tests": True,
                     "is_mcp_server": True},
        "artifact_scan": {"is_mcp_server": True},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _never_started(reason: str, plan: str = "npm-mcp", *, exercised: bool = True) -> dict:
    """A finished run whose tool never started. ``exercised=False`` is a run that
    stopped before the launch was attempted (install failed, wall clock, resource cap):
    no transcript, so ``server_failed_to_start`` is False even though nothing ran."""
    return {
        "ran": True, "plan": plan, "findings": [], "canary_exfil": [],
        "exercise": ({"launch_ok": False, "calls": [], "tools": []} if exercised else None),
        "exit_code": 1 if not exercised else 0,
        "grade_summary": {"ran": True, "plan": plan, "exercised": exercised,
                          "launch_ok": False, "server_failed_to_start": exercised,
                          "start_reason": reason, "start_reason_detail": ""},
        "attestation": {"jws": "aaa.bbb.ccc", "observed_at": "2026-11-07T01:15:42+00:00"},
    }


def _started(plan: str = "npm-mcp") -> dict:
    return {
        "ran": True, "plan": plan, "findings": [], "canary_exfil": [],
        "exercise": {"launch_ok": True, "calls": [{"tool": "t", "ok": True}], "tools": []},
        "exit_code": 0,
        "grade_summary": {"ran": True, "plan": plan, "exercised": True, "launch_ok": True,
                          "server_failed_to_start": False, "start_reason": "started"},
        "attestation": {"jws": "aaa.bbb.ccc", "observed_at": "2026-11-07T01:15:42+00:00"},
    }


def _install_only(plan: str = "npm", exit_code: int = 0) -> dict:
    """A plain library: the install/import plan launches nothing (``not_applicable``)."""
    return {
        "ran": True, "plan": plan, "findings": [], "canary_exfil": [], "exercise": None,
        "exit_code": exit_code,
        "grade_summary": {"ran": True, "plan": plan, "exercised": False, "launch_ok": False,
                          "server_failed_to_start": False, "start_reason": "not_applicable"},
        "attestation": {"jws": "aaa.bbb.ccc", "observed_at": "2026-11-07T01:15:42+00:00"},
    }


def _gap(block):
    return (psr._apply_behavioral_score(_scan(), block).get("coverage_gaps") or {}).get(
        "sandbox_not_observed")


def _mark(block) -> tuple[bool, str]:
    from src.scanner.verdict import certified_mark_status, decide
    applied = {**psr._apply_behavioral_score(_scan(), block), "behavioral": block}
    return certified_mark_status(applied, decide(applied))


# ── the gap, per start reason and plan ───────────────────────────────────────────────

@pytest.mark.parametrize("plan", EXEC_PLANS)
@pytest.mark.parametrize("reason", START_REASONS)
def test_every_start_reason_on_an_exec_plan_withholds_the_mark(reason, plan):
    block = _never_started(reason, plan)
    assert _gap(block) == reason.replace("_", " ")
    assert _mark(block) == (False, "coverage_gaps")


@pytest.mark.parametrize("plan", EXEC_PLANS)
@pytest.mark.parametrize("reason", ("install_failed", "timeout", "resource_limit", "unknown"))
def test_a_run_that_stopped_before_the_launch_is_a_gap_too(reason, plan):
    """No transcript at all (server_failed_to_start False): the plan was meant to start
    the tool and never got that far. Before this change it read as a clean run."""
    block = _never_started(reason, plan, exercised=False)
    assert _gap(block) == reason.replace("_", " ")
    assert _mark(block) == (False, "coverage_gaps")


@pytest.mark.parametrize("plan", EXEC_PLANS)
def test_an_exec_plan_with_no_summary_fails_closed(plan):
    block = {**_never_started("crashed", plan, exercised=False), "grade_summary": {}}
    assert _gap(block) == "unknown"
    assert _mark(block)[0] is False


@pytest.mark.parametrize("plan", EXEC_PLANS)
def test_a_started_tool_keeps_the_mark(plan):
    assert _gap(_started(plan)) is None
    assert _mark(_started(plan)) == (True, "")


@pytest.mark.parametrize("plan", ("npm", "pypi", "npm-git", "pypi-git"))
@pytest.mark.parametrize("exit_code", (0, 1))
def test_install_only_plans_are_not_affected(plan, exit_code):
    """The not_applicable control: a plain npm / PyPI library has no exec plan, so
    nothing was meant to start, whatever the install step did."""
    block = _install_only(plan, exit_code)
    assert _gap(block) is None
    assert _mark(block) == (True, "")


def test_an_install_only_plan_missing_its_reason_is_not_affected():
    block = _install_only("npm")
    block["grade_summary"] = {k: v for k, v in block["grade_summary"].items()
                              if k != "start_reason"}
    assert _gap(block) is None
    assert _mark(block) == (True, "")


@pytest.mark.parametrize("block", [
    {"ran": False, "pending": True, "state": "running"},
    {"ran": False, "pending": False, "state": "unavailable", "reason": "sandbox unavailable"},
    {**_never_started("crashed"), "plan": "live-probe"},   # advisory live probe
])
def test_pending_unavailable_and_advisory_are_unchanged(block):
    from src.scanner.verdict import certified_mark_status, decide
    applied = {**psr._apply_behavioral_score(_scan(), block), "behavioral": block}
    before = certified_mark_status({**_scan(), "behavioral": block},
                                   decide({**_scan(), "behavioral": block}))
    assert certified_mark_status(applied, decide(applied)) == before


@pytest.mark.parametrize("reason", START_REASONS)
def test_decision_and_score_do_not_move(reason):
    from src.scanner.verdict import decide
    for block in (_never_started(reason), _never_started(reason, exercised=False)):
        applied = psr._apply_behavioral_score(_scan(), block)
        assert applied["trust_score"] == 92
        d = decide({**applied, "behavioral": block})
        clean = decide({**psr._apply_behavioral_score(_scan(), _started()),
                        "behavioral": _started()})
        assert d.decision == "safe" and d.final is True
        assert clean.decision == "safe"


def test_the_legacy_a_plus_follows_the_mark():
    applied = psr._apply_behavioral_score(_scan(), _never_started("crashed"))
    assert applied["grade"] == "A"
    assert psr._apply_behavioral_score(_scan(), _install_only())["grade"] == "A+"


# ── the API response (and /mcp, which reads it) ─────────────────────────────────────

def _signed(body: dict) -> dict:
    return json.loads(base64.urlsafe_b64decode(body["jws"].split(".")[1] + "==="))


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _get(client, block: dict | None) -> dict:
    with patch("src.config.settings.scanner_behavioral_enabled", True), \
         patch.object(psr, "_get_cached", new=AsyncMock(return_value=_scan())), \
         patch.object(psr, "_get_cached_behavioral", new=AsyncMock(return_value=block)), \
         patch.object(psr, "_start_behavioral_payload",
                      new=AsyncMock(return_value="started")):
        r = await client.get(URL)
    assert r.status_code == 200
    return r.json()


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ("crashed", "install_failed", "needs_credentials"))
async def test_api_withholds_the_mark_and_keeps_the_answer(client, reason):
    body = await _get(client, _never_started(reason, exercised=reason != "install_failed"))
    assert body["certified_mark"] is False
    assert body["certified_mark_reason"] == "coverage_gaps"
    assert body["decision"] == "safe" and body["decision_final"] is True
    assert body["trust_score"] == 92
    assert body["certified"]["eligible"] is True          # the signed gate is unchanged
    assert _signed(body)["scan"]["coverageGaps"]["sandbox_not_observed"] == \
        reason.replace("_", " ")
    # /mcp structuredContent is built from this response
    from src.bridges.mcp_streamable import _certified_mark_of
    assert _certified_mark_of(body) is False


@pytest.mark.asyncio
async def test_api_keeps_the_mark_on_a_started_run(client):
    body = await _get(client, _started())
    assert body["certified_mark"] is True and body["decision"] == "safe"


# ── badges, cards, OG previews, preflight ───────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("reason", START_REASONS)
async def test_badge_and_card_view_withholds_the_mark(monkeypatch, reason):
    async def cached(_d):
        return _never_started(reason)
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached)
    assert await psr._badge_view(_scan(), 92, ("npm", "left-pad")) == ("safe", False)
    assert await psr._mark_for_cached(_scan(), ("npm", "left-pad")) is False


@pytest.mark.asyncio
async def test_badge_view_keeps_the_mark_for_a_plain_library(monkeypatch):
    async def cached(_d):
        return _install_only()
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached)
    assert await psr._badge_view(_scan(), 92, ("npm", "left-pad")) == ("safe", True)


@pytest.mark.asyncio
async def test_og_package_preview_withholds_the_mark(monkeypatch):
    from src.api import og_router

    async def cached_block(_d):
        return _never_started("crashed")
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached_block)
    monkeypatch.setattr(psr, "_get_cached", AsyncMock(return_value=_scan()))
    monkeypatch.setattr(psr, "_get_stale_cached", AsyncMock(return_value=None))
    monkeypatch.setattr(og_router, "_adoption_for", AsyncMock(return_value=None))
    html = (await og_router.og_package("npm", "left-pad")).body.decode()
    assert "Safe to connect" in html
    assert "Certified" not in html and "certified=1" not in html


@pytest.mark.asyncio
async def test_og_package_preview_keeps_the_mark_on_a_started_run(monkeypatch):
    from src.api import og_router

    async def cached_block(_d):
        return _started()
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached_block)
    monkeypatch.setattr(psr, "_get_cached", AsyncMock(return_value=_scan()))
    monkeypatch.setattr(psr, "_get_stale_cached", AsyncMock(return_value=None))
    monkeypatch.setattr(og_router, "_adoption_for", AsyncMock(return_value=None))
    html = (await og_router.og_package("npm", "left-pad")).body.decode()
    assert "Certified" in html and "certified=1" in html


@pytest.mark.asyncio
async def test_og_skill_preview_withholds_the_mark(monkeypatch):
    from src.api import og_router
    seen = []

    async def cached_block(d):
        seen.append(d.get("surface_kind"))
        return _never_started("no_entrypoint", "skill")
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached_block)
    monkeypatch.setattr(psr, "_get_cached", AsyncMock(return_value=_scan()))
    monkeypatch.setattr(psr, "_get_stale_cached", AsyncMock(return_value=None))
    html = (await og_router.og_skill("acme", "skills", db=None)).body.decode()
    assert "skill" in seen
    assert "Certified" not in html and "certified=1" not in html


@pytest.mark.asyncio
async def test_preflight_repo_withholds_the_mark(monkeypatch):
    from src.api import preflight_router

    async def cached_block(_d):
        return _never_started("crashed", "npm-git-mcp")
    monkeypatch.setattr(psr, "_cached_behavioral_for", cached_block)
    monkeypatch.setattr(preflight_router, "_cache_get",
                        AsyncMock(return_value={"data": _scan()}))
    out = await preflight_router.preflight_repo("acme", "server", request=None, force=False)
    assert out.decision == "safe"
    assert out.certified is False
