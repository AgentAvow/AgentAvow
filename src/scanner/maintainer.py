"""Phase 5 — maintainer / behavioral trust signals (GitHub metadata only).

Grades *how a project is maintained*, not just how its code reads — the behavioral
axis (roadmap §2.E). Everything here is **cheap GitHub-metadata**: no code
execution, no sandbox, no artifact download. A handful of read-only API calls
(bounded to ``max_calls``, ~5) yield:

  * **Bus factor / concentration** — contributor count + how concentrated the
    commits are in the top author (``/contributors``).
  * **Release cadence & recency** — last release + last-push age (``/releases`` +
    repo ``pushed_at``); actively-maintained vs stale.
  * **Archived / abandoned** — repo ``archived``/``disabled`` flag + ``pushed_at``
    age (an explicit hard-kill or a silent one).
  * **Responsiveness** — open-issue count + a coarse "ignored issue tracker" tell.
  * **Hygiene (where readable)** — default-branch protection (``/branches/{b}``),
    org ``two_factor_requirement_enabled`` (``/orgs/{org}``, when visible), and a
    signed-commit ratio (``/commits``) when the budget allows.

Design rules (identical discipline to ``supply_chain.py`` / ``provenance.py``):
  * **Feature-flagged** (``settings.scanner_maintainer_signals``, default False).
  * **Fail-open, always.** Any network/parse error returns empty signals; a
    maintainer lookup must NEVER break a scan.
  * **Additive & anti-false-F.** Absent/unreadable signals contribute **0** — we
    never penalize absence. The only score *penalty* is a small, BOUNDED one for
    clear negatives (archived / long-abandoned), capped like the dependency model
    so a repo that is merely small or new is never dragged to an F. Positives
    (active maintenance, protected branch, org 2FA, signed commits, contributor
    diversity) flow through the scanner's normal ``positive_signals`` bonus.
  * **Cost-aware.** ``max_calls`` caps the extra GitHub API calls per scan; a
    skipped call logs and leaves its signal absent (0).
  * **Pure reducers** (``contributor_concentration``, ``days_since``,
    ``build_signals``, ``maintainer_penalty``) are network-free and unit-tested
    with canned JSON; the async ``analyze_maintainer_signals`` orchestrates I/O.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from src.scanner.supply_chain import signed_commit_ratio

logger = logging.getLogger(__name__)

_GH_API = "https://api.github.com"
_HTTP_TIMEOUT = 12.0

# --- Thresholds (days) -------------------------------------------------------
ACTIVE_PUSH_DAYS = 180        # pushed within ~6 months → actively maintained
STALE_PUSH_DAYS = 365         # informational "stale" label (no penalty)
ABANDONED_PUSH_DAYS = 730     # >2y no push → abandoned (bounded penalty)
RECENT_RELEASE_DAYS = 365     # a release within a year → healthy cadence

# --- Bus-factor thresholds ---------------------------------------------------
SOLE_MAINTAINER_SHARE = 0.80  # top author >80% of commits → SPOF
DIVERSE_CONTRIBUTORS = 5      # ≥5 contributors …
DIVERSE_TOP1_MAX = 0.60       # … and top author <60% → healthy diversity

# --- Responsiveness ----------------------------------------------------------
STALE_TRACKER_OPEN_ISSUES = 50  # many open issues + a very stale repo → ignored

# --- Bounded score penalty (never a false-F; mirrors the dependency model) ---
MAINTAINER_PENALTY_CAP = 15   # max points a repo can lose to maintainer negatives
_PENALTY_ARCHIVED = 12
_PENALTY_DISABLED = 12
_PENALTY_ABANDONED = 8

# --- Positive-signal labels (fed to the scanner's positive_signals bonus) ----
SIG_ACTIVE = "Actively maintained"
SIG_PROTECTED_BRANCH = "Protected default branch"
SIG_ORG_2FA = "Org enforces 2FA"
SIG_SIGNED_COMMITS = "Signed commits"
SIG_DIVERSITY = "Healthy contributor diversity"

# --- Negative-signal labels (surfaced; only archived/abandoned score-penalize) -
NEG_ARCHIVED = "Repository archived (unmaintained)"
NEG_DISABLED = "Repository disabled"
NEG_ABANDONED = "Abandoned — no push in over 2 years"
NEG_SOLE_MAINTAINER = "Sole-maintainer bus factor (SPOF)"
NEG_STALE_TRACKER = "Stale, unattended issue tracker"


@dataclass
class MaintainerSignals:
    """Structured maintainer/behavioral outcome for one repo."""

    ok: bool = False              # True once at least the repo metadata was read
    present: bool = False         # any usable signal was captured

    # Bus factor / concentration
    contributor_count: int | None = None
    contributors_capped: bool = False   # count is a floor (API page cap hit)
    top_contributor_share: float | None = None

    # Cadence / recency
    last_push_days: int | None = None
    last_release_days: int | None = None
    releases_total: int | None = None

    # Abandonment
    archived: bool = False
    disabled: bool = False

    # Responsiveness
    open_issues: int | None = None
    stale_issue_tracker: bool = False

    # Hygiene
    branch_protected: bool | None = None
    org_2fa_required: bool | None = None
    signed_commit_ratio: float | None = None

    # Derived
    maintainer_health: int | None = None   # informational 0-100 composite
    positive_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)

    api_calls_used: int = 0
    error: str | None = None

    def summary(self) -> dict:
        """A JSON-ready dict for the scan's ``maintainer`` block (no None churn)."""
        out: dict = {
            "ok": self.ok,
            "present": self.present,
            "archived": self.archived,
            "disabled": self.disabled,
            "stale_issue_tracker": self.stale_issue_tracker,
            "positive_signals": list(self.positive_signals),
            "negative_signals": list(self.negative_signals),
            "api_calls_used": self.api_calls_used,
        }
        # Include any captured signal (None means "not read" → omitted). Tri-state
        # booleans (branch_protected / org_2fa_required) are kept even when False,
        # since False here is a real, read value.
        for key in (
            "contributor_count", "top_contributor_share",
            "last_push_days", "last_release_days", "releases_total",
            "open_issues", "branch_protected", "org_2fa_required",
            "signed_commit_ratio", "maintainer_health",
        ):
            val = getattr(self, key)
            if val is not None:
                out[key] = val
        if self.contributors_capped:
            out["contributors_capped"] = True
        if self.error is not None:
            out["error"] = self.error
        return out


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def days_since(iso: str | None) -> int | None:
    """Whole days between an ISO-8601 timestamp and now (UTC). None on bad input."""
    if not isinstance(iso, str) or not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def contributor_concentration(
    contributors: list[dict] | None,
) -> tuple[int | None, float | None]:
    """Return ``(contributor_count, top_contributor_share)`` from ``/contributors``.

    ``top_contributor_share`` is the top author's fraction of total contributions
    across the returned page — the bus-factor concentration signal. Returns
    ``(None, None)`` for an empty/invalid list.
    """
    if not isinstance(contributors, list) or not contributors:
        return None, None
    totals: list[int] = []
    for c in contributors:
        if isinstance(c, dict) and isinstance(c.get("contributions"), int):
            totals.append(c["contributions"])
    count = len(contributors)
    if not totals:
        return count, None
    grand = sum(totals)
    share = round(max(totals) / grand, 4) if grand else None
    return count, share


def _clamp(value: float, lo: int = 0, hi: int = 100) -> int:
    return int(max(lo, min(hi, value)))


def build_signals(
    *,
    repo_meta: dict | None,
    contributors: list[dict] | None = None,
    releases: list[dict] | None = None,
    branch: dict | None = None,
    org: dict | None = None,
    commits: list[dict] | None = None,
    api_calls_used: int = 0,
) -> MaintainerSignals:
    """Pure reducer: raw GitHub JSON blobs → :class:`MaintainerSignals`.

    Network-free and deterministic — unit-tested directly with canned JSON, and a
    verifier can replay it from pinned inputs. Any blob may be ``None`` (call
    skipped / unreadable); an absent signal contributes nothing and is never a
    penalty.
    """
    sig = MaintainerSignals(api_calls_used=api_calls_used)
    if not isinstance(repo_meta, dict):
        return sig  # nothing read → empty, ok=False

    sig.ok = True
    sig.present = True
    sig.archived = bool(repo_meta.get("archived"))
    sig.disabled = bool(repo_meta.get("disabled"))
    oi = repo_meta.get("open_issues_count")
    sig.open_issues = oi if isinstance(oi, int) else None
    sig.last_push_days = days_since(repo_meta.get("pushed_at"))

    # Bus factor.
    sig.contributor_count, sig.top_contributor_share = contributor_concentration(
        contributors,
    )
    if isinstance(contributors, list) and len(contributors) >= 100:
        sig.contributors_capped = True

    # Release cadence.
    if isinstance(releases, list):
        sig.releases_total = len(releases)
        if releases and isinstance(releases[0], dict):
            sig.last_release_days = days_since(releases[0].get("published_at"))

    # Hygiene: default-branch protection.
    if isinstance(branch, dict) and "protected" in branch:
        sig.branch_protected = bool(branch.get("protected"))

    # Hygiene: org-wide 2FA (only meaningful when the field is visible).
    if isinstance(org, dict) and org.get("two_factor_requirement_enabled") is not None:
        sig.org_2fa_required = bool(org.get("two_factor_requirement_enabled"))

    # Hygiene: signed-commit ratio (reuse the supply-chain reducer).
    if isinstance(commits, list) and commits:
        ratio = signed_commit_ratio(commits).get("ratio")
        sig.signed_commit_ratio = ratio

    _derive_labels_and_health(sig)
    return sig


def _derive_labels_and_health(sig: MaintainerSignals) -> None:
    """Populate positive/negative labels + the 0-100 informational health score.

    Health starts at a neutral 50 and moves only on signals we actually have, so
    an absent signal is genuinely neutral (never a penalty).
    """
    health = 50.0
    pos = sig.positive_signals
    neg = sig.negative_signals

    # --- Abandonment (the score-penalizing negatives) ---
    if sig.archived:
        neg.append(NEG_ARCHIVED)
        health -= 40
    if sig.disabled:
        neg.append(NEG_DISABLED)
        health -= 25
    if (
        not sig.archived
        and sig.last_push_days is not None
        and sig.last_push_days > ABANDONED_PUSH_DAYS
    ):
        neg.append(NEG_ABANDONED)
        health -= 25

    # --- Cadence / recency (positives + health) ---
    active = (
        (sig.last_push_days is not None and sig.last_push_days <= ACTIVE_PUSH_DAYS)
        or (
            sig.last_release_days is not None
            and sig.last_release_days <= RECENT_RELEASE_DAYS
        )
    )
    if active and not sig.archived:
        pos.append(SIG_ACTIVE)
        health += 15
    elif (
        sig.last_push_days is not None
        and STALE_PUSH_DAYS < sig.last_push_days <= ABANDONED_PUSH_DAYS
    ):
        health -= 8  # stale-but-not-abandoned: informational dent, no label/penalty
    if sig.last_release_days is not None and sig.last_release_days <= RECENT_RELEASE_DAYS:
        health += 8

    # --- Bus factor (surfaced label + health; NOT a score penalty → no false-F) ---
    if sig.contributor_count is not None:
        sole = sig.contributor_count <= 1 or (
            sig.top_contributor_share is not None
            and sig.top_contributor_share > SOLE_MAINTAINER_SHARE
        )
        diverse = (
            sig.contributor_count >= DIVERSE_CONTRIBUTORS
            and (sig.top_contributor_share or 1.0) < DIVERSE_TOP1_MAX
        )
        if sole:
            neg.append(NEG_SOLE_MAINTAINER)
            health -= 10
        elif diverse:
            pos.append(SIG_DIVERSITY)
            health += 10

    # --- Responsiveness: an ignored, very stale issue tracker ---
    if (
        sig.open_issues is not None
        and sig.open_issues >= STALE_TRACKER_OPEN_ISSUES
        and sig.last_push_days is not None
        and sig.last_push_days > STALE_PUSH_DAYS
    ):
        sig.stale_issue_tracker = True
        neg.append(NEG_STALE_TRACKER)
        health -= 8

    # --- Hygiene positives ---
    if sig.branch_protected:
        pos.append(SIG_PROTECTED_BRANCH)
        health += 8
    if sig.org_2fa_required:
        pos.append(SIG_ORG_2FA)
        health += 7
    if sig.signed_commit_ratio is not None and sig.signed_commit_ratio >= 0.5:
        pos.append(SIG_SIGNED_COMMITS)
        health += int(10 * sig.signed_commit_ratio)

    sig.maintainer_health = _clamp(health)


def maintainer_penalty(sig: MaintainerSignals) -> int:
    """Bounded, capped score penalty for the CLEAR negatives only.

    Archived / disabled / long-abandoned repos lose a small, capped number of
    points (never enough to false-flip a healthy grade to F, and never applied to
    a repo that is simply small or new — those have no archived flag and a recent
    ``pushed_at``). Bus-factor / stale-tracker are surfaced as labels but do NOT
    penalize the score, exactly to avoid a false-F on small projects.
    """
    penalty = 0
    if sig.archived:
        penalty += _PENALTY_ARCHIVED
    if sig.disabled:
        penalty += _PENALTY_DISABLED
    if (
        not sig.archived
        and sig.last_push_days is not None
        and sig.last_push_days > ABANDONED_PUSH_DAYS
    ):
        penalty += _PENALTY_ABANDONED
    return min(penalty, MAINTAINER_PENALTY_CAP)


# ---------------------------------------------------------------------------
# Async I/O layer — cost-capped, fail-open
# ---------------------------------------------------------------------------
class _Budget:
    """Tiny GitHub-API call budget: counts calls, skips (and logs) past the cap."""

    def __init__(self, owner: str, repo: str, max_calls: int) -> None:
        self.owner = owner
        self.repo = repo
        self.max_calls = max_calls
        self.used = 0

    def take(self, what: str) -> bool:
        if self.used >= self.max_calls:
            logger.debug(
                "maintainer: skipping %s for %s/%s — API call budget (%d) exhausted",
                what, self.owner, self.repo, self.max_calls,
            )
            return False
        self.used += 1
        return True


async def _get_json(
    client: httpx.AsyncClient, url: str, *, params: dict | None = None,
):
    """GET → parsed JSON, or None on any non-200 / error (fail-open per call)."""
    try:
        resp = await client.get(url, params=params, timeout=_HTTP_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def analyze_maintainer_signals(
    owner: str,
    repo: str,
    token: str | None = None,
    *,
    repo_meta: dict | None = None,
    max_calls: int = 5,
    client: httpx.AsyncClient | None = None,
) -> MaintainerSignals:
    """Gather cheap GitHub maintainer/behavioral signals. **Fail-open, cost-capped.**

    Makes at most ``max_calls`` GitHub API GETs (default 5), reusing the caller's
    token/client. Any error at any point returns whatever was captured so far (or
    empty), never an exception — a maintainer lookup must not break a scan.

    ``repo_meta`` may be supplied by the caller (it is fetched during the normal
    repo scan) to save the first call; otherwise it is fetched here and counted
    against the budget. Priority order when the budget is tight:
    repo-meta → contributors → releases → default-branch protection → (org 2FA for
    org-owned repos, else signed-commit ratio).
    """
    budget = _Budget(owner, repo, max_calls)
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(headers=headers)
    else:
        # Ensure our headers (esp. auth) are applied on a borrowed client too.
        client.headers.update(headers)

    contributors = releases = branch = org = commits = None
    try:
        # 1) Repo metadata (drives everything). Reuse the caller's if given.
        if repo_meta is None and budget.take("repo metadata"):
            repo_meta = await _get_json(client, f"{_GH_API}/repos/{owner}/{repo}")
        if not isinstance(repo_meta, dict):
            # No metadata → nothing to say; empty signals (fail-open).
            return MaintainerSignals(api_calls_used=budget.used)

        default_branch = repo_meta.get("default_branch") or "main"
        owner_obj = repo_meta.get("owner") or {}
        is_org = isinstance(owner_obj, dict) and owner_obj.get("type") == "Organization"
        owner_login = owner_obj.get("login") if isinstance(owner_obj, dict) else owner

        # 2) Contributors (bus factor).
        if budget.take("contributors"):
            contributors = await _get_json(
                client, f"{_GH_API}/repos/{owner}/{repo}/contributors",
                params={"per_page": "100", "anon": "1"},
            )

        # 3) Releases (cadence).
        if budget.take("releases"):
            releases = await _get_json(
                client, f"{_GH_API}/repos/{owner}/{repo}/releases",
                params={"per_page": "1"},
            )

        # 4) Default-branch protection (hygiene).
        if budget.take("branch protection"):
            branch = await _get_json(
                client, f"{_GH_API}/repos/{owner}/{repo}/branches/{default_branch}",
            )

        # 5) Org 2FA (org-owned) OR signed-commit ratio (user-owned).
        if is_org and owner_login:
            if budget.take("org 2FA"):
                org = await _get_json(client, f"{_GH_API}/orgs/{owner_login}")
        elif budget.take("commits (signed ratio)"):
            commits = await _get_json(
                client, f"{_GH_API}/repos/{owner}/{repo}/commits",
                params={"per_page": "30"},
            )

        return build_signals(
            repo_meta=repo_meta,
            contributors=contributors,
            releases=releases,
            branch=branch,
            org=org,
            commits=commits,
            api_calls_used=budget.used,
        )
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        logger.warning(
            "Maintainer-signal pass failed for %s/%s (fail-open): %s",
            owner, repo, exc,
        )
        return MaintainerSignals(api_calls_used=budget.used, error=str(exc))
    finally:
        if owns_client and client is not None:
            await client.aclose()
