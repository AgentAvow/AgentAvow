"""Engagement / usage metrics dashboard — admin-only.

AgentAvow has no user signups (checking a tool is anonymous), so
account-creation can't measure engagement. This dashboard is the real
signal, computed entirely from data the product already stores:

  * on-demand scans          -> community_scans (one row per repo, upserted)
  * watches                  -> tool_watches
  * repo ownership claims     -> repo_claims
  * per-account alert hooks   -> alert_webhooks
  * API keys                 -> api_keys
  * formal attestations       -> formal_attestations / verification_badges
  * static launch corpus      -> data/launch-scans/*.json (scan-catalog)

Two signals the product did NOT previously persist — trust-badge SVG
fetches and API-key call volume — are captured here via lightweight,
best-effort Redis day counters (``bump_metric``). They start counting at
deploy time (no historical backfill) and never block the hot path.

Endpoints (both under the ``/admin`` prefix, reusing ``require_admin``):
  * GET /admin/metrics            -> JSON aggregation (window = today|7d|30d)
  * GET /admin/metrics/dashboard  -> minimal server-rendered HTML view
  * GET /admin/metrics/behavioral -> behavioral sandbox health (Redis counters) plus
    the latest scheduled eval report (``last_eval``) and the known-good corpus
  * POST /admin/metrics/behavioral/eval   -> start an eval run now (202 / 409 if running)
  * POST /admin/metrics/behavioral/corpus -> add / remove a known-good corpus entry
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import (
    AlertWebhook,
    APIKey,
    CommunityScan,
    Entity,
    FormalAttestation,
    GitHubAppInstallation,
    PrivateScanResult,
    RepoClaim,
    ToolWatch,
    VerificationBadge,
)
from src.trust_tiers import TIERS
from src.usage_scope import LEGACY_HOSTS, REDIRECTED_METRIC, RULES_CHANGED_ON

router = APIRouter(prefix="/admin", tags=["admin"])

_WINDOW_DAYS = {"today": 1, "7d": 7, "30d": 30}

# ---------------------------------------------------------------------------
# Lightweight best-effort Redis day counters (badge fetches, API-key calls).
# These are the ONLY new instrumentation; everything else reads stored rows.
# ---------------------------------------------------------------------------
_METRICS_PREFIX = "ag:metrics:"
_COUNTER_TTL = 60 * 60 * 24 * 45  # keep ~45 days of daily counters


async def bump_metric(name: str) -> None:
    """Increment today's counter for ``name``. Best-effort — never raises.

    Safe to call from hot public paths (badge render, API-key auth): a Redis
    outage is swallowed and the request proceeds unaffected.

    Inside a request the bump first asks ``src.usage_scope.admit``: a redirect or
    a legacy-host request is not usage and the bump is dropped (or queued until
    the response status is known). Outside a request it always counts.
    """
    from src.usage_scope import admit

    if not admit(name):
        return
    try:
        from src.redis_client import get_redis

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"{_METRICS_PREFIX}{name}:{day}"
        r = get_redis()
        await r.incr(key)
        await r.expire(key, _COUNTER_TTL)
    except Exception:
        pass


async def bump_metric_by_client(name: str, user_agent: str | None) -> None:
    """Increment ``name`` and ``name:client:<human|agent|automated>`` for the caller.

    The aggregate counter is unchanged, so existing readers keep working; the
    per-class counters let the dashboard separate people and agents from the
    crawlers, monitors and scripts that otherwise pass as usage.
    """
    from src.traffic_class import classify_user_agent

    await bump_metric(name)
    await bump_metric(f"{name}:client:{classify_user_agent(user_agent)}")


async def _read_client_split(name: str, day_strs: list[str]) -> dict[str, int]:
    """``{total, human, agent, automated}`` for ``name`` over the window."""
    from src.traffic_class import CLIENT_CLASSES

    out = {"total": sum((await _read_daily_counter(name, day_strs)).values())}
    for cls in CLIENT_CLASSES:
        out[cls] = sum((await _read_daily_counter(f"{name}:client:{cls}", day_strs)).values())
    return out


# ---------------------------------------------------------------------------
# Unique human visitors per UTC day — a salted HyperLogLog.
#
# Method: for every request the User-Agent classifies as ``human``
# (src/traffic_class) and that counts as usage (src/usage_scope), the member
# ``sha256(daily_salt || client_ip || user_agent)`` is PFADDed to the day's HLL.
# The salt is 16 random bytes, created on first use with SET NX, kept only in
# Redis under a 48-hour TTL, and never logged — so the HLL holds no raw IP or
# UA, and once the salt expires nothing in it can be re-derived. Each day has
# its own salt, so the same person hashes differently on different days and
# days cannot be joined: ``unique_humans`` over a window is the union of the
# daily HLLs, which is the SUM of each day's distinct humans (one person on
# three days counts three). Reads degrade to 0 when Redis is unavailable.
# ---------------------------------------------------------------------------
_HUMANS_PREFIX = f"{_METRICS_PREFIX}unique_humans:"
_HUMANS_SALT_TTL = 60 * 60 * 48
_salt_cache: dict[str, str] = {}  # {day: salt}; one entry, in-process only


async def _daily_salt(r, day: str) -> str | None:
    """Today's salt: from the in-process cache, else Redis, else freshly minted
    (SET NX so concurrent workers agree). None when Redis is unavailable."""
    cached = _salt_cache.get(day)
    if cached:
        return cached
    key = f"{_HUMANS_PREFIX}salt:{day}"
    salt = await r.get(key)
    if not salt:
        candidate = secrets.token_hex(16)
        if await r.set(key, candidate, nx=True, ex=_HUMANS_SALT_TTL):
            salt = candidate
        else:
            salt = await r.get(key)
    if isinstance(salt, bytes):
        salt = salt.decode()
    if salt:
        _salt_cache.clear()
        _salt_cache[day] = salt
    return salt or None


async def record_human_visitor(client_ip: str | None, user_agent: str | None) -> None:
    """PFADD this human request's salted identity to today's HLL. Best-effort —
    never raises, and stores nothing that identifies the visitor (see above).
    The caller is responsible for the ``human`` classification and usage scope."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        salt = await _daily_salt(r, day)
        if not salt:
            return
        raw = f"{salt}|{client_ip or ''}|{user_agent or ''}".encode("utf-8", "ignore")
        key = f"{_HUMANS_PREFIX}{day}"
        await r.pfadd(key, hashlib.sha256(raw).hexdigest())
        await r.expire(key, _COUNTER_TTL)
    except Exception:
        pass


async def _read_unique_humans(day_strs: list[str]) -> int:
    """PFCOUNT over the window's daily HLLs (missing days count 0). 0 on failure."""
    if not day_strs:
        return 0
    try:
        from src.redis_client import get_redis

        r = get_redis()
        return int(await r.pfcount(*[f"{_HUMANS_PREFIX}{d}" for d in day_strs]))
    except Exception:
        return 0


# Distinct callers per UTC day for any named metric — the same salted HLL as
# ``unique_humans`` (same daily salt, same privacy properties: nothing stored can
# name a machine, days cannot be joined), keyed by a metric name so the dashboard
# can say "N distinct machines invoked the connector from Claude Code today"
# rather than "N calls". A caller is sha256(daily salt | client IP | User-Agent).
# Limitation: traffic that reaches us through a vendor proxy (the claude.ai
# connector arrives from a few Anthropic egress IPs with one User-Agent) collapses
# to a handful of callers; the direct surfaces (Claude Code, Cursor, the hook)
# are per-machine and read true.
_UNIQ_PREFIX = f"{_METRICS_PREFIX}uniq:"


async def record_unique(name: str, client_ip: str | None, user_agent: str | None) -> None:
    """PFADD this caller's salted identity to today's HLL for ``name``. Best-effort —
    never raises, stores nothing identifying (see ``record_human_visitor``)."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        salt = await _daily_salt(r, day)
        if not salt:
            return
        raw = f"{salt}|{client_ip or ''}|{user_agent or ''}".encode("utf-8", "ignore")
        key = f"{_UNIQ_PREFIX}{name}:{day}"
        await r.pfadd(key, hashlib.sha256(raw).hexdigest())
        await r.expire(key, _COUNTER_TTL)
    except Exception:
        pass


# The Claude Code plugin's session-start hook identifies itself as
# ``agentavow-precheck/<version> (plugin|manual)``. Its scans go through the
# public scan API and never touch the MCP tool counters; and most of what it
# grades is already cached, so it is counted from the request middleware
# (src/usage_scope) on EVERY scan request, not from the cache-miss path.
HOOK_UA_PREFIX = "agentavow-precheck"
HOOK_PATH_PREFIX = "/api/v1/public/scan"


def is_hook_request(path: str | None, user_agent: str | None) -> bool:
    return bool(
        path and path.startswith(HOOK_PATH_PREFIX)
        and (user_agent or "").strip().lower().startswith(HOOK_UA_PREFIX)
    )


async def record_hook_checkin(client_ip: str | None, user_agent: str | None) -> None:
    """One hook scan today, on one more distinct machine (salted per-day HLL, nothing
    identifying stored). Best-effort — never raises."""
    try:
        await bump_metric("hook_scan")
        await record_unique("hook:machines", client_ip, user_agent)
    except Exception:
        pass


async def _read_unique_by_day(name: str, day_strs: list[str]) -> dict[str, int]:
    """``{day: distinct callers}`` for ``name`` (missing days 0; {} on failure).
    Each day is counted on its own: salts differ per day, so a window total is
    the SUM of days, like ``unique_humans``."""
    if not day_strs:
        return {}
    try:
        from src.redis_client import get_redis

        r = get_redis()
        out: dict[str, int] = {}
        for d in day_strs:
            out[d] = int(await r.pfcount(f"{_UNIQ_PREFIX}{name}:{d}"))
        return out
    except Exception:
        return {}


async def _read_daily_counter(name: str, day_strs: list[str]) -> dict[str, int]:
    """Return ``{day: count}`` for the given days. Best-effort ({} on failure)."""
    if not day_strs:
        return {}
    try:
        from src.redis_client import get_redis

        r = get_redis()
        keys = [f"{_METRICS_PREFIX}{name}:{d}" for d in day_strs]
        vals = await r.mget(keys)
        return {d: (int(v) if v is not None else 0) for d, v in zip(day_strs, vals)}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utc_date_expr(col):
    """date() of a tz-aware column, normalized to UTC so it aligns with the
    UTC day strings we build in Python (independent of DB session timezone).

    'UTC' is emitted as a SQL literal (not a bind param) so the expression renders
    byte-identically in both the SELECT and GROUP BY clauses — otherwise Postgres
    sees two distinct bind params and raises GroupingError."""
    return func.date(func.timezone(literal_column("'UTC'"), col))


# The distribution buckets ARE the six trust tiers (src/trust_tiers.py): one bucket per
# tier at its floor, keyed by the API's `trust_tier` value. Highest tier first — the
# first floor the score clears wins, exactly as tier_for_score() does in Python.
_TIER_CASE = case(
    *[(CommunityScan.trust_score >= t.floor, t.value) for t in TIERS[:-1]],
    else_=TIERS[-1].value,
)

_TIER_ORDER = [t.value for t in TIERS]

# The three-phrase headline over the same corpus, from what a catalog row stores (the
# blocking critical / high counts + the score): the `decide()` rule without the inputs
# a row does not keep (advisories, deprecation, coverage, sandbox), so it is the
# catalog's view, matching CatalogRow.decision.
_DECISION_CASE = case(
    (func.coalesce(CommunityScan.critical, 0) > 0, "do_not_connect"),
    (func.coalesce(CommunityScan.high, 0) > 0, "review"),
    (CommunityScan.trust_score < 51, "review"),
    else_="safe",
)
_DECISION_ORDER = ["safe", "review", "do_not_connect"]


def metrics_baseline() -> dict:
    """The counting rules, one sentence each, and the date they took effect.

    Shown on the dashboard so the step change in every usage line on
    ``RULES_CHANGED_ON`` reads as what it is — a rule change — not a drop.
    """
    return {
        "rules_changed_on": RULES_CHANGED_ON,
        "rules": [
            "Redirects (301/302/308) are not usage: they reach no counter and are "
            "tallied once as 'requests_redirected'.",
            "Requests whose Host is a retired domain (" + ", ".join(sorted(LEGACY_HOSTS))
            + ") are not usage, whatever their status.",
            "Humans = a real browser User-Agent; agents = Claude, ChatGPT, Perplexity, "
            "Cursor, VS Code, the plugin hook and README badge renders; everything else "
            "(crawlers, monitors, scripts, vendor index bots) is automated.",
            "Unique humans = distinct sha256(daily random salt + IP + UA) per UTC day in "
            "a HyperLogLog; the salt lives 48h in Redis only, so days cannot be joined "
            "and a window is the sum of its days.",
        ],
    }


async def _aggregate(db: AsyncSession, window: str) -> dict:
    n_days = _WINDOW_DAYS[window]
    # Site-wide distinct checkers over the window (HLL union) — real reach, no raw IPs.
    try:
        from src.scanner.adoption_sources import get_global_unique_checkers
        unique_checkers_window = await get_global_unique_checkers(n_days)
    except Exception:
        unique_checkers_window = 0
    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(n_days - 1, -1, -1)]  # ascending
    day_strs = [d.isoformat() for d in days]
    cutoff = datetime(days[0].year, days[0].month, days[0].day, tzinfo=timezone.utc)

    # --- Scans (community_scans: one upserted row per repo) ---
    scans_total_alltime = await db.scalar(
        select(func.coalesce(func.sum(CommunityScan.scan_count), 0))
    ) or 0
    unique_repos_total = await db.scalar(
        select(func.count()).select_from(CommunityScan)
    ) or 0
    repos_scanned_window = await db.scalar(
        select(func.count()).select_from(CommunityScan).where(
            CommunityScan.last_scanned_at >= cutoff
        )
    ) or 0
    new_repos_window = await db.scalar(
        select(func.count()).select_from(CommunityScan).where(
            CommunityScan.first_scanned_at >= cutoff
        )
    ) or 0

    # Trust-tier distribution over the live scanned corpus (single grouped query).
    # The response key stays `grade_distribution`; its keys are the six tier values.
    grade_rows = (
        await db.execute(
            select(_TIER_CASE.label("tier"), func.count().label("cnt"))
            .where(CommunityScan.trust_score.isnot(None))
            .group_by(_TIER_CASE)
        )
    ).all()
    grade_map = {g: c for g, c in grade_rows}
    grade_distribution = {g: int(grade_map.get(g, 0)) for g in _TIER_ORDER}
    decision_rows = (
        await db.execute(
            select(_DECISION_CASE.label("decision"), func.count().label("cnt"))
            .where(CommunityScan.trust_score.isnot(None))
            .group_by(_DECISION_CASE)
        )
    ).all()
    _dmap = {d: c for d, c in decision_rows}
    decision_distribution = {d: int(_dmap.get(d, 0)) for d in _DECISION_ORDER}

    # --- Watches ---
    watches_created_window = await db.scalar(
        select(func.count()).select_from(ToolWatch).where(ToolWatch.created_at >= cutoff)
    ) or 0
    watches_active = await db.scalar(
        select(func.count()).select_from(ToolWatch).where(ToolWatch.active.is_(True))
    ) or 0
    watches_total = await db.scalar(
        select(func.count()).select_from(ToolWatch)
    ) or 0

    # --- API keys (usage volume not persisted per-key; see notes) ---
    api_keys_active = await db.scalar(
        select(func.count()).select_from(APIKey).where(APIKey.is_active.is_(True))
    ) or 0
    api_keys_created_window = await db.scalar(
        select(func.count()).select_from(APIKey).where(APIKey.created_at >= cutoff)
    ) or 0

    # --- Repo claims ---
    claims_created_window = await db.scalar(
        select(func.count()).select_from(RepoClaim).where(RepoClaim.created_at >= cutoff)
    ) or 0
    claims_verified_total = await db.scalar(
        select(func.count()).select_from(RepoClaim).where(RepoClaim.status == "verified")
    ) or 0
    # Public vs private claims (is_private is authoritative, set at claim time).
    claims_private = await db.scalar(
        select(func.count()).select_from(RepoClaim).where(
            RepoClaim.status == "verified", RepoClaim.is_private.is_(True)
        )
    ) or 0
    claims_public = await db.scalar(
        select(func.count()).select_from(RepoClaim).where(
            RepoClaim.status == "verified", RepoClaim.is_private.is_(False)
        )
    ) or 0
    # Private-repo scanning: GitHub-App path (stored, source="app") + published-to-
    # search + active installs. One-time token scans are ephemeral → Redis counter.
    private_scans_app = await db.scalar(
        select(func.count()).select_from(PrivateScanResult).where(PrivateScanResult.source == "app")
    ) or 0
    private_published = await db.scalar(
        select(func.count()).select_from(PrivateScanResult).where(PrivateScanResult.published.is_(True))
    ) or 0
    app_installs_active = await db.scalar(
        select(func.count()).select_from(GitHubAppInstallation).where(
            GitHubAppInstallation.revoked_at.is_(None)
        )
    ) or 0
    onetime_by_day = await _read_daily_counter("private_scan_onetime", day_strs)
    private_scans_onetime_window = sum(onetime_by_day.values())

    # --- Alert webhooks ---
    alert_webhooks_active = await db.scalar(
        select(func.count()).select_from(AlertWebhook).where(AlertWebhook.active.is_(True))
    ) or 0

    # --- Attestations issued (persisted rows; scan JWS are signed on the fly) ---
    attestations_window = await db.scalar(
        select(func.count()).select_from(FormalAttestation).where(
            FormalAttestation.is_revoked.is_(False),
            FormalAttestation.created_at >= cutoff,
        )
    ) or 0
    attestations_total = await db.scalar(
        select(func.count()).select_from(FormalAttestation).where(
            FormalAttestation.is_revoked.is_(False)
        )
    ) or 0
    badges_issued_total = await db.scalar(
        select(func.count()).select_from(VerificationBadge).where(
            VerificationBadge.is_active.is_(True)
        )
    ) or 0

    # --- Redis-backed counters (badge fetches, API-key calls, + v2 signals) ---
    badge_by_day = await _read_daily_counter("badge_fetch", day_strs)
    readme_render_by_day = await _read_daily_counter("badge_render_readme", day_strs)
    api_call_by_day = await _read_daily_counter("api_call", day_strs)
    adoption_by_day = await _read_daily_counter("adoption_hit", day_strs)
    rescan_by_day = await _read_daily_counter("force_rescan", day_strs)
    install_by_day = await _read_daily_counter("install_click", day_strs)
    # Redirects and legacy-host requests never reach a usage counter
    # (src/usage_scope); they are counted once here so the junk volume stays visible.
    redirected_by_day = await _read_daily_counter(REDIRECTED_METRIC, day_strs)
    requests_redirected_window = sum(redirected_by_day.values())
    # Distinct people (browser UA) per day, salted HLL — see record_human_visitor.
    unique_humans_window = await _read_unique_humans(day_strs)
    badge_fetches_window = sum(badge_by_day.values())
    readme_renders_window = sum(readme_render_by_day.values())
    # Who is calling: the same counters split by client class (src/traffic_class).
    # Counting started when the split shipped, so "total" here can trail the
    # aggregate counters above for the first window.
    scan_requests_by_client = await _read_client_split("scan_request", day_strs)
    badge_fetches_by_client = await _read_client_split("badge_fetch", day_strs)
    # "Badges rendering in READMEs" leaderboard (cumulative, all-time) — the live
    # adoption-proof list + warmest re-outreach targets.
    from src.scanner.adoption_sources import get_readme_badge_leaderboard
    readme_leaderboard = await get_readme_badge_leaderboard(15)
    api_calls_window = sum(api_call_by_day.values())
    adoption_hits_window = sum(adoption_by_day.values())
    force_rescans_window = sum(rescan_by_day.values())
    install_clicks_window = sum(install_by_day.values())

    # --- MCP Directory connector usage (fail-open counters from src/bridges/mcp_streamable) ---
    mcp_tools = [
        "scan_repo", "scan_package", "scan_mcp_server", "verify_trust",
        "check_interaction_safety", "lookup_identity", "get_trust_badge",
    ]
    mcp_calls_by_day = await _read_daily_counter("mcp:calls:total", day_strs)
    mcp_calls_window = sum(mcp_calls_by_day.values())
    mcp_errors_window = sum((await _read_daily_counter("mcp:result:error", day_strs)).values())
    mcp_safe_window = sum((await _read_daily_counter("mcp:verdict:safe", day_strs)).values())
    mcp_review_window = sum(
        (await _read_daily_counter("mcp:verdict:needs_review", day_strs)).values()
    )
    mcp_by_tool = {
        t: sum((await _read_daily_counter(f"mcp:tool:{t}", day_strs)).values())
        for t in mcp_tools
    }
    # Per-surface attribution (from the request User-Agent, tagged in
    # src/bridges/mcp_streamable._bump_s). Surfaces sum back to the aggregate.
    mcp_surfaces = ["claude", "chatgpt", "claude-code", "cursor", "vscode", "other"]
    # Per-day calls and distinct callers per surface (the trend lines). Callers come
    # from the salted per-day HLL fed by src/bridges/mcp_streamable._record_caller.
    mcp_calls_by_surface_day = {
        s: await _read_daily_counter(f"mcp:calls:total:{s}", day_strs) for s in mcp_surfaces
    }
    mcp_callers_by_surface_day = {
        s: await _read_unique_by_day(f"mcp:callers:{s}", day_strs) for s in mcp_surfaces
    }
    mcp_callers_by_day = await _read_unique_by_day("mcp:callers", day_strs)
    mcp_callers_window = sum(mcp_callers_by_day.values())
    # The Claude Code plugin's session-start hook grades servers through the public
    # scan API (never the MCP tool counter), so it is its own adoption signal: scans
    # it ran, and distinct machines it ran on.
    hook_scans_by_day = await _read_daily_counter("hook_scan", day_strs)
    hook_machines_by_day = await _read_unique_by_day("hook:machines", day_strs)
    from src.traffic_class import CLIENT_CLASSES

    scan_requests_by_class_day = {
        c: await _read_daily_counter(f"scan_request:client:{c}", day_strs) for c in CLIENT_CLASSES
    }
    mcp_by_surface = {
        s: {
            "calls": sum(mcp_calls_by_surface_day[s].values()),
            "callers": sum(mcp_callers_by_surface_day[s].values()),
            "errors": sum(
                (await _read_daily_counter(f"mcp:result:error:{s}", day_strs)).values()
            ),
            "safe": sum(
                (await _read_daily_counter(f"mcp:verdict:safe:{s}", day_strs)).values()
            ),
            "needs_review": sum(
                (await _read_daily_counter(f"mcp:verdict:needs_review:{s}", day_strs)).values()
            ),
        }
        for s in mcp_surfaces
    }

    # --- Daily time-series (grouped queries, then aligned to day_strs) ---
    async def _series_by_date(date_col) -> dict[str, int]:
        day_expr = _utc_date_expr(date_col)
        rows = (
            await db.execute(
                select(day_expr.label("d"), func.count().label("cnt"))
                .where(date_col >= cutoff)
                .group_by(day_expr)
            )
        ).all()
        out: dict[str, int] = {}
        for d, cnt in rows:
            key = d.isoformat() if hasattr(d, "isoformat") else str(d)
            out[key] = int(cnt)
        return out

    repos_scanned_by_day = await _series_by_date(CommunityScan.last_scanned_at)
    new_repos_by_day = await _series_by_date(CommunityScan.first_scanned_at)
    watches_by_day = await _series_by_date(ToolWatch.created_at)

    def _align(d: dict[str, int]) -> list[int]:
        return [int(d.get(ds, 0)) for ds in day_strs]

    series = {
        "repos_scanned": _align(repos_scanned_by_day),
        "new_repos": _align(new_repos_by_day),
        "watches_created": _align(watches_by_day),
        "badge_fetches": _align(badge_by_day),
        "api_calls": _align(api_call_by_day),
        "adoption_hits": _align(adoption_by_day),
        "force_rescans": _align(rescan_by_day),
        "install_clicks": _align(install_by_day),
        "requests_redirected": _align(redirected_by_day),
        # Adoption trend lines (daily). ``mcp_callers*`` and ``hook_machines`` are
        # distinct machines per day; the rest are request counts.
        "mcp_calls": _align(mcp_calls_by_day),
        "mcp_callers": _align(mcp_callers_by_day),
        "hook_scans": _align(hook_scans_by_day),
        "hook_machines": _align(hook_machines_by_day),
    }
    for s_name in mcp_surfaces:
        series[f"mcp_calls:{s_name}"] = _align(mcp_calls_by_surface_day[s_name])
        series[f"mcp_callers:{s_name}"] = _align(mcp_callers_by_surface_day[s_name])
    for c_name in CLIENT_CLASSES:
        series[f"scan_requests:{c_name}"] = _align(scan_requests_by_class_day[c_name])

    # --- Surface breakdown: static launch corpus + live community scans ---
    surface_breakdown: dict[str, int] = {}
    category_breakdown: dict[str, int] = {}
    catalog_static_total = 0
    try:
        from src.api.scan_catalog_router import _get_catalog

        cat = _get_catalog()
        surface_breakdown = dict(cat["summary"].by_surface)
        catalog_static_total = int(cat["summary"].total_scans)
        category_breakdown = dict(cat.get("static_cats") or {})
    except Exception:
        category_breakdown = {}
    surface_breakdown["community"] = int(unique_repos_total)
    catalog_size_total = catalog_static_total + int(unique_repos_total)

    notes = [
        "Scans are stored as one upserted row per repo (community_scans): "
        "'repos scanned' counts distinct repos touched in the window; "
        "'scans (all-time)' sums per-repo scan_count.",
        "Live on-demand scans are GitHub repos (the 'community' surface). "
        "Per-surface counts for x402/mcp/npm/pypi/openclaw come from the static "
        "launch corpus (data/launch-scans/*.json).",
        "Badge fetches and API-key calls are counted via best-effort Redis day "
        "counters added with this dashboard — they start at deploy time and have "
        "NO historical backfill. Zero can mean 'no traffic' or 'counter not yet "
        "deployed'.",
        "Per-key API call volume is not otherwise persisted (rate limiting is "
        "ephemeral in Redis); only active/created key counts come from the DB.",
        "Grade distribution is over the live scanned corpus (community_scans), "
        "not the static launch corpus.",
        "MCP connector metrics come from fail-open Redis day counters in the "
        "Streamable-HTTP server (src/bridges/mcp_streamable): total calls, per-tool "
        "calls, safe/needs-review scan verdicts, and errors. Ok = total - errors. "
        "No backfill; zero means no connector traffic yet.",
        "Since " + RULES_CHANGED_ON + " a 301/302/308 response, or any request whose "
        "Host is a retired domain (" + ", ".join(sorted(LEGACY_HOSTS)) + "), is not "
        "usage: it reaches no counter above and is tallied once as "
        "'requests_redirected'. Only redirects the backend itself serves are seen "
        "here; the ones nginx answers never reach the app.",
        "'mcp_callers' (total and per surface) and 'hook_machines' are distinct "
        "callers per UTC day from the same salted HyperLogLog as unique_humans: "
        "sha256(daily salt + IP + User-Agent). Over a window they are the sum of each "
        "day's distinct callers. Surfaces that arrive through a vendor proxy (the "
        "claude.ai connector) share a few IPs and one User-Agent, so their caller "
        "count is a floor; Claude Code, Cursor and the hook are per-machine. "
        "'hook_scans' / 'hook_machines' count the Claude Code plugin's session-start "
        "hook (User-Agent agentavow-precheck) grading servers through the public scan "
        "API — automated use that the MCP call counters never see.",
        "'unique_humans' is distinct browser-UA visitors per UTC day from a salted "
        "HyperLogLog: sha256(daily random salt + IP + UA), salt kept only in Redis "
        "for 48h and never logged. Days cannot be joined, so over a window it is the "
        "sum of each day's distinct people. 0 when Redis is unavailable.",
    ]

    return {
        "window": window,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days": day_strs,
        "headline": {
            "repos_scanned": int(repos_scanned_window),
            "new_repos": int(new_repos_window),
            "watches_created": int(watches_created_window),
            "badge_fetches": int(badge_fetches_window),
            "readme_renders": int(readme_renders_window),
            "attestations_issued": int(attestations_window),
            "api_calls": int(api_calls_window),
            "adoption_hits": int(adoption_hits_window),
            "force_rescans": int(force_rescans_window),
            "install_clicks": int(install_clicks_window),
            "unique_checkers": int(unique_checkers_window),
            "mcp_calls": int(mcp_calls_window),
            "mcp_callers": int(mcp_callers_window),
            "hook_scans": int(sum(hook_scans_by_day.values())),
            "hook_machines": int(sum(hook_machines_by_day.values())),
            "requests_redirected": int(requests_redirected_window),
            "unique_humans": int(unique_humans_window),
        },
        "scans": {
            "repos_scanned_window": int(repos_scanned_window),
            "new_repos_window": int(new_repos_window),
            "unique_repos_total": int(unique_repos_total),
            "scans_total_alltime": int(scans_total_alltime),
            "grade_distribution": grade_distribution,
            "decision_distribution": decision_distribution,
        },
        "watches": {
            "created_window": int(watches_created_window),
            "active": int(watches_active),
            "total": int(watches_total),
        },
        "api_keys": {
            "active": int(api_keys_active),
            "created_window": int(api_keys_created_window),
            "calls_window": int(api_calls_window),
        },
        "attestations": {
            "issued_window": int(attestations_window),
            "issued_total": int(attestations_total),
            "verification_badges_active": int(badges_issued_total),
        },
        "claims": {
            "created_window": int(claims_created_window),
            "verified_total": int(claims_verified_total),
            "public": int(claims_public),
            "private": int(claims_private),
        },
        "private_repos": {
            "app_scans": int(private_scans_app),
            "published_to_search": int(private_published),
            "app_installs_active": int(app_installs_active),
            "onetime_scans_window": int(private_scans_onetime_window),
        },
        "mcp": {
            "calls_window": int(mcp_calls_window),
            "callers_window": int(mcp_callers_window),
            "errors_window": int(mcp_errors_window),
            "ok_window": int(max(0, mcp_calls_window - mcp_errors_window)),
            "safe_window": int(mcp_safe_window),
            "needs_review_window": int(mcp_review_window),
            "by_tool": {t: int(n) for t, n in mcp_by_tool.items()},
            "by_surface": {
                s: {k: int(v) for k, v in d.items()} for s, d in mcp_by_surface.items()
            },
        },
        "alert_webhooks": {"active": int(alert_webhooks_active)},
        # Humans vs agents vs automation, from the User-Agent. "automated" is the
        # crawlers, monitors and scripts; the honest usage number is total minus it.
        "traffic_quality": {
            "scan_requests": scan_requests_by_client,
            "badge_fetches": badge_fetches_by_client,
        },
        "badges": {
            "fetches_window": int(badge_fetches_window),
            "readme_renders_window": int(readme_renders_window),
            "leaderboard": [
                {"repo": repo, "renders": renders} for repo, renders in readme_leaderboard
            ],
        },
        "catalog": {
            "size_total": int(catalog_size_total),
            "community_scans": int(unique_repos_total),
            "static_corpus": int(catalog_static_total),
            "by_surface": surface_breakdown,
            "by_category": category_breakdown,
        },
        # The Claude Code plugin's session-start hook: scans it ran + machines it ran on.
        "hook": {
            "scans_window": int(sum(hook_scans_by_day.values())),
            "machines_window": int(sum(hook_machines_by_day.values())),
        },
        # Adoption funnel — how far users travel: scan → watch → claim (the drop-off).
        "funnel": {
            "scanned": int(repos_scanned_window),
            "watched": int(watches_created_window),
            "claimed": int(claims_created_window),
            "installs": int(install_clicks_window),
        },
        "series": series,
        "notes": notes,
        # The counting rules + the date they changed, so the trend break is explained.
        "baseline": metrics_baseline(),
    }


@router.get("/metrics", dependencies=[Depends(rate_limit_reads)])
async def engagement_metrics(
    window: str = Query("7d", pattern="^(today|7d|30d)$"),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Engagement / usage metrics over a selectable window. Admin only.

    Every number is backed by stored data (community_scans, tool_watches,
    repo_claims, alert_webhooks, api_keys, formal_attestations) except badge
    fetches / API-key calls, which come from best-effort Redis day counters.
    """
    require_admin(current_entity)

    from src import cache

    cache_key = f"admin:metrics:{window}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    result = await _aggregate(db, window)
    await cache.set(cache_key, result, ttl=cache.TTL_SHORT)
    return result


# ---------------------------------------------------------------------------
# Behavioral sandbox counters (written by src/api/public_scan_router.py).
# Daily keys carry a ``:<YYYY-MM-DD>`` (UTC) suffix; lifetime totals have none.
# Readers here are defensive: a missing key is 0, a malformed value is 0.
# ---------------------------------------------------------------------------
BEHAVIORAL_PREFIX = f"{_METRICS_PREFIX}behavioral:"
BEHAVIORAL_DAILY = (
    "runs", "exercised", "with_findings", "canary_leaks", "slot_rejected",
    "cache_hit", "cache_miss", "killed", "duration_sum", "duration_max",
)
BEHAVIORAL_START_REASONS = (
    "started", "needs_credentials", "needs_arguments", "missing_binary",
    "install_failed", "resource_limit", "no_entrypoint", "timeout", "crashed",
    "unknown", "not_applicable",
)
BEHAVIORAL_RULES = (
    "behavioral_undeclared_egress", "annotation_readonly_violated",
    "annotation_open_world_violated", "credential_canary_exfiltrated",
    "canary_echoed_in_result", "tool_call_crashed_server", "cloud_metadata_probe",
)
BEHAVIORAL_TOTALS = ("runs", "exercised", "tools_called", "findings", "canary_leaks")


def _num(v: object) -> float:
    """Redis value -> number; None, garbage or negatives read as 0."""
    if v is None:
        return 0.0
    try:
        if isinstance(v, bytes):
            v = v.decode()
        n = float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return n if n > 0 and n == n else 0.0  # drop negatives and NaN


def window_day_strs(n_days: int) -> list[str]:
    """The last ``n_days`` UTC dates, oldest first, as YYYY-MM-DD."""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=i)).isoformat() for i in range(n_days - 1, -1, -1)]


def behavioral_daily_names() -> list[str]:
    """Every daily counter name under ``behavioral:`` the readers know about."""
    return (
        list(BEHAVIORAL_DAILY)
        + [f"start:{r}" for r in BEHAVIORAL_START_REASONS]
        + [f"rule:{r}" for r in BEHAVIORAL_RULES]
    )


async def read_behavioral_counters(
    day_strs: list[str], daily: list[str], totals: tuple[str, ...] | list[str] = (),
) -> tuple[dict[str, list[float]], dict[str, float]]:
    """Read daily + lifetime behavioral counters in ONE Redis MGET.

    Returns ``(daily_values, totals)`` where ``daily_values[name]`` is aligned to
    ``day_strs``. On any Redis failure everything reads as 0.
    """
    keys = [f"{BEHAVIORAL_PREFIX}{name}:{d}" for name in daily for d in day_strs]
    keys += [f"{BEHAVIORAL_PREFIX}total:{t}" for t in totals]
    vals: list[object]
    try:
        from src.redis_client import get_redis

        vals = list(await get_redis().mget(keys)) if keys else []
        if len(vals) != len(keys):
            vals = [None] * len(keys)
    except Exception:
        vals = [None] * len(keys)
    n = len(day_strs)
    out_daily: dict[str, list[float]] = {}
    for i, name in enumerate(daily):
        out_daily[name] = [_num(v) for v in vals[i * n:(i + 1) * n]]
    base = len(daily) * n
    out_totals = {t: _num(vals[base + j]) for j, t in enumerate(totals)}
    return out_daily, out_totals


def behavioral_scaling_hint(runs: int, slot_rejected: int, killed: int) -> str:
    """'add capacity' when >5% of attempts were turned away for lack of a slot,
    'watch memory' when >10% of runs were killed, else 'ok'."""
    attempts = runs + slot_rejected
    if attempts and slot_rejected / attempts > 0.05:
        return "add capacity"
    if runs and killed / runs > 0.10:
        return "watch memory"
    return "ok"


BACKFILL_DAILY = ("attempted", "started", "deferred", "skipped")
TRIGGER_REASONS = ("version_change", "watch", "backfill")


async def _behavioral_backfill_block(day_strs: list[str]) -> dict:
    """Backfill progress (``ag:backfill:behavioral:progress``) + the window's backfill
    and trigger counters, for the ``backfill`` key of /admin/metrics/behavioral."""
    from src.jobs.behavioral_backfill import read_backfill_progress

    names = [f"backfill:{n}" for n in BACKFILL_DAILY]
    names += [f"trigger:{r}" for r in TRIGGER_REASONS]
    names += [f"trigger:{r}:started" for r in TRIGGER_REASONS]
    daily, _ = await read_behavioral_counters(day_strs, names)
    progress = await read_backfill_progress()

    def tot(name: str) -> int:
        return int(sum(daily.get(name, [])))

    total = int(progress.get("total_eligible") or 0)
    done = int(progress.get("done") or 0)
    return {
        **progress,
        "pct_done": round(100.0 * done / total, 1) if total else None,
        **{n: tot(f"backfill:{n}") for n in BACKFILL_DAILY},
        "triggers": {
            r: {"enqueued": tot(f"trigger:{r}"), "started": tot(f"trigger:{r}:started")}
            for r in TRIGGER_REASONS
        },
        "series": {n: [int(v) for v in daily[f"backfill:{n}"]] for n in ("started", "deferred")},
    }


async def _behavioral_aggregate(window: str) -> dict:
    from src.config import settings

    day_strs = window_day_strs(_WINDOW_DAYS[window])
    daily, _ = await read_behavioral_counters(day_strs, behavioral_daily_names())

    def tot(name: str) -> int:
        return int(sum(daily.get(name, [])))

    runs = tot("runs")
    slot_rejected = tot("slot_rejected")
    killed = tot("killed")
    hits, misses = tot("cache_hit"), tot("cache_miss")
    duration_sum = sum(daily.get("duration_sum", []))
    duration_max = max(daily.get("duration_max", []) or [0.0])
    return {
        "window": window,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days": day_strs,
        "runs": runs,
        "exercised": tot("exercised"),
        "with_findings": tot("with_findings"),
        "canary_leaks": tot("canary_leaks"),
        "slot_rejected": slot_rejected,
        "killed": killed,
        "cache_hits": hits,
        "cache_misses": misses,
        "cache_hit_rate": round(hits / (hits + misses), 3) if hits + misses else None,
        "avg_duration_s": round(duration_sum / runs, 1) if runs else None,
        "max_duration_s": round(duration_max, 1) if duration_max else None,
        "start_reasons": {r: tot(f"start:{r}") for r in BEHAVIORAL_START_REASONS},
        "findings_by_rule": {r: tot(f"rule:{r}") for r in BEHAVIORAL_RULES},
        "series": {
            k: [int(v) for v in daily[k]] for k in ("runs", "exercised", "slot_rejected")
        },
        "concurrency_limit": int(
            getattr(settings, "scanner_behavioral_max_concurrent", 2) or 2
        ),
        "scaling_hint": behavioral_scaling_hint(runs, slot_rejected, killed),
        "backfill": await _behavioral_backfill_block(day_strs),
        "last_eval": await _last_eval(),
        "corpus": await _eval_corpus(),
    }


async def _last_eval() -> dict | None:
    """The latest scheduled-eval report minus its rows, plus whether one is running.
    Never raises: a Redis outage reads as no report."""
    try:
        from src.jobs import behavioral_eval as be

        summary = be.report_summary(await be.read_latest())
        running = await be.is_running()
    except Exception:
        return None
    if summary is None and not running:
        return None
    return dict(summary or {}, running=running)


async def _eval_corpus() -> list[dict]:
    try:
        from src.jobs import behavioral_eval as be

        return await be.corpus_view()
    except Exception:
        return []


@router.get("/metrics/behavioral", dependencies=[Depends(rate_limit_reads)])
async def behavioral_metrics(
    window: str = Query("7d", pattern="^(today|7d|30d)$"),
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Behavioral sandbox health over a window. Admin only.

    Runs, exercised servers, findings, canary leaks, slot rejections (runs turned
    away because every sandbox slot was busy), killed runs, cache hit rate,
    durations, start-reason and finding-rule breakdowns, a per-day series, and a
    ``scaling_hint`` ('add capacity' | 'watch memory' | 'ok'). One Redis MGET.
    """
    require_admin(current_entity)
    return await _behavioral_aggregate(window)


_TRAFFIC_PREFIX = f"{_METRICS_PREFIX}traffic:"
_TRAFFIC_INT_COLUMNS = (
    "cc_machines", "cc_new_machines_30d", "cc_reqs", "cc_sessions", "claudeai_reqs",
    "claudeai_ips", "hook_machines_nginx", "hook_reqs", "gate_machines",
    "preinstall_machines", "scans_200", "badges_200", "calls_claude", "callers_claude",
    "calls_claude_code", "callers_claude_code", "calls_chatgpt", "callers_chatgpt",
    "calls_other", "callers_other", "calls_total", "hook_machines_hll",
    "owner_cc_reqs", "owner_cc_sessions", "owner_hook_reqs", "owner_scans_200",
    "cc_machines_excl_owner", "hook_machines_excl_owner", "log_complete",
)
_TRAFFIC_NOTES = [
    "Claude-origin traffic per UTC day, written once a day by scripts/ops/"
    "anthropic_traffic_snapshot.py on the prod host (cron 00:40 UTC for the previous day); "
    "kept in Redis without expiry so the series outlives the 4-day nginx log window.",
    "cc_machines = distinct client IPs that POSTed /mcp with a claude-code/* user agent "
    "(Claude Code connecting the plugin's MCP server); cc_new_machines_30d = not seen in "
    "the previous 30 days (salted hashes, no IPs stored). These are nginx-origin counts, "
    "NOT the Redis tool-call counters shown elsewhere on this page.",
    "claudeai_reqs = requests from the claude.ai connector (Claude-User UA, via Anthropic's "
    "proxy, so claudeai_ips is a floor). hook_machines_nginx = distinct IPs running the "
    "plugin's session-start hook; hook_machines_hll = the same from the salted HLL.",
    "calls_*/callers_* = real MCP tool invocations and distinct machines per surface (the "
    "same Redis counters as the MCP panel). owner_* and *_excl_owner strip IPs listed in "
    "data/owner-ips.txt on the host (Kenne's test machines).",
    "log_complete = 0 means the nginx log did not cover all 24 hours of that day (partial "
    "day or a log rotation gap); treat that row as a lower bound.",
]


async def _traffic_rows(n_days: int) -> tuple[list[str], list[dict]]:
    """``(days, rows)`` for the last ``n_days`` UTC days from the durable traffic hashes.
    Missing days are absent from ``rows`` (never fabricated). Fail-open: ([], [])."""
    days = window_day_strs(n_days)
    rows: list[dict] = []
    try:
        from src.redis_client import get_redis

        r = get_redis()
        for day in days:
            raw = await r.hgetall(f"{_TRAFFIC_PREFIX}{day}")
            if not raw:
                continue
            row: dict = {"day": day}
            for k, v in raw.items():
                key = k.decode() if isinstance(k, bytes) else str(k)
                val = v.decode() if isinstance(v, bytes) else str(v)
                if key in _TRAFFIC_INT_COLUMNS:
                    try:
                        row[key] = int(float(val)) if val != "" else None
                    except ValueError:
                        row[key] = None
                elif key != "day":
                    row[key] = val
            rows.append(row)
    except Exception:
        logging.getLogger(__name__).exception("traffic rows unavailable")
        return [], []
    return days, rows


@router.get("/metrics/traffic", dependencies=[Depends(rate_limit_reads)])
async def traffic_metrics(
    days: int = Query(30, ge=1, le=366),
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Durable Claude-origin traffic series (machines connecting, claude.ai connector
    requests, plugin-hook machines, tool calls + distinct callers by surface), one row per
    UTC day, for the admin dashboard. Admin only. See ``notes`` for what each column counts
    and why it differs from the live MCP counters."""
    require_admin(current_entity)
    day_strs, rows = await _traffic_rows(days)
    by_day = {r["day"]: r for r in rows}
    series = {
        col: [by_day.get(d, {}).get(col) for d in day_strs]
        for col in ("cc_machines", "cc_new_machines_30d", "cc_sessions", "claudeai_reqs",
                    "hook_machines_nginx", "hook_reqs", "calls_claude_code",
                    "callers_claude_code", "calls_claude", "callers_claude", "calls_chatgpt",
                    "cc_machines_excl_owner", "hook_machines_excl_owner")
    }
    latest = rows[-1] if rows else None
    return {
        "days": day_strs,
        "rows": rows,
        "series": series,
        "latest": latest,
        "covered_days": len(rows),
        "notes": _TRAFFIC_NOTES,
    }


_EVAL_TASKS: set[asyncio.Task] = set()


@router.post("/metrics/behavioral/eval", status_code=202,
             dependencies=[Depends(rate_limit_writes)])
async def trigger_behavioral_eval(
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Start a behavioral eval run now (fixtures + known-good corpus through the
    sandbox). Admin only. 202 when queued; 409 when a run is already in progress.
    The run holds one sandbox slot at a time and takes tens of minutes; the report
    lands in ``last_eval`` on ``GET /admin/metrics/behavioral``."""
    from src.jobs import behavioral_eval as be

    require_admin(current_entity)
    if not await be.mark_running():
        raise HTTPException(status_code=409, detail="A behavioral eval is already running")

    async def _run() -> None:
        try:
            await be.run_behavioral_eval(reason="admin", _already_marked=True)
        except Exception:
            logging.getLogger(__name__).exception("admin-triggered behavioral eval failed")

    # Detached from the request (a Starlette BackgroundTask is tied to it); the strong
    # reference keeps the task alive until it finishes.
    task = asyncio.create_task(_run(), name="behavioral-eval-admin")
    _EVAL_TASKS.add(task)
    task.add_done_callback(_EVAL_TASKS.discard)
    return {"status": "queued", "reason": "admin"}


class CorpusEdit(BaseModel):
    action: str = Field(pattern="^(add|remove)$")
    surface: str = Field(min_length=1, max_length=16)
    name: str | None = Field(default=None, max_length=200)
    repo: str | None = Field(default=None, max_length=200)
    expect_rules: list[str] = Field(default_factory=list, max_length=20)


@router.post("/metrics/behavioral/corpus", dependencies=[Depends(rate_limit_writes)])
async def edit_behavioral_corpus(
    body: CorpusEdit,
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Add or remove a known-good corpus entry (admin override kept in Redis, merged
    with the file corpus on every eval). ``surface`` is npm / pypi / skill; a skill
    is named by ``repo`` (owner/repo). ``expect_rules`` marks findings that are true,
    not false positives. Removing a file entry hides it; adding it back restores it."""
    from src.jobs import behavioral_eval as be

    require_admin(current_entity)
    name = (body.name or body.repo or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="name (or repo for a skill) is required")
    try:
        corpus = await be.apply_corpus_edit(
            body.action, body.surface, name,
            [r.strip() for r in body.expect_rules if r and r.strip()])
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=503, detail="corpus store unavailable") from e
    return {"corpus": corpus}
