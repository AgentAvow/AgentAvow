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
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads
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
    """
    try:
        from src.redis_client import get_redis

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"{_METRICS_PREFIX}{name}:{day}"
        r = get_redis()
        await r.incr(key)
        await r.expire(key, _COUNTER_TTL)
    except Exception:
        pass


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


_GRADE_CASE = case(
    (CommunityScan.trust_score >= 96, "A+"),
    (CommunityScan.trust_score >= 81, "A"),
    (CommunityScan.trust_score >= 61, "B"),
    (CommunityScan.trust_score >= 41, "C"),
    (CommunityScan.trust_score >= 21, "D"),
    else_="F",
)

_GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]


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

    # Grade distribution over the live scanned corpus (single grouped query).
    grade_rows = (
        await db.execute(
            select(_GRADE_CASE.label("grade"), func.count().label("cnt"))
            .where(CommunityScan.trust_score.isnot(None))
            .group_by(_GRADE_CASE)
        )
    ).all()
    grade_map = {g: c for g, c in grade_rows}
    grade_distribution = {g: int(grade_map.get(g, 0)) for g in _GRADE_ORDER}

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
    badge_fetches_window = sum(badge_by_day.values())
    readme_renders_window = sum(readme_render_by_day.values())
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
    mcp_by_surface = {
        s: {
            "calls": sum(
                (await _read_daily_counter(f"mcp:calls:total:{s}", day_strs)).values()
            ),
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
    }

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
        },
        "scans": {
            "repos_scanned_window": int(repos_scanned_window),
            "new_repos_window": int(new_repos_window),
            "unique_repos_total": int(unique_repos_total),
            "scans_total_alltime": int(scans_total_alltime),
            "grade_distribution": grade_distribution,
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
        # Adoption funnel — how far users travel: scan → watch → claim (the drop-off).
        "funnel": {
            "scanned": int(repos_scanned_window),
            "watched": int(watches_created_window),
            "claimed": int(claims_created_window),
            "installs": int(install_clicks_window),
        },
        "series": series,
        "notes": notes,
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
