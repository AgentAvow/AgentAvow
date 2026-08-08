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
from fastapi.responses import HTMLResponse
from sqlalchemy import case, func, select
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
    UTC day strings we build in Python (independent of DB session timezone)."""
    return func.date(func.timezone("UTC", col))


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

    # --- Redis-backed counters (badge fetches, API-key calls) ---
    badge_by_day = await _read_daily_counter("badge_fetch", day_strs)
    api_call_by_day = await _read_daily_counter("api_call", day_strs)
    badge_fetches_window = sum(badge_by_day.values())
    api_calls_window = sum(api_call_by_day.values())

    # --- Daily time-series (grouped queries, then aligned to day_strs) ---
    async def _series_by_date(date_col) -> dict[str, int]:
        rows = (
            await db.execute(
                select(_utc_date_expr(date_col).label("d"), func.count().label("cnt"))
                .where(date_col >= cutoff)
                .group_by(_utc_date_expr(date_col))
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
    }

    # --- Surface breakdown: static launch corpus + live community scans ---
    surface_breakdown: dict[str, int] = {}
    catalog_static_total = 0
    try:
        from src.api.scan_catalog_router import _get_catalog

        cat = _get_catalog()
        surface_breakdown = dict(cat["summary"].by_surface)
        catalog_static_total = int(cat["summary"].total_scans)
    except Exception:
        pass
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
            "attestations_issued": int(attestations_window),
            "api_calls": int(api_calls_window),
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
        },
        "alert_webhooks": {"active": int(alert_webhooks_active)},
        "badges": {"fetches_window": int(badge_fetches_window)},
        "catalog": {
            "size_total": int(catalog_size_total),
            "community_scans": int(unique_repos_total),
            "static_corpus": int(catalog_static_total),
            "by_surface": surface_breakdown,
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


@router.get("/metrics/dashboard", include_in_schema=False)
async def engagement_metrics_dashboard() -> HTMLResponse:
    """Minimal server-rendered dashboard shell (no external libs).

    The shell carries no data — it fetches the admin-gated ``/admin/metrics``
    JSON client-side using the admin's Bearer token from localStorage (key
    ``token``, same as the SPA). All sensitive data stays behind ``require_admin``.
    """
    return HTMLResponse(_DASHBOARD_HTML)


# ---------------------------------------------------------------------------
# Server-rendered dashboard shell — self-contained, brand-token styled.
# ---------------------------------------------------------------------------
_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentAvow — Engagement Metrics</title>
<style>
  :root {
    --primary:#0D9488; --primary-light:#2DD4BF; --surface:#111B1B;
    --surface-elevated:#162222; --bg:#0A0F0F; --text:#CDD6F4;
    --muted:#6C7086; --border:#1E3333; --success:#A6E3A1;
    --warning:#F9E2AF; --danger:#F38BA8; --accent:#E879F9;
  }
  * { box-sizing:border-box; }
  body {
    margin:0; background:var(--bg); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-variant-numeric:tabular-nums; -webkit-font-smoothing:antialiased;
  }
  .wrap { max-width:1080px; margin:0 auto; padding:28px 20px 60px; }
  header { display:flex; align-items:baseline; justify-content:space-between; flex-wrap:wrap; gap:12px; margin-bottom:6px; }
  h1 { font-size:20px; margin:0; font-weight:700; letter-spacing:-0.01em; }
  h1 .dot { color:var(--primary-light); }
  .sub { color:var(--muted); font-size:13px; margin:2px 0 22px; }
  .windows { display:inline-flex; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .windows button {
    background:transparent; color:var(--muted); border:0; padding:7px 14px;
    font-size:13px; cursor:pointer; font-variant-numeric:tabular-nums;
  }
  .windows button.active { background:var(--primary); color:#04110f; font-weight:600; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:14px; margin-bottom:26px; }
  .card {
    background:var(--surface); border:1px solid var(--border); border-radius:12px;
    padding:16px 16px 12px; position:relative; overflow:hidden;
  }
  .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.05em; }
  .card .value { font-size:30px; font-weight:700; margin:6px 0 2px; letter-spacing:-0.02em; }
  .card .foot { color:var(--muted); font-size:12px; min-height:15px; }
  .card svg.spark { display:block; width:100%; height:34px; margin-top:8px; }
  section h2 { font-size:14px; font-weight:600; color:var(--text); margin:26px 0 12px; }
  .panel { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:18px; }
  .bars { display:flex; align-items:flex-end; gap:10px; height:120px; }
  .bar-col { flex:1; display:flex; flex-direction:column; align-items:center; gap:6px; justify-content:flex-end; }
  .bar { width:100%; border-radius:5px 5px 0 0; min-height:2px; }
  .bar-lab { font-size:12px; color:var(--muted); }
  .bar-val { font-size:12px; color:var(--text); font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td, th { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }
  .two { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:720px){ .two { grid-template-columns:1fr; } }
  .notes { margin-top:26px; }
  .notes li { color:var(--muted); font-size:12px; line-height:1.55; margin-bottom:6px; }
  .err { background:var(--surface); border:1px solid var(--danger); color:var(--danger); padding:16px; border-radius:12px; font-size:13px; }
  .muted { color:var(--muted); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>AgentAvow <span class="dot">&bull;</span> Engagement Metrics</h1>
      <div class="sub" id="sub">Loading&hellip;</div>
    </div>
    <div class="windows" id="windows">
      <button data-w="today">Today</button>
      <button data-w="7d" class="active">7 days</button>
      <button data-w="30d">30 days</button>
    </div>
  </header>
  <div id="root"></div>
</div>
<script>
const GRADE_COLORS = {"A+":"#A6E3A1","A":"#2DD4BF","B":"#0D9488","C":"#F9E2AF","D":"#E8A44A","F":"#F38BA8"};
let currentWindow = "7d";

function esc(s){ return String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
function fmt(n){ return (n==null?0:n).toLocaleString("en-US"); }

function sparkline(data){
  const w=200, h=34, n=data.length;
  if(!n) return "";
  const max=Math.max(1, ...data);
  const step = n>1 ? w/(n-1) : 0;
  const pts = data.map((v,i)=>[i*step, h-2-(v/max)*(h-4)]);
  const line = pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ");
  const area = line+" L "+w+" "+h+" L 0 "+h+" Z";
  return '<svg class="spark" viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none">'
    +'<path d="'+area+'" fill="#0D948822"/>'
    +'<path d="'+line+'" fill="none" stroke="#2DD4BF" stroke-width="1.5" '
    +'stroke-linejoin="round" stroke-linecap="round"/></svg>';
}

function card(label, value, foot, series){
  return '<div class="card"><div class="label">'+esc(label)+'</div>'
    +'<div class="value">'+fmt(value)+'</div>'
    +'<div class="foot">'+(foot?esc(foot):"")+'</div>'
    +(series?sparkline(series):"")+'</div>';
}

function gradeBars(dist){
  const order=["A+","A","B","C","D","F"];
  const max=Math.max(1, ...order.map(g=>dist[g]||0));
  let out='<div class="bars">';
  for(const g of order){
    const v=dist[g]||0; const hpct=(v/max)*100;
    out+='<div class="bar-col"><div class="bar-val">'+fmt(v)+'</div>'
      +'<div class="bar" style="height:'+hpct+'%;background:'+(GRADE_COLORS[g]||"#0D9488")+'"></div>'
      +'<div class="bar-lab">'+g+'</div></div>';
  }
  return out+'</div>';
}

function surfaceTable(bySurface){
  const rows=Object.entries(bySurface).sort((a,b)=>b[1]-a[1]);
  let out='<table><thead><tr><th>Surface</th><th class="num">Scans</th></tr></thead><tbody>';
  for(const [s,c] of rows){ out+='<tr><td>'+esc(s)+'</td><td class="num">'+fmt(c)+'</td></tr>'; }
  return out+'</tbody></table>';
}

function render(d){
  document.getElementById("sub").textContent =
    "Window: "+d.window+"  ·  generated "+new Date(d.generated_at).toLocaleString();
  const s=d.series||{};
  let html='<div class="grid">'
    + card("Repos scanned", d.scans.repos_scanned_window, "new: "+fmt(d.scans.new_repos_window), s.repos_scanned)
    + card("Watches created", d.watches.created_window, fmt(d.watches.active)+" active", s.watches_created)
    + card("Badge fetches", d.badges.fetches_window, "Redis counter", s.badge_fetches)
    + card("Attestations issued", d.attestations.issued_window, fmt(d.attestations.issued_total)+" total", null)
    + card("API keys active", d.api_keys.active, fmt(d.api_keys.calls_window)+" calls (win)", s.api_calls)
    + card("Catalog size", d.catalog.size_total, fmt(d.catalog.community_scans)+" community", null)
    + card("Verified claims", d.claims.verified_total, "+"+fmt(d.claims.created_window)+" in window", null)
    + card("Alert webhooks", d.alert_webhooks.active, "active", null)
    + '</div>';

  html+='<div class="two">'
    + '<section><h2>Grade distribution (scanned corpus)</h2><div class="panel">'+gradeBars(d.scans.grade_distribution)+'</div></section>'
    + '<section><h2>Scans by surface</h2><div class="panel">'+surfaceTable(d.catalog.by_surface)+'</div></section>'
    + '</div>';

  html+='<section class="notes"><h2>How these are computed</h2><div class="panel"><ul>';
  for(const note of (d.notes||[])){ html+='<li>'+esc(note)+'</li>'; }
  html+='</ul></div></section>';
  document.getElementById("root").innerHTML=html;
}

async function load(){
  const token = localStorage.getItem("token");
  const root=document.getElementById("root");
  if(!token){
    root.innerHTML='<div class="err">Not signed in. Open the AgentAvow site, sign in as an '
      +'admin, then reload this page (it reads your session token from localStorage).</div>';
    document.getElementById("sub").textContent="Admin sign-in required";
    return;
  }
  root.innerHTML='<div class="muted">Loading metrics&hellip;</div>';
  try{
    const res=await fetch("/api/v1/admin/metrics?window="+encodeURIComponent(currentWindow),
      {headers:{Authorization:"Bearer "+token}});
    if(res.status===401||res.status===403){
      root.innerHTML='<div class="err">Access denied ('+res.status+'). This dashboard '
        +'requires an admin account.</div>';
      document.getElementById("sub").textContent="Admin access required";
      return;
    }
    if(!res.ok){ throw new Error("HTTP "+res.status); }
    render(await res.json());
  }catch(e){
    root.innerHTML='<div class="err">Failed to load metrics: '+esc(e.message||e)+'</div>';
  }
}

document.getElementById("windows").addEventListener("click", ev=>{
  const b=ev.target.closest("button"); if(!b) return;
  currentWindow=b.dataset.w;
  for(const el of document.querySelectorAll(".windows button")) el.classList.toggle("active", el===b);
  load();
});
load();
</script>
</body>
</html>
"""
