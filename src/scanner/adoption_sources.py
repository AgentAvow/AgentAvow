"""Adoption data collectors — async, fail-open I/O feeding ``adoption.py``.

Separates network / Redis I/O from the pure scoring engine so the scoring stays
deterministic and offline-recomputable.  Every collector fails open: on any
error it returns ``None``/empty and the corresponding axis is simply marked
absent (never scored as a zero).

Axis wiring status (see the module functions):

    (A) registry downloads + trend   — WIRED   (npm downloads/range, pypistats,
                                                 crates, Docker pull_count)
    (B) reverse-dependents           — WIRED   (ecosyste.ms, deps.dev)
    (C) social stars + velocity      — PARTIAL (GitHub star count + prev-snapshot
                                                 velocity WIRED; fake-star burst
                                                 sampling of stargazer accounts is
                                                 a STUB hook — pass suspect_accounts)
    (D) first-party (ours)           — WIRED   (unique-checker HLL, badge-embed
                                                 domain diversity, raw vanity,
                                                 verify-pulls HLL, in-graph agent
                                                 connections from the entity graph)
    (E) MCP / agent-registry usage   — WIRED   (Smithery / PulseMCP community
                                                 signals — cached on the tool's
                                                 Entity, or re-fetched live via the
                                                 source_import MCP fetchers)

First-party Redis keyspace (all best-effort, all TTL'd):

    adopt:uniq:{owner}/{repo}          HyperLogLog of distinct checker identities
    adopt:badge:ref:{entity}:{day}     SET of distinct Referer hosts per UTC day
    adopt:verify:{owner}/{repo}        HyperLogLog of distinct verify/recompute consumers
    adopt:verify:raw:{owner}/{repo}    INTERNAL raw INCR counter of verify pulls (vanity)

**Publication policy:** the first-party raw counts here (raw verify INCR, raw
graph rows) stay INTERNAL — only the deduplicated / distinct estimates
(``get_verify_pulls`` PFCOUNT, ``get_graph_connections`` distinct-agent count)
are surfaced to scoring and the public adoption view.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_UNIQ_TTL = 60 * 60 * 24 * 90       # 90d unique-checker window
_BADGE_REF_TTL = 60 * 60 * 24 * 32  # 32d so a 30d union always has coverage
_README_LEADERBOARD_KEY = "adopt:badge:readme:top"  # cumulative ZSET: repo -> README renders
_README_LEADERBOARD_TTL = 60 * 60 * 24 * 120  # 120d idle TTL (refreshed on each render)
_VERIFY_TTL = 60 * 60 * 24 * 90

# Our own hosts — never counted toward badge-embed domain diversity.
_OUR_DOMAINS = {
    "agentavow.com", "www.agentavow.com", "agentgraph.co",
    "www.agentgraph.co", "localhost", "127.0.0.1",
}


# ---------------------------------------------------------------------------
# (D) First-party — unique checkers (replaces the inflatable INCR)
# ---------------------------------------------------------------------------

def checker_identity(entity_id: str | None, ip: str, user_agent: str) -> str:
    """Derive a stable, privacy-preserving checker identity.

    Prefers the authenticated entity id; falls back to a salted hash of IP+UA so
    the same anonymous client dedupes without us storing raw IPs.
    """
    if entity_id:
        return f"e:{entity_id}"
    raw = f"{ip}|{user_agent}".encode("utf-8", "ignore")
    return "a:" + hashlib.sha256(raw).hexdigest()[:24]


async def record_unique_checker(owner: str, repo: str, identity: str) -> None:
    """Add a checker identity to the per-tool HyperLogLog. Best-effort."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        key = f"adopt:uniq:{owner}/{repo}"
        await r.pfadd(key, identity)
        await r.expire(key, _UNIQ_TTL)
    except Exception:
        pass


async def get_unique_checkers(owner: str, repo: str) -> int:
    """Distinct-checker estimate from the HLL. 0 on failure."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        return int(await r.pfcount(f"adopt:uniq:{owner}/{repo}"))
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Global (site-wide) unique-checker reach — a daily HLL per day, unioned over a
# window with a single PFCOUNT. Distinct-people/agents reach, no raw IPs stored.
# ---------------------------------------------------------------------------
_GLOBAL_UNIQ_PREFIX = "metrics:uniq_checkers:"


async def record_global_checker(identity: str) -> None:
    """Add a checker identity to TODAY's site-wide unique-checker HLL. Best-effort."""
    if not identity:
        return
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"{_GLOBAL_UNIQ_PREFIX}{day}"
        await r.pfadd(key, identity)
        await r.expire(key, _UNIQ_TTL)
    except Exception:
        pass


async def get_global_unique_checkers(days: int) -> int:
    """Distinct site-wide checkers over the last ``days`` — the union cardinality of
    the daily HLLs (PFCOUNT accepts multiple keys and ignores missing ones). 0 on error."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        now = datetime.now(timezone.utc)
        keys = [
            f"{_GLOBAL_UNIQ_PREFIX}" + (now - timedelta(days=i)).strftime("%Y-%m-%d")
            for i in range(max(1, days))
        ]
        return int(await r.pfcount(*keys))
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# (D) First-party — badge-embed domain diversity
# ---------------------------------------------------------------------------

def _referer_host(referer: str | None) -> str | None:
    if not referer:
        return None
    try:
        from urllib.parse import urlparse

        host = (urlparse(referer).hostname or "").lower()
        if not host or host in _OUR_DOMAINS:
            return None
        return host
    except Exception:
        return None


async def record_badge_referer(entity_id: str, referer: str | None) -> None:
    """Log the badge-embed Referer host into today's per-entity set.

    Best-effort — must NEVER break badge render.  Our own domains are dropped.
    """
    host = _referer_host(referer)
    if not host:
        return
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key = f"adopt:badge:ref:{entity_id}:{day}"
        await r.sadd(key, host)
        await r.expire(key, _BADGE_REF_TTL)
    except Exception:
        pass


async def get_badge_embed_domains(entity_id: str, days: int = 30) -> int:
    """Distinct real Referer hosts over the last ``days`` (30d window)."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        now = datetime.now(timezone.utc)
        keys = [
            f"adopt:badge:ref:{entity_id}:"
            + (now - timedelta(days=i)).strftime("%Y-%m-%d")
            for i in range(days)
        ]
        hosts: set = set()
        for k in keys:
            try:
                members = await r.smembers(k)
                hosts.update(members)
            except Exception:
                continue
        hosts.discard("")
        return len(hosts)
    except Exception:
        return 0


def _is_github_camo(user_agent: str | None) -> bool:
    """True if the request is GitHub's image proxy fetching an embedded badge.

    A badge in a GitHub README is fetched server-side by ``camo.githubusercontent``
    (User-Agent ``github-camo (<hash>)``), which strips the Referer — so the
    User-Agent, not the Referer, is the reliable "rendered in a README" signal.
    """
    return "camo" in (user_agent or "").lower()


async def record_badge_render(repo_label: str | None, user_agent: str | None) -> None:
    """Segment a badge render: if it's a GitHub README embed (camo proxy), bump
    the ``badge_render_readme`` counter and a cumulative per-repo leaderboard.

    Best-effort — MUST NEVER break the badge render. This is the "badges actually
    rendering in READMEs" signal (real adoption), distinct from ``badge_fetch``
    which counts every render including score-page previews.
    """
    if not _is_github_camo(user_agent):
        return
    try:
        from src.api.metrics_dashboard_router import bump_metric

        await bump_metric("badge_render_readme")
    except Exception:
        pass
    if not repo_label:
        return
    try:
        from src.redis_client import get_redis

        r = get_redis()
        await r.zincrby(_README_LEADERBOARD_KEY, 1, repo_label)
        await r.expire(_README_LEADERBOARD_KEY, _README_LEADERBOARD_TTL)
    except Exception:
        pass


async def get_readme_badge_leaderboard(top_n: int = 15) -> list[tuple[str, int]]:
    """Top-N repos by cumulative README badge renders: ``[(owner/repo, count)]``.

    The live "badges rendering in the wild" list — adoption proof + the warmest
    re-outreach targets. Best-effort ([] on any failure)."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        rows = await r.zrevrange(_README_LEADERBOARD_KEY, 0, max(0, top_n - 1), withscores=True)
        out: list[tuple[str, int]] = []
        for member, score in rows:
            label = member.decode() if isinstance(member, bytes) else str(member)
            out.append((label, int(score)))
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# (D) First-party — verify-pulls + in-graph agent connections
# ---------------------------------------------------------------------------

async def record_verify_pull(
    owner: str, repo: str, identity: str | None = None,
) -> None:
    """Record one attestation-verify / offline-recompute / JWKS-key pull.

    First-party axis-D signal: the deepest proof of downstream reliance is a
    distinct consumer actually *verifying* a scan's signed attestation (offline
    recompute, JWKS fetch, composed-slot verify).  Best-effort — MUST NEVER
    break the verify/JWKS response.

    Two things are recorded:

    - ``adopt:verify:raw:{owner}/{repo}`` — a plain INCR counter of every pull
      (INTERNAL vanity number; inflatable, so never scored).
    - ``adopt:verify:{owner}/{repo}`` — a HyperLogLog of *distinct* consumer
      identities (the deduplicated estimate that IS scored, per the §3
      anti-gaming design).  Only updated when an ``identity`` is supplied.

    ``identity`` should be a stable, privacy-preserving consumer id (reuse
    ``checker_identity(entity_id, ip, user_agent)`` at the call site).

    CALLER WIRING (one line each — to be added by whoever owns those routes;
    this module only provides the helper):

        # src/api/jwks_router.py — on a per-tool JWKS / verify hit:
        await record_verify_pull(owner, repo, checker_identity(eid, ip, ua))

        # src/attestation/composed_slot.py verify path — on offline recompute:
        await record_verify_pull(owner, repo, identity)
    """
    try:
        from src.redis_client import get_redis

        r = get_redis()
        raw_key = f"adopt:verify:raw:{owner}/{repo}"
        await r.incr(raw_key)
        await r.expire(raw_key, _VERIFY_TTL)
        if identity:
            uniq_key = f"adopt:verify:{owner}/{repo}"
            await r.pfadd(uniq_key, identity)
            await r.expire(uniq_key, _VERIFY_TTL)
    except Exception:
        pass


async def get_verify_pulls(owner: str, repo: str) -> int:
    """Distinct verify-path consumers (deduplicated PFCOUNT) — the SCORED value.

    0 on failure or until the verify hooks call ``record_verify_pull`` with an
    identity.  This distinct estimate (never the raw INCR) feeds axis D.
    """
    try:
        from src.redis_client import get_redis

        r = get_redis()
        return int(await r.pfcount(f"adopt:verify:{owner}/{repo}"))
    except Exception:
        return 0


async def get_verify_pulls_raw(owner: str, repo: str) -> int:
    """INTERNAL raw verify-pull count (vanity). Never surfaced publicly / scored."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        val = await r.get(f"adopt:verify:raw:{owner}/{repo}")
        if val is None:
            return 0
        if isinstance(val, bytes):
            val = val.decode("utf-8", "ignore")
        return int(val)
    except Exception:
        return 0


async def get_graph_connections(owner: str, repo: str) -> int:
    """Distinct in-graph agents that connect to / depend on this tool.

    Fail-open reader over our OWN entity graph (``src/models`` —
    ``EntityRelationship``): resolve the tool's Entity by its ``source_url``
    (``github.com/{owner}/{repo}``) and count the DISTINCT active AGENT entities
    that point at it via a SERVICE or COLLABORATION relationship — i.e. real
    registered agents whose manifests wire this tool in.  This is the
    unfakeable first-party depth signal (§3.3 axis D): it requires *other*
    registered agents in our graph to actually connect to the tool.

    ``src/graph/lineage.py`` only computes evolution *fork* trees (a different
    relation), so it exposes no query we can reuse here; this reader queries the
    relationship graph directly.  Returns 0 fail-open (missing tool, no DB, or
    any error) so a cold-start / un-imported tool simply contributes nothing to
    axis D — never a scored zero.
    """
    try:
        from sqlalchemy import func, select

        from src.database import async_session
        from src.models import (
            Entity,
            EntityRelationship,
            EntityType,
            RelationshipType,
        )

        async with async_session() as db:
            tool_id = await db.scalar(
                select(Entity.id).where(
                    Entity.is_active.is_(True),
                    Entity.source_url.ilike(f"%github.com/{owner}/{repo}%"),
                ).limit(1)
            )
            if tool_id is None:
                return 0
            count = await db.scalar(
                select(func.count(func.distinct(EntityRelationship.source_entity_id)))
                .select_from(EntityRelationship)
                .join(Entity, Entity.id == EntityRelationship.source_entity_id)
                .where(
                    EntityRelationship.target_entity_id == tool_id,
                    EntityRelationship.type.in_(
                        [RelationshipType.SERVICE, RelationshipType.COLLABORATION]
                    ),
                    Entity.type == EntityType.AGENT,
                    Entity.is_active.is_(True),
                )
            )
            return int(count or 0)
    except Exception:
        logger.debug(
            "graph-connections read failed for %s/%s", owner, repo, exc_info=True,
        )
        return 0


# ---------------------------------------------------------------------------
# (E) MCP / agent-registry usage — fail-open reader for the repo-scan path
# ---------------------------------------------------------------------------

# Community-signal keys the axis-E engine understands (see
# ``adoption.build_axis_mcp_registry``).  Only these are lifted from a stored /
# fetched ``community_signals`` blob; everything else is ignored.
_MCP_SIGNAL_KEYS = (
    "smithery_downloads",
    "smithery_stars",
    "pulsemcp_stars",
    "tool_call_count",
    "marketplace_installs",
)


def _extract_mcp_signals(community_signals: dict | None) -> dict | None:
    """Project an arbitrary community_signals blob onto the axis-E keys.

    Returns a dict of the recognized keys with non-None values, or None when the
    blob carries no MCP-registry usage signal.
    """
    if not community_signals:
        return None
    out = {
        k: community_signals[k]
        for k in _MCP_SIGNAL_KEYS
        if community_signals.get(k) is not None
    }
    return out or None


async def get_mcp_registry_signals(owner: str, repo: str) -> dict | None:
    """MCP / agent-registry usage signals for a scanned tool (axis E).

    The scoring engine already accepts Smithery / PulseMCP ``community_signals``
    but nothing fed it from the repo-scan path; this fail-open reader closes
    that gap.  Resolution order (best-effort, all fail-open):

    1. **Cached** — the tool's Entity may already carry a ``community_signals``
       blob captured at import time (Smithery / PulseMCP fetchers stash it in
       ``onboarding_data``); prefer that (offline, recomputable).
    2. **Live** — if the Entity was imported as an MCP registry listing
       (``source_type`` smithery / pulsemcp with a ``source_url``), re-fetch via
       the existing ``source_import`` MCP fetchers.

    Returns a dict of axis-E keys (``smithery_downloads`` etc.) to hand to
    ``adoption.build_axis_mcp_registry(**signals)``, or None when the tool is not
    an MCP-registry-listed server (axis E simply stays absent — never a zero).

    CALLER WIRING (the repo-scan adoption path — e.g. ``scan_adoption`` in
    ``public_scan_router`` — should add, alongside the other axis readers):

        mcp = await get_mcp_registry_signals(owner, repo)
        if mcp:
            raw_inputs["E"] = {"source": "mcp-registry", **mcp}
            axes.append(build_axis_mcp_registry(**mcp))
    """
    entity = None
    try:
        from sqlalchemy import select

        from src.database import async_session
        from src.models import Entity

        async with async_session() as db:
            entity = await db.scalar(
                select(Entity).where(
                    Entity.is_active.is_(True),
                    Entity.source_url.ilike(f"%github.com/{owner}/{repo}%"),
                ).limit(1)
            )
    except Exception:
        logger.debug(
            "mcp-registry entity lookup failed for %s/%s", owner, repo,
            exc_info=True,
        )
        entity = None

    if entity is None:
        return None

    # 1. Cached community_signals stashed on the entity at import time.
    try:
        cached = (getattr(entity, "onboarding_data", None) or {}).get(
            "community_signals"
        )
        signals = _extract_mcp_signals(cached)
        if signals:
            return signals
    except Exception:
        pass

    # 2. Live re-fetch via the existing MCP fetchers.
    source_type = getattr(entity, "source_type", None)
    source_url = getattr(entity, "source_url", None)
    if not source_url:
        return None
    try:
        if source_type == "smithery":
            from src.source_import.smithery_fetcher import (
                fetch_smithery,
                parse_smithery_url,
            )

            res = await fetch_smithery(parse_smithery_url(source_url), source_url)
            return _extract_mcp_signals(res.community_signals)
        if source_type == "pulsemcp":
            from src.source_import.pulsemcp_fetcher import (
                fetch_pulsemcp,
                parse_pulsemcp_url,
            )

            res = await fetch_pulsemcp(parse_pulsemcp_url(source_url), source_url)
            return _extract_mcp_signals(res.community_signals)
    except Exception:
        logger.debug(
            "live MCP-registry fetch failed for %s/%s", owner, repo, exc_info=True,
        )
    return None


# ---------------------------------------------------------------------------
# (A) Registry downloads + trend
# ---------------------------------------------------------------------------

async def fetch_npm_downloads(package: str) -> dict | None:
    """npm downloads/range (last-year daily series). None on failure."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://api.npmjs.org/downloads/range/last-year/{package}"
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        downloads = data.get("downloads", []) or []
        series = [d.get("downloads", 0) for d in downloads]
        return {
            "source": "npm:downloads/range/last-year",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": int(sum(series)),
            "series": series,
        }
    except Exception:
        logger.debug("npm downloads fetch failed for %s", package, exc_info=True)
        return None


async def fetch_pypi_downloads(package: str) -> dict | None:
    """pypistats overall (mirror-EXCLUDED — mirrors massively overcount CI)."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://pypistats.org/api/packages/{package}/overall",
                params={"mirrors": "false"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        rows = data.get("data", []) or []
        # rows: [{category: without_mirrors, date, downloads}, ...]
        series = [r.get("downloads", 0) for r in rows]
        return {
            "source": "pypistats:overall?mirrors=false",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": int(sum(series)),
            "series": series,
        }
    except Exception:
        logger.debug("pypi downloads fetch failed for %s", package, exc_info=True)
        return None


async def fetch_docker_pulls(repo: str) -> dict | None:
    """Docker Hub image adoption — total ``pull_count`` + ``star_count`` (no auth).
    ``repo`` is ``namespace/name`` (official = ``library/name``). Fail-open → None."""
    try:
        import httpx

        ns, _, name = repo.partition("/")
        if not name:
            ns, name = "library", ns
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"https://hub.docker.com/v2/repositories/{ns}/{name}")
            if resp.status_code != 200:
                return None
            data = resp.json()
        return {
            "source": "dockerhub:repositories",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "pulls": int(data.get("pull_count") or 0),
            "stars": int(data.get("star_count") or 0),
        }
    except Exception:
        logger.debug("docker pulls fetch failed for %s", repo, exc_info=True)
        return None


async def fetch_crates_stats(name: str) -> dict | None:
    """crates.io adoption — total + recent (90d) downloads (no auth). Fail-open → None.
    crates.io's crawl policy asks for a descriptive User-Agent with contact info."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8, headers={
            "User-Agent": "AgentAvow-Adoption (safety scanning; kenne@agentavow.com)",
        }) as client:
            resp = await client.get(f"https://crates.io/api/v1/crates/{name}")
            if resp.status_code != 200:
                return None
            crate = (resp.json() or {}).get("crate") or {}
        return {
            "source": "crates.io",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "downloads": int(crate.get("downloads") or 0),
            "recent_downloads": int(crate.get("recent_downloads") or 0),
        }
    except Exception:
        logger.debug("crates stats fetch failed for %s", name, exc_info=True)
        return None


async def fetch_hf_stats(model_id: str) -> dict | None:
    """Hugging Face model adoption — monthly ``downloads`` + ``likes`` (no auth).
    ``model_id`` is ``org/model``. Fail-open → None."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(f"https://huggingface.co/api/models/{model_id}")
            if resp.status_code != 200:
                return None
            data = resp.json()
        return {
            "source": "huggingface:models",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "downloads": int(data.get("downloads") or 0),
            "likes": int(data.get("likes") or 0),
        }
    except Exception:
        logger.debug("hf stats fetch failed for %s", model_id, exc_info=True)
        return None


async def fetch_clawhub_stats(owner: str, repo: str) -> dict | None:
    """OpenClaw skill adoption from ClawHub (the skill registry, no auth) — unique
    ``installs``, raw ``downloads``, ``stars``, and a 60-day install ``trend``. A skill
    is scanned as a GitHub ``owner/repo``; ClawHub keys skills by ``ownerHandle`` +
    ``slug``, so we search by the repo/skill name and keep only the row whose owner
    matches — never a different owner's identically-named skill. Fail-open → None.

    This is a strict upgrade over the GitHub-star proxy: it measures the SKILL's real
    adoption, not the repo's, and one repo can hold several skills. When a skill isn't
    on ClawHub, the caller falls back to repo stars."""
    owner = (owner or "").strip()
    repo = (repo or "").strip()
    if not owner or not repo:
        return None
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8, headers={
            "User-Agent": "AgentAvow-Adoption (safety scanning; kenne@agentavow.com)",
        }) as client:
            resp = await client.get(
                "https://clawhub.ai/api/v1/search",
                params={"q": repo, "limit": 20},
            )
            if resp.status_code != 200:
                return None
            results = (resp.json() or {}).get("results") or []

        def _owner_of(row: dict) -> str:
            return str(
                row.get("ownerHandle")
                or (row.get("sourceIdentity") or {}).get("owner")
                or ""
            ).lower()

        match = next((r for r in results if _owner_of(r) == owner.lower()), None)
        if match is None:
            return None
        stats = match.get("stats") or {}
        metrics = match.get("metrics") or {}
        installs = int(stats.get("installs") or 0)
        downloads = int(stats.get("downloads") or match.get("downloads") or 0)
        stars = int(stats.get("stars") or 0)
        trend = int(metrics.get("rolling60DayInstalls") or 0)
        if not (installs or downloads or stars or trend):
            return None
        return {
            "source": "clawhub",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "installs": installs,
            "downloads": downloads,
            "stars": stars,
            "trend_60d_installs": trend,
        }
    except Exception:
        logger.debug("clawhub stats fetch failed for %s/%s", owner, repo, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Bulk discovery — the most-depended-upon packages per registry (ecosyste.ms).
# These are the tools agents actually pull, so they're the highest-value catalog
# additions. No auth; bounded + paged by the caller.
# ---------------------------------------------------------------------------

async def discover_top_packages(
    ecosystem: str, *, per_page: int = 50, page: int = 1,
) -> list[str]:
    """Names of the most-depended-upon packages on a registry, most-relied-on first.

    ``ecosystem`` is the ecosyste.ms registry host key (``npmjs.org`` / ``pypi.org`` /
    ``crates.io``). Fail-open → ``[]``."""
    try:
        import httpx

        url = (
            f"https://packages.ecosyste.ms/api/v1/registries/{ecosystem}/packages"
            f"?sort=dependent_packages_count&order=desc"
            f"&per_page={int(per_page)}&page={int(page)}"
        )
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
        if not isinstance(data, list):
            return []
        out: list[str] = []
        for row in data:
            name = row.get("name") if isinstance(row, dict) else None
            if name and isinstance(name, str):
                out.append(name)
        return out
    except Exception:
        logger.debug("ecosyste.ms top-packages fetch failed for %s", ecosystem, exc_info=True)
        return []


# ---------------------------------------------------------------------------
# (B) Reverse-dependents — ecosyste.ms (no auth)
# ---------------------------------------------------------------------------

async def fetch_ecosystems_dependents(
    ecosystem: str, package: str
) -> dict | None:
    """ecosyste.ms dependent_packages_count + dependent_repos_count.

    ``ecosystem`` is the ecosyste.ms registry host key (e.g. ``npmjs.org``,
    ``pypi.org``, ``crates.io``).
    """
    try:
        import httpx

        url = (
            f"https://packages.ecosyste.ms/api/v1/registries/{ecosystem}"
            f"/packages/{package}"
        )
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
        return {
            "source": "ecosyste.ms",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "dependent_packages": data.get("dependent_packages_count"),
            "dependent_repos": data.get("dependent_repos_count"),
        }
    except Exception:
        logger.debug(
            "ecosyste.ms fetch failed for %s/%s", ecosystem, package,
            exc_info=True,
        )
        return None
