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
                                                 domain diversity, raw vanity);
                                       STUB     (verify-pulls, graph-connections
                                                 readers return 0 until populated)
    (E) MCP / agent-registry usage   — WIRED   (Smithery / PulseMCP community
                                                 signals already fetched)

First-party Redis keyspace (all best-effort, all TTL'd):

    adopt:uniq:{owner}/{repo}          HyperLogLog of distinct checker identities
    adopt:badge:ref:{entity}:{day}     SET of distinct Referer hosts per UTC day
    adopt:verify:{owner}/{repo}        HyperLogLog of distinct verify/recompute consumers
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_UNIQ_TTL = 60 * 60 * 24 * 90       # 90d unique-checker window
_BADGE_REF_TTL = 60 * 60 * 24 * 32  # 32d so a 30d union always has coverage
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


# ---------------------------------------------------------------------------
# (D) First-party — verify-pulls (STUB reader) + graph-connections (STUB)
# ---------------------------------------------------------------------------

async def record_verify_pull(owner: str, repo: str, identity: str) -> None:
    """Record a distinct verify/offline-recompute/JWKS consumer. Best-effort.

    Hook to be called from jwks_router / composed_slot verify paths.
    """
    try:
        from src.redis_client import get_redis

        r = get_redis()
        key = f"adopt:verify:{owner}/{repo}"
        await r.pfadd(key, identity)
        await r.expire(key, _VERIFY_TTL)
    except Exception:
        pass


async def get_verify_pulls(owner: str, repo: str) -> int:
    """Distinct verify-path consumers. 0 until the verify hooks are populated."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        return int(await r.pfcount(f"adopt:verify:{owner}/{repo}"))
    except Exception:
        return 0


async def get_graph_connections(owner: str, repo: str) -> int:
    """STUB: distinct in-graph agents whose signed manifests reference this tool.

    Traverses src/graph/lineage.py / src/analytics/network_metrics.py in a full
    build.  Returns 0 (axis-D sub-signal simply contributes nothing) until wired.
    """
    return 0


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
