"""Adoption for a bare MCP endpoint (an MCP server checked by its URL).

A live endpoint has no download counter of its own. The one reliable public signal is
the **official MCP registry** (registry.modelcontextprotocol.io): a server that lists
this exact remote URL under ``remotes[].url`` is a published, named server, and when
that listing names a GitHub repository, the repo's stars are a real, independent
signal of reliance. So:

* listed + linked GitHub repo → headline = that repo's stars, unit ``stars (linked repo)``
* listed, no repo            → no count ("listed in the official MCP registry" only)
* not listed / registry down → nothing (the page says "no signal yet"; never a guess)

The registry's search is a name substring match, so candidate search terms are built
from the endpoint's host labels and path segments, and only a listing whose remote URL
matches the endpoint exactly (scheme-insensitive, trailing slash ignored) counts.
Results are cached for a day. Fail-open everywhere.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

REGISTRY_API = "https://registry.modelcontextprotocol.io/v0/servers"
_CACHE_PREFIX = "mcp_endpoint_adoption:"
_CACHE_TTL = 24 * 3600
_FAIL_TTL = 3600  # a slow/failed registry is retried hourly, not on every page view
_TIMEOUT = 6.0
_BUDGET = 10.0  # total seconds for one lookup across all terms and pages
_PAGE_LIMIT = 100
_MAX_TERMS = 3
_MAX_PAGES = 2
_GENERIC = {
    "mcp", "api", "www", "server", "servers", "com", "io", "ai", "dev", "app", "net",
    "org", "co", "sse", "http", "https", "v1", "v2", "remote", "cloud", "prod",
}
_GH_REPO = re.compile(r"github\.com[/:]([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})", re.I)


def normalize_endpoint(url: str) -> str:
    """``host/path`` lowercased, scheme dropped, trailing slash and query stripped."""
    try:
        parts = urlsplit(url.strip() if "://" in url else "https://" + url.strip())
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        return f"{host}{path}" if host else ""
    except Exception:  # noqa: BLE001
        return ""


def search_terms(url: str) -> list[str]:
    """Most-specific-first registry search terms from an endpoint URL."""
    norm = normalize_endpoint(url)
    if not norm:
        return []
    host, _, path = norm.partition("/")
    terms: list[str] = []
    for seg in reversed([p.lstrip("@") for p in path.split("/") if p]):
        if seg and seg not in _GENERIC and len(seg) >= 3:
            terms.append(seg)
    for label in host.split("."):
        if label and label not in _GENERIC and len(label) >= 3:
            terms.append(label)
    seen: list[str] = []
    for t in terms:
        if t not in seen:
            seen.append(t)
    return seen[:_MAX_TERMS]


def match_listing(servers: list, endpoint: str) -> dict | None:
    """The registry entry whose ``remotes[].url`` is this endpoint, or None."""
    want = normalize_endpoint(endpoint)
    if not want:
        return None
    for item in servers or []:
        sv = item.get("server", item) if isinstance(item, dict) else None
        if not isinstance(sv, dict):
            continue
        for r in sv.get("remotes") or []:
            if isinstance(r, dict) and normalize_endpoint(str(r.get("url") or "")) == want:
                repo = (sv.get("repository") or {}).get("url") if isinstance(
                    sv.get("repository"), dict) else None
                return {"name": sv.get("name"), "repository": repo}
    return None


def linked_github(repo_url: str | None) -> tuple[str, str] | None:
    m = _GH_REPO.search(repo_url or "")
    if not m:
        return None
    return m.group(1), m.group(2).removesuffix(".git")


async def _find_listing(endpoint: str) -> dict | None:
    import httpx
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for term in search_terms(endpoint):
            cursor = None
            for _ in range(_MAX_PAGES):
                params = {"search": term, "limit": _PAGE_LIMIT}
                if cursor:
                    params["cursor"] = cursor
                r = await client.get(REGISTRY_API, params=params)
                if r.status_code != 200:
                    return None
                body = r.json()
                hit = match_listing(body.get("servers") or [], endpoint)
                if hit:
                    return hit
                cursor = (body.get("metadata") or {}).get("nextCursor")
                if not cursor:
                    break
    return None


async def endpoint_registry_listing(endpoint: str) -> dict:
    """``{"listed": bool, "name"?, "repository"?}`` for an MCP endpoint, cached 24h.
    ``{"listed": False}`` when not found or on any failure."""
    key = _CACHE_PREFIX + normalize_endpoint(endpoint)
    try:
        from src.redis_client import get_redis
        raw = await get_redis().get(key)
        if raw:
            return json.loads(raw)
    except Exception:  # noqa: BLE001
        pass
    import asyncio
    out: dict = {"listed": False}
    ttl = _CACHE_TTL
    try:
        hit = await asyncio.wait_for(_find_listing(endpoint), timeout=_BUDGET)
        if hit:
            out = {"listed": True, **{k: v for k, v in hit.items() if v}}
    except Exception:  # noqa: BLE001 — registry down = no signal, never an error
        logger.debug("MCP registry lookup failed for %s", endpoint, exc_info=True)
        ttl = _FAIL_TTL
    try:
        from src.redis_client import get_redis
        await get_redis().set(key, json.dumps(out), ex=ttl)
    except Exception:  # noqa: BLE001
        pass
    return out
