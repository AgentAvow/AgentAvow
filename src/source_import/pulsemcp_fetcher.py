"""PulseMCP server directory fetcher for source imports.

PulseMCP (https://www.pulsemcp.com) is a third-party MCP server
directory. Added to the Q3 2026 scan corpus per
docs/internal/execution-plan-rebalance.md week of Jun 22 (#111).

API reference (as of 2026-10): https://www.pulsemcp.com/api/docs/v0.1

The original ``v0beta`` API (``/v0beta/servers/<slug>``, no auth) was
progressively failed from January 2026 and fully sunset in September 2026 —
every request now returns HTTP 410 ``API_SUNSET``. The replacement is the
**Sub-Registry API v0.1**, which implements the Generic MCP Registry API
spec with ``com.pulsemcp/*`` ``_meta`` extensions:

* ``GET https://api.pulsemcp.com/v0.1/servers?search=…&version=latest``
  (cursor-paginated; ``limit`` 1-100; 200 req/min, 5k/h, 10k/day)
* ``GET /v0.1/servers/{serverName}/versions/latest``
* Headers: ``X-API-Key`` (required, private B2B key — contact
  hello@pulsemcp.com) and ``X-Tenant-ID`` (required for data endpoints).

There is **no key-less read path** on v0.1 and no per-slug lookup: servers
are keyed by reverse-DNS name (``io.github.owner/repo``), while our source
URLs carry the directory slug (``pulsemcp.com/servers/<slug>``). So
``fetch_pulsemcp`` searches by the slug and picks the result whose
normalized name/title equals the normalized slug.

Key-less fallback: when ``PULSEMCP_API_KEY`` is not configured (or the API
rejects it with 401/403) the fetcher returns ``None`` — PulseMCP is simply
"unavailable" for that import — and logs the condition once per process.
It never raises for a missing key; hard failures (network, 5xx, not found)
still raise ``SourceFetchError`` like every other fetcher.
"""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# URL forms:
#   https://www.pulsemcp.com/servers/<slug>
#   https://pulsemcp.com/servers/<slug>
_PULSEMCP_URL_RE = re.compile(
    r"https?://(?:www\.)?pulsemcp\.com/servers/(?P<slug>[^?#/]+)",
)

_API_BASE = "https://api.pulsemcp.com/v0.1"
_REQUEST_TIMEOUT = 15.0
_SEARCH_LIMIT = 50

_META_SERVER = "com.pulsemcp/server"
_META_VERSION = "com.pulsemcp/server-version"

# Reverse-DNS namespaces the registry prefixes onto server names; stripped
# before comparing against a directory slug.
_NAME_PREFIXES = ("io.github.", "com.github.", "io.modelcontextprotocol.")

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

# Log the "no key / key rejected" condition once per process, then stay
# quiet: the population scan would otherwise emit it per server.
_unavailable_logged = False


def parse_pulsemcp_url(url: str) -> str:
    """Extract the server slug from a PulseMCP server URL.

    Raises:
        SourceParseError: if the URL does not match the expected shape.
    """
    match = _PULSEMCP_URL_RE.search(url)
    if not match:
        raise SourceParseError(
            f"Cannot parse PulseMCP server slug from URL: {url}",
        )
    return match.group("slug")


def _make_client() -> httpx.AsyncClient:
    """SSRF-pinned client (constant host, but every outbound fetch goes
    through the guard so a DNS answer can never land on an internal IP)."""
    from src.ssrf import ssrf_safe_async_client

    return ssrf_safe_async_client(timeout=_REQUEST_TIMEOUT, follow_redirects=False)


def _auth_headers() -> dict[str, str] | None:
    """Request headers for v0.1, or None when no API key is configured."""
    from src.config import settings

    api_key = (getattr(settings, "pulsemcp_api_key", None) or "").strip()
    if not api_key:
        return None
    headers = {"Accept": "application/json", "X-API-Key": api_key}
    tenant = (getattr(settings, "pulsemcp_tenant_id", None) or "").strip()
    if tenant:
        headers["X-Tenant-ID"] = tenant
    return headers


def _log_unavailable_once(reason: str) -> None:
    global _unavailable_logged
    if _unavailable_logged:
        logger.debug("PulseMCP unavailable (%s)", reason)
        return
    _unavailable_logged = True
    logger.warning(
        "PulseMCP metadata unavailable: %s. v0.1 requires an API key — set "
        "PULSEMCP_API_KEY (+ PULSEMCP_TENANT_ID) to enable; imports continue "
        "without PulseMCP signals.",
        reason,
    )


def _normalize(value: str | None) -> str:
    return _NON_ALNUM_RE.sub("", (value or "").lower())


def _name_candidates(server: dict) -> set[str]:
    """Normalized forms of a server's name/title that a directory slug may equal."""
    name = str(server.get("name") or "")
    out = {_normalize(name), _normalize(server.get("title"))}
    for prefix in _NAME_PREFIXES:
        if name.startswith(prefix):
            out.add(_normalize(name[len(prefix):]))
    if "/" in name:
        out.add(_normalize(name.rsplit("/", 1)[-1]))
    out.discard("")
    return out


def _search_terms(slug: str) -> list[str]:
    """Search strings to try, in order. v0.1 ``search`` is a substring match on
    names/titles, so ``owner-repo`` slugs also get tried as ``owner/repo``."""
    terms = [slug]
    if "-" in slug:
        terms.append(slug.replace("-", "/", 1))
    return terms


def _pick_match(items: list, slug: str) -> dict | None:
    want = _normalize(slug)
    for item in items:
        server = item.get("server") if isinstance(item, dict) else None
        if isinstance(server, dict) and want in _name_candidates(server):
            return item
    return None


async def _search(client: httpx.AsyncClient, headers: dict, term: str) -> list | None:
    """One ``GET /v0.1/servers`` search. Returns the ``servers`` list, or None
    when the key was rejected (caller degrades to unavailable).

    Raises:
        SourceFetchError: on transport errors or unexpected statuses.
    """
    try:
        resp = await client.get(
            f"{_API_BASE}/servers",
            params={"search": term, "version": "latest", "limit": _SEARCH_LIMIT},
            headers=headers,
        )
    except httpx.RequestError as exc:
        raise SourceFetchError(f"PulseMCP fetch failed: {exc}") from exc

    if resp.status_code in (401, 403):
        return None
    if resp.status_code != 200:
        raise SourceFetchError(
            f"PulseMCP returned HTTP {resp.status_code} for search {term!r}",
        )
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceFetchError("PulseMCP returned a non-JSON body") from exc
    servers = data.get("servers") if isinstance(data, dict) else None
    return servers if isinstance(servers, list) else []


def _collect_tools(version_meta: dict) -> list[str]:
    """Tool names from the (premium) ``remotes[N]`` / ``packages[N]`` entries."""
    names: list[str] = []
    for key, entry in version_meta.items():
        if not (key.startswith("remotes[") or key.startswith("packages[")):
            continue
        if not isinstance(entry, dict):
            continue
        for tool in entry.get("tools") or []:
            name = tool.get("name") if isinstance(tool, dict) else str(tool)
            if name and name not in names:
                names.append(str(name))
    return names


def _to_result(item: dict, slug: str, url: str) -> SourceImportResult:
    server = item.get("server") or {}
    meta = item.get("_meta") or {}
    server_meta = meta.get(_META_SERVER) or {}
    version_meta = meta.get(_META_VERSION) or {}

    display_name = server.get("title") or server.get("name") or slug
    bio = server.get("description") or ""

    icons = server.get("icons") or []
    avatar_url = None
    if icons and isinstance(icons[0], dict):
        avatar_url = icons[0].get("src")

    repository = server.get("repository") or {}
    packages = server.get("packages") or []
    remotes = server.get("remotes") or []

    community_signals = {
        # v0.1 carries no GitHub star count (the old ``pulsemcp_stars``);
        # stars still arrive via axis C from the repo itself.
        "pulsemcp_visitors_week": server_meta.get("visitorsEstimateMostRecentWeek"),
        "pulsemcp_visitors_4w": server_meta.get("visitorsEstimateLastFourWeeks"),
        "pulsemcp_visitors_total": server_meta.get("visitorsEstimateTotal"),
        "pulsemcp_is_official": server_meta.get("isOfficial"),
        "pulsemcp_listed_at": version_meta.get("publishedAt"),
        "pulsemcp_status": version_meta.get("status"),
    }

    return SourceImportResult(
        source_type="pulsemcp",
        source_url=url,
        display_name=display_name,
        bio=bio,
        capabilities=_collect_tools(version_meta),
        detected_framework="mcp",
        community_signals=community_signals,
        raw_metadata={
            "server": server,
            "_meta": meta,
            "registry_name": server.get("name"),
            "repository_url": repository.get("url"),
            "website_url": server.get("websiteUrl"),
            "packages": [
                {
                    "registry": p.get("registryType"),
                    "identifier": p.get("identifier"),
                    "version": p.get("version"),
                }
                for p in packages
                if isinstance(p, dict)
            ],
            "remotes": [
                {"type": r.get("type"), "url": r.get("url")}
                for r in remotes
                if isinstance(r, dict)
            ],
        },
        readme_excerpt="",  # v0.1 does not expose README content
        avatar_url=avatar_url,
        version=server.get("version"),
    )


async def fetch_pulsemcp(slug: str, url: str) -> SourceImportResult | None:
    """Fetch PulseMCP server metadata and return a SourceImportResult.

    Args:
        slug: identifier returned by ``parse_pulsemcp_url``.
        url: original URL provided by the caller (preserved as ``source_url``).

    Returns:
        A ``SourceImportResult``, or ``None`` when PulseMCP is unavailable
        because no ``PULSEMCP_API_KEY`` is configured or the API rejected the
        key (401/403). That soft failure is logged once per process and never
        raises — callers treat it as "no PulseMCP signal".

    Raises:
        SourceFetchError: on network errors, unexpected HTTP statuses, or when
            no listed server matches ``slug``.
    """
    headers = _auth_headers()
    if headers is None:
        _log_unavailable_once("PULSEMCP_API_KEY not configured")
        return None

    async with _make_client() as client:
        for term in _search_terms(slug):
            items = await _search(client, headers, term)
            if items is None:
                _log_unavailable_once("API key rejected (HTTP 401/403)")
                return None
            match = _pick_match(items, slug)
            if match is not None:
                return _to_result(match, slug, url)

    raise SourceFetchError(f"PulseMCP has no server matching slug {slug!r}")
