"""URL pattern matching and dispatch for source imports.

Parses a URL, determines the source type, fetches metadata via the
appropriate fetcher, and caches the result in Redis for 5 minutes.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from urllib.parse import urlparse

from src import cache
from src.source_import.errors import UnsupportedSourceError
from src.source_import.types import SourceImportResult
from src.ssrf import validate_url

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # 5 minutes


async def resolve_source(url: str) -> SourceImportResult:
    """Resolve a URL to a SourceImportResult.

    Validates the URL for SSRF, checks Redis cache, then dispatches
    to the appropriate fetcher based on URL pattern.

    Raises:
        ValueError: If the URL is unsupported or points to internal addresses.
    """
    validate_url(url, field_name="source_url")

    # Check cache
    cache_key = _cache_key(url)
    cached = await cache.get(cache_key)
    if cached is not None:
        return SourceImportResult(**cached)

    result = await _dispatch(url)

    # Cache the result
    await cache.set(cache_key, asdict(result), ttl=_CACHE_TTL)

    return result


def _cache_key(url: str) -> str:
    digest = hashlib.sha256(url.encode()).hexdigest()[:16]
    return f"source:preview:{digest}"


async def _dispatch(url: str) -> SourceImportResult:
    """Match URL patterns and call the correct fetcher."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.strip("/")
    parts = path.split("/")

    # A2A agent card — check before .json catch-all
    if "/.well-known/agent-card.json" in url or "/.well-known/agent.json" in url:
        from src.source_import.a2a_fetcher import fetch_a2a
        return await fetch_a2a(url)

    # GitHub: github.com/{owner}/{repo}
    if host == "github.com" and len(parts) >= 2:
        owner, repo = parts[0], parts[1]
        from src.source_import.github_fetcher import fetch_github
        return await fetch_github(owner, repo, url)

    # npm: npmjs.com/package/{name} or npm/package/{name}
    if host in ("www.npmjs.com", "npmjs.com") and len(parts) >= 2 and parts[0] == "package":
        package_name = "/".join(parts[1:])  # support scoped packages
        from src.source_import.npm_fetcher import fetch_npm
        return await fetch_npm(package_name, url)

    # PyPI: pypi.org/project/{name}
    if host == "pypi.org" and len(parts) >= 2 and parts[0] == "project":
        package_name = parts[1]
        from src.source_import.pypi_fetcher import fetch_pypi
        return await fetch_pypi(package_name, url)

    # HuggingFace: huggingface.co/{org}/{model} (not api paths)
    if host in ("huggingface.co", "www.huggingface.co"):
        if len(parts) >= 2 and parts[0] != "api":
            model_id = "/".join(parts[:2])
            from src.source_import.huggingface_fetcher import fetch_huggingface
            return await fetch_huggingface(model_id, url)

    # Docker Hub: hub.docker.com/r/{namespace}/{name} or hub.docker.com/_/{name}
    if host == "hub.docker.com":
        from src.source_import.docker_fetcher import fetch_docker, parse_docker_url
        namespace, name = parse_docker_url(url)
        return await fetch_docker(namespace, name, url)

    # Moltbook
    if "moltbook" in host:
        from src.source_import.moltbook_fetcher import fetch_moltbook
        return await fetch_moltbook(url)

    # MCP manifest: any URL ending in .json
    if parsed.path.endswith(".json"):
        from src.source_import.mcp_fetcher import fetch_mcp
        return await fetch_mcp(url)

    raise UnsupportedSourceError(
        f"Unsupported source URL: {url}. "
        "Supported: GitHub, npm, PyPI, HuggingFace, Docker Hub, "
        "MCP manifest (.json), A2A agent card, Moltbook."
    )
