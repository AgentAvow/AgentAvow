"""MCP manifest fetcher for source imports."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.types import SourceImportResult
from src.ssrf import validate_url

logger = logging.getLogger(__name__)


async def fetch_mcp(manifest_url: str) -> SourceImportResult:
    """Fetch an MCP manifest JSON and return a SourceImportResult.

    Expects the manifest to contain a ``tools`` array where each item
    has at least ``name`` and optionally ``description``.

    Args:
        manifest_url: URL pointing to an MCP manifest JSON file.

    Returns:
        Populated SourceImportResult with source_type ``mcp_manifest``.

    Raises:
        SourceFetchError: If the manifest cannot be fetched.
        SourceParseError: If the response is not valid MCP manifest JSON.
    """
    # SSRF protection — reject private/internal IPs
    try:
        validate_url(manifest_url, field_name="manifest_url")
    except ValueError as exc:
        raise SourceFetchError(str(exc)) from exc

    from src.ssrf import ssrf_safe_async_client

    try:
        async with ssrf_safe_async_client(timeout=10, follow_redirects=False) as client:
            resp = await client.get(manifest_url)
    except (httpx.HTTPError, ValueError) as exc:
        raise SourceFetchError(
            f"Failed to fetch MCP manifest: {exc}"
        ) from exc

    if resp.status_code != 200:
        raise SourceFetchError(
            f"Failed to fetch MCP manifest: HTTP {resp.status_code}"
        )

    try:
        data = resp.json()
    except Exception as exc:
        raise SourceParseError(
            "MCP manifest URL did not return valid JSON"
        ) from exc

    if not isinstance(data, dict):
        raise SourceParseError("MCP manifest must be a JSON object")

    tools = data.get("tools")
    if not isinstance(tools, list):
        raise SourceParseError("MCP manifest must contain a 'tools' array")

    # Extract tool names as capabilities (max 20)
    capabilities: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "")
        if name:
            capabilities.append(str(name))
    capabilities = capabilities[:20]

    # display_name: manifest "name" field, or derive from URL hostname
    display_name = data.get("name") or ""
    if not display_name:
        parsed = urlparse(manifest_url)
        display_name = parsed.hostname or "MCP Server"

    # bio: manifest "description", or default
    bio = data.get("description") or "MCP-compatible tool server"

    return SourceImportResult(
        source_type="mcp_manifest",
        source_url=manifest_url,
        display_name=display_name,
        bio=bio,
        capabilities=capabilities,
        detected_framework="mcp",
        community_signals={"tool_count": len(tools)},
        raw_metadata=data,
        version=data.get("version"),
    )
