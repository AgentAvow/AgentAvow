"""Adoption for a bare MCP endpoint: official-registry listing → linked repo stars."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scanner import mcp_endpoint_adoption as m

_PAGE = {
    "servers": [
        {"server": {"name": "ai.smithery/other", "remotes": [
            {"url": "https://server.smithery.ai/@x/other/mcp"}]}},
        {"server": {"name": "ai.smithery/smithery-ai-github",
                    "remotes": [{"type": "streamable-http",
                                 "url": "https://server.smithery.ai/@smithery-ai/github/mcp/"}],
                    "repository": {"url": "https://github.com/smithery-ai/mcp-servers"}}},
    ],
    "metadata": {"count": 2},
}


def test_normalize_and_terms():
    assert m.normalize_endpoint("HTTPS://Mcp.DeepWiki.com/mcp/?x=1") == "mcp.deepwiki.com/mcp"
    assert m.normalize_endpoint("mcp.deepwiki.com/mcp") == "mcp.deepwiki.com/mcp"
    assert m.search_terms("https://mcp.deepwiki.com/mcp") == ["deepwiki"]
    assert m.search_terms("https://server.smithery.ai/@smithery-ai/github/mcp") == [
        "github", "smithery-ai", "smithery"]


def test_match_requires_the_exact_remote():
    hit = m.match_listing(_PAGE["servers"], "https://server.smithery.ai/@smithery-ai/github/mcp")
    assert hit == {"name": "ai.smithery/smithery-ai-github",
                   "repository": "https://github.com/smithery-ai/mcp-servers"}
    # Same host, different path: not this server.
    assert m.match_listing(_PAGE["servers"], "https://server.smithery.ai/@smithery-ai/x/mcp") is None


def test_linked_github():
    assert m.linked_github("https://github.com/smithery-ai/mcp-servers.git") == (
        "smithery-ai", "mcp-servers")
    assert m.linked_github("https://gitlab.com/a/b") is None
    assert m.linked_github(None) is None


def _client(payload, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _no_redis():
    r = MagicMock()
    r.get = AsyncMock(return_value=None)
    r.set = AsyncMock(return_value=True)
    return r


@pytest.mark.asyncio
async def test_listing_found_and_cached():
    redis = _no_redis()
    with patch("httpx.AsyncClient", return_value=_client(_PAGE)), \
            patch("src.redis_client.get_redis", return_value=redis):
        out = await m.endpoint_registry_listing(
            "https://server.smithery.ai/@smithery-ai/github/mcp")
    assert out["listed"] is True and out["repository"].endswith("mcp-servers")
    assert redis.set.await_args.kwargs["ex"] == m._CACHE_TTL


@pytest.mark.asyncio
async def test_registry_error_is_no_signal_with_short_cache():
    redis = _no_redis()
    with patch("httpx.AsyncClient", return_value=_client({}, status=503)), \
            patch("src.redis_client.get_redis", return_value=redis):
        out = await m.endpoint_registry_listing("https://mcp.deepwiki.com/mcp")
    assert out == {"listed": False}

    boom = _client({})
    boom.get = AsyncMock(side_effect=RuntimeError("timeout"))
    with patch("httpx.AsyncClient", return_value=boom), \
            patch("src.redis_client.get_redis", return_value=redis):
        out = await m.endpoint_registry_listing("https://mcp.deepwiki.com/mcp")
    assert out == {"listed": False}
    assert redis.set.await_args.kwargs["ex"] == m._FAIL_TTL


@pytest.mark.asyncio
async def test_surface_adoption_uses_linked_repo_stars_for_endpoint():
    from src.api import public_scan_router as r
    with patch("src.scanner.mcp_endpoint_adoption.endpoint_registry_listing",
               AsyncMock(return_value={"listed": True, "name": "ai.smithery/x",
                                       "repository": "https://github.com/o/r"})), \
            patch.object(r, "_github_stars", AsyncMock(return_value=1234)) as stars:
        axes, headline = await r._surface_adoption_axes(
            "mcp", "mcp", "https://server.smithery.ai/@o/r/mcp")
    stars.assert_awaited_once_with("o", "r")
    assert headline["count"] == 1234 and headline["unit"] == "stars (linked repo)"
    assert len(axes) == 1


@pytest.mark.asyncio
async def test_surface_adoption_unlisted_endpoint_is_absent_not_zero():
    from src.api import public_scan_router as r
    with patch("src.scanner.mcp_endpoint_adoption.endpoint_registry_listing",
               AsyncMock(return_value={"listed": False})), \
            patch.object(r, "_github_stars", AsyncMock(return_value=99)) as stars:
        # Schemeless endpoint from the check page (owner="mcp") is still an endpoint.
        axes, headline = await r._surface_adoption_axes("mcp", "mcp", "mcp.deepwiki.com/mcp")
    stars.assert_not_awaited()
    assert axes == [] and headline is None
