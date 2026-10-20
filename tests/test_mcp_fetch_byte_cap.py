"""The scanner's MCP session refuses a response past MCP_MAX_RESPONSE_BYTES.

agentgraph-72's #207 review: fetch_mcp_tools had no response-size cap of its own, so a
hostile server could stream an arbitrarily large tools/list into the scanner.
"""
from __future__ import annotations

import json

import httpx
import pytest

from src.scanner import mcp_scan as ms

URL = "https://mcp.example.com/mcp"


def _client(tools_body: bytes, *, declared: bool = True) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content or b"{}").get("method")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "x", "version": "1"}}})
        if method == "tools/list":
            if declared:
                return httpx.Response(200, content=tools_body,
                                      headers={"content-type": "application/json"})
            # no content-length: a chunked stream the reader must stop itself
            return httpx.Response(200, stream=httpx.ByteStream(tools_body),
                                  headers={"content-type": "application/json"})
        return httpx.Response(202)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _tools_doc(n: int, pad: int = 0) -> bytes:
    tools = [{"name": f"t{i}", "description": "x" * pad,
              "inputSchema": {"type": "object"}} for i in range(n)]
    return json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}).encode()


@pytest.mark.asyncio
async def test_normal_tool_list_is_read():
    async with _client(_tools_doc(3)) as c:
        s = ms.McpSession(c, URL)
        assert await s.initialize() == 200
        tools = await s.list("tools/list", "tools")
    assert [t["name"] for t in tools] == ["t0", "t1", "t2"]
    assert "tools/list" not in s.__dict__.get("list_failed", set())


@pytest.mark.asyncio
@pytest.mark.parametrize("declared", [True, False], ids=["content-length", "chunked"])
async def test_oversized_tool_list_is_refused_and_recorded(monkeypatch, declared):
    monkeypatch.setattr(ms, "MCP_MAX_RESPONSE_BYTES", 10_000)
    async with _client(_tools_doc(50, pad=1_000), declared=declared) as c:
        s = ms.McpSession(c, URL)
        assert await s.initialize() == 200
        tools = await s.list("tools/list", "tools")
    assert tools == []
    assert "tools/list" in s.__dict__["list_failed"]


@pytest.mark.asyncio
async def test_post_capped_raises_past_the_limit():
    async with _client(b"x" * 5_000, declared=False) as c:
        with pytest.raises(ms.ResponseTooLargeError):
            await ms._post_capped(c, URL, limit=1_000,
                                  json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})


def test_default_cap_is_generous_for_real_servers():
    # A large real tools/list is a few hundred KB; the cap must sit well above that.
    assert ms.MCP_MAX_RESPONSE_BYTES >= 2 * 1024 * 1024
