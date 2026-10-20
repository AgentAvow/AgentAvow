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


# ── a refused tools/list must never read Safe (agentgraph-72's #208 gate) ────────────
def _server(tools_body: bytes, *, with_resources: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content or b"{}").get("method")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "padded", "version": "1"}}})
        if method == "tools/list":
            return httpx.Response(200, stream=httpx.ByteStream(tools_body))
        if method == "resources/list" and with_resources:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {
                "resources": [{"uri": "x://a", "name": "a"}]}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {}})
    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize("with_resources", [False, True], ids=["tools-only", "with-resources"])
async def test_padded_tool_list_is_flagged_not_dropped(monkeypatch, with_resources):
    monkeypatch.setattr(ms, "MCP_MAX_RESPONSE_BYTES", 10_000)
    handler = _server(_tools_doc(50, pad=1_000), with_resources=with_resources)
    import src.ssrf as ssrf
    monkeypatch.setattr(ssrf, "validate_url_https", lambda url, *a, **k: url)
    monkeypatch.setattr(ssrf, "ssrf_safe_async_client",
                        lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    data = await ms.fetch_mcp_tools(URL)
    assert data is not None, "a server whose only list was refused must still be graded"
    assert data["lists_too_large"] == ["tools/list"]
    assert data.get("tools_list_failed") is True


def test_oversize_findings_severity():
    f = ms.oversize_findings(["tools/list", "prompts/list"])
    sev = {x.file_path: x.severity for x in f}
    assert sev == {"server:tools/list": "high", "server:prompts/list": "medium"}
    assert ms.oversize_findings(None) == [] and ms.oversize_findings([]) == []


@pytest.mark.asyncio
async def test_scan_of_a_padded_tool_list_reads_review(monkeypatch):
    async def fake_fetch(url):
        return {"tools": [], "resources": [], "prompts": [],
                "server_info": {"name": "padded"}, "tools_list_failed": True,
                "lists_too_large": ["tools/list"]}
    monkeypatch.setattr(ms, "fetch_mcp_tools", fake_fetch)
    from src.scanner.local_scan import decision_for_result
    from src.scanner.scan import scan_mcp
    res = await scan_mcp(URL)
    assert any(f.file_path == "server:tools/list" and f.severity == "high"
               for f in res.findings)
    d = decision_for_result(res)
    assert d.decision == "review", (d.decision, d.reason)
