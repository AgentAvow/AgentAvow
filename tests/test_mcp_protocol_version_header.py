"""The scanner sends MCP-Protocol-Version after initialize, as the gates already do.

Without the header a Streamable-HTTP server assumes 2025-03-26 and may serve tools
without outputSchema or title (HISTOR's note on AgentAvow #240: isitabizday.com served
0 of 8 outputSchemas without it), so the issuer would sign a thinner definition than
a client that follows the spec is served.
"""
from __future__ import annotations

import json

import httpx
import pytest

from src.scanner import mcp_scan as ms

URL = "https://mcp.example.com/mcp"

FULL = {"name": "t", "title": "T", "description": "Adds numbers.",
        "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"}}
OLD = {"name": "t", "description": "Adds numbers.", "inputSchema": {"type": "object"}}


def _server(seen: list, negotiated="2025-06-18"):
    """Serves the 2025-06-18 shape only when tools/list carries the header."""
    def handler(request: httpx.Request) -> httpx.Response:
        doc = json.loads(request.content or b"{}")
        method, rid = doc.get("method"), doc.get("id")
        seen.append((method, request.headers.get("mcp-protocol-version")))
        if method == "initialize":
            result = {"capabilities": {"tools": {}}, "serverInfo": {"name": "s", "version": "1"}}
            if negotiated is not None:
                result["protocolVersion"] = negotiated
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result},
                                  headers={"mcp-session-id": "abc"})
        if method == "tools/list":
            hdr = request.headers.get("mcp-protocol-version")
            tool = FULL if hdr and hdr >= "2025-06-18" else OLD
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid,
                                             "result": {"tools": [tool]}})
        if method in ("resources/list", "prompts/list"):
            key = method.split("/")[0]
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {key: []}})
        return httpx.Response(202)
    return handler


@pytest.fixture
def serve(monkeypatch):
    import src.ssrf as ssrf

    def _use(handler):
        monkeypatch.setattr(ssrf, "validate_url_https", lambda url, *a, **k: url)
        monkeypatch.setattr(
            ssrf, "ssrf_safe_async_client",
            lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return _use


@pytest.mark.asyncio
async def test_header_sent_after_initialize_and_full_definition_signed(serve):
    seen: list = []
    serve(_server(seen))
    data = await ms.fetch_mcp_tools(URL)
    # The scan opens more than one session; each initialize goes out bare and every
    # request after it carries the header.
    assert {v for m, v in seen if m == "initialize"} == {None}
    assert {v for m, v in seen if m != "initialize"} == {"2025-06-18"}, seen
    assert data["tools"] == [FULL]
    assert ms.compute_tool_digests(data["tools"]) == ms.compute_tool_digests([FULL])


@pytest.mark.asyncio
async def test_header_carries_the_negotiated_version(serve):
    seen: list = []
    serve(_server(seen, negotiated="2025-03-26"))
    await ms.fetch_mcp_tools(URL)
    assert {v for m, v in seen if m != "initialize"} == {"2025-03-26"}


@pytest.mark.asyncio
@pytest.mark.parametrize("negotiated", [None, 7, "latest\r\nX-Evil: 1"])
async def test_missing_or_malformed_version_falls_back_to_requested(serve, negotiated):
    seen: list = []
    serve(_server(seen, negotiated=negotiated))
    await ms.fetch_mcp_tools(URL)
    assert {v for m, v in seen if m != "initialize"} == {ms._MCP_PROTOCOL_VERSION}
