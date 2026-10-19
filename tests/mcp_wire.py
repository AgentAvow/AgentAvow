"""Drive the hosted MCP server (/mcp) in-process, over its real Streamable HTTP entry.

Each call runs a fresh session manager configured like the module's own (a session
manager can only be run once), with the module's ASGI front so the User-Agent →
surface attribution runs exactly as in production.
"""
from __future__ import annotations

import json

import httpx
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from src.bridges import mcp_streamable as m

UA_CHATGPT = "openai-mcp/1.0.0"
UA_CLAUDE = "Claude-User"
UA_CLAUDE_CODE = "claude-code/2.1.300 (cli)"
MODERN = "2026-07-28"


def modern_envelope(**params) -> dict:
    """Request params carrying the 2026-07-28 per-request `_meta` envelope."""
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "probe", "version": "1.0"},
        },
        **params,
    }


def modern_headers(method: str, params: dict | None) -> dict:
    """The SEP-2243 routing headers a 2026-07-28 client sends with each request."""
    h = {"mcp-protocol-version": MODERN, "mcp-method": method}
    params = params or {}
    name = params.get("uri") if method == "resources/read" else params.get("name")
    if isinstance(name, str):
        h["mcp-name"] = name
    return h


async def post(
    method: str,
    params: dict | None = None,
    *,
    ua: str = UA_CHATGPT,
    protocol_version: str | None = "2025-11-25",
    headers: dict | None = None,
    request_id: int = 1,
) -> httpx.Response:
    body: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    h = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "user-agent": ua,
    }
    if protocol_version is not None:
        h["mcp-protocol-version"] = protocol_version
    h.update(headers or {})
    sm = StreamableHTTPSessionManager(app=m.server, json_response=m.session_manager.json_response,
                                      stateless=m.session_manager.stateless)
    saved = m.session_manager
    async with sm.run():
        m.session_manager = sm
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.mcp_asgi_app),
                                         base_url="http://testserver") as c:
                return await c.post("/mcp", headers=h, content=json.dumps(body))
        finally:
            m.session_manager = saved


def initialize_params(protocol_version: str = "2025-11-25") -> dict:
    return {"protocolVersion": protocol_version, "capabilities": {},
            "clientInfo": {"name": "probe", "version": "1.0"}}
