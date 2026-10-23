"""An MCP server that refuses ``initialize`` until the caller signs in (HTTP 401, or any
error with a ``WWW-Authenticate: Bearer`` OAuth challenge, e.g. https://mcp.notion.com/mcp)
gets a scan error that says so (a bare 403, which a WAF block also sends, does not), not the generic "could not handshake" one, and the public API
passes that detail through. The ``resource_metadata`` URL in the challenge is never
fetched."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from src.scanner import mcp_scan as ms
from src.scanner import scan as scan_mod

URL = "https://mcp.example.com/mcp"
NOTION_CHALLENGE = (
    'Bearer realm="OAuth", '
    'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", '
    'error="invalid_token", error_description="Missing or invalid access token"'
)


def _patch_transport(monkeypatch, handler, seen: list | None = None):
    def wrapped(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        return handler(request)

    import src.ssrf as ssrf
    monkeypatch.setattr(ssrf, "validate_url_https", lambda url, *a, **k: url)
    monkeypatch.setattr(ssrf, "ssrf_safe_async_client",
                        lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(wrapped)))


def _refuse(status: int, www_authenticate: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"WWW-Authenticate": www_authenticate} if www_authenticate else {}
        return httpx.Response(status, headers=headers, json={"error": "nope"})
    return handler


# ── fetch_mcp_tools: the reason comes out, falsy ─────────────────────────────────────
@pytest.mark.asyncio
async def test_401_bearer_challenge_is_auth_required(monkeypatch):
    seen: list = []
    _patch_transport(monkeypatch, _refuse(401, NOTION_CHALLENGE), seen)
    data = await ms.fetch_mcp_tools(URL)
    assert not data, "a failure must stay falsy for every `if not data` caller"
    assert isinstance(data, ms.McpFetchFailure)
    assert data.reason == ms.MCP_FAILURE_AUTH_REQUIRED
    assert data.status == 401
    # Only the endpoint itself was contacted: the server-supplied resource_metadata
    # URL is never followed.
    assert seen and all(u == URL for u in seen)


@pytest.mark.asyncio
async def test_401_without_header_is_auth_required(monkeypatch):
    _patch_transport(monkeypatch, _refuse(401))
    data = await ms.fetch_mcp_tools(URL)
    assert isinstance(data, ms.McpFetchFailure) and not data
    assert data.reason == ms.MCP_FAILURE_AUTH_REQUIRED


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403])
async def test_bearer_challenge_on_other_status_is_auth_required(monkeypatch, status):
    _patch_transport(monkeypatch, _refuse(status, 'Bearer error="insufficient_scope"'))
    data = await ms.fetch_mcp_tools(URL)
    assert isinstance(data, ms.McpFetchFailure)
    assert data.reason == ms.MCP_FAILURE_AUTH_REQUIRED
    assert data.status == status


@pytest.mark.asyncio
@pytest.mark.parametrize("status,header", [
    (403, None),                # a WAF / bot block: not sign-in
    (403, 'Basic realm="x"'),
    (404, None),
    (500, None),
    (405, None),
    (400, 'Basic realm="x"'),  # not an OAuth Bearer challenge
    (502, "Bearerish"),         # a word that merely starts with "Bearer"
])
async def test_other_failures_stay_generic(monkeypatch, status, header):
    _patch_transport(monkeypatch, _refuse(status, header))
    assert await ms.fetch_mcp_tools(URL) is None


@pytest.mark.asyncio
async def test_transport_error_stays_generic(monkeypatch):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)
    _patch_transport(monkeypatch, boom)
    assert await ms.fetch_mcp_tools(URL) is None


def test_auth_required_predicate():
    assert ms._auth_required(401, None)
    assert not ms._auth_required(403, None)  # bare 403: WAF blocks look the same
    assert ms._auth_required(403, 'Bearer error="insufficient_scope"')
    assert ms._auth_required(400, "Bearer")
    assert ms._auth_required(400, 'DPoP algs="ES256", Bearer realm="x"')
    assert ms._auth_required(400, 'bearer realm="x"')
    assert not ms._auth_required(200, "Bearer")
    assert not ms._auth_required(0, "Bearer")
    assert not ms._auth_required(None, None)
    assert not ms._auth_required(404, None)
    assert not ms._auth_required(400, 'Basic realm="x"')


# ── scan_mcp: the error text ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_scan_mcp_names_signin(monkeypatch):
    _patch_transport(monkeypatch, _refuse(401, NOTION_CHALLENGE))
    res = await scan_mod.scan_mcp(URL)
    assert res.error == scan_mod.MCP_SIGNIN_REQUIRED_ERROR
    assert "requires sign-in (OAuth)" in res.error
    assert "Scan its source repo or package instead" in res.error
    assert "not found" not in res.error.lower()  # routers must not turn it into a 404
    assert not res.findings


@pytest.mark.asyncio
async def test_scan_mcp_generic_message_kept(monkeypatch):
    _patch_transport(monkeypatch, _refuse(500))
    res = await scan_mod.scan_mcp(URL)
    assert res.error.startswith("Could not handshake the MCP server")


@pytest.mark.asyncio
async def test_scan_mcp_none_from_a_fake_fetch_still_generic(monkeypatch):
    async def fake_fetch(url):
        return None
    monkeypatch.setattr(ms, "fetch_mcp_tools", fake_fetch)
    res = await scan_mod.scan_mcp(URL)
    assert res.error.startswith("Could not handshake the MCP server")


# ── the public API passes the detail through ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_public_scan_endpoint_passes_signin_detail(monkeypatch):
    from src.api import public_scan_router as psr

    async def _none(*a, **k):
        return None
    monkeypatch.setattr(psr, "_get_cached", _none)
    monkeypatch.setattr(psr, "_get_stale_cached", _none)
    _patch_transport(monkeypatch, _refuse(401, NOTION_CHALLENGE))
    monkeypatch.setattr("src.ssrf.mcp_endpoint_identity", lambda u: u)

    with pytest.raises(HTTPException) as exc:
        await psr.scan_mcp_endpoint(endpoint=URL, request=None, force=True, probe=False,
                                    db=None)
    assert exc.value.status_code == 422
    assert exc.value.detail == f"Scan error: {scan_mod.MCP_SIGNIN_REQUIRED_ERROR}"
