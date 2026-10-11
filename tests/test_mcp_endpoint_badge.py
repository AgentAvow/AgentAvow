"""A live MCP endpoint gets the same badge/card and history as repos and packages."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import src.api.public_scan_router as m


def _data(score=74):
    return {"trust_score": score, "decision": "safe", "decision_final": True,
            "findings": {"critical": 0, "high": 0, "items": []},
            "certified": {"eligible": False}, "metadata": {"files_scanned": 3}}


@pytest.fixture
def stubs(monkeypatch):
    seen = {"cache_keys": [], "scans": 0}

    async def _get_cached(owner, repo):
        seen["cache_keys"].append((owner, repo))
        return _data()

    async def _stale(owner, repo):
        return None

    async def _adopt(surface, owner, repo):
        return (None, None, None)

    monkeypatch.setattr(m, "_get_cached", _get_cached)
    monkeypatch.setattr(m, "_get_stale_cached", _stale)
    monkeypatch.setattr(m, "surface_adoption_summary", _adopt)
    return seen


async def test_mcp_badge_reads_the_endpoint_result(stubs):
    resp = await m.mcp_badge(endpoint="https://mcp.deepwiki.com/mcp", style="compact", theme="auto")
    assert resp.media_type == "image/svg+xml"
    assert resp.headers["access-control-allow-origin"] == "*"
    body = resp.body.decode()
    assert "74" in body
    url, key = m._mcp_identity("https://mcp.deepwiki.com/mcp")
    assert ("mcp", key) in stubs["cache_keys"]


async def test_mcp_card_svg(stubs):
    resp = await m.mcp_card(endpoint="https://mcp.deepwiki.com/mcp", style="card", theme="dark")
    assert resp.body.decode().lstrip().startswith("<svg")


def test_identity_matches_scan_route_and_rejects_bad_urls():
    url, key = m._mcp_identity("https://mcp.deepwiki.com/mcp")
    assert url.startswith("https://mcp.deepwiki.com")
    assert key.startswith("mcp_") and len(key) == 4 + 22
    with pytest.raises(HTTPException):
        m._mcp_identity("http://not-https.example/mcp")
    with pytest.raises(HTTPException):
        m._mcp_identity("not a url")


async def test_unscannable_endpoint_renders_not_scanned(monkeypatch):
    async def _none(owner, repo):
        return None

    async def _adopt(surface, owner, repo):
        return (None, None, None)

    async def _fail(url):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(m, "_get_cached", _none)
    monkeypatch.setattr(m, "_get_stale_cached", _none)
    monkeypatch.setattr(m, "surface_adoption_summary", _adopt)
    import src.scanner.scan as scan_mod
    monkeypatch.setattr(scan_mod, "scan_mcp", _fail)
    resp = await m.mcp_badge(endpoint="https://example.com/mcp", style="compact", theme="auto")
    assert resp.media_type == "image/svg+xml"
