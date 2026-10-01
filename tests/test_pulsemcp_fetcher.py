"""Tests for the PulseMCP v0.1 fetcher.

All HTTP goes through an ``httpx.MockTransport`` — no network. Covers the
key-less graceful fallback (None + one warning), the v0.1 search + slug
matching, the response mapping, and the hard-failure paths that still raise.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from src.config import settings
from src.source_import import pulsemcp_fetcher as pm
from src.source_import.errors import SourceFetchError

URL = "https://www.pulsemcp.com/servers/jwaldor-api-connect"
SLUG = "jwaldor-api-connect"


def _item(name="io.github.jwaldor/api-connect", title="API Connect", **extra):
    item = {
        "server": {
            "name": name,
            "title": title,
            "description": "Call any REST API from an agent.",
            "version": "1.4.2",
            "websiteUrl": "https://example.com",
            "repository": {"url": "https://github.com/jwaldor/api-connect", "source": "github"},
            "icons": [{"src": "https://example.com/icon.png"}],
            "packages": [
                {"registryType": "npm", "identifier": "api-connect-mcp", "version": "1.4.2"}
            ],
            "remotes": [{"type": "streamable-http", "url": "https://mcp.example.com"}],
        },
        "_meta": {
            "com.pulsemcp/server": {
                "visitorsEstimateMostRecentWeek": 120,
                "visitorsEstimateLastFourWeeks": 480,
                "visitorsEstimateTotal": 2900,
                "isOfficial": False,
            },
            "com.pulsemcp/server-version": {
                "status": "active",
                "publishedAt": "2026-02-01T00:00:00Z",
                "isLatest": True,
                "remotes[0]": {
                    "tools": [{"name": "http_request"}, {"name": "list_apis"}],
                },
                "packages[0]": {"tools": [{"name": "http_request"}]},
            },
        },
    }
    item.update(extra)
    return item


def _install_transport(monkeypatch, handler):
    """Route the fetcher's client through a MockTransport; return the request log."""
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(
        pm, "_make_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    return seen


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    monkeypatch.setattr(pm, "_unavailable_logged", False)
    monkeypatch.setattr(settings, "pulsemcp_api_key", None)
    monkeypatch.setattr(settings, "pulsemcp_tenant_id", None)


# ---------------------------------------------------------------------------
# Key-less fallback
# ---------------------------------------------------------------------------

async def test_no_key_returns_none_without_network(monkeypatch, caplog):
    seen = _install_transport(monkeypatch, lambda r: httpx.Response(500))
    with caplog.at_level(logging.WARNING, logger=pm.__name__):
        assert await pm.fetch_pulsemcp(SLUG, URL) is None
        assert await pm.fetch_pulsemcp(SLUG, URL) is None
    assert seen == []  # never hit the API without a key
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1  # logged once per process
    assert "PULSEMCP_API_KEY" in warnings[0].getMessage()


async def test_blank_key_treated_as_missing(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "   ")
    seen = _install_transport(monkeypatch, lambda r: httpx.Response(200, json={"servers": []}))
    assert await pm.fetch_pulsemcp(SLUG, URL) is None
    assert seen == []


@pytest.mark.parametrize("status", [401, 403])
async def test_rejected_key_returns_none_and_logs_once(monkeypatch, caplog, status):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "bad-key")
    body = {"error": "Invalid or missing API key", "code": "unauthorized"}
    _install_transport(monkeypatch, lambda r: httpx.Response(status, json=body))
    with caplog.at_level(logging.WARNING, logger=pm.__name__):
        assert await pm.fetch_pulsemcp(SLUG, URL) is None
        assert await pm.fetch_pulsemcp(SLUG, URL) is None
    assert sum(r.levelno == logging.WARNING for r in caplog.records) == 1


# ---------------------------------------------------------------------------
# v0.1 request shape
# ---------------------------------------------------------------------------

async def test_sends_v01_headers_and_search_params(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k-123")
    monkeypatch.setattr(settings, "pulsemcp_tenant_id", "tenant-9")
    seen = _install_transport(
        monkeypatch, lambda r: httpx.Response(200, json={"servers": [_item()]}),
    )
    res = await pm.fetch_pulsemcp(SLUG, URL)
    assert res is not None
    assert len(seen) == 1
    req = seen[0]
    assert req.url.scheme == "https" and req.url.host == "api.pulsemcp.com"
    assert req.url.path == "/v0.1/servers"
    assert req.url.params["search"] == SLUG
    assert req.url.params["version"] == "latest"
    assert 1 <= int(req.url.params["limit"]) <= 100
    assert req.headers["X-API-Key"] == "k-123"
    assert req.headers["X-Tenant-ID"] == "tenant-9"
    assert req.headers["Accept"] == "application/json"


async def test_tenant_header_omitted_when_unset(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k-123")
    seen = _install_transport(
        monkeypatch, lambda r: httpx.Response(200, json={"servers": [_item()]}),
    )
    await pm.fetch_pulsemcp(SLUG, URL)
    assert "x-tenant-id" not in {k.lower() for k in seen[0].headers}


# ---------------------------------------------------------------------------
# Response mapping
# ---------------------------------------------------------------------------

async def test_maps_v01_server_to_result(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    _install_transport(monkeypatch, lambda r: httpx.Response(200, json={"servers": [_item()]}))
    res = await pm.fetch_pulsemcp(SLUG, URL)
    assert res is not None
    assert res.source_type == "pulsemcp"
    assert res.source_url == URL
    assert res.display_name == "API Connect"
    assert res.bio == "Call any REST API from an agent."
    assert res.detected_framework == "mcp"
    assert res.version == "1.4.2"
    assert res.avatar_url == "https://example.com/icon.png"
    assert res.capabilities == ["http_request", "list_apis"]  # deduped across entries
    assert res.readme_excerpt == ""
    assert res.community_signals == {
        "pulsemcp_visitors_week": 120,
        "pulsemcp_visitors_4w": 480,
        "pulsemcp_visitors_total": 2900,
        "pulsemcp_is_official": False,
        "pulsemcp_listed_at": "2026-02-01T00:00:00Z",
        "pulsemcp_status": "active",
    }
    assert "pulsemcp_stars" not in res.community_signals  # not available on v0.1
    raw = res.raw_metadata
    assert raw["registry_name"] == "io.github.jwaldor/api-connect"
    assert raw["repository_url"] == "https://github.com/jwaldor/api-connect"
    assert raw["packages"] == [
        {"registry": "npm", "identifier": "api-connect-mcp", "version": "1.4.2"}
    ]
    assert raw["remotes"] == [{"type": "streamable-http", "url": "https://mcp.example.com"}]
    assert raw["server"]["name"] == "io.github.jwaldor/api-connect"


async def test_minimal_server_maps_with_defaults(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    minimal = {"server": {"name": "io.github.acme/widget"}, "_meta": {}}
    _install_transport(monkeypatch, lambda r: httpx.Response(200, json={"servers": [minimal]}))
    res = await pm.fetch_pulsemcp("acme-widget", "https://pulsemcp.com/servers/acme-widget")
    assert res is not None
    assert res.display_name == "io.github.acme/widget"
    assert res.bio == "" and res.capabilities == [] and res.avatar_url is None
    assert res.version is None
    assert all(v is None for v in res.community_signals.values())


# ---------------------------------------------------------------------------
# Slug matching
# ---------------------------------------------------------------------------

async def test_picks_matching_server_not_first_result(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    decoy = _item(name="io.github.other/api-connect-pro", title="API Connect Pro")
    body = {"servers": [decoy, _item()]}
    _install_transport(monkeypatch, lambda r: httpx.Response(200, json=body))
    res = await pm.fetch_pulsemcp(SLUG, URL)
    assert res is not None
    assert res.raw_metadata["registry_name"] == "io.github.jwaldor/api-connect"


async def test_matches_by_title_when_name_differs(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    item = _item(name="com.example/thing", title="Jwaldor API Connect")
    _install_transport(monkeypatch, lambda r: httpx.Response(200, json={"servers": [item]}))
    res = await pm.fetch_pulsemcp(SLUG, URL)
    assert res is not None and res.display_name == "Jwaldor API Connect"


async def test_retries_search_as_owner_slash_repo(monkeypatch):
    """``owner-repo`` slugs are not substrings of ``io.github.owner/repo``; the
    second search term flips the first hyphen to a slash."""
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["search"] == "jwaldor/api-connect":
            return httpx.Response(200, json={"servers": [_item()]})
        return httpx.Response(200, json={"servers": []})

    seen = _install_transport(monkeypatch, handler)
    res = await pm.fetch_pulsemcp(SLUG, URL)
    assert res is not None
    assert [r.url.params["search"] for r in seen] == [SLUG, "jwaldor/api-connect"]


# ---------------------------------------------------------------------------
# Hard failures still raise (callers already catch SourceFetchError)
# ---------------------------------------------------------------------------

async def test_no_match_raises(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    seen = _install_transport(monkeypatch, lambda r: httpx.Response(200, json={"servers": []}))
    with pytest.raises(SourceFetchError, match="no server matching"):
        await pm.fetch_pulsemcp(SLUG, URL)
    assert len(seen) == 2  # bounded: both search terms, then give up


@pytest.mark.parametrize("status", [404, 429, 500])
async def test_unexpected_status_raises(monkeypatch, status):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    _install_transport(monkeypatch, lambda r: httpx.Response(status, json={"error": "x"}))
    with pytest.raises(SourceFetchError, match=f"HTTP {status}"):
        await pm.fetch_pulsemcp(SLUG, URL)


async def test_network_error_raises(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    _install_transport(monkeypatch, handler)
    with pytest.raises(SourceFetchError, match="fetch failed"):
        await pm.fetch_pulsemcp(SLUG, URL)


async def test_non_json_body_raises(monkeypatch):
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    _install_transport(monkeypatch, lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(SourceFetchError, match="non-JSON"):
        await pm.fetch_pulsemcp(SLUG, URL)


async def test_sunset_v0beta_shape_is_not_used(monkeypatch):
    """Regression: the sunset ``/v0beta/servers/<slug>`` route must never be hit."""
    monkeypatch.setattr(settings, "pulsemcp_api_key", "k")
    sunset = {"error": {"code": "API_SUNSET", "message": "deprecated"}}

    def handler(request: httpx.Request) -> httpx.Response:
        if "v0beta" in request.url.path:
            return httpx.Response(410, content=json.dumps(sunset).encode())
        return httpx.Response(200, json={"servers": [_item()]})

    seen = _install_transport(monkeypatch, handler)
    assert await pm.fetch_pulsemcp(SLUG, URL) is not None
    assert all("/v0.1/" in r.url.path for r in seen)
