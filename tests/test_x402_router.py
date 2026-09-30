"""Tests for the x402 trust-surface endpoints.

Covers SSRF validation on /x402/rescan, basic happy-path mocked probe, and
the /x402/explorer read path against a tmp results file.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


RESCAN_URL = "/api/v1/x402/rescan"
EXPLORER_URL = "/api/v1/x402/explorer"


# ── SSRF guard -----------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",
    "http://localhost/",
    "http://127.0.0.1/foo",
    "http://10.0.0.1/foo",
    "http://192.168.1.1/",
    "http://169.254.169.254/",   # AWS metadata
    "ftp://example.com/",
    "http://172.17.0.1/",        # Docker bridge: the old prefix check let this through
    "http://100.64.0.1/",        # CGNAT
    "http://[::ffff:127.0.0.1]/",
    "http://[fd00::1]/",
])
async def test_rescan_rejects_unsafe_endpoints(client, bad_url):
    r = await client.post(RESCAN_URL, params={"endpoint": bad_url})
    assert r.status_code == 400


# ── happy path (mocked) --------------------------------------------------


@pytest.mark.asyncio
async def test_rescan_happy_path_returns_surface(client):
    """A well-formed public endpoint returns observed posture, not a grade."""
    url = "https://api.example.com/x402/paid"

    head_resp = MagicMock(status_code=200, headers={})
    probe_resp = MagicMock(
        status_code=402,
        headers={
            "content-type": "application/json",
            "content-length": "256",
            "www-authenticate": "x402 realm=pay",
        },
        url=url,
    )

    fake_client = MagicMock()
    fake_client.__aenter__.return_value = fake_client
    fake_client.__aexit__.return_value = False
    fake_client.request = AsyncMock(
        side_effect=lambda method, _url, **kw: head_resp if method == "HEAD" else probe_resp)

    with patch("src.ssrf._check_resolved_ips"), \
            patch("src.ssrf.ssrf_safe_async_client", return_value=fake_client) as factory:
        r = await client.post(RESCAN_URL, params={"endpoint": url})
    # The probe goes out through the pinned client, with redirects handled by hand.
    assert factory.call_args.kwargs["follow_redirects"] is False

    assert r.status_code == 200
    body = r.json()
    assert body["endpoint_url"] == url
    assert body["http_status"] == 402
    assert body["has_x402_header"] is True
    # x402_router returns surface only — must NOT leak a trust score
    assert "trust_score" not in body
    assert "grade" not in body


# ── explorer read --------------------------------------------------------


@pytest.mark.asyncio
async def test_explorer_returns_empty_when_no_results_file(client, tmp_path, monkeypatch):
    # Point the results path at an empty tmp file
    missing = tmp_path / "nothing.json"
    monkeypatch.setattr("src.api.x402_router._RESULTS_PATH", missing)
    r = await client.get(EXPLORER_URL)
    assert r.status_code == 200
    assert r.json() == {"count": 0, "results": []}


@pytest.mark.asyncio
async def test_explorer_reads_results_file(client, tmp_path, monkeypatch):
    results_file = tmp_path / "x402-results.json"
    results_file.write_text(json.dumps({
        "results": [
            {
                "endpoint_url": "https://a.example/x402",
                "http_status": 402,
                "has_x402_header": True,
                "content_type": "application/json",
            },
            {
                "endpoint_url": "https://b.example/x402",
                "error": "timeout",
            },
            {"endpoint_url": "", "http_status": 500},  # skipped — no url
        ],
    }))
    monkeypatch.setattr("src.api.x402_router._RESULTS_PATH", results_file)
    r = await client.get(EXPLORER_URL)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    urls = [row["endpoint_url"] for row in body["results"]]
    assert urls == ["https://a.example/x402", "https://b.example/x402"]
    # Errored rows show scanned=False
    assert body["results"][1]["scanned"] is False


@pytest.mark.asyncio
async def test_explorer_handles_malformed_json(client, tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setattr("src.api.x402_router._RESULTS_PATH", bad)
    r = await client.get(EXPLORER_URL)
    assert r.status_code == 200
    assert r.json() == {"count": 0, "results": []}


@pytest.mark.asyncio
async def test_rescan_does_not_follow_a_redirect_to_an_internal_address(client):
    """A public endpoint that answers 302 -> cloud metadata must not be followed."""
    url = "https://api.example.com/x402/paid"
    redirect = MagicMock(
        status_code=302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
    fake_client = MagicMock()
    fake_client.__aenter__.return_value = fake_client
    fake_client.__aexit__.return_value = False
    fake_client.request = AsyncMock(return_value=redirect)

    with patch("src.ssrf._check_resolved_ips"), \
            patch("src.ssrf.ssrf_safe_async_client", return_value=fake_client):
        r = await client.post(RESCAN_URL, params={"endpoint": url})

    assert r.status_code == 200
    assert r.json()["error"] == "blocked"
    assert r.json()["http_status"] is None
    # Only the first hop was requested; the internal target never was.
    assert [c.args[1] for c in fake_client.request.call_args_list] == [url]
