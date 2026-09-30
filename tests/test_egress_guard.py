"""Outbound requests to URLs that a caller, a user, or fetched content controls go
through the shared guard in ``src/ssrf.py``: validated, pinned to the validated
address, and never redirected without each hop being checked.
"""
from __future__ import annotations

import inspect
import socket
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src import ssrf
from src.ssrf import build_ssrf_safe_transport, ssrf_safe_follow


def _resp(status: int, location: str | None = None):
    return MagicMock(status_code=status, headers={"location": location} if location else {})


# ── ssrf_safe_follow ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_follow_returns_a_direct_response(monkeypatch):
    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda *a, **k: None)
    client = MagicMock()
    client.request = AsyncMock(return_value=_resp(200))
    resp, final = await ssrf_safe_follow(client, "GET", "https://a.example.com/x")
    assert resp.status_code == 200 and final == "https://a.example.com/x"


@pytest.mark.asyncio
async def test_follow_resolves_a_relative_redirect_against_the_hostname(monkeypatch):
    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda *a, **k: None)
    client = MagicMock()
    client.request = AsyncMock(side_effect=[_resp(301, "/moved"), _resp(200)])
    _, final = await ssrf_safe_follow(client, "GET", "https://a.example.com/x")
    assert final == "https://a.example.com/moved"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "http://10.0.0.5/",
    "file:///etc/passwd",
])
async def test_follow_refuses_a_redirect_to_a_blocked_target(monkeypatch, target):
    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda *a, **k: None)
    client = MagicMock()
    client.request = AsyncMock(return_value=_resp(302, target))
    with pytest.raises(ValueError):
        await ssrf_safe_follow(client, "GET", "https://a.example.com/x")
    assert client.request.await_count == 1  # the blocked hop was never requested


@pytest.mark.asyncio
async def test_follow_stops_a_redirect_loop(monkeypatch):
    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda *a, **k: None)
    client = MagicMock()
    client.request = AsyncMock(return_value=_resp(302, "https://a.example.com/again"))
    with pytest.raises(ValueError):
        await ssrf_safe_follow(client, "GET", "https://a.example.com/x", max_redirects=2)
    assert client.request.await_count == 3


# ── the pinned transport fails closed ────────────────────────────────────────
@pytest.mark.asyncio
async def test_transport_refuses_when_the_host_does_not_resolve(monkeypatch):
    """If the guard's own lookup fails, the request must not be handed to httpx to
    resolve again unchecked."""
    def no_dns(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    transport = build_ssrf_safe_transport()
    request = httpx.Request("GET", "https://does-not-resolve.example/x")
    with pytest.raises(httpx.ConnectError):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_transport_refuses_a_host_that_resolves_internally(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))])
    transport = build_ssrf_safe_transport()
    with pytest.raises(ValueError):
        await transport.handle_async_request(httpx.Request("GET", "https://rebind.example/x"))


# ── partner scan-change webhooks: subscribing needs no login ─────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("callback", [
    "https://127.0.0.1/hook",
    "https://169.254.169.254/hook",
    "https://10.1.2.3/hook",
    "http://93.184.216.34/hook",
])
async def test_partner_webhook_subscribe_refuses_internal_callback(monkeypatch, callback):
    from src.api.trust_gateway_router import WebhookSubscribeRequest, webhook_subscribe
    from src.trust import outbound_webhooks

    register = AsyncMock()
    monkeypatch.setattr(outbound_webhooks, "register_subscription", register)
    resp = await webhook_subscribe(
        WebhookSubscribeRequest(repo="o/r", callback_url=callback, provider="p"))
    assert resp.subscribed is False
    register.assert_not_awaited()


# ── every delivery site for a user-controlled URL uses the pinned client ─────
@pytest.mark.parametrize("module_path, func", [
    ("src.events", "dispatch_webhooks"),
    ("src.jobs.webhook_worker", "process_event"),
    ("src.trust.outbound_webhooks", "notify_scan_change"),
    ("src.jobs.api_health_check", "_ping"),
    ("src.api.account_claims_router", "_mcp_challenge_ok"),
    ("src.source_import.moltbook_fetcher", "fetch_moltbook"),
    ("src.source_import.a2a_fetcher", "fetch_a2a"),
    ("src.source_import.mcp_fetcher", "fetch_mcp"),
    ("src.api.x402_router", "rescan_x402_endpoint"),
    ("src.api.account_webhook_router", "deliver_alert_webhook"),
])
def test_user_controlled_fetch_uses_the_pinned_client(module_path, func):
    import importlib

    source = inspect.getsource(getattr(importlib.import_module(module_path), func))
    assert "ssrf_safe_async_client(" in source
    assert "httpx.AsyncClient(" not in source
