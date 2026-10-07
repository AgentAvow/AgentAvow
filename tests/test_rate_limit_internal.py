"""MCP bridge → API calls are rate-limited per END USER, not as one loopback bucket.

The bridge proves it is the bridge with a shared token and forwards the user's
address and surface; the API honors that only from loopback, and applies the
agent-tier MCP limits (multiplied for vendor-proxy surfaces). Without a token,
nothing changes.
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

import src.api.rate_limit as rl
from src.config import settings

TOKEN = "t0ken-for-tests"


def _req(headers: dict | None = None, client_ip: str = "127.0.0.1") -> Request:
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/api/v1/public/scan/x",
                    "headers": hdrs, "client": (client_ip, 1234), "query_string": b"",
                    "scheme": "http", "server": ("t", 80)})


def _internal(ip="203.0.113.9", surface="claude-code", token=TOKEN):
    return {"X-AgentAvow-Internal": token, "X-AgentAvow-Client-Ip": ip, "X-AgentAvow-Surface": surface}


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(settings, "mcp_internal_token", TOKEN, raising=False)


@pytest.fixture
def recorder(monkeypatch):
    seen: list[tuple[str, int]] = []

    async def check(key, limit, window_seconds=60):
        seen.append((key, limit))
        return True

    async def headers(request, key, limit):
        return None

    monkeypatch.setattr(rl._limiter, "check", check)
    monkeypatch.setattr(rl, "_set_rate_limit_headers", headers)
    return seen


def test_internal_call_requires_token_match_and_loopback(token):
    assert rl._internal_call(_req(_internal())) == ("203.0.113.9", "claude-code")
    assert rl._internal_call(_req(_internal(token="wrong"))) is None
    assert rl._internal_call(_req(_internal(), client_ip="198.51.100.4")) is None  # not loopback
    assert rl._internal_call(_req()) is None
    assert rl._internal_call(_req(_internal(ip="", surface=""))) == ("mcp-unknown", "other")


def test_without_a_configured_token_nothing_changes(monkeypatch):
    monkeypatch.setattr(settings, "mcp_internal_token", "", raising=False)
    assert rl._internal_call(_req(_internal())) is None
    assert rl._get_client_ip(_req(_internal())) == "127.0.0.1"


def test_client_ip_is_the_forwarded_end_user(token):
    assert rl._get_client_ip(_req(_internal(ip="203.0.113.9"))) == "203.0.113.9"
    assert rl._get_client_ip(_req()) == "127.0.0.1"


@pytest.mark.asyncio
async def test_reads_and_scans_use_a_per_user_mcp_bucket_at_agent_rates(token, recorder):
    await rl.rate_limit_reads(_req(_internal(ip="203.0.113.9", surface="claude-code")))
    await rl.rate_limit_scans(_req(_internal(ip="203.0.113.9", surface="claude-code")))
    assert ("read:mcp:203.0.113.9", settings.rate_limit_mcp_reads_per_minute) in recorder
    assert ("scan:mcp:203.0.113.9", settings.rate_limit_mcp_scans_per_minute) in recorder


@pytest.mark.asyncio
async def test_vendor_proxy_surfaces_get_the_shared_egress_multiplier(token, recorder):
    await rl.rate_limit_reads(_req(_internal(ip="34.1.2.3", surface="claude")))
    await rl.rate_limit_scans(_req(_internal(ip="34.1.2.3", surface="chatgpt")))
    assert ("read:mcp:34.1.2.3", settings.rate_limit_mcp_reads_per_minute * rl._SHARED_EGRESS_MULTIPLIER) in recorder
    assert ("scan:mcp:34.1.2.3", settings.rate_limit_mcp_scans_per_minute * rl._SHARED_EGRESS_MULTIPLIER) in recorder


@pytest.mark.asyncio
async def test_ordinary_requests_keep_the_ordinary_buckets(token, recorder):
    await rl.rate_limit_reads(_req(client_ip="198.51.100.4"))
    await rl.rate_limit_scans(_req(client_ip="198.51.100.4"))
    assert ("read:198.51.100.4", settings.rate_limit_reads_per_minute) in recorder
    assert ("scan:198.51.100.4", settings.rate_limit_scans_per_minute) in recorder
    assert not any(":mcp:" in k for k, _ in recorder)
