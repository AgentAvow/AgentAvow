"""Per-surface MCP session-start counter (agentgraph-72, 2026-10-21).

A session starts with initialize (handshake-era protocols) or server/discover
(2026-07-28 clients never send initialize). Each successful one bumps session_start and
its own key, per surface, and adds the caller to the distinct-starters HLL.
"""
from __future__ import annotations

import asyncio

import pytest

from tests import mcp_wire as wire


@pytest.fixture
def captured(monkeypatch):
    bumps: list[str] = []
    uniques: list[str] = []

    async def bump_metric(name):
        bumps.append(name)

    async def record_unique(name, ip, ua):
        uniques.append(name)

    import src.api.metrics_dashboard_router as mdr
    monkeypatch.setattr(mdr, "bump_metric", bump_metric)
    monkeypatch.setattr(mdr, "record_unique", record_unique)
    return bumps, uniques


async def _drain():
    # Counting is inline (no background task), so nothing is left to wait for.
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_initialize_counts_a_session_start_per_surface(captured):
    bumps, uniques = captured
    resp = await wire.post("initialize", wire.initialize_params(), ua=wire.UA_CLAUDE_CODE,
                           protocol_version=None, request_id=0)
    assert resp.status_code == 200
    await _drain()
    for k in ("mcp:session_start", "mcp:session_start:claude-code",
              "mcp:initialize", "mcp:initialize:claude-code"):
        assert k in bumps, (k, bumps)
    assert "mcp:initializers" in uniques and "mcp:initializers:claude-code" in uniques


@pytest.mark.asyncio
async def test_discover_counts_a_session_start_for_2026_clients(captured):
    bumps, uniques = captured
    params = wire.modern_envelope()
    resp = await wire.post("server/discover", params, ua=wire.UA_CLAUDE,
                           protocol_version=None,
                           headers=wire.modern_headers("server/discover", params))
    assert resp.status_code == 200
    await _drain()
    assert "mcp:session_start:claude" in bumps and "mcp:discover:claude" in bumps
    assert "mcp:initializers:claude" in uniques


@pytest.mark.asyncio
async def test_tools_list_is_counted_but_is_not_a_session_start(captured):
    bumps, uniques = captured
    resp = await wire.post("tools/list", None, ua=wire.UA_CHATGPT, request_id=1)
    assert resp.status_code == 200
    await _drain()
    assert "mcp:tools_list:chatgpt" in bumps
    assert not any(b.startswith("mcp:session_start") for b in bumps)
    assert uniques == []


@pytest.mark.asyncio
async def test_unknown_method_counts_nothing(captured):
    bumps, uniques = captured
    await wire.post("foo/bar", None, request_id=9)
    await _drain()
    assert not any(b.startswith(("mcp:session_start", "mcp:tools_list")) for b in bumps)
    assert uniques == []
