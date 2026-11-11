"""Admin metrics dashboard fixes (2026-11-11 audit).

Pins:
  * MCP: every tool call (about_agentavow included) has a per-tool row, so the rows
    add up to the total; scan answers are counted three ways (Safe / Review / Do not
    connect); hand-run checks leave out about_agentavow and owner machines.
  * A Codex User-Agent lands in its own surface.
  * The install-time hook counts as a plugin hook scan.
  * x402 is out of every catalog total and reported on its own.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import src.api.metrics_dashboard_router as md
from src.bridges import mcp_streamable as ms
from tests.test_metrics_unique_callers import _FakeRedis


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    md._salt_cache.clear()
    yield fake
    md._salt_cache.clear()


def _count(redis, name: str) -> int:
    return redis.counters.get(f"ag:metrics:{name}:{_today()}", 0)


# --- MCP counters -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_about_is_a_call_but_not_a_check(redis, monkeypatch):
    monkeypatch.setattr("src.config.settings.metrics_owner_ips", "")
    ms._SURFACE.set("claude-code")
    ms._CLIENT_IP.set("203.0.113.7")
    await ms._call_tool("about_agentavow", {})
    assert _count(redis, "mcp:calls:total") == 1
    assert _count(redis, "mcp:tool:about_agentavow") == 1
    assert _count(redis, "mcp:checks") == 0


@pytest.mark.asyncio
async def test_checks_count_per_surface_and_skip_owner_machines(redis, monkeypatch):
    monkeypatch.setattr("src.config.settings.metrics_owner_ips", "198.51.100.1, 198.51.100.2")

    async def _no_entity(path, params=None):
        raise ms.httpx.TimeoutException("slow")

    monkeypatch.setattr(ms, "_get", _no_entity)
    ms._SURFACE.set("cursor")
    ms._CLIENT_IP.set("203.0.113.7")
    await ms._call_tool("scan_repo", {"repo": "a/b"})
    ms._CLIENT_IP.set("198.51.100.2")  # an owner machine
    await ms._call_tool("scan_repo", {"repo": "a/b"})
    assert _count(redis, "mcp:calls:total") == 2
    assert _count(redis, "mcp:checks") == 1
    assert _count(redis, "mcp:checks:cursor") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("data,answer", [
    ({"trust_score": 92, "findings": {}}, "safe"),
    ({"trust_score": 70, "findings": {"high": 1}}, "review"),
    ({"trust_score": 40, "findings": {"critical": 1}}, "do_not_connect"),
])
async def test_scan_answers_are_counted_three_ways(redis, data, answer):
    ms._SURFACE.set("chatgpt")
    await ms._bump_verdict(data)
    assert _count(redis, f"mcp:answer:{answer}") == 1
    assert _count(redis, f"mcp:answer:{answer}:chatgpt") == 1
    # The legacy two-way split keeps counting so its series does not break.
    assert _count(redis, "mcp:verdict:safe") + _count(redis, "mcp:verdict:needs_review") == 1


@pytest.mark.asyncio
async def test_verdict_counting_never_raises(redis):
    redis.counters = None  # any access blows up
    await ms._bump_verdict({"trust_score": 90})


@pytest.mark.parametrize("ua,surface", [
    ("codex_cli_rs/0.58.0 (Mac OS 15.6.1; arm64) Apple_Terminal/455", "codex"),
    ("Codex/1.2 (openai)", "codex"),
    ("openai-mcp/1.0.0", "chatgpt"),
    ("claude-code/2.1.287 (cli)", "claude-code"),
    ("agentavow-tool-gate/0.4.2 (js)", "other"),
])
def test_surface_from_ua(ua, surface):
    assert ms._surface_from_ua(ua) == surface


# --- Hooks ------------------------------------------------------------------------


@pytest.mark.parametrize("ua", [
    "agentavow-precheck/0.1.34 (plugin)",
    "agentavow-preinstall/0.1.34 (plugin)",
    "agentavow-pre_install/0.1.28 (plugin)",
])
def test_both_plugin_hooks_count_as_hook_scans(ua):
    assert md.is_hook_request("/api/v1/public/scan/mcp", ua)


def test_the_tool_gate_is_not_a_hook():
    assert not md.is_hook_request("/api/v1/public/scan/mcp", "agentavow-gate/0.1.34 (plugin)")


# --- Aggregate --------------------------------------------------------------------


class _Row:
    def __init__(self, surface, score=None, decision=None, testnet=None, category="Library"):
        self.surface, self.trust_score, self.decision = surface, score, decision
        self.testnet_only, self.category = testnet, category


class _Summary:
    by_surface = {"x402": 4, "mcp": 2}
    total_scans = 6


def _fake_catalog():
    rows = [
        _Row("mcp", 90, "safe", category="Dev tools"), _Row("mcp", 40, "do_not_connect"),
        _Row("x402", 95, "safe", category="x402 endpoint"),
        _Row("x402", 95, "safe", testnet=True, category="x402 endpoint"),
        _Row("x402", 60, "review", category="x402 endpoint"),
        _Row("x402", None, None, category="x402 endpoint"),
    ]
    return {"rows": rows, "summary": _Summary(), "static_cats": {"x402 endpoint": 4}}


@pytest.mark.asyncio
async def test_aggregate_keeps_x402_out_of_catalog_totals(db, redis, monkeypatch):
    monkeypatch.setattr("src.api.scan_catalog_router._get_catalog", _fake_catalog)
    out = await md._aggregate(db, "7d")
    cat = out["catalog"]
    assert "x402" not in cat["by_surface"]
    assert cat["static_corpus"] == 2
    assert cat["size_total"] == 2 + cat["community_scans"]
    assert "x402 endpoint" not in cat["by_category"]
    assert cat["by_category"] == {"Dev tools": 1, "Library": 1}
    assert out["x402"] == {
        "listings": 4, "scored": 3, "testnet_hidden": 1,
        "answers": {"safe": 1, "review": 1, "do_not_connect": 0},
    }


@pytest.mark.asyncio
async def test_aggregate_tool_rows_add_up_and_answers_are_three_way(db, redis):
    for _ in range(3):
        await md.bump_metric("mcp:calls:total")
    await md.bump_metric("mcp:tool:scan_repo")
    await md.bump_metric("mcp:tool:about_agentavow")
    await md.bump_metric("mcp:answer:review")
    await md.bump_metric("mcp:answer:review:codex")
    await md.bump_metric("mcp:checks")
    await md.bump_metric("mcp:checks:codex")
    out = await md._aggregate(db, "7d")
    mcp = out["mcp"]
    assert mcp["by_tool"]["about_agentavow"] == 1
    assert mcp["by_tool"]["unlisted"] == 1
    assert sum(mcp["by_tool"].values()) == mcp["calls_window"] == 3
    assert mcp["answers_window"] == {"safe": 0, "review": 1, "do_not_connect": 0}
    assert mcp["checks_window"] == 1
    assert mcp["by_surface"]["codex"]["answer_review"] == 1
    assert mcp["by_surface"]["codex"]["checks"] == 1
