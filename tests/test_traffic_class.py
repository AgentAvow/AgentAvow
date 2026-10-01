"""src.traffic_class: human / agent / automated from the User-Agent.

The strings below are real ones from production nginx logs (2026-09-29 → 10-01).
"""
from __future__ import annotations

import pytest

from src.traffic_class import CLIENT_CLASSES, classify_user_agent

HUMAN = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
]

AGENT = [
    "Claude-User (claude-code/2.1.284; +https://support.anthropic.com/en/articles/claude-user)",
    "Claude-User",
    "claude-code/2.1.284 (claude-desktop, agent-sdk/0.3.284)",
    "claude-code/2.1.286 (claude-vscode, agent-sdk/0.3.286)",
    "claude-code/2.1.285 (sdk-cli)",
    "openai-mcp/1.0.0",
    "agentavow-precheck/0.1.4 (plugin)",
    "agentavow-precheck",
    "github-camo (1ff761db)",
]

AUTOMATED = [
    "",
    "node",
    "undici",
    "curl/8.7.1",
    "Python-urllib/3.9",
    "python-httpx/0.28.1",
    "Python/3.11 aiohttp/3.14.3",
    "Go-http-client/1.1",
    "mcpbeat/0.1 (+https://mcpbeat.com/bot/; liveness check)",
    "SentinelOracle/0.1 (+https://glimind.com/opt-out; liveness-only, never stores content)",
    "zevruna-monitor/1.0 (+https://zevruna.com)",
    "BrickBlueBot/0.1 (+https://brick.blue/bot; agentic-web registry)",
    "rokmcp-collector/0.2 (+https://rokmcp.com/bot)",
    "TalandorBot/0.1 (+https://talandor.com/methodology)",
    "WellknownBot/0.1 (+https://wellknown.network/bot; listing: https://wellknown.network)",
    "GolemreachTrustBot/0.1 (+https://golemreach.com/trust/bot)",
    "mcp2-research/1.0 (+https://github.com/dosixxx; KHU SIFT Lab)",
    "protogrid-probe/0.1 (+https://protogrid.dev/probe)",
    "MCPScoringEngine/1.0",
    "heldfast (+https://github.com/rufat325/heldfast)",
    "StillOS-MCP-SurfaceClock/1.0 (+https://github.com/stillmarcus24/mcp-ce)",
    "MCPWatch/0.1.0 (+mcpwatch@iyre.com) longitudinal MCP security research",
    "CSOAI-census/0.1 (+https://councilof.ai/census)",
    "Tendle (+https://tendle.ai)",
    "mcpmon/1.0 (MCP liveness+drift archive; non-commercial research)",
    "mcplane",
    "Lightpanda/1.0",
    "Mozilla/5.0 (compatible; SolvedEarthPriceBot/2.0; +https://solvedearth.com/bot)",
    "Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/bot)",
    "SofyaBot/1.0 (+https://sofya.co/bot)",
    "Twitterbot/1.0",
    "tphotobot/0.1 (+https://crawler.estidraft.com/bot)",
    "Mozilla/5.0 (compatible; crawler)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/128.0 Safari/537.36",
    "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0)",
]


@pytest.mark.parametrize("ua", HUMAN)
def test_browsers_are_human(ua):
    assert classify_user_agent(ua) == "human"


@pytest.mark.parametrize("ua", AGENT)
def test_agent_clients_are_agents(ua):
    assert classify_user_agent(ua) == "agent"


@pytest.mark.parametrize("ua", AUTOMATED)
def test_crawlers_monitors_and_scripts_are_automated(ua):
    assert classify_user_agent(ua) == "automated"


def test_every_result_is_a_known_class():
    for ua in HUMAN + AGENT + AUTOMATED:
        assert classify_user_agent(ua) in CLIENT_CLASSES


def test_agent_wins_over_bot_words():
    # The claude.ai connector UA carries a support URL; it must not read as a bot.
    assert classify_user_agent(
        "Claude-User (claude-code/2.1.284; +https://support.anthropic.com/robots)"
    ) == "agent"


@pytest.mark.asyncio
async def test_bump_metric_by_client_bumps_aggregate_and_class(monkeypatch):
    from src.api import metrics_dashboard_router as mod

    seen: list[str] = []

    async def _fake_bump(name: str) -> None:
        seen.append(name)

    monkeypatch.setattr(mod, "bump_metric", _fake_bump)
    await mod.bump_metric_by_client("scan_request", "curl/8.7.1")
    await mod.bump_metric_by_client("badge_fetch", "github-camo (1ff761db)")
    assert seen == [
        "scan_request", "scan_request:client:automated",
        "badge_fetch", "badge_fetch:client:agent",
    ]
