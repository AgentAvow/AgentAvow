"""src.traffic_class: human / agent / automated from the User-Agent.

The strings below are real ones from production nginx logs (2026-09-29 → 10-01,
re-pulled for 48h on 2026-10-02). The caveat stands and is pinned at the bottom:
a crawler that sends a clean browser string is counted as a person. Only the
honest strings are classified here.
"""
from __future__ import annotations

import pytest

from src.traffic_class import CLIENT_CLASSES, classify_user_agent

HUMAN = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.7778.96 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0",
    "Mozilla/5.0 (Linux; arm_64; Android 12; CPH2205) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/110.0.0.0 YaBrowser/23.3.3.86.00 SA/3 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 8.0.0; SAMSUNG SM-G930V) AppleWebKit/537.36 (KHTML, like Gecko) "
    "SamsungBrowser/11.2 Chrome/75.0.3770.143 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.6099.210 Mobile Safari/537.36 OPR/75.2.3995.72468",
    # The Claude desktop app's in-app browser: a person following a link inside
    # Claude, not the connector (that one is "Claude-User" / "claude-code/…").
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Claude/2.9939.4 Chrome/152.0.7977.130 Safari/537.36",
]

AGENT = [
    "Claude-User (claude-code/2.1.284; +https://support.anthropic.com/en/articles/claude-user)",
    "Claude-User",
    "claude-code/2.1.284 (claude-desktop, agent-sdk/0.3.284)",
    "claude-code/2.1.286 (claude-vscode, agent-sdk/0.3.286)",
    "claude-code/2.1.285 (sdk-cli)",
    "claude-code/2.1.287 (cli)",
    "claude-code/2.1.286 (local-agent, agent-sdk/0.3.286)",
    "claude-code/2.1.280 (sdk-ts, agent-sdk/0.3.280)",
    "openai-mcp/1.0.0",
    # User-triggered fetchers: a person asked the assistant, it read our page.
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; "
    "+https://openai.com/bot",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; "
    "+https://perplexity.ai/perplexitybot)",
    "agentavow-precheck/0.1.4 (plugin)",
    "agentavow-precheck",
    "github-camo (1ff761db)",
]

AUTOMATED = [
    "",
    "node",
    "undici",
    "Bun/1.4.3",
    "curl/8.7.1",
    "curl/8.17.0",
    "Python-urllib/3.9",
    "python-httpx/0.28.1",
    "python-requests/2.33.0",
    "Python/3.11 aiohttp/3.14.3",
    "Go-http-client/1.1",
    "libredtail-http",
    # Uptime monitors — the single noisiest client on the old domain.
    "SentryUptimeBot/1.0 (+http://docs.sentry.io/product/alerts/uptime-monitoring/)",
    "ado-p5-health/1",
    "referencesource-mcp-health/0.1 (+https://referencesource.org/mcp-health/; daily MCP "
    "liveness probe; opt out: contact@referencesource.org)",
    # MCP directory crawlers and research scanners.
    "mcpbeat/0.1 (+https://mcpbeat.com/bot/; liveness check)",
    "SentinelOracle/0.1 (+https://glimind.com/opt-out; liveness-only, never stores content)",
    "SentinelOracle/0.1 (+https://glimind.com/opt-out; liveness-only, never invokes tools)",
    "zevruna-monitor/1.0 (+https://zevruna.com)",
    "BrickBlueBot/0.1 (+https://brick.blue/bot; agentic-web registry)",
    "rokmcp-collector/0.2 (+https://rokmcp.com/bot)",
    "TalandorBot/0.1 (+https://talandor.com/methodology)",
    "WellknownBot/0.1 (+https://wellknown.network/bot; listing: https://wellknown.network)",
    "GolemreachTrustBot/0.1 (+https://golemreach.com/trust/bot)",
    "AgenstryBot/0.3.0 (+https://agenstry.com/bot)",
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
    "SaSame-MCP-Audit/0.1",
    "Toucan-Datagen/1.0",
    "TaifoonHarvester/1.0.0 (+https://www.taifoon.io/docs/harvester) taifoon-probe/2 "
    "(+https://www.taifoon.io/v1/agents/readiness/summary; ERC-8004 onboarding reachability)",
    "CALLSET-Directory/1 (+http://127.0.0.1:4319/market?source=directory; health check of MCP "
    "Registry entries: initialize and tools/list at most once a day, never calls a tool)",
    "Enerlio GmbH FACTANKER marc@enerlio.de",
    # Internet-wide scanners and exploit probes.
    "Hello from Palo Alto Networks, find out more about our scans in "
    "https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity",
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    "Mozilla/5.0 (compatible; InternetMeasurement/1.0; +https://internet-measurement.com/)",
    "Mozilla/5.0 zgrab/0.x",
    "cve-2026-87902-poc/1.0",
    "http://agentgraph.co/wp-admin/install.php?step=1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 "
    "Safari/537.36 ModatScanner/1.2 (+https://modat.io/)",
    # Search / AI index crawlers (incl. the AI vendors' own — not agents using us).
    "Lightpanda/1.0",
    "Mozilla/5.0 (compatible; SolvedEarthPriceBot/2.0; +https://solvedearth.com/bot)",
    "Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/bot)",
    "SofyaBot/1.0 (+https://sofya.co/bot)",
    "Twitterbot/1.0",
    "tphotobot/0.1 (+https://crawler.estidraft.com/bot)",
    "Mozilla/5.0 (compatible; crawler)",
    "Mozilla/5.0 (compatible; jscrawler/0.1; +https://github.com/)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/153.0.8010.52 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; "
    "+http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1 "
    "(+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 "
    "(+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Reflectionbot/1.0; "
    "+https://reflection.ai/bot) Chrome/151.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; GrokBot/1.0; +https://x.ai/)",
    "Mozilla/5.0 (compatible; YiBot/1.0; +https://01.ai/)",
    "Mozilla/5.0 (compatible; DeepSeekBot/1.0; +https://www.deepseek.com/)",
    "Mozilla/5.0 (compatible; YouBot/1.0; +https://you.com/bot)",
    "Mozilla/5.0 (compatible; Bravebot/1.0; +https://brave.com/search/)",
    "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0)",
    "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0; +https://zhipuai.cn/)",
    "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Version/7.0 Mobile Safari/537.36 (compatible; Bytespider; "
    "https://bytedance.sg.larkoffice.com/docx/K5bxdypulop3IIxrJb0lOjLVgFe)",
    "Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/genomecrawler)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; "
    "+https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; "
    "+claudebot@anthropic.com)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; "
    "+https://openai.com/gptbot",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; robots.txt; "
    "+https://openai.com/searchbot",
    # Crawlers that append themselves to a real browser string.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/137.0.0.0 Safari/537.36 ForestEngine/1.0 (+https://forestengine.net/#opt-out)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/112.0.0.0 Safari/537.36 AppEngine-Google; (+http://code.google.com/appengine; "
    "appid: s~virustotalcloud)",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
    "Mobile Safari/537.36 [ip:93.41.125.186]",
    # Headless and automation builds.
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/154.0.0.0 Safari/537.36",
    # Truncated or bare "browser" strings: no engine token, which no browser sends.
    "Mozilla/5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Shap-User/0.1.0",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ShapBot/0.1.0",
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


def test_vendor_crawlers_are_not_agents():
    # ClaudeBot carries "anthropic", OAI-SearchBot carries "openai": index
    # crawlers, not agents using the product. They must lose to the crawler test.
    assert classify_user_agent(
        "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
    ) == "automated"
    assert classify_user_agent("OAI-SearchBot/1.4; +https://openai.com/searchbot") == "automated"
    # ...while the user-triggered fetchers from the same vendors are agents.
    assert classify_user_agent("Claude-User") == "agent"
    assert classify_user_agent("ChatGPT-User/1.0; +https://openai.com/bot") == "agent"


def test_spoofed_browser_still_lands_in_human():
    # The caveat, pinned: a crawler that sends a clean browser string and nothing
    # else is indistinguishable from a person. We do not pretend otherwise.
    assert classify_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ) == "human"


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
