"""Who is calling: a person in a browser, a known agent client, or automation.

Raw request counts overstate usage: the MCP endpoint alone sees a dozen directory
crawlers and uptime monitors, and the public scan API is hit by our own scripts.
This classifies a request by its User-Agent so usage counters can be split into
``human`` / ``agent`` / ``automated`` without storing anything about the caller.

Best effort by design. A User-Agent is self-declared, so a crawler that spoofs a
browser lands in ``human``; the point is to stop counting the honest bots, which
are nearly all of them. Checked against 72 hours of production traffic on
2026-10-01 (see tests/test_traffic_class.py for the real strings).
"""
from __future__ import annotations

import re
from typing import Literal

ClientClass = Literal["human", "agent", "automated"]

CLIENT_CLASSES: tuple[ClientClass, ...] = ("human", "agent", "automated")

# Clients that are an AI agent, or a tool acting for one, using the product as
# intended. Checked first: "Claude-User (claude-code/…; +https://support.anthropic…)"
# must not fall to the bot test below on a stray word.
_AGENT_MARKERS = (
    "agentavow-precheck",  # the Claude Code plugin's pre-connect hook
    "claude-user", "claude-code", "claude code", "claudecode", "anthropic",
    "openai-mcp", "chatgpt",
    "cursor", "vscode", "visual studio code",
    "github-camo",  # a README rendering our badge — real adoption, not a crawler
)

# Crawlers, monitors and research scanners. Word-boundary on "bot" so "Robot" in a
# product name still matches, but "bottom" does not.
_BOT_RE = re.compile(
    r"\bbot\b|bot/|crawler|spider|slurp|monitor|probe|liveness|uptime|pingdom|"
    r"headless|lightpanda|phantom|census|archive|research|scoringengine|scanner|"
    r"heldfast|mcpbeat|sentineloracle|zevruna|rokmcp|talandor|wellknown|golemreach|"
    r"protogrid|mcpmon|mcplane|tendle|facebookexternalhit|twitterbot|slackbot|"
    r"discordbot|whatsapp|telegrambot|linkedinbot|embedly|bingpreview|yandex|"
    r"baidu|duckduck|semrush|ahrefs|mj12|dotbot|petalbot|bytespider|gptbot|"
    r"claudebot|ccbot|perplexitybot|applebot|amazonbot",
    re.IGNORECASE,
)

# HTTP libraries and CLI tools: scripts, cron jobs, our own curl. Anchored at the
# start, which is where a library puts its own name.
_SCRIPT_RE = re.compile(
    r"^(?:python-urllib|python-requests|python-httpx|httpx|aiohttp|urllib3|curl|wget|"
    r"go-http-client|java/|okhttp|apache-httpclient|libwww|lwp|node(?:$|[ /])|undici|"
    r"axios|got(?:$|[ /])|node-fetch|ruby|faraday|php|guzzle|perl|postman|insomnia|"
    r"restsharp|dart|reqwest|hyper|ureq|k6|ab(?:$|/)|siege|httpie|powershell)",
    re.IGNORECASE,
)

# A real browser engine string. Headless/automation builds are caught above.
_BROWSER_RE = re.compile(
    r"mozilla/\d.*(?:chrome/|safari/|firefox/|edg/|opr/|version/|trident/)",
    re.IGNORECASE,
)


def classify_user_agent(user_agent: str | None) -> ClientClass:
    """Bucket a User-Agent. Empty or unparseable strings count as automated."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return "automated"
    if any(marker in ua for marker in _AGENT_MARKERS):
        return "agent"
    if _BOT_RE.search(ua) or _SCRIPT_RE.match(ua):
        return "automated"
    if _BROWSER_RE.search(ua):
        return "human"
    return "automated"
