"""Per-surface attribution for the remote MCP connector.

The server is stateless, so the reliable per-request signal for *which* surface
(Claude Directory, ChatGPT, the Claude Code plugin, Cursor, VS Code) a call came
from is the User-Agent header. `_surface_from_ua` buckets it; these tests pin the
bucketing so the dashboard's per-surface panel stays trustworthy.
"""
from __future__ import annotations

import pytest

from src.bridges.mcp_streamable import _surface_from_ua


@pytest.mark.parametrize(
    "ua,expected",
    [
        ("openai-mcp/1.2 (ChatGPT)", "chatgpt"),
        ("ChatGPT/1.0", "chatgpt"),
        ("claude-code/0.9 (node)", "claude-code"),
        ("Claude Code CLI", "claude-code"),
        ("Cursor/0.42", "cursor"),
        ("Visual Studio Code 1.99 (vscode-mcp)", "vscode"),
        ("Claude/2.0 (Anthropic connector)", "claude"),
        ("anthropic-sdk-python/0.30", "claude"),
        ("python-httpx/0.27", "other"),
        ("curl/8.4", "other"),
        ("", "other"),
    ],
)
def test_surface_from_ua(ua: str, expected: str) -> None:
    assert _surface_from_ua(ua) == expected


@pytest.mark.parametrize(
    "ua,expected",
    [
        # Real strings hitting /mcp (prod nginx, 48h to 2026-10-02).
        ("claude-code/2.1.284 (claude-desktop, agent-sdk/0.3.284)", "claude-code"),
        ("claude-code/2.1.286 (claude-vscode, agent-sdk/0.3.286)", "claude-code"),
        ("claude-code/2.1.287 (cli)", "claude-code"),
        ("claude-code/2.1.286 (local-agent, agent-sdk/0.3.286)", "claude-code"),
        ("Claude-User", "claude"),
        ("mcpbeat/0.1 (+https://mcpbeat.com/bot/; liveness check)", "other"),
        ("SentinelOracle/0.1 (+https://glimind.com/opt-out; liveness-only)", "other"),
        ("zevruna-monitor/1.0 (+https://zevruna.com)", "other"),
        ("node", "other"),
        ("undici", "other"),
        ("Python/3.11 aiohttp/3.14.3", "other"),
        ("Toucan-Datagen/1.0", "other"),
        ("CALLSET-Directory/1 (health check of MCP Registry entries)", "other"),
    ],
)
def test_surface_from_real_ua(ua: str, expected: str) -> None:
    assert _surface_from_ua(ua) == expected


@pytest.mark.parametrize(
    "ua",
    [
        # Index crawlers that carry a vendor name must not count as that surface.
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; "
        "+claudebot@anthropic.com)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; "
        "+https://openai.com/gptbot",
    ],
)
def test_vendor_crawlers_are_other_not_a_surface(ua: str) -> None:
    assert _surface_from_ua(ua) == "other"


def test_claude_code_beats_bare_claude() -> None:
    # "claude-code" contains "claude"; ordering must resolve it to the plugin,
    # not the generic Claude Directory bucket.
    assert _surface_from_ua("claude-code/1.0") == "claude-code"


def test_none_and_junk_fail_open_to_other() -> None:
    assert _surface_from_ua(None) == "other"  # type: ignore[arg-type]
    assert _surface_from_ua("\x00\x01 garbage") == "other"
