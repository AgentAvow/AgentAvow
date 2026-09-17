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


def test_claude_code_beats_bare_claude() -> None:
    # "claude-code" contains "claude"; ordering must resolve it to the plugin,
    # not the generic Claude Directory bucket.
    assert _surface_from_ua("claude-code/1.0") == "claude-code"


def test_none_and_junk_fail_open_to_other() -> None:
    assert _surface_from_ua(None) == "other"  # type: ignore[arg-type]
    assert _surface_from_ua("\x00\x01 garbage") == "other"
