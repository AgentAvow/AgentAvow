"""Regression tests for the content-integrity gate (2026-08-20).

The marketing bot was publicly posting its own LLM scaffolding — content briefs
("Short thread… Open with… Close with the link") and meta-refusals ("the post appears
empty, could you share what X wrote…"). content_quality_issue is the single gate that
must catch all of it before anything posts. These lock the patterns the audit found live.
"""
from __future__ import annotations

from src.marketing.content.engine import content_quality_issue

# Real leaks pulled from the bot's live Bluesky feed on 2026-08-20.
LEAKS = [
    "Short thread (2-3 skeets). Open with the HN question. Pivot: identity tells you "
    "WHO the agent is. Close with agentavow.com/check link.",
    "Show a redacted screenshot of a mcp-security-scan finding: env-var leakage. "
    "Label '🤖 AgentAvow bot post'.",
    "Short take on the Aug 4 CNN piece about AI agents. Tag as [bot post by AgentAvow].",
    "Quote-react to the HN 'LLM-as-judge' piece. Argument: audit trails beat "
    "evaluations. Bot-labelled.",
    "3-post thread. Post 1: Agents don't scale. Post 2: nod to Moltbook. Disclose: 🤖",
    "The post content appears to be empty — could you share what Xe Iaso actually "
    "wrote so I can draft something useful?",
    "Draft a reply about MCP security and close with the check link.",
]

# Genuine finished copy that must NOT be flagged.
GOOD = [
    "World shipping 'proof of human' for shopping agents while OpenClaw sits at 512 "
    "CVEs. Agent ecosystems don't need more agents, they need verifiable identity "
    "underneath. https://agentavow.com/check",
    "Agent session state has the same vibe — you didn't crash, you just stopped "
    "existing in a context. A clean logout vs a cold kill matters when the session is "
    "an agent mid-tool-call.",
    "CSP misconfigurations are basically a fingerprint of how the server was assembled "
    "— each weird header combo tells a story about which tutorial someone followed.",
    "Signed attestations let anyone re-verify a safety score offline. No trust-me "
    "pixel — check the math yourself.",
]


def test_gate_catches_every_live_leak():
    for text in LEAKS:
        assert content_quality_issue(text), f"MISSED leak: {text[:60]!r}"


def test_gate_passes_genuine_copy():
    for text in GOOD:
        assert content_quality_issue(text) is None, f"FALSE POSITIVE: {text[:60]!r}"


def test_gate_still_catches_empty_and_placeholder():
    assert content_quality_issue("") == "empty"
    assert content_quality_issue("   ") == "empty"
    assert content_quality_issue("Scanned it and found {count} issues")  # {var}
    assert content_quality_issue("Grade dropped to XX after the scan")   # XX
