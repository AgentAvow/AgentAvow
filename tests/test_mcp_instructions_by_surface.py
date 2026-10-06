"""Connect-time instructions differ by surface, on purpose.

ChatGPT (and anything unknown) must keep the reviewed, byte-identical base text; the
Claude surfaces get an addendum that says what to do when a tool question comes up —
every line conditioned on the user's ask, never an auto-invoke. And a user-invoked
prompt grades the other connectors in the conversation on request.
"""
from __future__ import annotations

import pytest

from src.bridges import mcp_streamable as ms


@pytest.mark.parametrize("surface", ["claude", "claude-code", "cursor", "vscode"])
def test_claude_surfaces_get_the_base_text_plus_the_addendum(surface):
    text = ms._instructions_for(surface)
    assert text.startswith(ms._INSTRUCTIONS)
    assert text.endswith(ms._INSTRUCTIONS_CLAUDE_ADDENDUM)
    assert "agentavow_check_my_connections" in text


@pytest.mark.parametrize("surface", ["chatgpt", "other", ""])
def test_chatgpt_and_unknown_keep_the_reviewed_text_byte_for_byte(surface):
    assert ms._instructions_for(surface) == ms._INSTRUCTIONS


def test_addendum_is_conditioned_on_the_user_not_an_auto_invoke():
    a = ms._INSTRUCTIONS_CLAUDE_ADDENDUM.lower()
    assert "when the user asks" in a and "if the user asks" in a
    for banned in ("always run", "at the start of every", "without being asked", "every reply"):
        assert banned not in a


def test_initialization_options_pick_instructions_for_the_calling_surface():
    ms._SURFACE.set("claude-code")
    assert ms.server.create_initialization_options().instructions == ms._instructions_for("claude-code")
    ms._SURFACE.set("chatgpt")
    assert ms.server.create_initialization_options().instructions == ms._INSTRUCTIONS
    ms._SURFACE.set("other")
    opts = ms.server.create_initialization_options()
    assert opts.instructions == ms._INSTRUCTIONS
    assert opts.server_name == "agentavow-trust" and opts.capabilities is not None


@pytest.mark.asyncio
async def test_check_my_connections_prompt_is_listed_and_user_invoked():
    names = [p.name for p in await ms._list_prompts()]
    assert names == ["agentavow_get_started", "agentavow_check_my_connections"]
    got = await ms._get_prompt("agentavow_check_my_connections", None)
    text = got.messages[0].content.text
    assert "other than AgentAvow" in text and "scan_mcp_server" in text and "scan_package" in text
    started = await ms._get_prompt("agentavow_get_started", None)
    assert started.messages[0].content.text == ms._GET_STARTED


@pytest.mark.asyncio
async def test_about_tool_offers_to_check_other_connectors_on_claude_surfaces_only():
    ms._SURFACE.set("claude")
    out = await ms._call_tool("about_agentavow", {})
    text = (out[0] if isinstance(out, tuple) else out)[0].text
    assert text.startswith(ms._ABOUT) and "check my connections" in text
    ms._SURFACE.set("chatgpt")
    out = await ms._call_tool("about_agentavow", {})
    assert (out[0] if isinstance(out, tuple) else out)[0].text == ms._ABOUT
    ms._SURFACE.set("other")
