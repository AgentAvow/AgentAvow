"""B8: the entity tools (verify_trust / check_interaction_safety / lookup_identity /
get_trust_badge) must return clearly-functional guidance for an unknown id/name — not a
bare "Not found" that reads as a broken tool to a Directory reviewer.
"""
from __future__ import annotations

import httpx
import pytest

from src.bridges import mcp_streamable as mod


def _text_of(out) -> str:
    items = out[0] if isinstance(out, tuple) else out
    return items[0].text


async def _get_404(path, params=None):
    req = httpx.Request("GET", "http://internal/api" + path)
    raise httpx.HTTPStatusError(
        "not found", request=req, response=httpx.Response(404, request=req),
    )


def test_no_entity_help_points_to_the_working_scan_flow():
    h = mod._no_entity_help("entity id 'x'")
    for tool in ("scan_repo", "scan_package", "scan_mcp_server", "lookup_identity"):
        assert tool in h
    assert "not found" not in h.lower()  # must not read as a dead-end error


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", [
    ("verify_trust", {"entity_id": "nope"}),
    ("check_interaction_safety", {"target_entity_id": "nope", "interaction_type": "delegate"}),
    ("get_trust_badge", {"entity_id": "nope"}),
])
async def test_entity_tools_unknown_id_return_guidance_not_error(monkeypatch, tool, args):
    monkeypatch.setattr(mod, "_get", _get_404)
    out = await mod._call_tool(tool, args)
    text = _text_of(out)
    assert "scan_repo" in text, f"{tool} should guide to the scan flow"
    assert text != "Not found — check the target coordinates and try again."


@pytest.mark.asyncio
async def test_lookup_identity_empty_returns_guidance(monkeypatch):
    async def _empty(path, params=None):
        return {"entities": []}

    monkeypatch.setattr(mod, "_get", _empty)
    out = await mod._call_tool("lookup_identity", {"query": "definitely-not-here"})
    text = _text_of(out)
    assert "scan_repo" in text and "No AgentAvow entity" in text


@pytest.mark.asyncio
async def test_entity_tool_non_404_error_still_raises_to_generic_handler(monkeypatch):
    """A 500 must NOT be swallowed as the friendly not-found message — it should fall
    through to the generic error handler (so real outages aren't masked as 'no entity')."""
    async def _get_500(path, params=None):
        req = httpx.Request("GET", "http://internal/api" + path)
        raise httpx.HTTPStatusError(
            "boom", request=req, response=httpx.Response(500, request=req),
        )

    monkeypatch.setattr(mod, "_get", _get_500)
    out = await mod._call_tool("verify_trust", {"entity_id": "x"})
    text = _text_of(out)
    assert "No AgentAvow entity" not in text  # not the friendly path
    assert "error" in text.lower()
