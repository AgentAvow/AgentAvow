"""B8: the entity tools (verify_trust / check_interaction_safety / lookup_identity /
get_trust_badge) must return clearly-functional guidance for an unknown id/name — not a
bare "Not found" that reads as a broken tool to a Directory reviewer.
"""
from __future__ import annotations

import httpx
import pytest

from src.bridges import mcp_streamable as mod


def _text_of(out) -> str:
    # A scan tool that could not scan returns a CallToolResult (isError) — see _call_tool.
    if hasattr(out, "content"):
        return out.content[0].text
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
async def test_lookup_identity_bio_only_match_returns_guidance(monkeypatch):
    """/search also matches bio text; 'requests' must not resolve to an agent whose
    bio says 'feature requests'."""
    async def _bio_hit(path, params=None):
        return {"entities": [{"id": "e1", "display_name": "FeatureBot",
                              "did_web": "did:web:agentgraph.co:featurebot",
                              "bio_markdown": "Triages feature requests.", "trust_score": 0.4}]}

    monkeypatch.setattr(mod, "_get", _bio_hit)
    text = _text_of(await mod._call_tool("lookup_identity", {"query": "requests"}))
    assert "FeatureBot" not in text
    assert "No AgentAvow entity" in text and "scan_package" in text


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["featurebot", "Feature", "agentgraph.co:featurebot"])
async def test_lookup_identity_name_or_did_match_is_listed(monkeypatch, query):
    async def _hits(path, params=None):
        return {"entities": [
            {"id": "e1", "display_name": "FeatureBot",
             "did_web": "did:web:agentgraph.co:featurebot", "trust_score": 0.4},
            {"id": "e2", "display_name": "Unrelated", "did_web": "did:web:agentgraph.co:other",
             "bio_markdown": "mentions featurebot in passing", "trust_score": 0.9},
        ]}

    monkeypatch.setattr(mod, "_get", _hits)
    text = _text_of(await mod._call_tool("lookup_identity", {"query": query}))
    assert "FeatureBot" in text and "trust 40/100" in text
    assert "Unrelated" not in text


@pytest.mark.asyncio
async def test_lookup_identity_unresolvable_did_returns_guidance(monkeypatch):
    """A did: that doesn't resolve must guide, not dead-end on 'Not found' (the DID
    branch previously bypassed the guidance the name branch already had)."""
    monkeypatch.setattr(mod, "_get", _get_404)
    out = await mod._call_tool("lookup_identity", {"query": "did:web:example.com"})
    text = _text_of(out)
    assert "scan_repo" in text
    assert text != "Not found — check the target coordinates and try again."


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
