"""MCP connector: per-user internal headers, server NAME resolution, background re-scans.

tools/list stays byte-identical (see test_mcp_tools_list_snapshot); everything here is
behavior behind the existing tool inputs.
"""
from __future__ import annotations

import asyncio

import pytest

from src.bridges import mcp_streamable as ms
from src.config import settings

CATALOG = {"rows": [
    {"name": "deepwiki", "endpoint_url": "https://mcp.deepwiki.com/mcp", "trust_score": 74, "surface": "mcp"},
    {"name": "deepwiki-mirror", "endpoint_url": "https://mirror.example/mcp", "trust_score": 60, "surface": "mcp"},
]}
SCAN = {"trust_score": 74, "trust_tier": "standard", "findings": {"items": []}, "category_scores": {},
        "metadata": {"files_scanned": 2}, "jws": "x", "tool_digests": {}}


@pytest.fixture(autouse=True)
def _reset_request_context():
    """The surface / client-ip contextvars must not leak into other test modules
    (the tools/list snapshot test reads initialize instructions for the default
    surface)."""
    t1 = ms._SURFACE.set("other")
    t2 = ms._CLIENT_IP.set("")
    yield
    ms._SURFACE.reset(t1)
    ms._CLIENT_IP.reset(t2)


def _text_of(out) -> str:
    # A scan tool that could not scan returns a CallToolResult (isError) — see _call_tool.
    if hasattr(out, "content"):
        return out.content[0].text
    items = out[0] if isinstance(out, tuple) else out
    return items[0].text


def _dispatch(calls, catalog=CATALOG, scan=SCAN):
    async def _get(path, params=None):
        calls.append((path, dict(params or {})))
        if path == "/public/scan-catalog":
            return catalog
        return dict(scan)
    return _get


# --- internal headers --------------------------------------------------------------

def test_internal_headers_only_with_a_token(monkeypatch):
    monkeypatch.setattr(settings, "mcp_internal_token", "", raising=False)
    assert ms._internal_headers() == {}
    monkeypatch.setattr(settings, "mcp_internal_token", "tok", raising=False)
    ms._CLIENT_IP.set("203.0.113.9")
    ms._SURFACE.set("claude-code")
    assert ms._internal_headers() == {"X-AgentAvow-Internal": "tok",
                                      "X-AgentAvow-Client-Ip": "203.0.113.9",
                                      "X-AgentAvow-Surface": "claude-code"}


# --- name resolution ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_exact_name_resolves_even_among_several_hits(monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "_get", _dispatch(calls))
    url, cands = await ms._resolve_mcp_name("DeepWiki")
    assert url == "https://mcp.deepwiki.com/mcp" and cands == []
    assert calls[0] == ("/public/scan-catalog", {"surface": "mcp", "q": "DeepWiki", "limit": 8})


@pytest.mark.asyncio
async def test_single_hit_resolves_and_ambiguity_returns_candidates(monkeypatch):
    one = {"rows": [CATALOG["rows"][1]]}
    monkeypatch.setattr(ms, "_get", _dispatch([], catalog=one))
    assert (await ms._resolve_mcp_name("mirror"))[0] == "https://mirror.example/mcp"
    monkeypatch.setattr(ms, "_get", _dispatch([]))
    url, cands = await ms._resolve_mcp_name("wiki")
    assert url is None and [c["name"] for c in cands] == ["deepwiki", "deepwiki-mirror"]
    monkeypatch.setattr(ms, "_get", _dispatch([], catalog={"rows": []}))
    assert await ms._resolve_mcp_name("nothing") == (None, [])


@pytest.mark.asyncio
async def test_scan_mcp_server_accepts_a_name_and_scans_the_resolved_url(monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "_get", _dispatch(calls))
    out = await ms._call_tool("scan_mcp_server", {"endpoint_url": "DeepWiki"})
    assert [p for p, _ in calls] == ["/public/scan-catalog", "/public/scan/mcp"]
    assert calls[1][1] == {"endpoint": "https://mcp.deepwiki.com/mcp"}
    assert "74" in _text_of(out)
    struct = out[1]
    assert struct["target"] == "https://mcp.deepwiki.com/mcp" and "rescan_pending" not in struct


@pytest.mark.asyncio
async def test_unresolvable_name_asks_for_the_url_with_candidates(monkeypatch):
    monkeypatch.setattr(ms, "_get", _dispatch([]))
    text = _text_of(await ms._call_tool("scan_mcp_server", {"endpoint_url": "wiki"}))
    assert "could not match 'wiki'" in text and "https://mcp.deepwiki.com/mcp" in text
    monkeypatch.setattr(ms, "_get", _dispatch([], catalog={"rows": []}))
    text = _text_of(await ms._call_tool("scan_mcp_server", {"endpoint_url": "nothing"}))
    assert "Give me its https endpoint URL" in text and "claude mcp get" in text


@pytest.mark.asyncio
async def test_a_url_is_never_sent_to_the_catalog(monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "_get", _dispatch(calls))
    await ms._call_tool("scan_mcp_server", {"endpoint_url": "https://mcp.deepwiki.com/mcp"})
    assert [p for p, _ in calls] == ["/public/scan/mcp"]


# --- forced re-scans run in the background -------------------------------------------

@pytest.mark.asyncio
async def test_force_returns_the_cached_grade_and_rescans_in_the_background(monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "_get", _dispatch(calls))
    ms._RESCANS_IN_FLIGHT.clear()
    out = await ms._call_tool("scan_package", {"registry": "npm", "name": "chalk", "force": True})
    card, struct = out
    assert struct["rescan_pending"] is True
    assert ms.RESCAN_NOTE in card[0].text
    # The inline call was NOT forced; the background task is.
    assert calls[0] == ("/public/scan/package/npm/chalk", {})
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert ("/public/scan/package/npm/chalk", {"force": "true"}) in calls
    assert ms._RESCANS_IN_FLIGHT == set()  # released when the background call finished


@pytest.mark.asyncio
async def test_a_second_force_while_one_is_in_flight_does_not_stack(monkeypatch):
    started = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def _get(path, params=None):
        calls.append((path, dict(params or {})))
        if (params or {}).get("force"):
            started.set()
            await release.wait()
        return dict(SCAN)

    monkeypatch.setattr(ms, "_get", _get)
    ms._RESCANS_IN_FLIGHT.clear()
    out1 = await ms._call_tool("scan_repo", {"repo": "vercel/next.js", "force": True})
    await started.wait()
    out2 = await ms._call_tool("scan_repo", {"repo": "vercel/next.js", "force": True})
    assert out1[1]["rescan_pending"] is True
    assert "rescan_pending" not in out2[1]  # one already running: no second task, no note
    assert sum(1 for p, q in calls if q.get("force")) == 1
    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert ms._RESCANS_IN_FLIGHT == set()


@pytest.mark.asyncio
async def test_force_on_mcp_server_also_runs_in_the_background(monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "_get", _dispatch(calls))
    ms._RESCANS_IN_FLIGHT.clear()
    out = await ms._call_tool("scan_mcp_server", {"endpoint_url": "https://mcp.deepwiki.com/mcp", "force": True})
    assert out[1]["rescan_pending"] is True
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert ("/public/scan/mcp", {"endpoint": "https://mcp.deepwiki.com/mcp", "force": "true"}) in calls


def test_claude_addendum_mentions_names_and_background_rescans():
    a = ms._INSTRUCTIONS_CLAUDE_ADDENDUM
    assert "connector or server NAME" in a and "background" in a
    assert ms._instructions_for("chatgpt") == ms._INSTRUCTIONS  # ChatGPT text untouched


# --- card polish: hosted-endpoint adoption wording, scan time, re-scan note on top -----

def test_hosted_endpoint_says_no_public_adoption_data_instead_of_new():
    data = dict(SCAN, scanned_at="2026-10-07T18:02:11+00:00")
    hosted = ms._scan_block(data, "connect", "/check/mcp?endpoint=x", "mcp.deepwiki.com", None, hosted=True)
    assert "Adoption: no public data for a hosted endpoint." in hosted
    assert "n/a (hosted endpoint)" in hosted and "new" not in hosted.split("```")[0]
    assert "scanned   2026-10-07 18:02 UTC" in hosted
    pkg = ms._scan_block(data, "use", "/check/pkg/npm/x", "x · npm", None)
    assert "Adoption: new (no established public data yet)." in pkg


def test_struct_carries_scanned_at_and_rescan_note_leads_the_card():
    struct = ms._scan_struct(dict(SCAN, scanned_at="2026-10-07T18:02:11+00:00"), "x", "npm", "/r", "/a", None)
    assert struct["scanned_at"] == "2026-10-07T18:02:11+00:00"
    card = ms._card_text("◍ Clean — x, 74/100.")
    card2, struct2 = ms._with_rescan_note(card, struct)
    assert card2[0].text.startswith("🔄 Fresh re-scan STARTED in the background")
    assert "(previous grade from 2026-10-07 18:02 UTC)" in card2[0].text
    assert card2[0].text.endswith("◍ Clean — x, 74/100.")
    assert struct2["rescan_pending"] is True
