"""A live MCP scan that read only part of what an agent receives reads Review.

Partial-coverage audit 2026-10-20 (V2, D1-MCP, D2, D4; Kenne "do what you recommend"):

- a tools/list read only in part (a later page failed, a cursor loop, the 20-page cap)
  records ``tool_list_paged`` + ``pages_read`` and reads Review, like #210's unread list;
  a paged list read to its last page is complete and records nothing;
- a resources/ or prompts/list that could not be read records a gap (and reads Review)
  only when ``initialize`` advertised that capability; an oversized one always does;
- the scan tools' structuredContent carries ``not_checked`` + ``coverage_gaps`` and a
  ``clean_partial`` verdict_reason, still valid against the frozen outputSchema.
"""
from __future__ import annotations

import json

import httpx
import mcp.types as types
import pytest

from src.scanner import mcp_scan as ms
from src.scanner.local_scan import decision_for_result
from src.scanner.verdict import coverage_gap_notes

URL = "https://mcp.example.com/mcp"


def _ok(rid, result: dict) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})


def _server(*, pages: int = 1, fail_page: int | None = None, loop_at: int | None = None,
            caps: dict | None = None, resources="ok", prompts="ok"):
    """A Streamable-HTTP MCP server. tools/list serves ``pages`` pages (page i holds tool
    ``t<i>``); ``fail_page`` answers that page with a 500, ``loop_at`` hands back an
    already-used cursor on that page. ``resources`` / ``prompts``: "ok" | "fail" |
    "missing" (method not found)."""
    def handler(request: httpx.Request) -> httpx.Response:
        doc = json.loads(request.content or b"{}")
        method, rid = doc.get("method"), doc.get("id")
        params = doc.get("params") or {}
        if method == "initialize":
            return _ok(rid, {"protocolVersion": "2025-06-18",
                             "capabilities": caps if caps is not None else {"tools": {}},
                             "serverInfo": {"name": "paged", "version": "1"}})
        if method == "tools/list":
            i = int(str(params.get("cursor") or "c0").removeprefix("c"))
            if fail_page is not None and i == fail_page:
                return httpx.Response(500)
            result: dict = {"tools": [{"name": f"t{i}", "description": "Adds numbers.",
                                       "inputSchema": {"type": "object"}}]}
            if loop_at is not None and i == loop_at:
                result["nextCursor"] = "c1"
            elif i + 1 < pages:
                result["nextCursor"] = f"c{i + 1}"
            return _ok(rid, result)
        for name, mode, key in (("resources/list", resources, "resources"),
                                ("prompts/list", prompts, "prompts")):
            if method == name:
                if mode == "fail":
                    return httpx.Response(503)
                if mode == "missing":
                    return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "error": {
                        "code": -32601, "message": "Method not found"}})
                return _ok(rid, {key: []})
        return httpx.Response(202)
    return handler


@pytest.fixture
def serve(monkeypatch):
    import src.ssrf as ssrf

    def _use(handler):
        monkeypatch.setattr(ssrf, "validate_url_https", lambda url, *a, **k: url)
        monkeypatch.setattr(
            ssrf, "ssrf_safe_async_client",
            lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return _use


async def _scan(monkeypatch, data: dict):
    async def fake_fetch(url):
        return data
    monkeypatch.setattr(ms, "fetch_mcp_tools", fake_fetch)
    from src.scanner.scan import scan_mcp
    res = await scan_mcp(URL)
    assert res.error is None
    return res


async def _scan_live(serve, handler):
    serve(handler)
    from src.scanner.scan import scan_mcp
    res = await scan_mcp(URL)
    assert res.error is None
    return res


# ── fetch side: each partial cause is recorded, a full paged read is not ─────────────

@pytest.mark.asyncio
async def test_all_pages_read_is_complete(serve):
    serve(_server(pages=5))
    data = await ms.fetch_mcp_tools(URL)
    assert [t["name"] for t in data["tools"]] == [f"t{i}" for i in range(5)]
    assert "tools_more_pages" not in data and "tools_pages_read" not in data
    assert data["observation"]["toolsList"]["complete"] is True


@pytest.mark.asyncio
async def test_exactly_the_page_cap_with_no_next_cursor_is_complete(serve):
    serve(_server(pages=ms._MCP_MAX_PAGES))
    data = await ms.fetch_mcp_tools(URL)
    assert len(data["tools"]) == ms._MCP_MAX_PAGES
    assert "tools_more_pages" not in data


@pytest.mark.asyncio
@pytest.mark.parametrize("kw,pages_read", [
    ({"pages": 5, "fail_page": 3}, 3),            # a later page failed
    ({"pages": 9, "loop_at": 4}, 5),              # the server handed back a used cursor
    ({"pages": ms._MCP_MAX_PAGES + 5}, ms._MCP_MAX_PAGES),  # the 20-page cap
], ids=["later-page-failed", "cursor-loop", "page-cap"])
async def test_partial_tool_list_is_recorded_with_pages_read(serve, kw, pages_read):
    serve(_server(**kw))
    data = await ms.fetch_mcp_tools(URL)
    assert data["tools_more_pages"] is True
    assert data["tools_pages_read"] == pages_read
    assert len(data["tools"]) == pages_read
    assert "tools_list_failed" not in data
    assert data["observation"]["toolsList"]["complete"] is False


@pytest.mark.asyncio
async def test_session_captures_advertised_capabilities():
    caps = {"tools": {}, "prompts": {"listChanged": True}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(_server(caps=caps))) as c:
        s = ms.McpSession(c, URL)
        assert await s.initialize() == 200
    assert s.capabilities == caps
    assert s.server_info["name"] == "paged"


@pytest.mark.asyncio
@pytest.mark.parametrize("caps,resources,prompts,unread", [
    ({"tools": {}, "resources": {}}, "fail", "ok", ["resources/list"]),
    ({"tools": {}, "prompts": {}}, "ok", "missing", ["prompts/list"]),
    ({"tools": {}, "resources": {}, "prompts": {}}, "fail", "fail",
     ["prompts/list", "resources/list"]),
    ({"tools": {}}, "missing", "missing", None),   # not advertised: no gap
    ({"tools": {}, "resources": {}}, "ok", "fail", None),  # failed one not advertised
], ids=["resources", "prompts", "both", "not-advertised", "only-advertised-counts"])
async def test_unread_lists_recorded_only_when_advertised(serve, caps, resources, prompts,
                                                          unread):
    serve(_server(caps=caps, resources=resources, prompts=prompts))
    data = await ms.fetch_mcp_tools(URL)
    assert data.get("lists_unread") == unread


# ── scan + decision (through local_scan.decision_for_result) ─────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("kw,note", [
    ({"pages": 5, "fail_page": 3}, "only the first 3 pages of the server's tool list were read"),
    ({"pages": 9, "loop_at": 4}, "only the first 5 pages of the server's tool list were read"),
    ({"pages": 30}, "only the first 20 pages of the server's tool list were read"),
    ({"pages": 3, "fail_page": 1}, "only the first page of the server's tool list was read"),
], ids=["later-page-failed", "cursor-loop", "page-cap", "one-page"])
async def test_partial_tool_list_reads_review(serve, kw, note):
    res = await _scan_live(serve, _server(**kw))
    assert res.coverage_gaps["tool_list_paged"] is True
    assert coverage_gap_notes({"coverage_gaps": res.coverage_gaps}) == [note]
    d = decision_for_result(res)
    assert (d.decision, d.reason) == ("review", "only part of the server's tool list could "
                                                "be read")


@pytest.mark.asyncio
async def test_paged_list_read_in_full_is_not_partial(serve):
    res = await _scan_live(serve, _server(pages=4))
    assert res.coverage_gaps == {}
    d = decision_for_result(res)
    assert d.decision == "safe", (d.decision, d.reason)
    assert "tool list" not in d.reason


@pytest.mark.asyncio
async def test_advertised_resource_list_unread_reads_review(serve):
    res = await _scan_live(serve, _server(caps={"tools": {}, "resources": {}},
                                          resources="fail"))
    assert res.coverage_gaps == {"resource_list_unread": True}
    assert coverage_gap_notes({"coverage_gaps": res.coverage_gaps}) == [
        "the server's resource list could not be read"]
    d = decision_for_result(res)
    assert (d.decision, d.reason) == ("review", "the server's resource list could not be read")


@pytest.mark.asyncio
async def test_unadvertised_resource_list_missing_is_no_gap_and_safe(serve):
    res = await _scan_live(serve, _server(caps={"tools": {}}, resources="missing",
                                          prompts="fail"))
    assert res.coverage_gaps == {}
    assert decision_for_result(res).decision == "safe"


@pytest.mark.asyncio
async def test_both_lists_unread_is_one_combined_reason(monkeypatch):
    res = await _scan(monkeypatch, {
        "tools": [{"name": "add", "description": "Adds.", "inputSchema": {"type": "object"}}],
        "resources": [], "prompts": [], "server_info": {"name": "x"},
        "lists_unread": ["prompts/list", "resources/list"]})
    assert res.coverage_gaps == {"resource_list_unread": True, "prompt_list_unread": True}
    d = decision_for_result(res)
    assert (d.decision, d.reason) == (
        "review", "the server's resource and prompt lists could not be read")


@pytest.mark.asyncio
async def test_prompts_too_large_is_a_gap_and_reads_review(monkeypatch):
    res = await _scan(monkeypatch, {
        "tools": [{"name": "add", "description": "Adds.", "inputSchema": {"type": "object"}}],
        "resources": [], "prompts": [], "server_info": {"name": "x"},
        "lists_too_large": ["prompts/list"]})
    # the #208 MEDIUM finding stays, and the gap is recorded beside it
    assert any(f.file_path == "server:prompts/list" and f.severity == "medium"
               for f in res.findings)
    assert res.coverage_gaps == {"prompt_list_too_large": True}
    assert coverage_gap_notes({"coverage_gaps": res.coverage_gaps}) == [
        "the server's prompt list was too large to read"]
    d = decision_for_result(res)
    assert (d.decision, d.reason) == ("review", "the server's prompt list could not be read")


@pytest.mark.asyncio
async def test_oversized_resource_list_from_the_live_read(serve, monkeypatch):
    """The #208 oversize path end to end: a resources/list past the byte cap records
    both the medium finding and ``resource_list_too_large`` (not a second unread note)."""
    monkeypatch.setattr(ms, "MCP_MAX_RESPONSE_BYTES", 2_000)
    base = _server(caps={"tools": {}, "resources": {}})

    def handler(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content or b"{}").get("method") == "resources/list":
            return httpx.Response(200, stream=httpx.ByteStream(b"x" * 5_000))
        return base(request)

    res = await _scan_live(serve, handler)
    assert res.coverage_gaps == {"resource_list_too_large": True}
    assert decision_for_result(res).decision == "review"


def test_pages_read_wording():
    def note(n):
        return coverage_gap_notes({"coverage_gaps": {"tool_list_paged": True,
                                                     "pages_read": n}})
    assert note(1) == ["only the first page of the server's tool list was read"]
    assert note(2) == ["only the first 2 pages of the server's tool list were read"]
    assert note(20) == ["only the first 20 pages of the server's tool list were read"]
    # an older cached shape without pages_read does not claim "first page"
    assert coverage_gap_notes({"coverage_gaps": {"tool_list_paged": True}}) == [
        "only part of the server's tool list was read"]


# ── the scan tools' structuredContent (D4) ───────────────────────────────────────────

_PARTIAL = {
    "trust_score": 90, "trust_tier": "trusted", "jws": "eyJ.sig.ned",
    "certified": {"eligible": False, "checks": {"no_critical_or_high": True}},
    "category_scores": {}, "findings": {"total": 0, "items": []},
    "metadata": {"files_scanned": 20}, "coverage": {"surface": "mcp"},
    "coverage_gaps": {"tool_list_paged": True, "pages_read": 20, "prompt_list_unread": True},
}


def _struct(data):
    from src.bridges import mcp_streamable as mod
    return mod._scan_struct(data, URL, "mcp", "/check/mcp", "/api/v1/public/scan/mcp", None)


# A Safe answer over disclosure-only gaps (here a repo with an unfetched file).
_SAFE_PARTIAL = {**_PARTIAL, "coverage": {}, "metadata": {"files_scanned": 120},
                 "coverage_gaps": {"fetch_failed": 1}}


def test_struct_carries_not_checked_and_gaps_on_a_review():
    sc = _struct(_PARTIAL)
    assert sc["not_checked"] == [
        "only the first 20 pages of the server's tool list were read",
        "the server's prompt list could not be read"]
    assert sc["coverage_gaps"] == _PARTIAL["coverage_gaps"]
    # the binary verdict follows decide(): a partly read tool list is not "safe"
    assert sc["decision"] == "review" and sc["verdict"] == "needs_review"
    assert sc["decision_reason"] == "only part of the server's tool list could be read"
    assert sc["verdict_reason"] not in ("clean", "clean_partial")


def test_struct_safe_with_a_gap_reads_clean_partial():
    sc = _struct(_SAFE_PARTIAL)
    assert sc["decision"] == "safe" and sc["verdict"] == "safe"
    assert sc["verdict_reason"] == "clean_partial"
    assert sc["not_checked"] == ["1 file could not be fetched"]
    assert sc["coverage_gaps"] == {"fetch_failed": 1}


def test_struct_not_checked_is_uncapped():
    gaps = {"oversized_files": 1, "fetch_failed": 2, "tree_truncated": True,
            "package_skipped": 3, "advisory_lookup": "failed"}
    sc = _struct({**_SAFE_PARTIAL, "coverage_gaps": gaps})
    assert len(sc["not_checked"]) == 5
    assert sc["verdict_reason"] == "clean_partial"


def test_struct_full_read_stays_clean():
    sc = _struct({**_SAFE_PARTIAL, "coverage_gaps": {}})
    assert sc["not_checked"] == [] and sc["coverage_gaps"] == {}
    assert sc["verdict_reason"] == "clean"
    # a gap-shaped key that names nothing unread (pages_read alone) is not partial
    assert _struct({**_SAFE_PARTIAL, "coverage_gaps": {"pages_read": 3}})[
        "verdict_reason"] == "clean"


def test_struct_non_clean_reason_is_kept():
    data = {**_PARTIAL, "trust_score": 40,
            "findings": {"total": 1, "items": [{"severity": "high", "name": "X"}]}}
    assert _struct(data)["verdict_reason"] == "blocking_findings"


async def _call_scan(monkeypatch, data: dict) -> types.CallToolResult:
    """Through the registered tools/call handler: the SDK's output validation and our
    jsonschema check against the frozen _SCAN_OUTPUT_SCHEMA (a violation is logged)."""
    import logging

    from src.bridges import mcp_streamable as mod

    async def _noop(*a, **k):
        return None

    async def _scan_api(path, params=None):
        return data

    monkeypatch.setattr(mod, "_bump", _noop)
    monkeypatch.setattr(mod, "_adoption", _noop)
    monkeypatch.setattr(mod, "_get", _scan_api)
    seen: list[str] = []

    class _Catch(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    h = _Catch(level=logging.ERROR)
    mod.logger.addHandler(h)
    try:
        entry = mod.server.get_request_handler("tools/call")
        params = entry.params_type.model_validate(
            {"name": "scan_mcp_server", "arguments": {"endpoint_url": URL}})
        res = await entry.handler(None, params)
    finally:
        mod.logger.removeHandler(h)
    assert not any("outputSchema" in m for m in seen), seen
    import jsonschema
    jsonschema.validate(instance=res.structured_content, schema=mod._SCAN_OUTPUT_SCHEMA)
    return res


@pytest.mark.asyncio
async def test_partial_mcp_result_through_the_real_tools_call(monkeypatch):
    res = await _call_scan(monkeypatch, _PARTIAL)
    assert res.is_error is False
    sc = res.structured_content
    assert sc["decision"] == "review"
    assert sc["coverage_gaps"]["pages_read"] == 20
    assert len(sc["not_checked"]) == 2
    # the text result names the gap and leads with the Review answer
    text = res.content[0].text
    assert "only part of the server's tool list could be read" in text.splitlines()[0]
    assert ("**Not checked:** only the first 20 pages of the server's tool list were read; "
            "the server's prompt list could not be read.") in text


@pytest.mark.asyncio
async def test_clean_partial_result_through_the_real_tools_call(monkeypatch):
    res = await _call_scan(monkeypatch, _SAFE_PARTIAL)
    assert res.is_error is False
    sc = res.structured_content
    assert sc["verdict_reason"] == "clean_partial"
    assert sc["not_checked"] == ["1 file could not be fetched"]
    assert "**Not checked:** 1 file could not be fetched." in res.content[0].text
