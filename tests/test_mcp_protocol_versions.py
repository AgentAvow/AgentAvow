"""/mcp speaks every protocol revision current clients send, over the real HTTP entry.

SDK 1.x answered a 2026-07-28 request (sent by current Claude clients) with
400 "Unsupported protocol version"; the 2.x SDK serves it. A 2025-11-25 client must
still get, byte for byte, what production served before the upgrade: the ChatGPT app
review was done against those bytes (fixtures/mcp_wire_2025_11_25, captured from
https://agentavow.com/mcp on 2026-10-19). A change to any of them needs an OpenAI
portal Rescan, so regenerate a fixture only on purpose.
"""
from __future__ import annotations

import pathlib

import pytest

from src.bridges import mcp_streamable as m
from tests import mcp_wire as wire

WIRE = pathlib.Path(__file__).parent / "fixtures" / "mcp_wire_2025_11_25"
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

_CLEAN = {
    "trust_score": 88,
    "trust_tier": "trusted",
    "jws": "eyJ.sig.ned",
    "certified": {"eligible": True, "checks": {"no_critical_or_high": True}},
    "category_scores": {"secret_hygiene": 100},
    "findings": {"total": 0, "items": []},
}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    """No metrics writes, no adoption lookup, no API: keep these tests offline."""
    async def _noop(*a, **k):
        return None

    async def _scan(path, params=None):
        return _CLEAN

    monkeypatch.setattr(m, "_bump", _noop)
    monkeypatch.setattr(m, "_record_caller", _noop)
    monkeypatch.setattr(m, "_adoption", _noop)
    monkeypatch.setattr(m, "_get", _scan)


# ── 2025-11-25: byte-identical to production ──────────────────────────────────────
@pytest.mark.parametrize("surface,ua", [
    ("chatgpt", wire.UA_CHATGPT),
    ("claude", wire.UA_CLAUDE),
    ("claude-code", wire.UA_CLAUDE_CODE),
])
async def test_initialize_is_byte_identical_to_production(surface, ua):
    # Real clients send initialize without the MCP-Protocol-Version header.
    resp = await wire.post("initialize", wire.initialize_params(), ua=ua,
                           protocol_version=None, request_id=0)
    assert resp.status_code == 200
    assert resp.content == (WIRE / f"initialize_{surface}.json").read_bytes()


@pytest.mark.parametrize("name,method,params,request_id", [
    ("tools_list", "tools/list", None, 1),
    ("resources_list", "resources/list", None, 2),
    ("resources_read", "resources/read", {"uri": "ui://agentavow/trust-card-v13.html"}, 3),
    ("prompts_list", "prompts/list", None, 4),
])
async def test_listings_are_byte_identical_to_production(name, method, params, request_id):
    resp = await wire.post(method, params, request_id=request_id)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    assert resp.content == (WIRE / f"{name}.json").read_bytes()


def test_the_transport_stays_stateless_json():
    # nginx-friendly: no sessions, no SSE.
    assert m.session_manager.stateless is True
    assert m.session_manager.json_response is True


# ── older handshake-era revisions keep working ────────────────────────────────────
@pytest.mark.parametrize("pv", LEGACY_VERSIONS)
async def test_handshake_versions_list_and_call_tools(pv):
    init = await wire.post("initialize", wire.initialize_params(pv), protocol_version=None)
    assert init.status_code == 200
    assert init.json()["result"]["protocolVersion"] == pv

    tools = await wire.post("tools/list", protocol_version=pv)
    assert tools.status_code == 200
    assert tools.content.replace(b'"id":1', b"", 1) == (
        (WIRE / "tools_list.json").read_bytes().replace(b'"id":1', b"", 1))

    call = await wire.post("tools/call", {"name": "about_agentavow", "arguments": {}},
                           protocol_version=pv)
    assert call.status_code == 200
    assert call.json()["result"]["isError"] is False


async def test_a_request_without_a_version_header_is_served_as_handshake_era():
    resp = await wire.post("tools/list", protocol_version=None)
    assert resp.status_code == 200
    assert resp.content == (WIRE / "tools_list.json").read_bytes()


# ── 2026-07-28 ────────────────────────────────────────────────────────────────────
async def _modern(method: str, ua: str = wire.UA_CLAUDE_CODE, **params):
    p = wire.modern_envelope(**params)
    return await wire.post(method, p, ua=ua, protocol_version=None,
                           headers=wire.modern_headers(method, p))


async def test_modern_discover_answers_with_the_surface_instructions():
    claude = await _modern("server/discover")
    assert claude.status_code == 200
    res = claude.json()["result"]
    assert wire.MODERN in res["supportedVersions"]
    assert res["instructions"] == m._instructions_for("claude-code")
    assert set(res["capabilities"]) >= {"tools", "resources", "prompts"}

    chatgpt = await _modern("server/discover", ua=wire.UA_CHATGPT)
    assert chatgpt.json()["result"]["instructions"] == m._INSTRUCTIONS


async def test_modern_tools_list_is_200_with_the_same_tools():
    resp = await _modern("tools/list")
    assert resp.status_code == 200  # 1.x: 400 Unsupported protocol version
    import json
    legacy = json.loads((WIRE / "tools_list.json").read_bytes())["result"]["tools"]
    assert resp.json()["result"]["tools"] == legacy


async def test_modern_tools_call_is_200_with_structured_content():
    resp = await _modern("tools/call", name="scan_package",
                         arguments={"registry": "npm", "name": "left-pad"})
    assert resp.status_code == 200
    res = resp.json()["result"]
    assert res["isError"] is False
    assert res["structuredContent"]["trust_score"] == 88
    assert res["structuredContent"]["decision"] in ("safe", "review", "do_not_connect")
    assert "left-pad" in res["content"][0]["text"]


async def test_modern_tools_call_keeps_the_surface_attribution():
    claude = await _modern("tools/call", name="about_agentavow", arguments={})
    chatgpt = await _modern("tools/call", ua=wire.UA_CHATGPT, name="about_agentavow",
                            arguments={})
    assert claude.json()["result"]["content"][0]["text"] == m._about_for("claude-code")
    assert chatgpt.json()["result"]["content"][0]["text"] == m._about_for("chatgpt")


async def test_modern_resources_and_prompts_are_200():
    import json
    read = await _modern("resources/read", uri=m._CARD_URI)
    assert read.status_code == 200
    legacy = json.loads((WIRE / "resources_read.json").read_bytes())["result"]["contents"]
    assert read.json()["result"]["contents"] == legacy

    assert (await _modern("resources/list")).status_code == 200
    prompts = await _modern("prompts/list")
    assert prompts.status_code == 200
    assert [p["name"] for p in prompts.json()["result"]["prompts"]] == [
        "agentavow_get_started", "agentavow_check_my_connections"]
    got = await _modern("prompts/get", name="agentavow_check_my_connections")
    assert got.status_code == 200
    assert got.json()["result"]["messages"][0]["content"]["text"] == m._CHECK_MY_CONNECTIONS


async def test_modern_request_without_the_envelope_is_refused_not_crashed():
    # A 2026-07-28 request must carry params._meta (protocol version + capabilities).
    resp = await wire.post("tools/list", protocol_version=wire.MODERN)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


# ── checks the 1.x @call_tool decorator ran, in both eras ─────────────────────────
@pytest.mark.parametrize("modern", [False, True])
async def test_arguments_are_validated_against_the_input_schema(modern):
    args = {"name": "scan_repo", "arguments": {"repo": "x" * 300}}  # maxLength 214
    resp = await (_modern("tools/call", **args) if modern
                  else wire.post("tools/call", args))
    res = resp.json()["result"]
    assert res["isError"] is True
    assert res["content"][0]["text"].startswith("Input validation error:")


async def test_a_crashing_tool_is_a_tool_error_not_a_protocol_error(monkeypatch):
    async def _boom(name, arguments):
        raise RuntimeError("boom")

    monkeypatch.setattr(m, "_call_tool", _boom)
    resp = await wire.post("tools/call", {"name": "about_agentavow", "arguments": {}})
    assert resp.status_code == 200
    res = resp.json()["result"]
    assert res == {"content": [{"type": "text", "text": "boom"}], "isError": True}
