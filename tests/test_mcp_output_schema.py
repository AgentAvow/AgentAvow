"""The three scan tools advertise an outputSchema for their structuredContent.

Declaring one changes the rules: the MCP SDK (and spec-following clients) reject a
successful result that has no structuredContent, and validate the one that is there. So
these tests pin three things — the schema matches what _scan_struct really emits, a scan
that could not run comes back as a tool error rather than a schema violation, and a
schema/struct drift never turns a good scan into a failure.
"""
from __future__ import annotations

import logging

import httpx
import jsonschema
import mcp.types as types
import pytest

from src.bridges import mcp_streamable as mod

_RICH = {
    "trust_score": 45,
    "trust_tier": "minimal",
    "jws": "eyJ.sig.ned",
    "cached": True,
    "certified": {"eligible": False, "checks": {"no_critical_or_high": False}},
    "category_scores": {"secret_hygiene": 40, "code_safety": 55, "data_handling": 90},
    "findings": {
        "total": 3,
        "items": [
            {"severity": "critical", "category": "secret_hygiene", "name": "Hardcoded key",
             "file_path": "src/a.py", "line_number": 7, "remediation": "Rotate it."},
            {"severity": "critical", "category": "secret_hygiene", "name": "Hardcoded key",
             "file_path": "src/b.py", "line_number": 9, "remediation": "Rotate it."},
            {"severity": "low", "category": "dependencies", "name": "Unpinned dep",
             "file_path": None, "line_number": None, "remediation": None},
        ],
    },
    "incident_history": {
        "has_incident": True, "current_version_affected": False, "count": 1,
        "incidents": [{"id": "MAL-2025-1", "summary": "Compromised release",
                       "published": "2025-09-08T00:00:00Z"}],
    },
}

_CLEAN = {
    "trust_score": 88,
    "trust_tier": "trusted",
    "jws": "eyJ.sig.ned",
    "certified": {"eligible": True, "checks": {"no_critical_or_high": True}},
    "category_scores": {"secret_hygiene": 100},
    "findings": {"total": 0, "items": []},
}


def _struct(data: dict, target_type: str = "npm", adoption=(583_000_000, "downloads/wk", 97)):
    return mod._scan_struct(data, "chalk", target_type, "/check/pkg/npm/chalk",
                            "/api/v1/public/scan/package/npm/chalk", adoption)


async def _call(name: str, arguments: dict) -> types.CallToolResult:
    """Run a call through the SDK's own handler, exactly as a client request would."""
    handler = mod.server.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    return (await handler(req)).root


@pytest.fixture
def _quiet(monkeypatch):
    """No metrics writes and no adoption lookup: keep these tests off Redis and the API."""
    async def _noop(metric):
        return None

    async def _no_adoption(surface, owner, repo):
        return None

    monkeypatch.setattr(mod, "_bump", _noop)
    monkeypatch.setattr(mod, "_adoption", _no_adoption)


def test_schema_is_a_valid_json_schema():
    jsonschema.Draft202012Validator.check_schema(mod._SCAN_OUTPUT_SCHEMA)


def test_only_the_scan_tools_declare_an_output_schema():
    # The other five return text only; an outputSchema there would make every call fail.
    declared = {t.name for t in mod._TOOLS if t.outputSchema is not None}
    assert declared == {"scan_repo", "scan_package", "scan_mcp_server"}


@pytest.mark.parametrize("data,target_type,adoption", [
    (_RICH, "npm", (583_000_000, "downloads/wk", 97)),
    (_CLEAN, "pypi", (12, "stars", 3)),
    (_CLEAN, "mcp", None),
    ({}, "github", None),  # an empty scan payload must still produce a valid result
])
def test_scan_struct_matches_the_schema(data, target_type, adoption):
    jsonschema.validate(instance=_struct(data, target_type, adoption),
                        schema=mod._SCAN_OUTPUT_SCHEMA)


def test_schema_describes_every_key_the_struct_emits():
    # A key added to _scan_struct without a schema entry would reach clients undescribed.
    described = set(mod._SCAN_OUTPUT_SCHEMA["properties"])
    assert set(_struct(_RICH)) <= described
    # The only schema key _scan_struct itself does not emit is the one _with_rescan_note adds.
    assert described - set(_struct(_RICH)) == {"rescan_pending"}
    assert set(mod._SCAN_OUTPUT_SCHEMA["required"]) <= set(_struct({}))


@pytest.mark.asyncio
async def test_successful_scan_passes_sdk_output_validation(monkeypatch, _quiet):
    async def _scan(path, params=None):
        return _CLEAN

    monkeypatch.setattr(mod, "_get", _scan)
    res = await _call("scan_package", {"registry": "npm", "name": "chalk"})
    assert res.isError is False
    assert res.structuredContent["verdict"] == "safe"
    assert res.structuredContent["trust_score"] == 88
    assert "chalk" in res.content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args,expect", [
    ("scan_repo", {"repo": "no-slash"}, "owner/name"),
    ("scan_repo", {"repo": "npm/chalk"}, "scan_package"),
    ("scan_package", {"name": "chalk"}, "registry"),
])
async def test_unusable_input_is_a_tool_error_with_the_guidance(_quiet, tool, args, expect):
    res = await _call(tool, args)
    assert res.isError is True
    assert res.structuredContent is None
    text = res.content[0].text
    assert expect in text
    assert "Output validation error" not in text  # our guidance, not the SDK's complaint


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expect", [(404, "Not found"), (503, "still running")])
async def test_failed_scan_is_a_tool_error_with_the_guidance(monkeypatch, _quiet, status, expect):
    async def _fail(path, params=None):
        req = httpx.Request("GET", "http://internal/api" + path)
        raise httpx.HTTPStatusError("x", request=req,
                                    response=httpx.Response(status, request=req))

    monkeypatch.setattr(mod, "_get", _fail)
    res = await _call("scan_mcp_server", {"endpoint_url": "https://example.com/mcp"})
    assert res.isError is True
    assert res.structuredContent is None
    assert expect in res.content[0].text


@pytest.mark.asyncio
async def test_scan_timeout_is_a_tool_error(monkeypatch, _quiet):
    async def _slow(path, params=None):
        raise httpx.TimeoutException("slow")

    monkeypatch.setattr(mod, "_get", _slow)
    res = await _call("scan_repo", {"repo": "vercel/next.js"})
    assert res.isError is True
    assert "longer than usual" in res.content[0].text


@pytest.mark.asyncio
async def test_schema_drift_does_not_fail_a_good_scan(monkeypatch, _quiet, caplog):
    async def _scan(path, params=None):
        return _CLEAN

    drifted = {**_struct(_CLEAN), "trust_score": "eighty-eight"}  # wrong type

    monkeypatch.setattr(mod, "_get", _scan)
    monkeypatch.setattr(mod, "_scan_struct", lambda *a, **k: drifted)
    with caplog.at_level(logging.ERROR, logger=mod.logger.name):
        res = await _call("scan_package", {"registry": "npm", "name": "chalk"})
    assert res.isError is False
    assert res.structuredContent["trust_score"] == "eighty-eight"
    assert "outputSchema" in caplog.text


@pytest.mark.asyncio
async def test_text_only_tools_are_unaffected(_quiet):
    res = await _call("about_agentavow", {})
    assert res.isError is False
    assert res.structuredContent is None
    assert "AgentAvow" in res.content[0].text
