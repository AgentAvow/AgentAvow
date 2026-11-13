"""The hosted connector's once-a-week "make this automatic" plugin tip.

Shown after a scan answer only to Claude Code callers that connected without the plugin
(no ?via=plugin), at most once per machine per 7 days, never when Redis is down or the
AGENTAVOW_PLUGIN_TIP kill switch is off. Every other surface, ChatGPT above all (its
published app pins the response bytes), must get exactly the bytes it got before.
"""
from __future__ import annotations

import json

import mcp.types as types
import pytest

import src.redis_client as redis_client
from src.bridges import mcp_streamable as mod
from src.config import settings
from tests import mcp_wire as wire

_CLEAN = {
    "trust_score": 88,
    "trust_tier": "trusted",
    "jws": "eyJ.sig.ned",
    "certified": {"eligible": True, "checks": {"no_critical_or_high": True}},
    "category_scores": {"secret_hygiene": 100},
    "findings": {"total": 0, "items": []},
}

_SCANS = [
    ("scan_repo", {"repo": "vercel/next.js"}),
    ("scan_package", {"registry": "npm", "name": "chalk"}),
    ("scan_mcp_server", {"endpoint_url": "https://mcp.example.com/mcp"}),
]


class _FakeRedis:
    """SET NX EX against a controllable clock."""

    def __init__(self) -> None:
        self.now = 1_000_000.0
        self.store: dict[str, tuple[str, float]] = {}
        self.calls: list[str] = []

    async def set(self, key, value, nx=False, ex=None):
        self.calls.append(key)
        cur = self.store.get(key)
        if cur is not None and cur[1] > self.now:
            if nx:
                return None
        self.store[key] = (value, self.now + (ex or 10**9))
        return True


class _DownRedis:
    async def set(self, *a, **k):
        raise ConnectionError("redis down")


@pytest.fixture
def env(monkeypatch):
    """No API, adoption or caller-HLL traffic; metrics captured; a fake Redis."""
    bumps: list[str] = []

    async def _bump(metric):
        bumps.append(metric)

    async def _scan(path, params=None):
        return _CLEAN

    async def _none(*a, **k):
        return None

    fake = _FakeRedis()
    monkeypatch.setattr(mod, "_bump", _bump)
    monkeypatch.setattr(mod, "_get", _scan)
    monkeypatch.setattr(mod, "_adoption", _none)
    monkeypatch.setattr(mod, "_record_caller", _none)
    monkeypatch.setattr(redis_client, "get_redis", lambda: fake)
    monkeypatch.setattr(settings, "agentavow_plugin_tip", True)
    return {"redis": fake, "bumps": bumps}


def _ctx(surface: str, via_plugin: bool = False, ip: str = "203.0.113.7"):
    mod._SURFACE.set(surface)
    mod._VIA_PLUGIN.set(via_plugin)
    mod._CLIENT_IP.set(ip)
    mod._HEALTH_PROBE.set(False)


async def _call(name: str, arguments: dict) -> types.CallToolResult:
    entry = mod.server.get_request_handler("tools/call")
    params = entry.params_type.model_validate({"name": name, "arguments": arguments})
    return await entry.handler(None, params)


def _has_tip(res: types.CallToolResult) -> bool:
    return any(mod.PLUGIN_TIP in (getattr(c, "text", "") or "") for c in res.content)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", _SCANS)
async def test_shown_once_for_claude_code_without_plugin(env, tool, args):
    _ctx("claude-code")
    res = await _call(tool, args)
    assert res.is_error is False
    text = res.content[-1].text
    assert text.endswith("\n\n" + mod.PLUGIN_TIP)
    assert text.count(mod.PLUGIN_TIP) == 1
    # The card keeps its audience annotation; structuredContent is untouched.
    assert res.content[-1].annotations.audience == ["user"]
    assert "plugin" not in json.dumps(res.structured_content)
    assert env["bumps"].count("plugin_tip_shown") == 1
    assert env["bumps"].count("plugin_tip_shown:claude-code") == 1
    # Stored key is a salted hash, never the IP.
    (key,) = env["redis"].store
    assert key.startswith("mcp:plugin_tip:") and "203.0.113.7" not in key
    assert len(key.removeprefix("mcp:plugin_tip:")) == 64


@pytest.mark.asyncio
async def test_not_shown_again_within_seven_days_then_shown_after(env):
    _ctx("claude-code")
    assert _has_tip(await _call(*_SCANS[1]))
    env["redis"].now += 6 * 24 * 3600
    for tool, args in _SCANS:
        assert not _has_tip(await _call(tool, args))
    env["redis"].now += 2 * 24 * 3600  # past the 7-day window
    assert _has_tip(await _call(*_SCANS[0]))
    assert env["bumps"].count("plugin_tip_shown") == 2


@pytest.mark.asyncio
async def test_window_is_per_machine(env):
    _ctx("claude-code", ip="203.0.113.7")
    assert _has_tip(await _call(*_SCANS[1]))
    _ctx("claude-code", ip="198.51.100.9")
    assert _has_tip(await _call(*_SCANS[1]))


@pytest.mark.asyncio
async def test_not_shown_via_plugin(env):
    _ctx("claude-code", via_plugin=True)
    assert not _has_tip(await _call(*_SCANS[1]))
    assert env["redis"].calls == []
    assert "plugin_tip_shown" not in env["bumps"]


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["chatgpt", "claude", "cursor", "vscode", "codex", "other"])
async def test_not_shown_on_other_surfaces(env, surface):
    _ctx(surface)
    for tool, args in _SCANS:
        assert not _has_tip(await _call(tool, args))
    assert env["redis"].calls == []  # never even consults Redis
    assert "plugin_tip_shown" not in env["bumps"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", [
    ("about_agentavow", {}),
    ("lookup_identity", {"query": "nobody-here"}),
])
async def test_not_shown_on_non_scan_tools(env, monkeypatch, tool, args):
    async def _empty(path, params=None):
        return {"entities": []}

    monkeypatch.setattr(mod, "_get", _empty)
    _ctx("claude-code")
    assert not _has_tip(await _call(tool, args))
    assert env["redis"].calls == []


@pytest.mark.asyncio
async def test_not_shown_on_a_scan_error(env):
    _ctx("claude-code")
    res = await _call("scan_repo", {"repo": "no-slash"})
    assert res.is_error is True
    assert not _has_tip(res)
    assert env["redis"].calls == []


@pytest.mark.asyncio
async def test_kill_switch(env, monkeypatch):
    monkeypatch.setattr(settings, "agentavow_plugin_tip", False)
    _ctx("claude-code")
    assert not _has_tip(await _call(*_SCANS[1]))
    assert env["redis"].calls == []


@pytest.mark.parametrize("raw,expected", [
    ("off", False), ("OFF", False), ("false", False), ("0", False), ("no", False),
    ("on", True), ("true", True), ("1", True),
])
def test_kill_switch_env_values(monkeypatch, raw, expected):
    from src.config import Settings

    monkeypatch.setenv("AGENTAVOW_PLUGIN_TIP", raw)
    assert Settings().agentavow_plugin_tip is expected


def test_kill_switch_defaults_on(monkeypatch):
    from src.config import Settings

    monkeypatch.delenv("AGENTAVOW_PLUGIN_TIP", raising=False)
    assert Settings().agentavow_plugin_tip is True


@pytest.mark.asyncio
async def test_redis_down_means_no_tip(env, monkeypatch):
    monkeypatch.setattr(redis_client, "get_redis", lambda: _DownRedis())
    _ctx("claude-code")
    res = await _call(*_SCANS[1])
    assert res.is_error is False
    assert not _has_tip(res)
    assert "plugin_tip_shown" not in env["bumps"]


@pytest.mark.asyncio
async def test_no_client_ip_means_no_tip(env):
    _ctx("claude-code", ip="")
    assert not _has_tip(await _call(*_SCANS[1]))


@pytest.mark.parametrize("qs,expected", [
    (b"via=plugin", True), (b"x=1&via=plugin", True), (b"via=plugins", False),
    (b"", False), (None, False), (b"via=", False), ("via=plugin", True),
])
def test_via_plugin_parsing(qs, expected):
    assert mod._is_via_plugin(qs) is expected


# --- over the real HTTP entry: bytes on the wire --------------------------------------


async def _wire_call(tool, args, ua, path="/mcp", request_id=7):
    return await wire.post("tools/call", {"name": tool, "arguments": args}, ua=ua,
                           path=path, request_id=request_id)


async def _identity(content):
    return content


@pytest.mark.asyncio
@pytest.mark.parametrize("ua", [wire.UA_CHATGPT, wire.UA_CLAUDE, "Cursor/0.42",
                                "python-httpx/0.27"])
@pytest.mark.parametrize("tool,args", _SCANS)
async def test_other_surfaces_bytes_identical_to_before(env, monkeypatch, ua, tool, args):
    now = await _wire_call(tool, args, ua)
    # "Before" = the module without the tip step at all.
    monkeypatch.setattr(mod, "_with_plugin_tip", _identity)
    before = await _wire_call(tool, args, ua)
    assert now.status_code == before.status_code == 200
    assert now.content == before.content
    assert mod.PLUGIN_TIP.encode() not in now.content
    assert env["redis"].calls == []


@pytest.mark.asyncio
async def test_claude_code_over_the_wire_tip_then_plugin_url(env, monkeypatch):
    plugin = await _wire_call(*_SCANS[1], wire.UA_CLAUDE_CODE, path="/mcp?via=plugin")
    assert mod.PLUGIN_TIP.encode() not in plugin.content
    assert env["redis"].calls == []

    first = await _wire_call(*_SCANS[1], wire.UA_CLAUDE_CODE)
    body = json.loads(first.content)["result"]
    assert body["content"][-1]["text"].endswith("\n\n" + mod.PLUGIN_TIP)
    # structuredContent identical to the plugin user's (no tip, no new field).
    assert body["structuredContent"] == json.loads(plugin.content)["result"]["structuredContent"]

    second = await _wire_call(*_SCANS[1], wire.UA_CLAUDE_CODE)
    assert mod.PLUGIN_TIP.encode() not in second.content
