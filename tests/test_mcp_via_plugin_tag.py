"""Plugin 0.1.37 tags its connector URL (https://agentavow.com/mcp?via=plugin) so
plugin machines can be told apart from hand-added connectors. The server must answer a
tagged request exactly as an untagged one, and the nightly snapshot must count it."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tests import mcp_wire as wire

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,params", [
    ("initialize", wire.initialize_params()),
    ("tools/list", {}),
])
async def test_tagged_connector_url_is_answered_like_the_plain_one(method, params):
    plain = await wire.post(method, params, ua=wire.UA_CLAUDE_CODE, path="/mcp")
    tagged = await wire.post(method, params, ua=wire.UA_CLAUDE_CODE, path="/mcp?via=plugin")
    assert tagged.status_code == plain.status_code == 200

    def result(resp):
        text = resp.text
        if "data:" in text:  # an SSE frame
            text = next(ln[5:] for ln in text.splitlines() if ln.startswith("data:"))
        return json.loads(text)["result"]

    assert result(tagged) == result(plain)


def test_plugin_connector_url_carries_the_tag():
    mcp = json.loads((ROOT / "plugins" / "agentavow-trust" / ".mcp.json").read_text())
    assert mcp["mcpServers"]["agentavow"]["url"] == "https://agentavow.com/mcp?via=plugin"


def _snap(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "anthropic_traffic_snapshot_via", ROOT / "scripts" / "ops" / "anthropic_traffic_snapshot.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr, name in (("SEEN_PATH", "seen.json"), ("CHECKED_PATH", "checked.json"),
                       ("FIRST_CHECKED_PATH", "first.json"), ("CLOUD_PATH", "cloud.json")):
        monkeypatch.setattr(mod, attr, str(tmp_path / name))
    monkeypatch.setattr(mod, "DATA", str(tmp_path))
    monkeypatch.setattr(mod, "_salt", lambda: "test-salt")
    monkeypatch.setattr(mod, "_owner_ips", lambda: {"192.0.2.99"})
    monkeypatch.setattr(mod, "_redis_counts", lambda day: {})
    return mod


@pytest.mark.parametrize("request_line,tagged", [
    ("POST /mcp?via=plugin HTTP/1.1", True),
    ("POST /mcp/?via=plugin HTTP/2.0", True),
    ("POST /mcp?x=1&via=plugin HTTP/1.1", True),
    ("POST /mcp HTTP/1.1", False),
    ("POST /mcp?via=plugins HTTP/1.1", False),
    ("GET /mcp?via=plugin HTTP/1.1", False),
    ("POST /api/v1/mcp?via=plugin HTTP/1.1", False),
    ("", False),
])
def test_plugin_connector_request_detection(tmp_path, monkeypatch, request_line, tagged):
    assert _snap(tmp_path, monkeypatch).is_plugin_connector_request(request_line) is tagged


def test_snapshot_counts_plugin_connector_machines(tmp_path, monkeypatch):
    snap = _snap(tmp_path, monkeypatch)
    cc = "claude-code/2.1.300 (claude-desktop, agent-sdk/0.3.300)"

    def row(ua, req, ip):
        return {"time": "2026-11-20T10:00:00+00:00", "remote_addr": ip,
                "http_user_agent": ua, "request": req, "status": 200}

    rows = [
        row(cc, "POST /mcp?via=plugin HTTP/1.1", "198.51.100.1"),   # plugin, checked
        row("agentavow-precheck/0.1.37 (plugin)",
            "GET /api/v1/public/scan/mcp?endpoint=x HTTP/1.1", "198.51.100.1"),
        row(cc, "POST /mcp?via=plugin HTTP/1.1", "198.51.100.2"),   # plugin, no check
        row(cc, "POST /mcp HTTP/1.1", "198.51.100.3"),              # hand-added connector
        row(cc, "POST /mcp?via=plugin HTTP/1.1", "192.0.2.99"),     # owner: left out
    ]
    monkeypatch.setattr(snap, "_nginx_rows", lambda hours: rows)
    out = snap.snapshot("2026-11-20", 24)
    assert out["cc_machines"] == 4  # the tag never changes who counts as connected
    assert out["cc_machines_plugin"] == 2
    assert out["checked_machines_plugin"] == 1


def test_plugin_columns_reach_the_dashboard(tmp_path, monkeypatch):
    import src.api.metrics_dashboard_router as md

    snap = _snap(tmp_path, monkeypatch)
    for col in ("cc_machines_plugin", "checked_machines_plugin"):
        assert col in snap.COLUMNS and col in md._TRAFFIC_INT_COLUMNS
