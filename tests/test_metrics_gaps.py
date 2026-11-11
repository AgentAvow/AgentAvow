"""Metrics-dashboard gaps closed before the Nov 17 ad test: one-click installs by client,
the npm tool gate and A2A card fetches in the nightly snapshot, and the IndexNow record."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- #19: one-click installs by client ---


@pytest.mark.asyncio
@pytest.mark.parametrize("event, bumped", [
    ("install_cursor", ["install_cursor", "install_click"]),
    ("install_vscode", ["install_vscode", "install_click"]),
    ("install_goose", ["install_goose", "install_click"]),
    ("install_click", ["install_click"]),
    ("install_copy", ["install_copy"]),
    ("install_zed", []),  # not allowlisted: nothing counted
])
async def test_install_beacon_counts_the_client_and_the_total(monkeypatch, event, bumped):
    from src.api import public_scan_router as ps

    seen: list[str] = []

    async def fake_bump(name: str) -> None:
        seen.append(name)

    monkeypatch.setattr("src.api.metrics_dashboard_router.bump_metric", fake_bump)
    assert await ps.metric_beacon(event) == {"ok": True}
    assert seen == bumped


# --- #9 / #17: the nightly snapshot ---


def _nginx(ua: str, request: str, status: int = 200, ip: str = "203.0.113.9",
           time: str = "2026-11-12T10:00:00+00:00") -> dict:
    return {"time": time, "remote_addr": ip, "http_user_agent": ua, "request": request,
            "status": status}


@pytest.fixture
def snap(tmp_path, monkeypatch):
    mod = _load("scripts/ops/anthropic_traffic_snapshot.py", "anthropic_traffic_snapshot_gaps")
    data = tmp_path / "data"
    for attr, name in (("SEEN_PATH", "seen.json"), ("CHECKED_PATH", "checked.json"),
                       ("FIRST_CHECKED_PATH", "first.json"), ("CLOUD_PATH", "cloud.json")):
        monkeypatch.setattr(mod, attr, str(data / name))
    monkeypatch.setattr(mod, "DATA", str(data))
    monkeypatch.setattr(mod, "_salt", lambda: "test-salt")
    monkeypatch.setattr(mod, "_owner_ips", lambda: set())
    monkeypatch.setattr(mod, "_redis_counts", lambda day: {})
    return mod


def test_snapshot_counts_the_tool_gate_apart_from_the_plugin_gate(snap, monkeypatch):
    rows = [
        _nginx("agentavow-gate/0.2.0", "GET /api/v1/public/scan/a/b HTTP/1.1", ip="198.51.100.1"),
        _nginx("agentavow-tool-gate/0.4.2", "GET /api/v1/public/scan/a/b HTTP/1.1",
               ip="198.51.100.2"),
        _nginx("agentavow-tool-gate/0.4.2", "GET /api/v1/public/scan/c/d HTTP/1.1",
               ip="198.51.100.2"),
        _nginx("agentavow-tool-gate/0.4.2", "GET /api/v1/public/scan/c/d HTTP/1.1",
               ip="198.51.100.3"),
    ]
    monkeypatch.setattr(snap, "_nginx_rows", lambda hours: rows)
    row = snap.snapshot("2026-11-12", 72)
    assert row["gate_machines"] == 1
    assert row["tool_gate_machines"] == 2
    assert row["tool_gate_reqs"] == 3


def test_snapshot_counts_answered_fetches_of_our_agent_card(snap, monkeypatch):
    rows = [
        _nginx("a2a-client/1", "GET /.well-known/agent-card.json HTTP/1.1", ip="198.51.100.1"),
        _nginx("a2a-client/1", "GET /.well-known/agent-card.json?x=1 HTTP/2.0", 304,
               ip="198.51.100.1"),
        _nginx("old-client", "HEAD /.well-known/agent.json HTTP/1.1", ip="198.51.100.2"),
        _nginx("x", "GET /.well-known/agent-card.json HTTP/1.1", 404, ip="198.51.100.3"),
        _nginx("x", "POST /.well-known/agent-card.json HTTP/1.1", ip="198.51.100.4"),
        _nginx("x", "GET /.well-known/agent-registration.json HTTP/1.1", ip="198.51.100.5"),
        _nginx("x", "GET /.well-known/agent-card.json HTTP/1.1", ip="198.51.100.6",
               time="2026-11-11T23:59:59+00:00"),  # the day before
    ]
    monkeypatch.setattr(snap, "_nginx_rows", lambda hours: rows)
    row = snap.snapshot("2026-11-12", 72)
    assert row["a2a_card_fetches"] == 3
    assert row["a2a_card_fetchers"] == 2


def test_new_snapshot_columns_reach_the_dashboard():
    import src.api.metrics_dashboard_router as md

    snap = _load("scripts/ops/anthropic_traffic_snapshot.py", "anthropic_traffic_snapshot_cols")
    for col in ("tool_gate_machines", "tool_gate_reqs", "a2a_card_fetches", "a2a_card_fetchers"):
        assert col in snap.COLUMNS, col
        assert col in md._TRAFFIC_INT_COLUMNS, col


# --- #24: IndexNow pings ---


class _FakeList:
    def __init__(self) -> None:
        self.items: list[str] = []

    async def lpush(self, key, value):
        self.items.insert(0, value)

    async def ltrim(self, key, start, end):
        self.items = self.items[start:end + 1]

    async def lrange(self, key, start, end):
        return [v.encode() for v in self.items[start:end + 1]]


@pytest.mark.asyncio
async def test_indexnow_runs_are_kept_newest_first_and_trimmed(monkeypatch):
    from src import indexnow_record as ir

    fake = _FakeList()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    for i in range(ir.KEEP + 3):
        assert await ir.record_run({"at": f"2026-11-12T10:{i:02d}:00+00:00", "outcome": "sent",
                                    "submitted": i, "status": 200})
    runs = await ir.recent_runs(3)
    assert [r["submitted"] for r in runs] == [ir.KEEP + 2, ir.KEEP + 1, ir.KEEP]
    assert len(fake.items) == ir.KEEP
    assert runs[0] == {"at": "2026-11-12T10:22:00+00:00", "outcome": "sent",
                       "submitted": ir.KEEP + 2, "status": 200}


def test_indexnow_record_keeps_only_checked_fields():
    from src.indexnow_record import clean_run

    assert clean_run({"outcome": "bogus"}) is None
    assert clean_run("sent") is None
    assert clean_run({"outcome": "sent", "at": "not a time"}) is None
    run = clean_run({"outcome": "http_error", "status": 403, "submitted": -1,
                     "at": "2026-11-12T10:00:00", "urlList": ["https://x"]})
    assert run == {"at": "2026-11-12T10:00:00+00:00", "outcome": "http_error",
                   "submitted": 0, "status": 403}
    assert clean_run({"outcome": "skipped", "status": 9999})["status"] is None


@pytest.mark.asyncio
async def test_indexnow_record_fails_open_without_redis(monkeypatch):
    from src import indexnow_record as ir

    def down():
        raise ConnectionError("redis down")

    monkeypatch.setattr("src.redis_client.get_redis", down)
    assert await ir.record_run({"outcome": "sent", "submitted": 1, "status": 200}) is False
    assert await ir.recent_runs() == []


@pytest.fixture
def ping():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import indexnow_ping
    finally:
        sys.path.pop(0)
    return indexnow_ping


def test_ping_writes_its_result(ping, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(ping, "post", lambda payload: 202)
    out = tmp_path / "result.json"
    assert ping.main(["--state", str(tmp_path / "s.json"), "--result", str(out)]) == 0
    result = json.loads(out.read_text())
    assert result["outcome"] == "sent" and result["status"] == 202
    assert result["submitted"] > 0 and result["at"]

    # Nothing moved since the last ping: recorded as such, nothing sent.
    assert ping.main(["--changed-only", "--state", str(tmp_path / "s.json"),
                      "--result", str(out)]) == 0
    assert json.loads(out.read_text())["outcome"] == "nothing_changed"


def test_ping_failure_is_recorded_and_still_one_line(ping, monkeypatch, capsys, tmp_path):
    def boom(_payload):
        raise TimeoutError("timed out")

    monkeypatch.setattr(ping, "post", boom)
    out = tmp_path / "result.json"
    assert ping.main(["--state", str(tmp_path / "s.json"), "--result", str(out)]) == 0
    assert capsys.readouterr().out.count("\n") == 1
    result = json.loads(out.read_text())
    assert result["outcome"] == "skipped" and result["submitted"] > 0


def test_ping_dry_run_records_nothing(ping, tmp_path):
    out = tmp_path / "result.json"
    assert ping.main(["--dry-run", "--state", str(tmp_path / "s.json"),
                      "--result", str(out)]) == 0
    assert not out.exists()


@pytest.mark.asyncio
async def test_growth_view_shows_the_last_indexnow_runs(monkeypatch):
    import src.api.metrics_dashboard_router as md
    from src.api.deps import get_current_entity
    from src.api.rate_limit import rate_limit_reads
    from src.database import get_db

    async def no_cache_get(key):
        return None

    async def no_cache_set(key, value, ttl=None):
        return None

    async def runs(limit=5):
        return [{"at": "2026-11-12T10:00:00+00:00", "outcome": "sent", "submitted": 4,
                 "status": 200}]

    async def empty(*a, **k):
        return {}

    monkeypatch.setattr("src.cache.get", no_cache_get)
    monkeypatch.setattr("src.cache.set", no_cache_set)
    monkeypatch.setattr("src.indexnow_record.recent_runs", runs)
    monkeypatch.setattr("src.jobs.metrics_daily.read_daily", empty)
    monkeypatch.setattr("src.jobs.metrics_daily.current_catalog_mix", empty)
    monkeypatch.setattr(md, "_referrals", empty)

    app = FastAPI()
    app.include_router(md.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=True)
    app.dependency_overrides[rate_limit_reads] = lambda: None
    app.dependency_overrides[get_db] = lambda: None
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/growth", params={"days": 7})
    assert res.status_code == 200
    assert res.json()["indexnow_runs"][0]["submitted"] == 4
