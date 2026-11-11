"""GET /admin/metrics/traffic — the durable Claude-origin traffic series the snapshot cron
writes to Redis (hash per UTC day, no TTL). Admin only; missing days are absent, never
fabricated; ints are ints; the notes explain why these differ from the MCP counters."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes


class _FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[bytes, bytes]] = {}

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


def _day(offset: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=offset)).strftime("%Y-%m-%d")


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


def _app(admin: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(md.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=admin)
    app.dependency_overrides[rate_limit_reads] = lambda: None
    app.dependency_overrides[rate_limit_writes] = lambda: None
    return app


def _row(day: str, machines: int, **extra) -> dict[bytes, bytes]:
    base = {"day": day, "cc_machines": machines, "cc_new_machines_30d": 10,
            "claudeai_reqs": 700, "hook_machines_nginx": 9, "calls_claude_code": 4,
            "callers_claude_code": 2, "log_complete": 1, "hook_top_version": "0.1.13"}
    base.update(extra)
    return {k.encode(): str(v).encode() for k, v in base.items()}


async def test_series_is_per_day_with_gaps_left_empty(redis):
    redis.hashes[f"ag:metrics:traffic:{_day(2)}"] = _row(_day(2), 132)
    redis.hashes[f"ag:metrics:traffic:{_day(0)}"] = _row(_day(0), 217, log_complete=0)
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 3})
    assert res.status_code == 200
    body = res.json()
    assert body["days"] == [_day(2), _day(1), _day(0)]
    # yesterday has no row: absent from rows, None in the series — never invented
    assert [r["day"] for r in body["rows"]] == [_day(2), _day(0)]
    assert body["series"]["cc_machines"] == [132, None, 217]
    assert body["covered_days"] == 2
    assert body["latest"]["cc_machines"] == 217 and body["latest"]["log_complete"] == 0
    # ints decoded as ints, strings kept as strings
    assert body["rows"][0]["calls_claude_code"] == 4
    assert body["rows"][0]["hook_top_version"] == "0.1.13"
    assert any("nginx-origin" in n for n in body["notes"])


@pytest.mark.parametrize("day,source,shown", [
    ("2026-10-19", None, True),            # the protocol-reject proxy, valid through 10-19
    ("2026-10-20", None, False),           # proxy gone after the SDK upgrade: blanked
    ("2026-10-21", "nginx_400", False),
    ("2026-10-25", "session_start", True),  # from the server's session-start counter
])
def test_cc_sessions_series_break(day, source, shown):
    row = {"day": day, "cc_sessions": 1400, "owner_cc_sessions": 3}
    if source:
        row["cc_sessions_source"] = source
    out = md._drop_dead_cc_sessions(dict(row))
    assert (out["cc_sessions"] == 1400) is shown
    assert (out["owner_cc_sessions"] == 3) is shown
    assert any("Series break at 2026-10-20" in n for n in md._TRAFFIC_NOTES)


async def test_non_admin_is_refused(redis):
    async with AsyncClient(transport=ASGITransport(app=_app(admin=False)), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic")
    assert res.status_code in (401, 403)


async def test_redis_failure_fails_open(monkeypatch):
    class _Down:
        async def hgetall(self, key):
            raise ConnectionError("redis down")

    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Down())
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 7})
    assert res.status_code == 200
    assert res.json()["rows"] == [] and res.json()["latest"] is None


def _snapshot_module():
    import importlib.util
    from pathlib import Path
    path = (Path(__file__).resolve().parents[1] / "scripts" / "ops"
            / "anthropic_traffic_snapshot.py")
    spec = importlib.util.spec_from_file_location("anthropic_traffic_snapshot", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_snapshot_reads_cc_sessions_from_the_session_start_counter():
    snap = _snapshot_module()
    assert snap._cc_sessions_fields({"session_start_cc": 312, "session_starters_cc": 240}) == {
        "cc_sessions": 312, "cc_sessions_source": "session_start",
        "cc_session_starters": 240, "owner_cc_sessions": ""}
    # Before the counter exists (key missing): the nginx 400 proxy, tagged as such.
    assert snap._cc_sessions_fields({"session_start_cc": None}) == {
        "cc_sessions_source": "nginx_400"}
    # The deploy day's count is partial: not used before the first full day.
    assert snap._cc_sessions_fields({"session_start_cc": 4}, "2026-10-21") == {
        "cc_sessions_source": "nginx_400"}
    assert snap._cc_sessions_fields({"session_start_cc": 4}, "2026-10-22")[
        "cc_sessions_source"] == "session_start"
    assert {"cc_sessions_source", "cc_session_starters"} <= set(snap.COLUMNS)


def test_snapshot_rewrites_old_rows_under_the_new_header(tmp_path):
    snap = _snapshot_module()
    path = tmp_path / "traffic.csv"
    path.write_text("day,cc_sessions\n2026-10-19,1903\n")
    snap.write_row({"day": "2026-10-22", "cc_sessions": 300,
                    "cc_sessions_source": "session_start"}, str(path))
    lines = path.read_text().splitlines()
    assert lines[0].split(",") == snap.COLUMNS
    rows = {r.split(",")[0]: r for r in lines[1:]}
    assert set(rows) == {"2026-10-19", "2026-10-22"}
    col = snap.COLUMNS.index("cc_sessions_source")
    assert rows["2026-10-22"].split(",")[col] == "session_start"
    assert rows["2026-10-19"].split(",")[col] == ""


def test_reach_fields_count_seven_days_and_retention():
    snapshot = _snapshot_module()
    seen = {
        "regular": ["2026-10-20", "2026-11-10"],
        "new_d7": ["2026-11-03", "2026-11-10"],
        "lost_d7": ["2026-11-03", "2026-11-03"],
        "new_d1": ["2026-11-09", "2026-11-09"],
        "owner": ["2026-11-03", "2026-11-10"],
    }
    checked = {"regular": "2026-11-04", "old": "2026-11-03", "owner": "2026-11-10"}
    today = {"regular", "new_d7", "owner"}
    fields = snapshot._reach_fields(seen, checked, today, "2026-11-10", {"owner"})
    # 11-04 is inside the window and 11-03 is not.
    assert fields["cc_machines_7d"] == 3
    assert fields["checked_machines_7d"] == 1
    assert (fields["d7_cohort"], fields["d7_returned"]) == (2, 1)
    assert (fields["d1_cohort"], fields["d1_returned"]) == (1, 0)


def test_snapshot_columns_cover_the_new_surfaces_and_checks():
    snap = _snapshot_module()
    new = [f"calls_{s}" for s in ("cursor", "vscode", "codex")] + [
        f"checks_{s}" for s in ("claude", "claude_code", "chatgpt", "cursor", "vscode",
                                "codex", "other", "total")]
    for col in new:
        assert col in snap.COLUMNS, col
        assert col in md._TRAFFIC_INT_COLUMNS, col


def test_snapshot_redis_program_reads_checks_and_leaves_pre_counter_days_empty(monkeypatch,
                                                                               capsys):
    """checks_<surface>: the counter's value; zero on a day with no calls; empty (None)
    on a day with calls but no counter yet, so the dashboard falls back to calls."""
    import sys

    snap = _snapshot_module()
    day = "2026-11-12"
    store = {
        f"ag:metrics:mcp:calls:total:{day}": b"9",
        f"ag:metrics:mcp:calls:total:claude-code:{day}": b"5",
        f"ag:metrics:mcp:calls:total:cursor:{day}": b"4",
        f"ag:metrics:mcp:checks:{day}": b"7",
        f"ag:metrics:mcp:checks:claude-code:{day}": b"4",
        # cursor had calls but no checks key: pre-counter style -> None
    }

    class _R:
        async def get(self, key):
            return store.get(key)

        async def pfcount(self, *keys):
            return 0

    monkeypatch.setattr("src.redis_client.get_redis", lambda: _R())
    monkeypatch.setattr(sys, "argv", ["-", day])
    exec(compile(snap.REDIS_PROGRAM, "<redis>", "exec"), {"__name__": "__main__"})
    import json

    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["checks_total"] == 7 and out["checks_claude-code"] == 4
    assert out["checks_cursor"] is None
    assert out["checks_vscode"] == 0 and out["calls_codex"] == 0


@pytest.mark.parametrize("ua,group", [
    ("claude-code/2.1.287 (cli)", "cli"),
    ("claude-code/2.1.286 (claude-vscode, agent-sdk/0.3.286)", "cli"),
    ("claude-code/2.1.284 (claude-desktop, agent-sdk/0.3.284)", "desktop"),
    ("claude-code/2.1.286 (local-agent, agent-sdk/0.3.286)", "desktop"),
    ("claude-code/2.1.285 (sdk-cli)", "sdk"),
    ("claude-code/2.1.280 (sdk-ts, agent-sdk/0.3.280)", "sdk"),
    ("claude-code/2.1.290 (remote, agent-sdk/0.3.290)", "cloud"),
    ("claude-code/2.1.290 (remote-agent)", "cloud"),
    ("claude-code/2.1.290", "other"),
    ("claude-code/2.1.290 (something-new)", "other"),
])
def test_snapshot_entrypoint_groups(ua, group):
    assert _snapshot_module().entrypoint_group(ua) == group


def test_activation_fields_drop_cloud_and_count_new_machines_that_see_a_verdict():
    snap = _snapshot_module()
    day = "2026-11-20"
    seen = {
        "laptop": ["2026-11-01", day],
        "cloudbox": ["2026-11-01", day],
        "new_checked": [day, day],
        "new_unchecked": [day, day],
        "d7_checked": ["2026-11-13", "2026-11-14"],
        "d7_late": ["2026-11-13", "2026-11-13"],
        "d7_never": ["2026-11-13", "2026-11-13"],
        "owner": [day, day],
    }
    checked_last = {"laptop": day, "cloudbox": day, "new_checked": day, "owner": day}
    first_checked = {"d7_checked": "2026-11-15", "d7_late": day, "new_checked": day,
                     "owner": day}
    out = snap._activation_fields(
        seen, checked_last, first_checked, {"cloudbox"},
        {"laptop", "cloudbox", "new_checked", "new_unchecked", "owner"},
        {"laptop", "cloudbox", "new_checked", "owner"}, day, {"owner"})
    assert out["cc_machines_7d_excl_cloud"] == 4  # laptop, the two new, d7_checked (11-14)
    assert out["checked_machines_7d_excl_cloud"] == 2  # laptop, new_checked
    assert out["new_checked_same_day"] == 1
    assert out["d7_cohort_checked"] == 1  # checked on 11-15; 11-20 is too late


def test_rolling_drops_old_entries():
    snap = _snapshot_module()
    assert snap._rolling({"a": "2026-10-01", "b": "2026-11-19", "c": 3}, "2026-11-20", 30) == {
        "b": "2026-11-19"}
