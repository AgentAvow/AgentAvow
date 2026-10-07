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
