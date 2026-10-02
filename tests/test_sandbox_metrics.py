"""Behavioral sandbox metrics: the admin panel endpoint and the public stats endpoint.

Both read the ``ag:metrics:behavioral:*`` counters in ONE Redis MGET, treat a
missing or malformed key as 0, and the public one never carries a name.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
import src.api.sandbox_stats_router as ss
from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads

P = "ag:metrics:behavioral:"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, object] = {}
        self.mget_calls: list[list[str]] = []
        self.fail = False

    async def mget(self, keys):
        if self.fail:
            raise ConnectionError("redis down")
        self.mget_calls.append(list(keys))
        return [self.store.get(k) for k in keys]

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


def _app(admin: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(md.router, prefix="/api/v1")
    app.include_router(ss.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=admin)
    app.dependency_overrides[rate_limit_reads] = lambda: None
    return app


async def _get(app: FastAPI, path: str, **params):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path, params=params)


def _today() -> str:
    return md.window_day_strs(1)[0]


# --- helpers -----------------------------------------------------------------

def test_scaling_hint_thresholds():
    assert md.behavioral_scaling_hint(0, 0, 0) == "ok"
    assert md.behavioral_scaling_hint(95, 5, 0) == "ok"  # exactly 5% is not over
    assert md.behavioral_scaling_hint(94, 6, 0) == "add capacity"
    assert md.behavioral_scaling_hint(100, 0, 10) == "ok"  # exactly 10%
    assert md.behavioral_scaling_hint(100, 0, 11) == "watch memory"
    # slot pressure wins over memory pressure
    assert md.behavioral_scaling_hint(10, 10, 5) == "add capacity"
    assert md.behavioral_scaling_hint(0, 3, 0) == "add capacity"


def test_num_is_defensive():
    assert md._num(None) == 0
    assert md._num(b"7") == 7
    assert md._num("2.5") == 2.5
    assert md._num("garbage") == 0
    assert md._num("-3") == 0
    assert md._num("nan") == 0


def test_window_days_oldest_first():
    days = md.window_day_strs(7)
    assert len(days) == 7 and days == sorted(days) and days[-1] == _today()


# --- admin endpoint ----------------------------------------------------------

async def test_admin_behavioral_window_one_mget(redis):
    days = md.window_day_strs(7)
    d0, d6 = days[0], days[-1]
    redis.store.update({
        f"{P}runs:{d0}": "10", f"{P}runs:{d6}": b"30",
        f"{P}exercised:{d6}": "12",
        f"{P}with_findings:{d6}": "4",
        f"{P}canary_leaks:{d0}": "1",
        f"{P}slot_rejected:{d6}": "1",
        f"{P}killed:{d6}": "2",
        f"{P}cache_hit:{d6}": "30", f"{P}cache_miss:{d6}": "10",
        f"{P}duration_sum:{d0}": "200", f"{P}duration_sum:{d6}": "600",
        f"{P}duration_max:{d0}": "95.5", f"{P}duration_max:{d6}": "61",
        f"{P}start:started:{d6}": "12", f"{P}start:needs_credentials:{d6}": "5",
        f"{P}rule:behavioral_undeclared_egress:{d6}": "3",
        f"{P}rule:credential_canary_exfiltrated:{d0}": "1",
        # outside the 7-day window: must not count
        f"{P}runs:1999-01-01": "999",
    })
    r = await _get(_app(), "/api/v1/admin/metrics/behavioral", window="7d")
    assert r.status_code == 200
    body = r.json()
    assert 1 <= len(redis.mget_calls) <= 2  # panel counters + backfill block: bounded round trips
    assert body["days"] == days
    assert body["runs"] == 40
    assert body["exercised"] == 12
    assert body["with_findings"] == 4
    assert body["canary_leaks"] == 1
    assert body["slot_rejected"] == 1 and body["killed"] == 2
    assert body["cache_hit_rate"] == 0.75
    assert body["avg_duration_s"] == 20.0
    assert body["max_duration_s"] == 95.5
    assert body["start_reasons"]["started"] == 12
    assert body["start_reasons"]["needs_credentials"] == 5
    assert body["start_reasons"]["timeout"] == 0
    assert set(body["start_reasons"]) == set(md.BEHAVIORAL_START_REASONS)
    assert body["findings_by_rule"]["behavioral_undeclared_egress"] == 3
    assert body["findings_by_rule"]["credential_canary_exfiltrated"] == 1
    assert body["series"]["runs"] == [10, 0, 0, 0, 0, 0, 30]
    assert body["series"]["exercised"][-1] == 12
    assert body["series"]["slot_rejected"][-1] == 1
    assert body["concurrency_limit"] >= 1
    assert body["scaling_hint"] == "ok"


async def test_admin_behavioral_empty_and_hints(redis):
    r = await _get(_app(), "/api/v1/admin/metrics/behavioral", window="today")
    body = r.json()
    assert body["runs"] == 0
    assert body["cache_hit_rate"] is None
    assert body["avg_duration_s"] is None and body["max_duration_s"] is None
    assert body["scaling_hint"] == "ok"
    assert body["series"]["runs"] == [0]

    t = _today()
    redis.store.update({f"{P}runs:{t}": "10", f"{P}slot_rejected:{t}": "5"})
    body = (await _get(_app(), "/api/v1/admin/metrics/behavioral", window="today")).json()
    assert body["scaling_hint"] == "add capacity"

    redis.store.update({f"{P}slot_rejected:{t}": "0", f"{P}killed:{t}": "3"})
    body = (await _get(_app(), "/api/v1/admin/metrics/behavioral", window="today")).json()
    assert body["scaling_hint"] == "watch memory"


async def test_admin_behavioral_redis_down_reads_zero(redis):
    redis.fail = True
    r = await _get(_app(), "/api/v1/admin/metrics/behavioral", window="30d")
    assert r.status_code == 200
    body = r.json()
    assert body["runs"] == 0 and len(body["series"]["runs"]) == 30


async def test_admin_behavioral_requires_admin(redis):
    r = await _get(_app(admin=False), "/api/v1/admin/metrics/behavioral")
    assert r.status_code == 403


async def test_admin_behavioral_rejects_bad_window(redis):
    r = await _get(_app(), "/api/v1/admin/metrics/behavioral", window="90d")
    assert r.status_code == 422


# --- public endpoint ---------------------------------------------------------

async def test_public_sandbox_stats_shape_and_cache(redis):
    days = md.window_day_strs(30)
    redis.store.update({
        f"{P}total:runs": "120", f"{P}total:exercised": "40",
        f"{P}total:tools_called": "333", f"{P}total:findings": "17",
        f"{P}total:canary_leaks": "2",
        f"{P}runs:{days[0]}": "5", f"{P}runs:{days[-1]}": "7",
        f"{P}exercised:{days[-1]}": "3",
        f"{P}with_findings:{days[-1]}": "2",
        f"{P}rule:behavioral_undeclared_egress:{days[-1]}": "2",
        f"{P}rule:canary_echoed_in_result:{days[3]}": "1",
        f"{P}runs:1999-01-01": "1000",
    })
    r = await _get(_app(), "/api/v1/public/sandbox-stats")
    assert r.status_code == 200
    body = r.json()
    assert body["totals"] == {
        "runs": 120, "exercised": 40, "tools_called": 333, "findings": 17, "canary_leaks": 2,
    }
    l30 = body["last_30_days"]
    assert l30["runs"] == 12 and l30["exercised"] == 3 and l30["runs_with_findings"] == 2
    assert l30["findings"] == 3
    assert l30["findings_by_rule"]["behavioral_undeclared_egress"] == 2
    assert l30["findings_by_rule"]["canary_echoed_in_result"] == 1
    assert set(l30["findings_by_rule"]) == set(md.BEHAVIORAL_RULES)
    assert 1 <= len(redis.mget_calls) <= 2  # panel counters + backfill block: bounded round trips

    # second call is served from the 5-minute cache: no new MGET
    redis.store[f"{P}total:runs"] = "999"
    body2 = (await _get(_app(), "/api/v1/public/sandbox-stats")).json()
    assert body2["totals"]["runs"] == 120
    assert 1 <= len(redis.mget_calls) <= 2  # panel counters + backfill block: bounded round trips


async def test_public_sandbox_stats_carries_no_names(redis):
    # a stray per-package key under the prefix must never surface
    redis.store[f"{P}pkg:npm:evil-package"] = "1"
    body = (await _get(_app(), "/api/v1/public/sandbox-stats")).json()
    assert "evil-package" not in str(body)
    assert set(body) == {"generated_at", "totals", "last_30_days"}


async def test_public_sandbox_stats_empty_and_redis_down(redis):
    body = (await _get(_app(), "/api/v1/public/sandbox-stats")).json()
    assert body["totals"]["runs"] == 0 and body["last_30_days"]["findings"] == 0
    redis.store.clear()
    redis.fail = True
    r = await _get(_app(), "/api/v1/public/sandbox-stats")
    assert r.status_code == 200 and r.json()["totals"]["runs"] == 0
