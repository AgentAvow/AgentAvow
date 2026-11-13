"""Plugin install IDs on the server (src/install_activity): read only from the plugin
hooks, only as a canonical UUIDv4, stored only as a keyed hash in per-day sets with no
IP beside it, expired after 40 days, and read back as active / new / D1 / D7 counts in
GET /admin/metrics/traffic."""
from __future__ import annotations

import asyncio
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
import src.install_activity as ia
from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes

UA = "agentavow-precheck/0.1.40 (plugin)"


class _Pipe:
    def __init__(self, r) -> None:
        self.r, self.ops = r, []

    def sismember(self, key, member):
        self.ops.append((key, member))
        return self

    async def execute(self):
        return [int(m in self.r.sets.get(k, set())) for k, m in self.ops]


class _FakeRedis:
    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}
        self.expire_at: dict[str, int] = {}
        self.hashes: dict = {}

    async def sadd(self, key, *members):
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def expireat(self, key, when):
        self.expire_at[key] = int(when)
        return 1

    async def smembers(self, key):
        return set(self.sets.get(key, set()))

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    monkeypatch.setattr("src.config.settings.install_id_hash_key", "test-key")
    return fake


# --- validation ---------------------------------------------------------------------

def test_only_a_canonical_uuid4_is_accepted():
    good = str(uuid.uuid4())
    assert ia.parse_install_id(good) == good
    for bad in (good.upper(), "{" + good + "}", good + " ", " " + good, good.replace("-", ""),
                "123e4567-e89b-12d3-a456-426614174000",  # v1
                "00000000-0000-4000-c000-000000000000",  # wrong variant
                "", None, 42, good + "0", "urn:uuid:" + good, good + "\n"):
        assert ia.parse_install_id(bad) is None, bad


def test_header_is_read_only_from_the_plugin_hooks(redis):
    iid = str(uuid.uuid4())
    for ua in ("agentavow-precheck/0.1.40 (plugin)", "agentavow-preinstall/0.1.40 (manual)"):
        assert ia.install_hash_from_headers({"user-agent": ua, "x-agentavow-install": iid})
    for ua in ("Mozilla/5.0", "curl/8", "agentavow-gate/0.1.40", "", "x agentavow-precheck/1"):
        assert ia.install_hash_from_headers({"user-agent": ua, "x-agentavow-install": iid}) is None
    assert ia.install_hash_from_headers({"user-agent": UA}) is None
    assert ia.install_hash_from_headers({"user-agent": UA, "x-agentavow-install": "junk"}) is None


def test_stored_value_is_a_keyed_hash_not_the_id(redis, monkeypatch):
    iid = str(uuid.uuid4())
    h = ia.install_hash_from_headers({"user-agent": UA, "x-agentavow-install": iid})
    assert h == ia.hash_install_id(iid) and len(h) == 32
    assert iid not in h and iid.replace("-", "") not in h
    monkeypatch.setattr("src.config.settings.install_id_hash_key", "another-key")
    assert ia.hash_install_id(iid) != h  # depends on the server key


def test_hash_key_falls_back_to_one_derived_from_the_jwt_secret(monkeypatch):
    monkeypatch.setattr("src.config.settings.install_id_hash_key", "")
    monkeypatch.setattr("src.config.settings.jwt_secret", "s1")
    a = ia.hash_install_id(str(uuid.UUID(int=1, version=4)))
    monkeypatch.setattr("src.config.settings.jwt_secret", "s2")
    assert ia.hash_install_id(str(uuid.UUID(int=1, version=4))) != a


# --- storage ------------------------------------------------------------------------

async def test_records_only_the_hash_per_day_with_a_40_day_expiry(redis):
    day = date(2026, 11, 12)
    await ia.record_install_hash("a" * 32, today=day)
    await ia.record_install_hash("a" * 32, today=day)  # same day: once
    active = f"{ia.ACTIVE_PREFIX}2026-11-12"
    assert redis.sets == {active: {"a" * 32}, f"{ia.NEW_PREFIX}2026-11-12": {"a" * 32}}
    expected = int(datetime(2026, 12, 23, tzinfo=timezone.utc).timestamp())  # day end + 40d
    assert redis.expire_at[active] == expected
    assert redis.expire_at[f"{ia.NEW_PREFIX}2026-11-12"] == expected


async def test_a_returning_install_is_not_new(redis):
    d0 = date(2026, 11, 1)
    await ia.record_install_hash("h1", today=d0)
    await ia.record_install_hash("h1", today=d0 + timedelta(days=5))
    await ia.record_install_hash("h2", today=d0 + timedelta(days=5))
    assert redis.sets[f"{ia.NEW_PREFIX}2026-11-06"] == {"h2"}
    assert redis.sets[f"{ia.ACTIVE_PREFIX}2026-11-06"] == {"h1", "h2"}
    # past the 39-day lookback it reads as new again (the old day has expired anyway)
    await ia.record_install_hash("h1", today=d0 + timedelta(days=45))
    assert redis.sets[f"{ia.NEW_PREFIX}2026-12-16"] == {"h1"}


async def test_redis_failure_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("down")

    monkeypatch.setattr("src.redis_client.get_redis", boom)
    await ia.record_install_hash("x" * 32)  # no exception
    out = await ia.install_series(["2026-11-12"])
    assert out["installs_active"] == [None]


async def test_dependency_records_without_the_ip_and_never_blocks(redis):
    app = FastAPI()

    @app.get("/scan", dependencies=[Depends(ia.install_activity)])
    async def scan(request: Request):
        return {"ok": True}

    iid = str(uuid.uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r1 = await c.get("/scan", headers={"user-agent": UA, "x-agentavow-install": iid,
                                           "x-forwarded-for": "203.0.113.9"})
        r2 = await c.get("/scan", headers={"user-agent": UA, "x-agentavow-install": "bad"})
        r3 = await c.get("/scan", headers={"user-agent": "curl/8", "x-agentavow-install": iid})
    assert r1.status_code == r2.status_code == r3.status_code == 200
    await asyncio.gather(*list(ia._pending))
    today = datetime.now(timezone.utc).date().isoformat()
    assert redis.sets[f"{ia.ACTIVE_PREFIX}{today}"] == {ia.hash_install_id(iid)}
    stored = repr(redis.sets) + repr(redis.expire_at)
    assert iid not in stored and "203.0.113.9" not in stored and "127.0.0.1" not in stored
    assert all(k.startswith(("ag:metrics:install:active:", "ag:metrics:install:new:"))
               for k in redis.sets)


def test_the_hook_scan_routes_carry_the_dependency():
    from src.api.public_scan_router import router

    paths = {"/public/scan/mcp", "/public/scan/package/{surface}/{name:path}"}
    found = set()
    for route in router.routes:
        if getattr(route, "path", None) in paths:
            calls = [d.call for d in route.dependant.dependencies]
            assert calls[0] is ia.install_activity  # first: a 429 still counts
            found.add(route.path)
    assert found == paths


# --- read side ----------------------------------------------------------------------

def _d(base: date, n: int) -> date:
    return base + timedelta(days=n)


async def test_series_counts_active_new_and_d1_d7_retention(redis):
    base = date(2026, 11, 1)
    today = _d(base, 10)
    # day 0: a, b, c new.  day 1: a returns, d new.  day 3: b.  day 7: a, c, e new.
    plan = {0: "abc", 1: "ad", 3: "b", 7: "ace", 8: "d"}
    for n, members in plan.items():
        for m in members:
            await ia.record_install_hash(m, today=_d(base, n))
    days = [_d(base, n).isoformat() for n in range(0, 11)]
    s = await ia.install_series(days, today=today)
    assert s["installs_active"] == [3, 2, 0, 1, 0, 0, 0, 3, 1, 0, 0]
    assert s["installs_new"] == [3, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0]
    # D1 on day 1: cohort = new on day 0 (a,b,c), returned on day 1 = {a}
    assert s["installs_d1_cohort"][1] == 3 and s["installs_d1_returned"][1] == 1
    # D1 on day 8: cohort = new on day 7 (e), e not active on day 8
    assert s["installs_d1_cohort"][8] == 1 and s["installs_d1_returned"][8] == 0
    # D7 on day 7: cohort = new on day 0 (a,b,c); active on day 7: a, c
    assert s["installs_d7_cohort"][7] == 3 and s["installs_d7_returned"][7] == 2
    # D7 on day 8: cohort = new on day 1 (d); d active on day 8
    assert s["installs_d7_cohort"][8] == 1 and s["installs_d7_returned"][8] == 1
    # any day 1..7 after day 0: a (d1, d7), b (d3), c (d7) -> all three
    assert s["installs_d7_returned_week"][7] == 3
    # day 0's own D1/D7 look before the window: data exists only from day 0 onwards
    # (empty sets before it are still within retention, so they read 0, not None)
    assert s["installs_d7_cohort"][0] == 0
    # rolling 7 days ending day 7: a, b, c, d, e
    assert s["installs_active_7d"][7] == 5


async def test_days_outside_retention_are_empty_not_zero(redis):
    today = date(2026, 11, 12)
    days = [(today - timedelta(days=n)).isoformat() for n in (45, 41, 40, 0)]
    s = await ia.install_series(days, today=today)
    assert s["installs_active"] == [None, None, 0, 0]
    # day -40's D1/D7 inputs are past retention
    assert s["installs_d1_cohort"][2] is None and s["installs_d7_cohort"][2] is None
    assert s["installs_active_7d"][2] is None


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(md.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=True)
    app.dependency_overrides[rate_limit_reads] = lambda: None
    app.dependency_overrides[rate_limit_writes] = lambda: None
    return app


async def test_traffic_payload_gains_the_install_fields(redis):
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    await ia.record_install_hash("a", today=yesterday)
    await ia.record_install_hash("b", today=yesterday)
    await ia.record_install_hash("a", today=today)
    redis.hashes[f"ag:metrics:traffic:{today.isoformat()}"] = {b"cc_machines": b"5"}
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 2})
    body = res.json()
    assert res.status_code == 200
    assert body["installs"]["days"] == body["days"] == [yesterday.isoformat(), today.isoformat()]
    inst = body["installs"]["series"]
    assert inst["installs_active"] == [2, 1]
    assert inst["installs_new"] == [2, 0]
    assert inst["installs_d1_cohort"][1] == 2 and inst["installs_d1_returned"][1] == 1
    assert body["installs"]["latest"]["installs_active"] == 1
    assert body["series"]["installs_active"] == [2, 1]  # also in the shared series
    assert body["series"]["cc_machines"] == [None, 5]  # existing fields untouched
    assert any("install ID" in n for n in body["notes"])


async def test_traffic_payload_requires_admin(redis):
    app = _app()
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 2})
    assert res.status_code == 403


# --- kept out of error reports ------------------------------------------------------

def test_sentry_events_and_traces_drop_the_header():
    from src.sentry_filters import before_send, before_send_transaction

    iid = str(uuid.uuid4())
    ev = {"request": {"url": "https://agentavow.com/api/v1/public/scan/mcp",
                      "headers": {"User-Agent": UA, "X-AgentAvow-Install": iid}}}
    out = before_send(ev, None)
    assert out["request"]["headers"] == {"User-Agent": UA}
    tr = {"request": {"headers": [["x-agentavow-install", iid], ["user-agent", UA]]}}
    assert before_send_transaction(tr, None)["request"]["headers"] == [["user-agent", UA]]
