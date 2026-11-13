"""The plugin's once-a-day active request on the server: POST /api/v1/public/plugin/active
records only a keyed hash of the install ID per UTC day, overall and per app type, never
the raw ID or an IP, leaves owner machines out, always answers 204, is rate-limited, is
never counted as a scan, and reads back in GET /admin/metrics/traffic as the
active-installs figure without touching any existing number."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
import src.install_activity as ia
from src.api.deps import get_current_entity
from src.api.plugin_active_router import router as active_router
from src.api.rate_limit import rate_limit_analytics, rate_limit_reads, rate_limit_writes

UA = "agentavow-active/0.1.41"


class _FakeRedis:
    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}
        self.expire_at: dict[str, int] = {}
        self.hashes: dict[str, dict] = {}
        self.strings: dict[str, str] = {}

    async def sadd(self, key, *members):
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    async def smembers(self, key):
        return set(self.sets.get(key, set()))

    async def expireat(self, key, when):
        self.expire_at[key] = int(when)
        return 1

    async def hincrby(self, key, field, n):
        h = self.hashes.setdefault(key, {})
        h[field] = int(h.get(field, 0)) + n
        return h[field]

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def setnx(self, key, value):
        if key in self.strings:
            return 0
        self.strings[key] = value
        return 1

    async def get(self, key):
        return self.strings.get(key)


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    monkeypatch.setattr("src.config.settings.install_id_hash_key", "test-key")
    monkeypatch.setattr("src.config.settings.metrics_owner_ips", "198.51.100.7")
    return fake


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(active_router, prefix="/api/v1")
    app.include_router(md.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=True)
    app.dependency_overrides[rate_limit_analytics] = lambda: None
    app.dependency_overrides[rate_limit_reads] = lambda: None
    app.dependency_overrides[rate_limit_writes] = lambda: None
    return app


async def _post(headers: dict, body: object = None, app: FastAPI | None = None):
    import json

    data = body if isinstance(body, (bytes, str)) else json.dumps(body or {})
    async with AsyncClient(transport=ASGITransport(app=app or _app()), base_url="http://t") as c:
        return await c.post("/api/v1/public/plugin/active", content=data,
                            headers={"content-type": "application/json", **headers})


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


# --- recording ----------------------------------------------------------------------

async def test_records_only_the_hash_overall_and_per_app(redis):
    iid = str(uuid.uuid4())
    r = await _post({"user-agent": UA, "x-agentavow-install": iid},
                    {"version": "0.1.41", "app": "desktop"})
    assert r.status_code == 204 and r.content == b""
    day = _today()
    h = ia.hash_install_id(iid)
    assert redis.sets == {f"{ia.PING_PREFIX}{day}": {h}, f"{ia.PING_PREFIX}{day}:desktop": {h}}
    assert redis.hashes == {f"{ia.PING_VERSIONS_PREFIX}{day}": {"0.1.41": 1}}
    assert redis.strings == {ia.PING_FIRST_DAY_KEY: day}
    stored = repr(redis.sets) + repr(redis.hashes) + repr(redis.strings)
    assert iid not in stored and "127.0.0.1" not in stored
    end = datetime.fromisoformat(day).replace(tzinfo=timezone.utc) + timedelta(days=41)
    assert set(redis.expire_at.values()) == {int(end.timestamp())}


async def test_same_install_twice_a_day_counts_once(redis):
    iid = str(uuid.uuid4())
    for _ in range(3):
        await _post({"user-agent": UA, "x-agentavow-install": iid},
                    {"version": "0.1.41", "app": "cli"})
    day = _today()
    assert len(redis.sets[f"{ia.PING_PREFIX}{day}"]) == 1
    assert redis.hashes[f"{ia.PING_VERSIONS_PREFIX}{day}"] == {"0.1.41": 1}


_VALID = str(uuid.uuid4())


@pytest.mark.parametrize("headers", [
    {"user-agent": "agentavow-precheck/0.1.41 (plugin)", "x-agentavow-install": _VALID},
    {"user-agent": "curl/8", "x-agentavow-install": _VALID},
    {"user-agent": "Mozilla/5.0", "x-agentavow-install": _VALID},
    {"user-agent": UA, "x-agentavow-install": "junk"},
    {"user-agent": UA, "x-agentavow-install": _VALID.upper()},
    {"user-agent": UA},
])
async def test_ignored_unless_the_plugin_sends_a_valid_id(redis, headers):
    r = await _post(headers, {"version": "0.1.41", "app": "cli"})
    assert r.status_code == 204
    assert redis.sets == {} and redis.strings == {}


async def test_owner_machines_are_left_out(redis, monkeypatch):
    client_ip = "127.0.0.1"  # what the in-process test client connects from
    monkeypatch.setattr("src.config.settings.metrics_owner_ips", f"198.51.100.7, {client_ip}")
    r = await _post({"user-agent": UA, "x-agentavow-install": str(uuid.uuid4())},
                    {"version": "0.1.41", "app": "cli"})
    assert r.status_code == 204
    assert redis.sets == {} and redis.strings == {}
    assert not ia._is_owner_ip("203.0.113.1") and not ia._is_owner_ip(None)


@pytest.mark.parametrize("body,app,version", [
    ({"version": "0.1.41", "app": "cloud"}, "cloud", "0.1.41"),
    ({"version": "0.1.41", "app": "../../etc"}, "other", "0.1.41"),
    ({"version": "1.0; drop", "app": "sdk"}, "sdk", None),
    ({}, "other", None),
    (b"not json", "other", None),
    (b"[1,2]", "other", None),
    (b"{\"app\": \"desktop\", \"pad\": \"" + b"x" * 600 + b"\"}", "other", None),  # too big
])
async def test_body_is_validated(redis, body, app, version):
    iid = str(uuid.uuid4())
    r = await _post({"user-agent": UA, "x-agentavow-install": iid}, body)
    assert r.status_code == 204
    day = _today()
    assert redis.sets[f"{ia.PING_PREFIX}{day}:{app}"] == {ia.hash_install_id(iid)}
    versions = redis.hashes.get(f"{ia.PING_VERSIONS_PREFIX}{day}", {})
    assert versions == ({version: 1} if version else {})


async def test_redis_failure_still_answers_204(monkeypatch):
    def boom():
        raise RuntimeError("down")

    monkeypatch.setattr("src.redis_client.get_redis", boom)
    r = await _post({"user-agent": UA, "x-agentavow-install": str(uuid.uuid4())},
                    {"version": "0.1.41", "app": "cli"})
    assert r.status_code == 204


def test_route_is_rate_limited_and_outside_the_scan_prefix():
    route = next(r for r in active_router.routes if getattr(r, "path", "") ==
                 "/public/plugin/active")
    assert rate_limit_analytics in [d.call for d in route.dependant.dependencies]
    assert "POST" in route.methods
    assert not md.is_hook_request("/api/v1/public/plugin/active", UA)
    from src.scan_kind import scan_kind

    assert scan_kind("/api/v1/public/plugin/active", "") is None


def test_registered_on_the_app():
    import fastapi.routing

    from src.main import app

    iter_ctx = getattr(fastapi.routing, "iter_route_contexts", None)
    if iter_ctx is None:  # older FastAPI lists the routes directly
        found = {(getattr(r, "path", ""), m) for r in app.routes
                 for m in getattr(r, "methods", None) or ()}
    else:
        found = {(c.path, m) for c in iter_ctx(app.routes) for m in (c.methods or ())}
    assert ("/api/v1/public/plugin/active", "POST") in found


# --- read side ----------------------------------------------------------------------

async def test_series_by_day_with_7_day_union_and_app_split(redis):
    base = date(2026, 11, 14)
    plan = {0: [("a", "desktop"), ("b", "cli")], 1: [("a", "desktop"), ("c", "cloud")],
            3: [("d", "sdk")], 8: [("a", "desktop")]}
    for n, members in plan.items():
        for h, app in members:
            await ia.record_active_ping(h, app, "0.1.41", today=base + timedelta(days=n))
    days = [(base + timedelta(days=n)).isoformat() for n in range(-2, 10)]
    out = await ia.active_ping_series(days, today=base + timedelta(days=9))
    assert out["counting_from"] == "2026-11-14"
    assert out["seven_day_complete_from"] == "2026-11-20"
    s = out["series"]
    assert s["active_installs"] == [None, None, 2, 2, 0, 1, 0, 0, 0, 0, 1, 0]
    assert s["active_installs_7d"][2:] == [2, 3, 3, 4, 4, 4, 4, 3, 2, 2]
    assert s["active_installs_desktop"][2:4] == [1, 1]
    assert s["active_installs_cloud"][3] == 1 and s["active_installs_sdk"][5] == 1
    assert s["active_installs_other"][2] == 0


async def test_series_before_any_signal_is_empty_not_zero(redis):
    out = await ia.active_ping_series(["2026-11-12", "2026-11-13"])
    assert out["counting_from"] is None
    assert all(v == [None, None] for v in out["series"].values())


async def test_traffic_payload_gains_active_installs_and_keeps_the_rest(redis):
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    await ia.record_active_ping("a", "desktop", "0.1.41", today=yesterday)
    await ia.record_active_ping("b", "cli", "0.1.41", today=yesterday)
    await ia.record_active_ping("a", "desktop", "0.1.41", today=today)
    await ia.record_install_hash("a", today=today)
    redis.hashes[f"ag:metrics:traffic:{today.isoformat()}"] = {b"checked_machines_7d": b"5"}
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 2})
    body = res.json()
    assert res.status_code == 200
    act = body["active_installs"]
    assert act["days"] == [yesterday.isoformat(), today.isoformat()]
    assert act["counting_from"] == yesterday.isoformat()
    assert act["series"]["active_installs"] == [2, 1]
    assert act["series"]["active_installs_7d"] == [2, 2]
    assert act["series"]["active_installs_desktop"] == [1, 1]
    assert act["latest"]["active_installs"] == 1
    assert body["series"]["active_installs"] == [2, 1]
    # existing numbers untouched
    assert body["series"]["checked_machines_7d"] == [None, 5]
    assert body["installs"]["series"]["installs_active"] == [0, 1]
    assert any("active_installs" in n for n in body["notes"])
    assert any("install ID" in n for n in body["notes"])


async def test_traffic_payload_requires_admin(redis):
    app = _app()
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/admin/metrics/traffic", params={"days": 2})
    assert res.status_code == 403
