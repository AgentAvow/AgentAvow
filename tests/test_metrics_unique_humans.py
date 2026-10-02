"""Unique human visitors per day: a salted HyperLogLog, nothing identifying stored.

Pins the privacy properties, not just the count: the HLL member is a sha256 of
(daily random salt, IP, UA); the salt lives only in Redis under a 48h TTL; a new
day gets a new salt so the same person is not joinable across days; and the
middleware only feeds it for requests that are both usage and from a browser.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
from src import usage_scope as us

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
HLL = f"ag:metrics:unique_humans:{TODAY}"
SALT = f"ag:metrics:unique_humans:salt:{TODAY}"

BROWSER = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36"
)
BOT = "SentryUptimeBot/1.0 (+http://docs.sentry.io/product/alerts/uptime-monitoring/)"
AGENT = "claude-code/2.1.287 (cli)"


class _FakeRedis:
    """Just enough of redis-py: strings with NX/EX, HLLs as sets, counters."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.hll: dict[str, set[str]] = {}
        self.counters: dict[str, int] = {}
        self.fail = False

    def _check(self):
        if self.fail:
            raise ConnectionError("redis down")

    async def get(self, key):
        self._check()
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        if ex:
            self.ttl[key] = ex
        return True

    async def pfadd(self, key, *members):
        self._check()
        before = len(self.hll.setdefault(key, set()))
        self.hll[key].update(members)
        return int(len(self.hll[key]) != before)

    async def pfcount(self, *keys):
        self._check()
        return len(set().union(*(self.hll.get(k, set()) for k in keys)))

    async def expire(self, key, ttl):
        self._check()
        self.ttl[key] = ttl
        return True

    async def incr(self, key):
        self._check()
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def mget(self, keys):
        self._check()
        return [self.counters.get(k) for k in keys]


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    md._salt_cache.clear()
    yield fake
    md._salt_cache.clear()


# --- record + read ------------------------------------------------------------

@pytest.mark.asyncio
async def test_same_visitor_counts_once_and_different_visitors_add(redis):
    await md.record_human_visitor("203.0.113.7", BROWSER)
    await md.record_human_visitor("203.0.113.7", BROWSER)
    assert await md._read_unique_humans([TODAY]) == 1
    await md.record_human_visitor("203.0.113.8", BROWSER)
    await md.record_human_visitor("203.0.113.7", BROWSER + " Edg/154.0")
    assert await md._read_unique_humans([TODAY]) == 3


@pytest.mark.asyncio
async def test_member_is_a_salted_sha256_with_nothing_identifying(redis):
    await md.record_human_visitor("203.0.113.7", BROWSER)
    (member,) = redis.hll[HLL]
    assert len(member) == 64 and int(member, 16) >= 0  # hex sha256
    assert "203.0.113.7" not in member and "Mozilla" not in member
    # It is exactly sha256(salt|ip|ua): no unsalted hash of the IP is stored.
    salt = redis.kv[SALT]
    assert member == hashlib.sha256(f"{salt}|203.0.113.7|{BROWSER}".encode()).hexdigest()
    assert member != hashlib.sha256(f"203.0.113.7|{BROWSER}".encode()).hexdigest()


@pytest.mark.asyncio
async def test_salt_is_random_redis_only_and_expires_in_48h(redis):
    await md.record_human_visitor("203.0.113.7", BROWSER)
    salt = redis.kv[SALT]
    assert len(salt) == 32 and int(salt, 16) >= 0  # 16 random bytes, hex
    assert redis.ttl[SALT] == 48 * 3600
    # A fresh process (empty cache) reuses the Redis salt rather than minting one.
    md._salt_cache.clear()
    await md.record_human_visitor("203.0.113.9", BROWSER)
    assert redis.kv[SALT] == salt
    # Two processes racing: SET NX makes them agree.
    md._salt_cache.clear()
    del redis.kv[SALT]
    assert await md._daily_salt(redis, TODAY) != salt  # new day-salt once the old expires


@pytest.mark.asyncio
async def test_days_are_not_joinable(redis):
    s1 = await md._daily_salt(redis, "2026-10-02")
    md._salt_cache.clear()
    s2 = await md._daily_salt(redis, "2026-10-03")
    assert s1 != s2
    m1 = hashlib.sha256(f"{s1}|203.0.113.7|{BROWSER}".encode()).hexdigest()
    m2 = hashlib.sha256(f"{s2}|203.0.113.7|{BROWSER}".encode()).hexdigest()
    assert m1 != m2
    # So the window count is the sum of per-day distinct people.
    redis.hll["ag:metrics:unique_humans:2026-10-02"] = {m1}
    redis.hll["ag:metrics:unique_humans:2026-10-03"] = {m2}
    assert await md._read_unique_humans(["2026-10-02", "2026-10-03"]) == 2


@pytest.mark.asyncio
async def test_salt_is_never_logged(redis, caplog):
    caplog.set_level(logging.DEBUG)
    await md.record_human_visitor("203.0.113.7", BROWSER)
    assert redis.kv[SALT] not in caplog.text


@pytest.mark.asyncio
async def test_degrades_to_zero_without_redis(redis):
    redis.fail = True
    await md.record_human_visitor("203.0.113.7", BROWSER)  # no raise
    assert await md._read_unique_humans([TODAY]) == 0
    assert await md._read_unique_humans([]) == 0


# --- fed only by human, counted requests ----------------------------------------

def _app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def _scope(request, call_next):
        return await us.usage_scope_middleware(request, call_next)

    @app.get("/page")
    async def page():
        return {"ok": True}

    @app.get("/moved")
    async def moved():
        return RedirectResponse(url="/page", status_code=301)

    return app


async def _get(path: str, ua: str, host: str = "agentavow.com"):
    async with AsyncClient(
        transport=ASGITransport(app=_app()), base_url="http://t",
        headers={"host": host, "user-agent": ua},
    ) as c:
        return await c.get(path)


@pytest.mark.asyncio
async def test_middleware_records_browsers_only(redis):
    assert (await _get("/page", BROWSER)).status_code == 200
    assert (await _get("/page", BROWSER)).status_code == 200  # same client, once
    assert (await _get("/page", BOT)).status_code == 200
    assert (await _get("/page", AGENT)).status_code == 200
    assert (await _get("/page", "")).status_code == 200
    assert await md._read_unique_humans([TODAY]) == 1


@pytest.mark.asyncio
async def test_middleware_skips_redirects_and_legacy_hosts(redis):
    assert (await _get("/moved", BROWSER)).status_code == 301
    assert (await _get("/page", BROWSER, host="agentgraph.co")).status_code == 200
    assert HLL not in redis.hll
    assert await md._read_unique_humans([TODAY]) == 0
