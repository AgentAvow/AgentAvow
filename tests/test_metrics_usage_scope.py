"""src.usage_scope: a redirect is not usage, and neither is a legacy-host request.

Exercises the real middleware on a tiny FastAPI app with a fake Redis, so the
whole path is covered: scope opened → handler bumps → settle → flush or drop →
``requests_redirected`` tallied once.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
from src import usage_scope as us


def _today() -> str:
    """Computed at call time, not import time: a run that straddles 00:00 UTC must
    not compare keys from one day against writes on the next."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _key(name: str) -> str:
    return f"ag:metrics:{name}:{_today()}"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.fail = False

    async def incr(self, key):
        if self.fail:
            raise ConnectionError("redis down")
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key, ttl):
        return True

    async def mget(self, keys):
        return [self.store.get(k) for k in keys]


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


def _app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def _scope(request, call_next):
        return await us.usage_scope_middleware(request, call_next)

    @app.get("/scan")
    async def scan():
        await md.bump_metric("scan_request")
        await md.bump_metric_by_client("badge_fetch", "github-camo (1ff761db)")
        return {"ok": True}

    @app.get("/moved")
    async def moved():
        await md.bump_metric("scan_request")  # bumped BEFORE the redirect is known
        return RedirectResponse(url="/scan", status_code=301)

    @app.get("/found")
    async def found():
        return RedirectResponse(url="/scan", status_code=302)

    @app.get("/temp")
    async def temp():
        await md.bump_metric("scan_request")
        return RedirectResponse(url="/scan", status_code=307)

    @app.get("/api/v1/badges/trust/{entity_id}.svg")
    async def badge_svg(entity_id: str):
        await md.bump_metric_by_client("badge_fetch", "github-camo (1ff761db)")
        return {"svg": entity_id}

    @app.get("/api/v1/badges/embed/{entity_id}")
    async def badge_embed(entity_id: str):
        await md.bump_metric("badge_fetch")
        return {"svg": entity_id}

    @app.get("/api/v1/badge-lookalike")
    async def badge_lookalike():
        await md.bump_metric("badge_fetch")
        return {"ok": True}

    @app.get("/api/v1/public/scan/package/npm/{name}")
    async def public_scan(name: str):
        return {"cached": True}  # the handler counts nothing; the middleware does

    @app.get("/api/v1/public/scan/missing")
    async def public_scan_missing():
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "no such target"}, status_code=404)

    @app.get("/late")
    async def late():
        # A bump after the scope settled must still count (background work).
        scope = us.current_scope()
        us.settle(scope, 200)
        await md.bump_metric("api_call")
        return {"ok": True}

    return app


async def _get(path: str, host: str = "agentavow.com", ua: str | None = None):
    headers = {"host": host}
    if ua is not None:
        headers["user-agent"] = ua
    async with AsyncClient(
        transport=ASGITransport(app=_app()), base_url="http://t", headers=headers
    ) as c:
        return await c.get(path)


BROWSER = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")


# --- every answered public scan request is counted once, by the middleware ------

@pytest.mark.asyncio
async def test_public_scan_request_is_counted_by_the_middleware_cached_or_not(redis):
    assert (await _get("/api/v1/public/scan/package/npm/chalk", ua=BROWSER)).status_code == 200
    assert (await _get("/api/v1/public/scan/package/npm/chalk", ua="claude-code/2.1 (cli)")).status_code == 200
    assert (await _get("/api/v1/public/scan/package/npm/chalk", ua="curl/8.4")).status_code == 200
    assert redis.store[_key("scan_request")] == 3
    assert redis.store[_key("scan_request:client:human")] == 1
    assert redis.store[_key("scan_request:client:agent")] == 1
    assert redis.store[_key("scan_request:client:automated")] == 1


@pytest.mark.asyncio
async def test_public_scan_404_legacy_host_and_other_paths_are_not_scan_requests(redis):
    assert (await _get("/api/v1/public/scan/missing", ua=BROWSER)).status_code == 404
    assert (await _get("/api/v1/public/scan/package/npm/chalk", host="agentgraph.co", ua=BROWSER)).status_code == 200
    assert (await _get("/late", ua=BROWSER)).status_code == 200
    assert not any(k.startswith("ag:metrics:scan_request") for k in redis.store)


# --- pure helpers -----------------------------------------------------------

@pytest.mark.parametrize("host", [
    "agentgraph.co", "www.agentgraph.co", "agentgraph.me", "www.agentgraph.me",
    "agentgraph.io", "www.agentgraph.io", "www.agentavow.com",
    "AgentGraph.co", "agentgraph.co:443", " agentgraph.co ", "agentgraph.co.",
])
def test_legacy_hosts(host):
    assert us.is_legacy_host(host)


@pytest.mark.parametrize("host", [
    "agentavow.com", "agentavow.com:443", "localhost:8000", "10.0.0.4:8001",
    "[::1]:8000", "", None, "notagentgraph.co", "agentgraph.com",
])
def test_live_hosts_are_not_legacy(host):
    assert not us.is_legacy_host(host)


def test_admit_outside_a_request_always_counts():
    assert us.current_scope() is None
    assert us.admit("scan_request") is True
    assert us.admit(us.REDIRECTED_METRIC) is True


def test_settle_flushes_usage_and_drops_redirects():
    scope = us.UsageScope()
    token = us._SCOPE.set(scope)
    try:
        assert us.admit("a") is False and us.admit("b") is False  # queued
        assert scope.pending == ["a", "b"]
        assert us.settle(scope, 200) == ["a", "b"]
        assert scope.pending == [] and not scope.excluded
        assert us.admit("c") is True  # settled as usage: write through
    finally:
        us._SCOPE.reset(token)

    scope = us.UsageScope()
    token = us._SCOPE.set(scope)
    try:
        us.admit("a")
        assert us.settle(scope, 301) == []
        assert scope.excluded and us.usage_excluded()
        assert us.admit("c") is False  # late bump on a redirect: dropped
        assert us.admit(us.REDIRECTED_METRIC) is True
    finally:
        us._SCOPE.reset(token)


# --- the middleware end to end ---------------------------------------------

@pytest.mark.asyncio
async def test_normal_request_counts_as_usage(redis):
    r = await _get("/scan")
    assert r.status_code == 200
    assert redis.store[_key("scan_request")] == 1
    assert redis.store[_key("badge_fetch")] == 1
    assert redis.store[_key("badge_fetch:client:agent")] == 1
    assert _key(us.REDIRECTED_METRIC) not in redis.store


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/moved", "/found"])
async def test_redirect_reaches_no_usage_counter(redis, path):
    r = await _get(path)
    assert r.status_code in (301, 302)
    assert _key("scan_request") not in redis.store
    assert redis.store[_key(us.REDIRECTED_METRIC)] == 1


@pytest.mark.asyncio
async def test_307_is_not_in_the_excluded_set(redis):
    # Only 301/302/308 are "not usage" by rule; a 307 counts like any response.
    r = await _get("/temp")
    assert r.status_code == 307
    assert redis.store[_key("scan_request")] == 1
    assert _key(us.REDIRECTED_METRIC) not in redis.store


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["agentgraph.co", "www.agentavow.com", "agentgraph.me:443"])
async def test_legacy_host_reaches_no_usage_counter_even_on_200(redis, host):
    r = await _get("/scan", host=host)
    assert r.status_code == 200  # the response is untouched
    assert not any(k.startswith("ag:metrics:scan_request") for k in redis.store)
    assert not any(k.startswith("ag:metrics:badge_fetch") for k in redis.store)
    assert redis.store[_key(us.REDIRECTED_METRIC)] == 1


@pytest.mark.parametrize("path", [
    "/api/v1/badges/trust/abc.svg", "/api/v1/badges/embed/abc", "/api/v1/badges/readme/abc",
])
def test_badge_paths(path):
    assert us.is_badge_path(path)


@pytest.mark.parametrize("path", ["/api/v1/badge-lookalike", "/api/v1/public/scan/x", "/", None])
def test_other_paths_are_not_badge_paths(path):
    assert not us.is_badge_path(path)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/badges/trust/abc.svg", "/api/v1/badges/embed/abc"])
async def test_badge_render_on_legacy_host_still_counts(redis, path):
    # A README badge embedded before the rebrand points at agentgraph.co; nginx
    # keeps proxying it, and a github-camo fetch there is real adoption.
    r = await _get(path, host="agentgraph.co")
    assert r.status_code == 200
    assert redis.store[_key("badge_fetch")] == 1
    assert _key(us.REDIRECTED_METRIC) not in redis.store


@pytest.mark.asyncio
async def test_badge_exemption_is_only_the_badge_paths(redis):
    # Anything else on a legacy host stays excluded, including a near-miss path.
    assert (await _get("/api/v1/badge-lookalike", host="agentgraph.co")).status_code == 200
    assert _key("badge_fetch") not in redis.store
    assert redis.store[_key(us.REDIRECTED_METRIC)] == 1
    assert (await _get("/scan", host="agentgraph.co")).status_code == 200
    assert _key("scan_request") not in redis.store
    assert redis.store[_key(us.REDIRECTED_METRIC)] == 2


@pytest.mark.asyncio
async def test_redirected_is_tallied_once_per_request(redis):
    await _get("/moved")
    await _get("/scan", host="agentgraph.co")
    await _get("/moved", host="agentgraph.co")  # both reasons: still one tick
    assert redis.store[_key(us.REDIRECTED_METRIC)] == 3


@pytest.mark.asyncio
async def test_bump_after_settle_still_counts(redis):
    r = await _get("/late")
    assert r.status_code == 200
    assert redis.store[_key("api_call")] == 1


@pytest.mark.asyncio
async def test_redis_outage_never_breaks_the_response(redis):
    redis.fail = True
    assert (await _get("/scan")).status_code == 200
    assert (await _get("/moved")).status_code == 301
    assert (await _get("/scan", host="agentgraph.co")).status_code == 200


@pytest.mark.asyncio
async def test_scope_does_not_leak_between_requests(redis):
    await _get("/scan", host="agentgraph.co")
    assert us.current_scope() is None
    await _get("/scan")
    assert redis.store[_key("scan_request")] == 1


# --- the dashboard reads it back --------------------------------------------

@pytest.mark.asyncio
async def test_metrics_reads_requests_redirected(redis):
    redis.store[_key(us.REDIRECTED_METRIC)] = 42
    by_day = await md._read_daily_counter(us.REDIRECTED_METRIC, [_today()])
    assert by_day == {_today(): 42}


@pytest.mark.asyncio
async def test_real_app_registers_the_middleware():
    from src.main import app

    names = [getattr(m.kwargs.get("dispatch"), "__name__", "") for m in app.user_middleware]
    assert "usage_scope_http_middleware" in names
