"""Admin metrics, PR 2: scan requests by kind, watch alerts by trigger, the daily
catalog mix / downloads job, and search referrals by host."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import src.api.metrics_dashboard_router as md
from src.api.analytics_router import referrer_host
from src.jobs import metrics_daily
from src.scan_kind import SCAN_KINDS, scan_kind
from tests.test_ad_spend import _auth, _token, client  # noqa: F401 (fixture)
from tests.test_metrics_unique_callers import _FakeRedis


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class _Redis(_FakeRedis):
    def __init__(self) -> None:
        super().__init__()
        self.hashes: dict[str, dict[str, str]] = {}

    async def delete(self, key):
        self.hashes.pop(key, None)

    async def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(mapping)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


@pytest.fixture
def redis(monkeypatch):
    fake = _Redis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    md._salt_cache.clear()
    yield fake
    md._salt_cache.clear()


# --- scan kinds ---------------------------------------------------------------------

P = "/api/v1/public/scan"


@pytest.mark.parametrize("path,query,kind", [
    (f"{P}/vercel/next.js", "", "repo"),
    (f"{P}/vercel/next.js/badge", "", "badge"),
    (f"{P}/vercel/next.js/card.svg", "", "card"),
    (f"{P}/vercel/next.js/og-image", "", "og"),
    (f"{P}/og.png", "", "og"),
    (f"{P}/vercel/next.js/verdict.json", "", "verdict_json"),
    (f"{P}/vercel/next.js/history", "", "read"),
    (f"{P}/vercel/next.js/checks", "", "read"),
    (f"{P}/package/npm/chalk", "", "package"),
    (f"{P}/package/npm/@scope/name", "", "package"),
    (f"{P}/package/npm/chalk/badge", "", "badge"),
    (f"{P}/mcp", "endpoint=https%3A%2F%2Fx", "mcp"),
    (f"{P}/mcp/badge", "", "badge"),
    (f"{P}/skill/a/b", "", "skill"),
    (f"{P}/skill/a/b/skills/x", "", "skill"),
    (f"{P}/a2a", "url=x", "a2a"),
    (f"{P}/erc8004/base/42", "", "erc8004"),
    (f"{P}/wallet/0xabc", "", "wallet"),
    (f"{P}/submit", "", "submit"),
    (f"{P}/beacon/install_click", "", "beacon"),
    (f"{P}/categories", "", "read"),
    ("/api/v1/public/scan-catalog", "surface=x402&limit=5", "x402"),
    ("/api/v1/public/scan-catalog", "surface=mcp", "catalog"),
    ("/api/v1/public/scan-catalog/flagged-stat", "", "catalog"),
    ("/api/v1/public/preflight/mcp", "endpoint=x", "preflight"),
    ("/api/v1/public/preflight/a/b", "", "preflight"),
    ("/api/v1/public/drift/mcp", "", "drift_feed"),
    ("/api/v1/public/registry-snippet/a/b", "", "registry_snippet"),
    ("/api/v1/public/sandbox-stats", "", None),
    ("/api/v1/badges/trust/x.svg", "", None),
    (None, None, None),
])
def test_scan_kind(path, query, kind):
    got = scan_kind(path, query)
    assert got == kind
    assert got is None or got in SCAN_KINDS


@pytest.mark.asyncio
async def test_usage_middleware_counts_a_kind_per_answered_request(redis):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from src import usage_scope as us

    app = FastAPI()

    @app.middleware("http")
    async def _scope(request, call_next):
        return await us.usage_scope_middleware(request, call_next)

    @app.get("/api/v1/public/scan/{owner}/{repo}/badge")
    async def badge(owner: str, repo: str):
        return {"ok": True}

    @app.get("/api/v1/public/preflight/mcp")
    async def preflight():
        return {"ok": True}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t",
                           headers={"host": "agentavow.com"}) as c:
        await c.get("/api/v1/public/scan/a/b/badge")
        await c.get("/api/v1/public/preflight/mcp?endpoint=x")
        await c.get("/api/v1/public/scan/a/b/nope/nope/nope")  # 404: not counted
    assert redis.counters[f"ag:metrics:scan_kind:badge:{_today()}"] == 1
    assert redis.counters[f"ag:metrics:scan_kind:preflight:{_today()}"] == 1
    assert not any("scan_kind:read" in k for k in redis.counters)


# --- watch alerts -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_count_watch_alert_bumps_each_trigger_and_never_raises(redis):
    from src.jobs.scheduler import count_watch_alert

    await count_watch_alert(["answer_worse", "certified_lost"], "public")
    await count_watch_alert(["good_news"], "private")
    assert redis.counters[f"ag:metrics:watch_alert:answer_worse:public:{_today()}"] == 1
    assert redis.counters[f"ag:metrics:watch_alert:good_news:private:{_today()}"] == 1
    redis.fail = True
    await count_watch_alert(["score_drop"], "public")


@pytest.mark.asyncio
async def test_aggregate_reports_kinds_and_alerts(db, redis):
    await md.bump_metric("scan_kind:repo")
    await md.bump_metric("scan_kind:badge")
    await md.bump_metric("scan_kind:x402")
    await md.bump_metric("watch_alert:definition_change:public")
    await md.bump_metric("watch_alert:definition_change:private")
    out = await md._aggregate(db, "7d")
    assert out["scan_kinds"]["checks"]["repo"] == 1
    assert out["scan_kinds"]["checks"]["x402"] == 1
    assert out["scan_kinds"]["renders"]["badge"] == 1
    assert out["watch_alerts"]["definition_change"] == {"public": 1, "private": 1}
    assert out["series"]["watch_alert:definition_change"][-1] == 2


# --- daily job ----------------------------------------------------------------------


def _row(surface, decision, score=80, certified=False):
    return SimpleNamespace(surface=surface, decision=decision, trust_score=score,
                           certified_mark=certified)


def test_catalog_mix_excludes_x402_and_counts_certified():
    rows = [
        _row("mcp", "safe", certified=True), _row("npm", "review"),
        _row("pypi", "do_not_connect"), _row("github", None, score=None),
        _row("x402", "safe", certified=True), _row("x402", "safe"),
    ]
    assert metrics_daily.catalog_mix(rows) == {
        "safe": 1, "review": 1, "do_not_connect": 1, "unscored": 1, "certified": 1,
        "total": 4,
    }


@pytest.mark.asyncio
async def test_run_metrics_daily_writes_today_and_read_back(redis, monkeypatch):
    async def mix(db):
        return {"safe": 3, "review": 2, "do_not_connect": 1, "unscored": 0,
                "certified": 1, "total": 6}

    async def dl():
        return {"npm_week": 120, "pypi_week": 80}

    monkeypatch.setattr(metrics_daily, "current_catalog_mix", mix)
    monkeypatch.setattr(metrics_daily, "fetch_registry_downloads", dl)
    await metrics_daily.run_metrics_daily(None)
    cat = await metrics_daily.read_daily(metrics_daily.CATALOG_PREFIX, ["2000-01-01", _today()])
    assert cat == {_today(): {"safe": 3, "review": 2, "do_not_connect": 1, "unscored": 0,
                              "certified": 1, "total": 6}}
    got = await metrics_daily.read_daily(metrics_daily.DOWNLOADS_PREFIX, [_today()])
    assert got[_today()] == {"npm_week": 120, "pypi_week": 80}


@pytest.mark.asyncio
async def test_run_metrics_daily_never_raises(redis, monkeypatch):
    async def boom(db):
        raise RuntimeError("catalog down")

    async def none():
        return {}

    monkeypatch.setattr(metrics_daily, "current_catalog_mix", boom)
    monkeypatch.setattr(metrics_daily, "fetch_registry_downloads", none)
    assert await metrics_daily.run_metrics_daily(None) == {"downloads": {}}


@pytest.mark.asyncio
async def test_fetch_registry_downloads_reads_both_and_skips_failures(monkeypatch):
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.npmjs.org":
            return httpx.Response(200, json={"downloads": 321, "package": "agentavow-trust"})
        return httpx.Response(503)

    real = httpx.AsyncClient

    def mock_client(**kw):
        return real(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", mock_client)
    assert await metrics_daily.fetch_registry_downloads() == {"npm_week": 321}


# --- referrals ----------------------------------------------------------------------


@pytest.mark.parametrize("raw,host", [
    ("https://www.google.com/search?q=secret+term", "www.google.com"),
    ("www.bing.com", "www.bing.com"),
    ("https://Example.org:8443/a?b", "example.org"),
    ("https://agentavow.com/check", None),
    ("", None), (None, None), ("not a url with spaces", None),
    ("javascript:alert(1)", None),
])
def test_referrer_host_keeps_only_the_host(raw, host):
    assert referrer_host(raw) == host


@pytest.mark.parametrize("host,group", [
    ("www.google.com", ("search", "google")),
    ("www.google.co.uk", ("search", "google")),
    ("www.bing.com", ("search", "bing")),
    ("duckduckgo.com", ("search", "duckduckgo")),
    ("chatgpt.com", ("ai", "chatgpt")),
    ("gemini.google.com", ("ai", "gemini")),
    ("www.reddit.com", ("other", "www.reddit.com")),
    ("notgoogle.com", ("other", "notgoogle.com")),
])
def test_referrer_group(host, group):
    assert md.referrer_group(host) == group


# --- growth endpoint ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_growth_is_admin_only(client, db):  # noqa: F811
    assert (await client.get("/api/v1/admin/metrics/growth")).status_code in (401, 403)
    token = await _token(client, db, admin=False)
    assert (await client.get("/api/v1/admin/metrics/growth",
                             headers=_auth(token))).status_code == 403


@pytest.mark.asyncio
async def test_growth_groups_landing_referrals(client, db, monkeypatch):  # noqa: F811
    import uuid

    async def mix(db):
        return {"safe": 1, "review": 0, "do_not_connect": 0, "unscored": 0,
                "certified": 1, "total": 1}

    monkeypatch.setattr(metrics_daily, "current_catalog_mix", mix)
    token = await _token(client, db, admin=True)
    for ref in ("https://www.google.com/search?q=x", "https://www.google.de/",
                "https://chatgpt.com/", "https://www.reddit.com/r/mcp", None):
        await client.post("/api/v1/analytics/event", json={
            "event_type": "lp_view", "session_id": str(uuid.uuid4()), "page": "/",
            **({"referrer": ref} if ref else {})})
    out = (await client.get("/api/v1/admin/metrics/growth", params={"days": 7},
                            headers=_auth(token))).json()
    ref = out["referrals"]
    assert ref["search"] == {"google": 2} and ref["search_total"] == 2
    assert ref["ai"] == {"chatgpt": 1}
    assert ref["other_top"] == {"www.reddit.com": 1}
    assert out["catalog_now"]["certified"] == 1
