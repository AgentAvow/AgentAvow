"""Per-process caches behind /public/scan-catalog and /flagged-stat.

`_community_rows` is cached for COMMUNITY_ROWS_TTL_SECONDS (one DB read shared by
concurrent cold callers, errors never cached); the /flagged-stat response is cached for
the same catalog and refreshed in the background (stale-while-revalidate) when it is past
FLAGGED_STAT_TTL_SECONDS or the community rows changed; the list's default views are
cached per (catalog, community fill, query). The DB read (`_fetch_community_rows`) is
stubbed, so nothing here touches a database.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx
import pytest
from fastapi import FastAPI

import src.api.scan_catalog_router as m
from src.api.scan_catalog_router import CatalogRow
from tests.test_scan_catalog_flagged_stat import _fixture_rows


def _community(n: int = 3) -> list[CatalogRow]:
    return [
        CatalogRow(surface="npm", name=f"langchain-thing-{i}", full_name=f"npm:x{i}",
                   trust_score=70 + i, critical=0, high=i % 2)
        for i in range(n)
    ]


@pytest.fixture(autouse=True)
def _clean_caches(monkeypatch):
    m.invalidate_community_rows_cache()
    monkeypatch.setattr(m, "_FLAGGED_STAT_TASK", None)
    monkeypatch.setattr(m, "_FLAGGED_STAT_TIMER", None)
    yield
    m.invalidate_community_rows_cache()


@pytest.fixture
async def bg():
    """Stops the refresh timer / in-flight refresh at teardown, on the test's loop."""
    yield
    await m.stop_flagged_stat_refresher()
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("flagged-stat")]


@pytest.fixture
def clock(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(m, "_now", lambda: t["now"])
    return t


@pytest.fixture
def fetch(monkeypatch):
    """Stub the DB read; counts calls; `result` is what the next read returns."""
    state = {"calls": 0, "result": _community(), "delay": 0.0}

    async def _fetch(db):
        state["calls"] += 1
        if state["delay"]:
            await asyncio.sleep(state["delay"])
        res = state["result"]
        return None if res is None else [r.model_copy() for r in res]

    monkeypatch.setattr(m, "_fetch_community_rows", _fetch)
    return state


async def test_rows_read_once_within_ttl(fetch, clock):
    a = await m._community_rows(None)
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS - 1
    b = await m._community_rows(None)
    assert fetch["calls"] == 1
    assert [r.name for r in a] == [r.name for r in b]


async def test_concurrent_cold_calls_do_one_read(fetch, clock):
    fetch["delay"] = 0.05
    results = await asyncio.gather(*(m._community_rows(None) for _ in range(10)))
    assert fetch["calls"] == 1
    assert all(len(r) == 3 for r in results)


async def test_cache_expires_after_ttl(fetch, clock):
    await m._community_rows(None)
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS + 0.01
    await m._community_rows(None)
    assert fetch["calls"] == 2


async def test_invalidation_clears_both_caches(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    await m.flagged_stat(db=None)
    assert m._COMMUNITY_CACHE is not None and m._FLAGGED_STAT_CACHE is not None
    m.invalidate_community_rows_cache()
    assert m._COMMUNITY_CACHE is None and m._FLAGGED_STAT_CACHE is None
    await m._community_rows(None)
    assert fetch["calls"] == 2


async def test_capture_community_scan_invalidates(fetch, clock):
    from src.api import public_scan_router as p

    await m._community_rows(None)
    assert m._COMMUNITY_CACHE is not None

    class _DB:
        async def execute(self, stmt):
            return None

        async def commit(self):
            return None

    await p._capture_community_scan(
        "acme", "tool", {"trust_score": None, "findings": {}}, _DB(),
    )
    assert m._COMMUNITY_CACHE is None


async def test_error_path_is_not_cached(fetch, clock):
    fetch["result"] = None  # DB error
    assert await m._community_rows(None) == []
    assert m._COMMUNITY_CACHE is None
    fetch["result"] = _community()
    assert len(await m._community_rows(None)) == 3
    assert fetch["calls"] == 2


async def test_real_fetch_db_error_returns_empty_and_does_not_cache(clock):
    class _Boom:
        async def execute(self, stmt):
            raise RuntimeError("db down")

    assert await m._community_rows(_Boom()) == []
    assert m._COMMUNITY_CACHE is None


async def test_callers_cannot_corrupt_the_cache(fetch, clock):
    first = await m._community_rows(None)
    # categories are filled at cache-fill time, so the handler never mutates rows
    assert all(r.category is not None for r in first)
    first.append(CatalogRow(surface="npm", name="intruder"))
    first.clear()
    _ = first + [CatalogRow(surface="npm", name="intruder-2")]
    again = await m._community_rows(None)
    assert len(again) == 3
    assert "intruder" not in {r.name for r in again}
    assert fetch["calls"] == 1


async def test_list_handler_leaves_cached_rows_untouched(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    assert m._COMMUNITY_CACHE is None
    r1 = await m.scan_catalog(
        surface=None, q=None, severity=None, grade=None, category=None,
        sort="default", limit=200, offset=0, db=None,
    )
    snap = [r.model_dump() for r in m._COMMUNITY_CACHE[0]]
    r2 = await m.scan_catalog(
        surface="community", q=None, severity=None, grade=None, category=None,
        sort="name", limit=200, offset=0, db=None,
    )
    assert [r.model_dump() for r in m._COMMUNITY_CACHE[0]] == snap
    assert r1.summary.by_surface["community"] == 3 == r2.total
    assert fetch["calls"] == 1


async def test_flagged_stat_identical_before_and_after_caching(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    community = await m._community_rows(None)
    uncached = m._compute_flagged_stat(m._CATALOG_CACHE, community)
    first = await m.flagged_stat(db=None)
    second = await m.flagged_stat(db=None)
    assert first == second == uncached
    # a caller mutating the returned dict does not affect the cached response
    second["by_surface"].clear()
    second["pct"] = -1
    assert await m.flagged_stat(db=None) == uncached


async def test_flagged_stat_cache_hit_skips_recount(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    calls = {"n": 0}
    real = m._compute_flagged_stat

    def _count(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(m, "_compute_flagged_stat", _count)
    await m.flagged_stat(db=None)
    await m.flagged_stat(db=None)
    assert calls["n"] == 1
    # community TTL refill with equal rows keeps the stat cached, no refresh started ...
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS + 1
    await m.flagged_stat(db=None)
    assert calls["n"] == 1 and fetch["calls"] == 2
    assert m._FLAGGED_STAT_TASK is None
    # ... changed rows: the old value is served, one background refresh recomputes
    fetch["result"] = _community(4)
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS + 1
    old = await m.flagged_stat(db=None)
    assert calls["n"] == 1
    await m._FLAGGED_STAT_TASK[1]
    assert calls["n"] == 2
    stat = await m.flagged_stat(db=None)
    assert stat["by_surface"]["npm"]["total"] == old["by_surface"]["npm"]["total"] + 1
    # past the stat TTL it refreshes in the background even with identical inputs
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    await m.flagged_stat(db=None)
    await m._FLAGGED_STAT_TASK[1]
    assert calls["n"] == 3


async def test_flagged_stat_recomputes_after_catalog_reset(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    before = await m.flagged_stat(db=None)
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog([]))
    after = await m.flagged_stat(db=None)
    assert before["scanned_total"] > after["scanned_total"]


async def test_refresh_endpoint_drops_flagged_stat_cache(fetch, clock, monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    await m.flagged_stat(db=None)
    assert m._FLAGGED_STAT_CACHE is not None
    monkeypatch.setattr(m, "require_admin", lambda e: None)
    real_build = m._build_catalog
    monkeypatch.setattr(m, "_build_catalog", lambda rows=None: real_build([]))
    await m.refresh_catalog(current_entity=None)
    assert m._FLAGGED_STAT_CACHE is None


async def test_cache_control_header_on_list_and_flagged_stat(fetch, clock, monkeypatch):
    from src.api.rate_limit import rate_limit_reads
    from src.database import get_db

    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    app = FastAPI()
    app.include_router(m.router, prefix="/api/v1")

    async def _no_db():
        yield None

    async def _no_limit():
        return None

    app.dependency_overrides[get_db] = _no_db
    app.dependency_overrides[rate_limit_reads] = _no_limit
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t",
    ) as c:
        stat = await c.get("/api/v1/public/scan-catalog/flagged-stat")
        lst = await c.get("/api/v1/public/scan-catalog?limit=5")
        pct = await c.get("/api/v1/public/scan-catalog/percentile?score=50")
    assert stat.status_code == 200 and lst.status_code == 200
    assert stat.headers["cache-control"] == "public, max-age=60"
    assert lst.headers["cache-control"] == "public, max-age=60"
    assert "response" not in stat.json()
    assert set(lst.json()) == set(m.CatalogResponse.model_fields)
    # other endpoints are untouched
    assert "cache-control" not in pct.headers


def test_get_catalog_builds_once_under_concurrency(monkeypatch):
    import threading
    import time

    calls = {"n": 0}

    def _slow_build(rows=None):
        calls["n"] += 1
        time.sleep(0.05)
        return {"rows": [], "summary": None, "static_cats": {}, "scores": []}

    monkeypatch.setattr(m, "_CATALOG_CACHE", None)
    monkeypatch.setattr(m, "_build_catalog", _slow_build)
    threads = [threading.Thread(target=m._get_catalog) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls["n"] == 1


# --- default-view cache for the list ---------------------------------------------------

HOME = dict(surface="mcp", sort="score-desc", limit=6)
BROWSE = dict(surface="mcp", sort="adoption", limit=30)
BARE = dict(surface=None, sort="default", limit=50)


async def _list(db=None, **p):
    kw = dict(surface=None, q=None, severity=None, grade=None, category=None,
              decision=None, sort="default", limit=50, offset=0, db=db)
    kw.update(p)
    return await m.scan_catalog(**kw)


@pytest.fixture
def view_spy(monkeypatch):
    """Counts calls into the filter/sort path."""
    calls = {"n": 0}
    real = m._catalog_view

    async def _spy(*a, **k):
        calls["n"] += 1
        return await real(*a, **k)

    monkeypatch.setattr(m, "_catalog_view", _spy)
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    return calls


@pytest.mark.parametrize("params", [HOME, BROWSE, BARE], ids=["home", "browse", "bare"])
async def test_default_view_hit_skips_filter_and_sort(fetch, clock, view_spy, params):
    first = await _list(**params)
    second = await _list(**params)
    assert view_spy["n"] == 1
    assert first.model_dump() == second.model_dump()
    # the cached response equals a fresh computation of the same query
    fresh = await m._catalog_view(
        params["surface"], None, None, None, None, None, params["sort"], params["limit"], 0,
        None,
    )
    assert fresh.model_dump() == first.model_dump()


async def test_default_view_callers_cannot_mutate_cache(fetch, clock, view_spy):
    first = await _list(**HOME)
    snap = first.model_dump()
    first.rows.clear()
    first.summary.by_surface.clear()
    first.summary.total_scans = -1
    again = await _list(**HOME)
    assert again.model_dump() == snap
    again.rows[0].name = "tampered"
    assert (await _list(**HOME)).model_dump() == snap
    assert view_spy["n"] == 1


@pytest.mark.parametrize("params", [
    dict(surface="mcp", sort="score-desc", limit=6, severity="clean"),
    dict(surface="mcp", sort="adoption", limit=30, offset=30),
    dict(surface="npm", sort="score-desc", limit=10),
    dict(surface="mcp", sort="name", limit=30),
    dict(surface="mcp", sort="adoption", limit=30, q="tool"),
    dict(surface="mcp", sort="adoption", limit=30, grade="certified"),
    dict(surface="mcp", sort="adoption", limit=30, category="MCP server"),
    dict(surface="mcp", sort="adoption", limit=30, decision="safe"),
    dict(surface="community", sort="default", limit=50),
])
async def test_non_default_params_compute_every_time(fetch, clock, view_spy, params):
    await _list(**params)
    await _list(**params)
    assert view_spy["n"] == 2
    assert m._VIEW_CACHE == {}


async def test_view_cache_keyed_by_limit(fetch, clock, view_spy):
    six = await _list(**HOME)
    two = await _list(**{**HOME, "limit": 2})
    assert view_spy["n"] == 2
    assert len(two.rows) <= 2 and two.rows == six.rows[:len(two.rows)]


async def test_invalidation_clears_view_cache(fetch, clock, view_spy):
    await _list(**HOME)
    assert m._VIEW_CACHE
    m.invalidate_community_rows_cache()
    assert m._VIEW_CACHE == {}
    fetch["result"] = _community(5)
    out = await _list(**HOME)
    assert view_spy["n"] == 2
    assert out.summary.by_surface["community"] == 5


async def test_view_cache_follows_community_refill_and_catalog_reset(
    fetch, clock, view_spy, monkeypatch,
):
    await _list(**HOME)
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS - 1
    await _list(**HOME)
    assert view_spy["n"] == 1
    # the community rows refill (new fill) -> recompute, even with equal rows
    clock["now"] += 2
    await _list(**HOME)
    assert view_spy["n"] == 2 and fetch["calls"] == 2
    # a new catalog object -> recompute
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    await _list(**HOME)
    assert view_spy["n"] == 3


async def test_refresh_endpoint_clears_view_cache(fetch, clock, view_spy, monkeypatch):
    await _list(**HOME)
    monkeypatch.setattr(m, "require_admin", lambda e: None)
    real_build = m._build_catalog
    monkeypatch.setattr(m, "_build_catalog", lambda rows=None: real_build(_fixture_rows()))
    await m.refresh_catalog(current_entity=None)
    assert m._VIEW_CACHE == {}


async def test_view_not_cached_when_community_read_fails(fetch, clock, view_spy):
    fetch["result"] = None  # DB error -> no community fill to key on
    await _list(**HOME)
    await _list(**HOME)
    assert view_spy["n"] == 2 and m._VIEW_CACHE == {}


# --- /flagged-stat stale-while-revalidate + background refresh -------------------------

@pytest.fixture
def stat_spy(monkeypatch):
    calls = {"n": 0, "delay": 0.0, "fail": False}
    real = m._compute_flagged_stat

    def _count(*a, **k):
        calls["n"] += 1
        if calls["delay"]:
            time.sleep(calls["delay"])
        if calls["fail"]:
            raise RuntimeError("boom")
        return real(*a, **k)

    monkeypatch.setattr(m, "_compute_flagged_stat", _count)
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))
    return calls


async def test_swr_serves_old_value_then_new_one(fetch, clock, stat_spy, bg):
    old = await m.flagged_stat(db=None)
    fetch["result"] = _community(6)
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    served = await m.flagged_stat(db=None)
    assert served == old and stat_spy["n"] == 1
    await m._FLAGGED_STAT_TASK[1]
    new = await m.flagged_stat(db=None)
    assert stat_spy["n"] == 2
    assert new["by_surface"]["npm"]["total"] == old["by_surface"]["npm"]["total"] + 3
    assert m._FLAGGED_STAT_TASK[1].done()


async def test_single_refresh_under_concurrent_stale_requests(fetch, clock, stat_spy, bg):
    await m.flagged_stat(db=None)
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    stat_spy["delay"] = 0.05
    results = await asyncio.gather(*(m.flagged_stat(db=None) for _ in range(10)))
    assert len({id(r) for r in results}) == 10  # every caller got its own copy
    await m._FLAGGED_STAT_TASK[1]
    assert stat_spy["n"] == 2  # the cold fill + exactly one refresh


async def test_refresh_failure_keeps_value_and_logs(fetch, clock, stat_spy, bg, caplog):
    old = await m.flagged_stat(db=None)
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    stat_spy["fail"] = True
    with caplog.at_level(logging.WARNING, logger=m.logger.name):
        await m.flagged_stat(db=None)
        await m._FLAGGED_STAT_TASK[1]  # completes, does not raise
    assert "flagged-stat background refresh failed" in caplog.text
    assert await m.flagged_stat(db=None) == old
    # the next stale request may try again
    stat_spy["fail"] = False
    await m._FLAGGED_STAT_TASK[1]
    assert m._FLAGGED_STAT_CACHE[3] > clock["now"]


async def test_refresh_skips_store_when_community_read_fails(fetch, clock, stat_spy, bg):
    old = await m.flagged_stat(db=None)
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    fetch["result"] = None  # the refresh's community read fails
    await m.flagged_stat(db=None)
    await m._FLAGGED_STAT_TASK[1]
    assert m._FLAGGED_STAT_CACHE[2] == old and stat_spy["n"] == 1


async def test_invalidation_during_refresh_is_not_overwritten(fetch, clock, stat_spy, bg):
    await m.flagged_stat(db=None)
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    stat_spy["delay"] = 0.05
    await m.flagged_stat(db=None)
    await asyncio.sleep(0.01)  # refresh is computing
    m.invalidate_community_rows_cache()  # a community-scan write lands
    await m._FLAGGED_STAT_TASK[1]
    assert m._FLAGGED_STAT_CACHE is None
    # the next request computes synchronously once
    stat_spy["delay"] = 0.0
    n = stat_spy["n"]
    await m.flagged_stat(db=None)
    assert stat_spy["n"] == n + 1 and m._FLAGGED_STAT_CACHE is not None


async def test_timer_refreshes_and_stops_cleanly(fetch, clock, stat_spy, bg):
    task = m.start_flagged_stat_refresher(interval=0.01)
    assert m.start_flagged_stat_refresher(interval=0.01) is task  # idempotent
    for _ in range(200):
        if stat_spy["n"] >= 2:
            break
        await asyncio.sleep(0.01)
    assert stat_spy["n"] >= 2 and m._FLAGGED_STAT_CACHE is not None
    # a request now is a pure cache hit
    n = stat_spy["n"]
    await m.stop_flagged_stat_refresher()
    assert task.done() and m._FLAGGED_STAT_TIMER is None
    await m.flagged_stat(db=None)
    assert stat_spy["n"] == n


async def test_timer_survives_refresh_failures(fetch, clock, stat_spy, bg):
    stat_spy["fail"] = True
    task = m.start_flagged_stat_refresher(interval=0.01)
    for _ in range(200):
        if stat_spy["n"] >= 3:
            break
        await asyncio.sleep(0.01)
    assert stat_spy["n"] >= 3 and not task.done()


async def test_stop_without_start_is_a_noop(bg):
    await m.stop_flagged_stat_refresher()
    assert m._FLAGGED_STAT_TIMER is None and m._FLAGGED_STAT_TASK is None


# --- Cache-Control through the full app (src.main middleware) --------------------------

async def test_cache_control_through_full_app(fetch, clock, monkeypatch):
    from src.api.rate_limit import rate_limit_reads
    from src.database import get_db
    from src.main import app

    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_fixture_rows()))

    async def _no_db():
        yield None

    async def _no_limit():
        return None

    monkeypatch.setitem(app.dependency_overrides, get_db, _no_db)
    monkeypatch.setitem(app.dependency_overrides, rate_limit_reads, _no_limit)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t",
    ) as c:
        stat = await c.get("/api/v1/public/scan-catalog/flagged-stat")
        lst1 = await c.get("/api/v1/public/scan-catalog?limit=1")
        lst50 = await c.get("/api/v1/public/scan-catalog?limit=50")
        authed = await c.get(
            "/api/v1/public/scan-catalog?limit=1", headers={"Authorization": "Bearer x"},
        )
        # a route that sets no Cache-Control still gets the middleware default
        other = await c.get("/api/v1/public/scan-catalog/percentile?score=50")
        other_authed = await c.get(
            "/api/v1/public/scan-catalog/percentile?score=50",
            headers={"Authorization": "Bearer x"},
        )
    for r in (stat, lst1, lst50, authed, other, other_authed):
        assert r.status_code == 200
    assert stat.headers["cache-control"] == "public, max-age=60"
    assert lst1.headers["cache-control"] == "public, max-age=60"
    assert lst50.headers["cache-control"] == "public, max-age=60"
    assert authed.headers["cache-control"] == "public, max-age=60"
    assert other.headers["cache-control"] == "private, no-cache"
    assert other_authed.headers["cache-control"] == "private, no-cache"
