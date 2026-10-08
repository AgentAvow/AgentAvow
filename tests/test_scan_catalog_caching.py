"""Per-process caches behind /public/scan-catalog and /flagged-stat.

`_community_rows` is cached for COMMUNITY_ROWS_TTL_SECONDS (one DB read shared by
concurrent cold callers, errors never cached); the /flagged-stat response is cached for
FLAGGED_STAT_TTL_SECONDS and only served for the same catalog + equal community rows.
The DB read (`_fetch_community_rows`) is stubbed, so nothing here touches a database.
"""
from __future__ import annotations

import asyncio

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
    yield
    m.invalidate_community_rows_cache()


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
    # community TTL refill with equal rows keeps the stat cached ...
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS + 1
    await m.flagged_stat(db=None)
    assert calls["n"] == 1 and fetch["calls"] == 2
    # ... changed rows recompute
    fetch["result"] = _community(4)
    clock["now"] += m.COMMUNITY_ROWS_TTL_SECONDS + 1
    stat = await m.flagged_stat(db=None)
    assert calls["n"] == 2
    assert stat["by_surface"]["npm"]["total"] >= 4
    # past the stat TTL it recomputes even with identical inputs
    clock["now"] += m.FLAGGED_STAT_TTL_SECONDS + 1
    await m.flagged_stat(db=None)
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
