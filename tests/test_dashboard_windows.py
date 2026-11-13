"""Admin dashboard: complete-day windows, window-unique checkers, PyPI 7/30-day sums."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import src.api.metrics_dashboard_router as md
from src.jobs import metrics_daily
from tests.test_ad_spend import _auth, _token, client  # noqa: F401 (fixture)
from tests.test_metrics_growth import redis  # noqa: F401 (fixture)


def _day(offset: int) -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=offset)).isoformat()


# --- complete-day windows -------------------------------------------------------------


def test_window_days_complete_ends_yesterday():
    days = md.window_days(7, include_today=False)
    assert [d.isoformat() for d in days] == [_day(i) for i in range(7, 0, -1)]
    assert md.window_days(7)[-1].isoformat() == _day(0)
    assert len(md.window_days(30, include_today=False)) == 30


@pytest.mark.asyncio
async def test_aggregate_complete_days_leaves_today_out(db, redis):  # noqa: F811
    await md.bump_metric("install_click")  # today
    yesterday = _day(1)
    redis.counters[f"ag:metrics:install_click:{yesterday}"] = 4
    out = await md._aggregate(db, "7d", include_today=False)
    assert out["include_today"] is False
    assert out["days"][-1] == yesterday and len(out["days"]) == 7
    assert out["headline"]["install_clicks"] == 4
    assert out["series"]["install_clicks"][-1] == 4
    out = await md._aggregate(db, "7d")
    assert out["days"][-1] == _day(0)
    assert out["headline"]["install_clicks"] == 5


@pytest.mark.asyncio
async def test_unique_checkers_union_over_the_window_days(db, redis):  # noqa: F811
    from src.scanner.adoption_sources import _GLOBAL_UNIQ_PREFIX

    redis.hll[f"{_GLOBAL_UNIQ_PREFIX}{_day(0)}"] = {"a", "b"}
    redis.hll[f"{_GLOBAL_UNIQ_PREFIX}{_day(1)}"] = {"a", "c"}
    redis.hll[f"{_GLOBAL_UNIQ_PREFIX}{_day(9)}"] = {"z"}
    assert (await md._aggregate(db, "7d"))["headline"]["unique_checkers"] == 3
    assert (await md._aggregate(db, "7d", include_today=False))["headline"][
        "unique_checkers"] == 2


@pytest.mark.asyncio
async def test_metrics_endpoint_accepts_include_today(client, db):  # noqa: F811
    token = await _token(client, db, admin=True)
    for path in ("/api/v1/admin/metrics", "/api/v1/admin/metrics/behavioral"):
        r = await client.get(path, params={"window": "7d", "include_today": "false"},
                             headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json()["include_today"] is False
        assert r.json()["days"][-1] == _day(1)
        # "today" always covers today, whatever the flag says.
        r = await client.get(path, params={"window": "today", "include_today": "false"},
                             headers=_auth(token))
        assert r.json()["days"] == [_day(0)]


@pytest.mark.asyncio
async def test_daily_conversion_takes_a_double_window(client, db):  # noqa: F811
    token = await _token(client, db, admin=True)
    r = await client.get("/api/v1/analytics/conversion/daily", params={"days": 181},
                         headers=_auth(token))
    assert r.status_code == 200, r.text
    r = await client.get("/api/v1/analytics/conversion/daily", params={"days": 191},
                         headers=_auth(token))
    assert r.status_code == 422


# --- PyPI downloads ---------------------------------------------------------------------


def _rows(n_days: int, per_day: int, end: str = "2026-11-11", category="without_mirrors"):
    last = datetime.fromisoformat(end).date()
    return [{"category": category, "date": (last - timedelta(days=i)).isoformat(),
             "downloads": per_day} for i in range(n_days)]


def test_pypi_window_sums_week_never_exceeds_month():
    data = _rows(40, 10) + _rows(40, 999, category="with_mirrors")
    data.append({"category": "without_mirrors", "date": "garbage", "downloads": 5})
    assert metrics_daily.pypi_window_sums(data) == {"pypi_week": 70, "pypi_month": 300}
    # A young package: fewer days than the window.
    assert metrics_daily.pypi_window_sums(_rows(3, 2)) == {"pypi_week": 6, "pypi_month": 6}
    assert metrics_daily.pypi_window_sums([]) == {}


def _mock_httpx(monkeypatch, handler):
    import httpx

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.asyncio
async def test_fetch_reads_pypi_daily_series_not_recent_month(monkeypatch):
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.npmjs.org":
            return httpx.Response(200, json={"downloads": 256})
        if request.url.path.endswith("/overall"):
            return httpx.Response(200, json={"data": _rows(30, 10)})
        # /recent, with the inconsistent month pypistats served on 2026-11-12
        return httpx.Response(200, json={"data": {"last_week": 1242, "last_month": 620}})

    _mock_httpx(monkeypatch, handler)
    assert await metrics_daily.fetch_registry_downloads() == {
        "npm_week": 256, "pypi_week": 70, "pypi_month": 300}


@pytest.mark.asyncio
async def test_fetch_falls_back_to_recent_week_only(monkeypatch):
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/recent"):
            return httpx.Response(200, json={"data": {"last_week": 1242, "last_month": 620}})
        return httpx.Response(503)

    _mock_httpx(monkeypatch, handler)
    assert await metrics_daily.fetch_registry_downloads() == {"pypi_week": 1242}
