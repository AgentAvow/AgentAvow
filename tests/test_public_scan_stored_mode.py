"""``?stored=true`` on the package scan route: the last stored grade, instantly, never a
fresh scan inline, never the fresh-scan budget. Hooks and bulk callers use it.

Fresh (1h) copy → 200 as usual. Only the 7-day copy → 200 with ``stale: true`` and a
background refresh scheduled. Nothing stored → 202 ``{status: queued}`` and a refresh
scheduled. The ordinary path (no flag) is untouched.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import src.api.public_scan_router as psr
from src.database import get_db
from src.main import app

URL = "/api/v1/public/scan/package/npm/left-pad"


def _scan_dict(score: int = 70) -> dict:
    return {
        "trust_score": score, "trust_tier": "standard", "scan_result": "clean",
        "recommended_limits": {"requests_per_minute": 60, "max_tokens_per_call": 4000,
                               "require_user_confirmation": False},
        "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0, "categories": {},
                     "suppressed_lines": 0},
        "positive_signals": [], "category_scores": {},
        "metadata": {"files_scanned": 3, "primary_language": "javascript", "has_readme": True,
                     "has_license": True, "has_tests": False, "is_mcp_server": False},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def no_sandbox():
    with patch("src.api.public_scan_router._behavioral_block", new=AsyncMock(return_value=None)):
        yield


@pytest.fixture
def refresh():
    calls: list[tuple] = []
    with patch("src.api.public_scan_router._schedule_package_refresh",
               new=lambda *a: calls.append(a)):
        yield calls


@pytest.mark.asyncio
async def test_fresh_copy_is_served_as_usual(client, no_sandbox, refresh):
    with patch("src.api.public_scan_router._get_cached", new=AsyncMock(return_value=_scan_dict(88))), \
         patch("src.api.public_scan_router._get_stale_cached", new=AsyncMock(return_value=None)):
        r = await client.get(URL, params={"stored": "true"})
    assert r.status_code == 200
    body = r.json()
    assert body["trust_score"] == 88 and body["cached"] is True and body["stale"] is False
    assert refresh == []


@pytest.mark.asyncio
async def test_only_the_stale_copy_is_served_marked_stale_and_refreshed_in_the_background(client, no_sandbox, refresh):
    with patch("src.api.public_scan_router._get_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router._get_stale_cached", new=AsyncMock(return_value=_scan_dict(70))):
        r = await client.get(URL, params={"stored": "true"})
    assert r.status_code == 200
    body = r.json()
    assert body["trust_score"] == 70 and body["stale"] is True and body["jws"]
    assert refresh == [("npm", "left-pad", None, "npm", "left-pad")]


@pytest.mark.asyncio
async def test_nothing_stored_is_a_202_queued_and_a_refresh_is_scheduled(client, no_sandbox, refresh):
    with patch("src.api.public_scan_router._get_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router._get_stale_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router.enforce_fresh_scan_limit", create=True):
        r = await client.get(URL, params={"stored": "true"})
    assert r.status_code == 202
    assert r.json()["status"] == "queued" and r.json()["name"] == "left-pad"
    assert len(refresh) == 1


@pytest.mark.asyncio
async def test_without_the_flag_the_ordinary_path_runs(client, no_sandbox, refresh):
    seen = {}

    async def fake_scan(surface, name, version=None):
        seen["called"] = (surface, name)

        class R:
            error = None
        return R()

    with patch("src.api.public_scan_router._get_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router._get_stale_cached", new=AsyncMock(return_value=_scan_dict())), \
         patch("src.scanner.scan.scan_package", new=fake_scan), \
         patch("src.api.public_scan_router._scan_result_to_dict", new=lambda r: _scan_dict(91)), \
         patch("src.api.public_scan_router._set_cached", new=AsyncMock()):
        r = await client.get(URL)
    assert r.status_code == 200 and r.json()["trust_score"] == 91 and r.json()["stale"] is False
    assert seen["called"] == ("npm", "left-pad")
    assert refresh == []  # no flag → no background path involved


@pytest.mark.asyncio
async def test_refresh_runs_once_per_coordinate_and_caches_the_result(monkeypatch):
    stored = {}
    held: dict[str, str] = {}

    class _Redis:
        async def set(self, key, value, nx=False, ex=None):
            if nx and key in held:
                return None
            held[key] = value
            return True

    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Redis())

    class R:
        error = None

    async def fake_scan(surface, name, version=None):
        stored["scanned"] = stored.get("scanned", 0) + 1
        return R()

    async def fake_set(owner, repo, data):
        stored["cached"] = (owner, repo, data["trust_score"])

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan)
    monkeypatch.setattr(psr, "_scan_result_to_dict", lambda r: _scan_dict(77))
    monkeypatch.setattr(psr, "_set_cached", fake_set)
    await psr._refresh_package("npm", "left-pad", None, "npm", "left-pad")
    await psr._refresh_package("npm", "left-pad", None, "npm", "left-pad")  # lock held: skipped
    assert stored == {"scanned": 1, "cached": ("npm", "left-pad", 77)}



@pytest.mark.asyncio
async def test_a_recorded_permanent_failure_is_a_422_with_the_reason_not_queued(client, no_sandbox, refresh):
    with patch("src.api.public_scan_router._get_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router._get_stale_cached", new=AsyncMock(return_value=None)), \
         patch("src.api.public_scan_router._get_refresh_error",
               new=AsyncMock(return_value="artifact exceeds unpacked-size cap (zip bomb?)")):
        r = await client.get("/api/v1/public/scan/package/pypi/sqlalchemy", params={"stored": "true"})
    assert r.status_code == 422
    assert r.json()["detail"] == "Not scannable: artifact exceeds unpacked-size cap (zip bomb?)"
    assert refresh == []  # nothing re-queued for a failure a retry will not fix


@pytest.mark.asyncio
async def test_refresh_records_a_scan_error(monkeypatch):
    held: dict = {}

    class _Redis:
        async def set(self, key, value, nx=False, ex=None):
            if nx and key in held:
                return None
            held[key] = (value, ex)
            return True

    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Redis())

    class R:
        error = "artifact exceeds unpacked-size cap (zip bomb?)"

    async def fake_scan(surface, name, version=None):
        return R()

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan)
    await psr._refresh_package("pypi", "sqlalchemy", None, "pypi", "sqlalchemy")
    assert held["public_scan_refresh_error:pypi/sqlalchemy"] == (
        "artifact exceeds unpacked-size cap (zip bomb?)", psr._REFRESH_ERROR_TTL)



@pytest.mark.asyncio
async def test_stored_reads_skip_the_scan_limiter_but_not_the_read_limiter(monkeypatch):
    from starlette.requests import Request

    import src.api.rate_limit as rl
    seen = []

    async def check(key, limit, window_seconds=60):
        seen.append(key)
        return True

    async def headers(request, key, limit):
        return None

    monkeypatch.setattr(rl._limiter, "check", check)
    monkeypatch.setattr(rl, "_set_rate_limit_headers", headers)

    def req(qs: bytes, path="/api/v1/public/scan/package/pypi/x"):
        return Request({"type": "http", "method": "GET", "path": path, "headers": [],
                        "client": ("198.51.100.4", 1), "query_string": qs,
                        "scheme": "http", "server": ("t", 80)})

    await rl.rate_limit_scans(req(b"stored=true"))
    assert seen == []
    await rl.rate_limit_reads(req(b"stored=true"))
    assert seen == ["read:198.51.100.4"]
    await rl.rate_limit_scans(req(b""))
    await rl.rate_limit_scans(req(b"stored=true", path="/api/v1/public/scan/owner/repo"))
    assert seen.count("scan:198.51.100.4") == 2


def test_refresh_scheduling_is_capped(monkeypatch):
    monkeypatch.setattr(psr, "_refresh_pending", psr._REFRESH_MAX_PENDING)
    started = []
    monkeypatch.setattr(psr.asyncio, "get_running_loop",
                        lambda: type("L", (), {"create_task": lambda self, c: started.append(c)})())
    psr._schedule_package_refresh("npm", "x", None, "npm", "x")
    assert started == []
