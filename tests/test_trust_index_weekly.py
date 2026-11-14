"""Trust Index weekly cards: the Do not connect review store, its public read, the
per-tool check counter and the "Most checked this week" top-5.

Redis and the public-read cache are replaced by in-memory fakes, and the catalog by a
fixed list of rows, so nothing here reads or writes a shared Redis or the launch corpus.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update
from starlette.requests import Request

import src.api.trust_index_router as ti
from src import tool_checks
from src.api.scan_catalog_router import CatalogRow
from src.database import get_db
from src.main import app
from src.models import DncReview, Entity

V1 = "/api/v1"
PW = "Str0ngP@ss"
ADMIN_URL = f"{V1}/admin/dnc-reviews"
DNC_URL = f"{V1}/public/trust-index/do-not-connect-week"
CHECKED_URL = f"{V1}/public/trust-index/most-checked-week"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
NOW = datetime.now(timezone.utc)


# --- fakes -------------------------------------------------------------------------
class FakeCache:
    def __init__(self) -> None:
        self.data: dict[str, object] = {}

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ttl=300):
        self.data[key] = value

    async def invalidate(self, key):
        self.data.pop(key, None)


class FakeRedis:
    def __init__(self) -> None:
        self.z: dict[str, dict[str, float]] = {}
        self.expire: dict[str, int] = {}

    async def zincrby(self, key, amount, member):
        d = self.z.setdefault(key, {})
        d[member] = d.get(member, 0) + amount
        return d[member]

    async def expireat(self, key, when):
        self.expire[key] = int(when)
        return True

    async def zrange(self, key, start, end, withscores=False):
        items = sorted(self.z.get(key, {}).items(), key=lambda kv: kv[1])
        return [(m.encode(), s) for m, s in items] if withscores else [m for m, _ in items]


def _row(name: str, *, decision: str, reason: str | None = None, score: int = 70,
         days_ago: float = 1, surface: str = "github", certified: bool = False) -> CatalogRow:
    return CatalogRow(
        surface=surface, name=name, full_name=name if "/" in name else None,
        trust_score=score, grade="A+" if certified else None,
        critical=1 if decision == "do_not_connect" else 0, high=0,
        decision=decision, decision_reason=reason or f"reason for {name}",
        last_scanned_at=NOW - timedelta(days=days_ago), scan_source="live")


@pytest.fixture
def fake_cache(monkeypatch):
    c = FakeCache()
    monkeypatch.setattr(ti, "cache", c)
    return c


@pytest.fixture
def catalog(monkeypatch):
    rows: list[CatalogRow] = []

    async def _rows(db):
        return list(rows)

    monkeypatch.setattr(ti, "catalog_rows", _rows)
    return rows


@pytest.fixture
def fake_redis(monkeypatch):
    r = FakeRedis()
    import src.redis_client as rc
    monkeypatch.setattr(rc, "get_redis", lambda: r)
    return r


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _user(client, db, tag: str, *, admin=False, viewer=False) -> str:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post(f"{V1}/auth/register", json={
        "email": email, "password": PW, "display_name": f"{tag.title()} Person"})
    assert r.status_code in (200, 201), r.text
    token = (await client.post(f"{V1}/auth/login",
                               json={"email": email, "password": PW})).json()["access_token"]
    me = (await client.get(f"{V1}/auth/me", headers=_auth(token))).json()
    entity = await db.get(Entity, uuid.UUID(me["id"]))
    entity.is_admin = admin
    entity.is_admin_viewer = viewer
    await db.flush()
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- the review store: who may write and read --------------------------------------
@pytest.mark.asyncio
async def test_review_write_is_admin_only(client, db, catalog, fake_cache):
    catalog.append(_row("acme/bad", decision="do_not_connect"))
    body = {"page_path": "/check/acme/bad", "verdict": "confirmed"}

    r = await client.post(ADMIN_URL, json=body)
    assert r.status_code in (401, 403)

    viewer = await _user(client, db, "viewer", viewer=True)
    assert (await client.post(ADMIN_URL, json=body, headers=_auth(viewer))).status_code == 403
    assert (await client.get(ADMIN_URL, headers=_auth(viewer))).status_code == 403

    plain = await _user(client, db, "plain")
    assert (await client.post(ADMIN_URL, json=body, headers=_auth(plain))).status_code == 403

    admin = await _user(client, db, "admin", admin=True)
    r = await client.post(ADMIN_URL, json=body, headers=_auth(admin))
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "confirmed"
    assert r.json()["page_key"] == "/check/acme/bad"

    # Re-review of the same page replaces the row, never adds a second one.
    r = await client.post(ADMIN_URL, json={**body, "verdict": "not_confirmed", "note": "test"},
                          headers=_auth(admin))
    assert r.status_code == 200
    rows = (await db.execute(
        DncReview.__table__.select().where(DncReview.page_key == "/check/acme/bad"))).all()
    assert len(rows) == 1 and rows[0].verdict == "not_confirmed" and rows[0].note == "test"


@pytest.mark.asyncio
async def test_review_rejects_confirming_a_tool_that_is_not_dnc(client, db, catalog, fake_cache):
    catalog.append(_row("acme/fine", decision="safe", score=90))
    admin = await _user(client, db, "admin", admin=True)
    r = await client.post(ADMIN_URL, json={"page_path": "/check/acme/fine",
                                           "verdict": "confirmed"}, headers=_auth(admin))
    assert r.status_code == 409
    r = await client.post(ADMIN_URL, json={"page_path": "/check/nobody/here",
                                           "verdict": "confirmed"}, headers=_auth(admin))
    assert r.status_code == 404
    r = await client.post(ADMIN_URL, json={"page_path": "/check/acme/fine",
                                           "verdict": "maybe"}, headers=_auth(admin))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_candidates_list_recent_dnc_with_status(client, db, catalog, fake_cache,
                                                      monkeypatch):
    monkeypatch.setattr(ti, "growth_review_keys", lambda since: {})
    catalog.extend([
        _row("acme/new-bad", decision="do_not_connect", days_ago=1),
        _row("acme/old-bad", decision="do_not_connect", days_ago=30),
        _row("acme/fine", decision="safe", score=90, days_ago=1),
        _row("acme/reviewed", decision="do_not_connect", days_ago=2),
    ])
    admin = await _user(client, db, "admin", admin=True)
    await client.post(ADMIN_URL, json={"page_path": "/check/acme/reviewed",
                                       "verdict": "confirmed"}, headers=_auth(admin))
    r = await client.get(ADMIN_URL, headers=_auth(admin))
    assert r.status_code == 200
    items = r.json()["items"]
    assert [i["page_key"] for i in items] == ["/check/acme/new-bad", "/check/acme/reviewed"]
    assert items[0]["status"] == "pending" and items[1]["status"] == "confirmed"
    assert items[0]["decision_reason"] == "reason for acme/new-bad"


# --- the public read: only confirmed, and only while still Do not connect -----------
@pytest.mark.asyncio
async def test_public_dnc_lists_only_confirmed_and_still_dnc(client, db, catalog, fake_cache):
    catalog.extend([
        _row("acme/confirmed", decision="do_not_connect"),
        _row("acme/unconfirmed", decision="do_not_connect"),
        _row("acme/rejected", decision="do_not_connect"),
        _row("acme/now-safe", decision="do_not_connect"),
        _row("acme/new-reason", decision="do_not_connect"),
        _row("acme/stale-review", decision="do_not_connect"),
    ])
    admin = await _user(client, db, "admin", admin=True)
    for name, verdict in [("confirmed", "confirmed"), ("rejected", "not_confirmed"),
                          ("now-safe", "confirmed"), ("new-reason", "confirmed"),
                          ("stale-review", "confirmed")]:
        r = await client.post(ADMIN_URL, json={"page_path": f"/check/acme/{name}",
                                               "verdict": verdict}, headers=_auth(admin))
        assert r.status_code == 200, r.text
    # Since the reviews: one tool re-scanned Safe, one now fails for another reason, and
    # one review is older than the 7-day window.
    catalog[3] = _row("acme/now-safe", decision="safe", score=88)
    catalog[4] = _row("acme/new-reason", decision="do_not_connect", reason="something else")
    await db.execute(update(DncReview).where(DncReview.page_key == "/check/acme/stale-review")
                     .values(reviewed_at=NOW - timedelta(days=8)))
    fake_cache.data.clear()

    r = await client.get(DNC_URL)
    assert r.status_code == 200
    items = r.json()["items"]
    assert [i["page_path"] for i in items] == ["/check/acme/confirmed"]
    assert items[0]["decision_reason"] == "reason for acme/confirmed"
    assert items[0]["confirmed_at"]
    # Served from the 10-minute cache next time.
    assert ti.DNC_CACHE_KEY in fake_cache.data


@pytest.mark.asyncio
async def test_public_dnc_newest_first_and_capped_at_five(db, catalog):
    for i in range(7):
        catalog.append(_row(f"acme/t{i}", decision="do_not_connect"))
        db.add(DncReview(page_key=f"/check/acme/t{i}", page_path=f"/check/acme/t{i}",
                         surface="github", name=f"acme/t{i}",
                         decision_at_review="do_not_connect",
                         reason_at_review=f"reason for acme/t{i}", verdict="confirmed",
                         reviewed_at=NOW - timedelta(hours=i)))
    await db.flush()
    data = await ti.build_dnc_week(db, now=NOW)
    assert [i["name"] for i in data["items"]] == [f"acme/t{i}" for i in range(5)]


# --- the counter ------------------------------------------------------------------------
def _request(ua: str, ip: str = "203.0.113.9") -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                    "headers": [(b"user-agent", ua.encode())], "client": (ip, 1234)})


def test_counts_people_and_agents_only(monkeypatch):
    from src.config import settings
    monkeypatch.setattr(settings, "metrics_owner_ips", "198.51.100.7")
    assert tool_checks.counts_for(_request(BROWSER_UA)) is True
    assert tool_checks.counts_for(_request("Claude-User (claude-code/2.0)")) is True
    assert tool_checks.counts_for(_request("Googlebot/2.1 (+http://google.com/bot)")) is False
    assert tool_checks.counts_for(_request("python-requests/2.32")) is False
    assert tool_checks.counts_for(_request("agentavow-gate/0.1.40")) is False
    assert tool_checks.counts_for(_request("")) is False
    # The owner's machine, even from a real browser.
    assert tool_checks.counts_for(_request(BROWSER_UA, ip="198.51.100.7")) is False
    # Internal callers pass no request, or a stand-in.
    assert tool_checks.counts_for(None) is False
    assert tool_checks.counts_for(object()) is False


@pytest.mark.asyncio
async def test_record_check_sets_expiry_and_stores_only_the_page(fake_redis):
    day = date(2026, 11, 13)
    await tool_checks.record_check("/check/acme/tool", today=day)
    await tool_checks.record_check("/check/acme/tool", today=day)
    key = "ag:checks:tool:2026-11-13"
    assert fake_redis.z == {key: {"/check/acme/tool": 2}}
    end = datetime(2026, 11, 14, tzinfo=timezone.utc)
    assert fake_redis.expire[key] == int((end + timedelta(days=14)).timestamp())


@pytest.mark.asyncio
async def test_week_counts_sum_seven_days_only(fake_redis):
    today = date(2026, 11, 13)
    for i in range(9):
        await tool_checks.record_check("/check/a/b", today=today - timedelta(days=i))
    await tool_checks.record_check("/check/c/d", today=today)
    assert await tool_checks.week_counts(today=today) == {"/check/a/b": 7, "/check/c/d": 1}


@pytest.mark.asyncio
async def test_counted_decorator_skips_bots_owner_internal_and_202(fake_redis, monkeypatch):
    from fastapi.responses import JSONResponse

    from src.config import settings
    monkeypatch.setattr(settings, "metrics_owner_ips", "198.51.100.7")
    status = {"code": 200}

    @tool_checks.counted(tool_checks.repo_key)
    async def route(owner: str, repo: str, request=None, force: bool = False):
        if status["code"] == 202:
            return JSONResponse({"status": "checking"}, status_code=202)
        return {"ok": True}

    await route(owner="Acme", repo="Tool", request=_request(BROWSER_UA))
    await route(owner="acme", repo="tool", request=_request(BROWSER_UA), force=True)
    await route(owner="acme", repo="tool", request=_request("curl/8.0"))
    await route(owner="acme", repo="tool", request=_request(BROWSER_UA, ip="198.51.100.7"))
    await route(owner="acme", repo="tool", request=None)
    status["code"] = 202  # still checking: the poll that lands the result counts instead
    await route(owner="acme", repo="tool", request=_request(BROWSER_UA), force=True)
    counts = await tool_checks.week_counts()
    assert counts == {"/check/acme/tool": 2}


def test_page_keys_match_the_catalog():
    assert tool_checks.repo_key({"owner": "Acme", "repo": "Tool"}) == "/check/acme/tool"
    assert tool_checks.skill_key({"owner": "a", "repo": "b"}) == "/check/skill/a/b"
    assert tool_checks.package_key({"surface": "python", "name": "Requests"}) == \
        "/check/pkg/pypi/Requests"
    assert tool_checks.mcp_key({"endpoint": "https://mcp.example.com/mcp?token=x"}) == \
        "/check/mcp?endpoint=https%3A%2F%2Fmcp.example.com%2Fmcp"
    row = _row("Acme/Tool", decision="safe")
    from src.api.scan_catalog_router import page_key
    assert page_key(row) == tool_checks.repo_key({"owner": "Acme", "repo": "Tool"})


# --- the top 5 ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_most_checked_top_five(db, catalog):
    catalog.extend([
        _row("acme/a", decision="safe", score=92, certified=True),
        _row("acme/b", decision="review", score=60),
        _row("acme/c", decision="safe", score=85),
        _row("acme/d", decision="review", score=55),
        _row("acme/e", decision="safe", score=80),
        _row("acme/f", decision="safe", score=81),
        _row("acme/dnc", decision="do_not_connect", score=20),
        _row("acme/dnc-ok", decision="do_not_connect", score=15),
    ])
    db.add(DncReview(page_key="/check/acme/dnc-ok", page_path="/check/acme/dnc-ok",
                     surface="github", name="acme/dnc-ok",
                     decision_at_review="do_not_connect",
                     reason_at_review="reason for acme/dnc-ok", verdict="confirmed"))
    await db.flush()
    counts = {"/check/acme/a": 40, "/check/acme/dnc": 39, "/check/acme/b": 30,
              "/check/acme/dnc-ok": 20, "/check/acme/c": 10, "/check/acme/d": 9,
              "/check/acme/e": 8, "/check/acme/f": 2, "/check/not/in-catalog": 50}
    data = await ti.build_most_checked(db, counts=counts)
    items = data["items"]
    assert [i["name"] for i in items] == ["acme/a", "acme/b", "acme/dnc-ok", "acme/c", "acme/d"]
    assert [i["checks"] for i in items] == [40, 30, 20, 10, 9]
    assert items[0]["certified_mark"] is True and items[0]["decision"] == "safe"
    assert "grade" not in items[0]


@pytest.mark.asyncio
async def test_most_checked_hidden_until_three_tools_have_three_checks(db, catalog):
    catalog.extend([_row("acme/a", decision="safe"), _row("acme/b", decision="safe"),
                    _row("acme/c", decision="safe")])
    few = {"/check/acme/a": 9, "/check/acme/b": 3, "/check/acme/c": 2}
    assert (await ti.build_most_checked(db, counts=few))["items"] == []
    enough = {**few, "/check/acme/c": 3}
    assert len((await ti.build_most_checked(db, counts=enough))["items"]) == 3


@pytest.mark.asyncio
async def test_most_checked_endpoint_is_public_and_cached(client, catalog, fake_cache,
                                                          fake_redis):
    catalog.extend([_row(f"acme/t{i}", decision="safe") for i in range(3)])
    for i in range(3):
        for _ in range(3):
            await tool_checks.record_check(f"/check/acme/t{i}")
    r = await client.get(CHECKED_URL)
    assert r.status_code == 200
    assert len(r.json()["items"]) == 3
    assert ti.CHECKED_CACHE_KEY in fake_cache.data
