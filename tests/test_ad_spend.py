"""Admin ad spend (t30) and cost per action per utm_content."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api.ad_spend_router import parse_spend_csv
from src.database import get_db
from src.main import app

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
CAMPAIGN = "2026-11-test-dev"


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
        headers={"User-Agent": BROWSER_UA},
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


async def _token(client: AsyncClient, db, admin: bool) -> str:
    from src.models import Entity

    email = f"spend-{uuid.uuid4().hex[:8]}@example.com"
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "Str0ngP@ss", "display_name": "Spend"})
    token = (await client.post("/api/v1/auth/login", json={
        "email": email, "password": "Str0ngP@ss"})).json()["access_token"]
    me = (await client.get("/api/v1/auth/me", headers=_auth(token))).json()
    if admin:
        entity = await db.get(Entity, uuid.UUID(me["id"]))
        entity.is_admin = True
        await db.flush()
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


# --- CSV parsing --------------------------------------------------------------------


REDDIT_CSV = (
    "Date,Campaign Name,Ad Group Name,Ad Name,Impressions,Clicks,Amount Spent (USD)\n"
    "2026-11-17,Dev test,r/mcp,d1-before-npx,1200,30,$12.50\n"
    "2026-11-17,Dev test,r/ClaudeAI,d1-before-npx,800,10,7.50\n"
    "2026-11-17,Dev test,r/mcp,d2-rug-pull,\"1,000\",5,4.00\n"
    "11/18/2026,Dev test,r/mcp,d1-before-npx,100,1,1.00\n"
    "not a date,Dev test,r/mcp,d1,1,1,1\n"
    "2026-11-18,Dev test,r/mcp,d1,1,1,\n"
)


def test_reddit_export_is_summed_per_day_campaign_and_ad():
    rows, errors = parse_spend_csv(REDDIT_CSV, utm_campaign=CAMPAIGN, utm_source="reddit")
    by = {(str(r["day"]), r["utm_content"]): r for r in rows}
    assert set(by) == {("2026-11-17", "d1-before-npx"), ("2026-11-17", "d2-rug-pull"),
                       ("2026-11-18", "d1-before-npx")}
    d1 = by[("2026-11-17", "d1-before-npx")]
    assert d1["spend_usd"] == Decimal("20.00")
    assert (d1["impressions"], d1["clicks"]) == (2000, 40)
    assert by[("2026-11-17", "d2-rug-pull")]["impressions"] == 1000
    assert all(r["utm_campaign"] == CAMPAIGN and r["source"] == "csv" for r in rows)
    assert len(errors) == 2 and "date" in errors[0] and "spend" in errors[1]


def test_campaign_name_is_used_when_no_override_and_required():
    rows, _ = parse_spend_csv("Date,Campaign,Spend\n2026-11-17,abc,3\n")
    assert rows[0]["utm_campaign"] == "abc" and rows[0]["utm_content"] == ""
    rows, errors = parse_spend_csv("Date,Spend\n2026-11-17,3\n")
    assert rows == [] and "campaign" in errors[0]


def test_garbage_csv_is_reported_not_raised():
    assert parse_spend_csv("") == ([], ["The CSV has no header row."])
    rows, errors = parse_spend_csv("a,b\n1,2\n")
    assert rows == [] and errors


# --- Endpoints ----------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", [
    ("get", "/api/v1/admin/ad-spend"),
    ("get", "/api/v1/admin/ad-spend/cost-per-action"),
])
async def test_reads_are_admin_only(client, db, method, path):
    assert (await client.request(method, path)).status_code in (401, 403)
    token = await _token(client, db, admin=False)
    assert (await client.request(method, path, headers=_auth(token))).status_code == 403


@pytest.mark.asyncio
async def test_writes_are_admin_only(client, db):
    token = await _token(client, db, admin=False)
    body = {"day": _today(), "utm_campaign": CAMPAIGN, "spend_usd": "5.00"}
    assert (await client.put("/api/v1/admin/ad-spend", json=body,
                             headers=_auth(token))).status_code == 403
    assert (await client.post("/api/v1/admin/ad-spend/import", json={"csv": REDDIT_CSV},
                              headers=_auth(token))).status_code == 403
    assert (await client.delete(f"/api/v1/admin/ad-spend/{uuid.uuid4()}",
                                headers=_auth(token))).status_code == 403


@pytest.mark.asyncio
async def test_put_replaces_the_same_day_and_delete_removes(client, db):
    token = await _token(client, db, admin=True)
    body = {"day": _today(), "utm_campaign": CAMPAIGN, "utm_content": "d1", "spend_usd": "5.00"}
    assert (await client.put("/api/v1/admin/ad-spend", json=body,
                             headers=_auth(token))).status_code == 200
    body["spend_usd"] = "7.25"
    await client.put("/api/v1/admin/ad-spend", json=body, headers=_auth(token))
    listed = (await client.get("/api/v1/admin/ad-spend", headers=_auth(token))).json()
    assert len(listed["rows"]) == 1 and listed["total_usd"] == 7.25
    row_id = listed["rows"][0]["id"]
    assert (await client.delete(f"/api/v1/admin/ad-spend/{row_id}",
                                headers=_auth(token))).status_code == 200
    assert (await client.delete(f"/api/v1/admin/ad-spend/{row_id}",
                                headers=_auth(token))).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [
    {"utm_campaign": "", "spend_usd": "1"},
    {"utm_campaign": "  ", "spend_usd": "1"},
    {"utm_campaign": "x", "spend_usd": "-1"},
    {"utm_campaign": "x", "spend_usd": "1.234"},
])
async def test_put_validates(client, db, bad):
    token = await _token(client, db, admin=True)
    resp = await client.put("/api/v1/admin/ad-spend", json={"day": _today(), **bad},
                            headers=_auth(token))
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_import_twice_changes_nothing(client, db):
    token = await _token(client, db, admin=True)
    for _ in range(2):
        resp = await client.post("/api/v1/admin/ad-spend/import", headers=_auth(token),
                                 json={"csv": REDDIT_CSV, "utm_campaign": CAMPAIGN})
        assert resp.status_code == 200 and resp.json()["imported"] == 3
    listed = (await client.get("/api/v1/admin/ad-spend", params={"days": 366},
                               headers=_auth(token))).json()
    dated = [r for r in listed["rows"] if r["day"] in ("2026-11-17", "2026-11-18")]
    if _today() <= "2027-11-16":  # the export's days are still inside a 366-day window
        assert len(dated) == 3 and sum(r["spend_usd"] for r in dated) == 25.0


@pytest.mark.asyncio
async def test_cost_per_action_divides_spend_by_the_funnel(client, db):
    token = await _token(client, db, admin=True)

    async def send(sid, event_type, **extra):
        await client.post("/api/v1/analytics/event", json={
            "event_type": event_type, "session_id": sid, "page": "/claude-code", **extra})

    utm = {"utm_source": "reddit", "utm_campaign": CAMPAIGN, "utm_content": "d1"}
    for i in range(4):
        sid = str(uuid.uuid4())
        await send(sid, "lp_view", metadata=utm)
        if i < 2:
            await send(sid, "cta_click", intent="copy_plugin_cmd")
    other = str(uuid.uuid4())  # another campaign: not in this view
    await send(other, "lp_view", metadata={**utm, "utm_campaign": "elsewhere"})

    for content, spend in (("d1", "10.00"), ("d2", "3.00")):
        await client.put("/api/v1/admin/ad-spend", headers=_auth(token), json={
            "day": _today(), "utm_campaign": CAMPAIGN, "utm_content": content,
            "spend_usd": spend})

    out = (await client.get("/api/v1/admin/ad-spend/cost-per-action", headers=_auth(token),
                            params={"days": 7, "campaign": CAMPAIGN})).json()
    rows = {r["utm_content"]: r for r in out["rows"]}
    assert rows["d1"]["lp_view"] == 4 and rows["d1"]["copy_plugin_cmd"] == 2
    assert rows["d1"]["cost_per_lp_view"] == 2.5
    assert rows["d1"]["cost_per_copy_plugin_cmd"] == 5.0
    assert rows["d2"]["lp_view"] == 0 and rows["d2"]["cost_per_lp_view"] is None
    assert out["total"]["spend_usd"] == 13.0 and out["total"]["lp_view"] == 4
    assert out["total"]["cost_per_lp_view"] == 3.25
