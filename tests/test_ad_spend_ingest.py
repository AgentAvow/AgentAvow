"""Ad spend: the token-authenticated Google ingest and the X / Google CSV paste."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from src.api.ad_spend_router import ad_tag_for, parse_spend_csv
from src.config import settings
from src.database import get_db
from src.main import app
from src.models import AdSpend, AuditLog

URL = "/api/v1/admin/ad-spend/ingest"
TOKEN = "t" * 40
CAMPAIGN = f"2026-11-test-google-{uuid.uuid4().hex[:6]}"
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


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


@pytest.fixture
def token_set(monkeypatch):
    monkeypatch.setattr(settings, "ad_spend_ingest_token", TOKEN)


def _day(back: int) -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=back)).isoformat()


def _body(**over) -> dict:
    row = {"day": _day(1), "campaign": CAMPAIGN, "ad_group": "scanner", "cost": "12.34",
           "impressions": 1000, "clicks": 20}
    row.update(over)
    return {"channel": "google", "rows": [row]}


async def _rows(db) -> list[AdSpend]:
    return list((await db.execute(
        select(AdSpend).where(AdSpend.utm_campaign == CAMPAIGN)
        .order_by(AdSpend.day, AdSpend.utm_content)
        .execution_options(populate_existing=True))).scalars().all())


# --- auth ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unset_token_is_404(client, monkeypatch):
    monkeypatch.setattr(settings, "ad_spend_ingest_token", "")
    r = await client.post(URL, json=_body(), headers={"X-Ad-Spend-Token": "anything"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_short_token_keeps_endpoint_off(client, monkeypatch):
    monkeypatch.setattr(settings, "ad_spend_ingest_token", "short")
    r = await client.post(URL, json=_body(), headers={"X-Ad-Spend-Token": "short"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_missing_token_is_401(client, token_set, db):
    assert (await client.post(URL, json=_body())).status_code == 401
    assert await _rows(db) == []


@pytest.mark.asyncio
async def test_wrong_token_is_401(client, token_set, db):
    r = await client.post(URL, json=_body(), headers={"X-Ad-Spend-Token": TOKEN + "x"})
    assert r.status_code == 401
    assert await _rows(db) == []


@pytest.mark.asyncio
async def test_auth_runs_before_body_validation(client, token_set):
    r = await client.post(URL, json={"junk": True}, headers={"X-Ad-Spend-Token": "nope"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_admin_jwt_alone_is_not_enough(client, token_set):
    r = await client.post(URL, json=_body(), headers={"Authorization": "Bearer abc"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_rate_limited(client, token_set, monkeypatch):
    import src.api.ad_spend_router as mod

    monkeypatch.setattr(mod, "_INGEST_PER_MINUTE", 2)
    codes = [(await client.post(URL, json=_body(), headers={"X-Ad-Spend-Token": "bad"}))
             .status_code for _ in range(3)]
    assert codes == [401, 401, 429]


# --- validation ---------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("over", [
    {"day": _day(401)},                         # older than 400 days
    {"day": _day(-3)},                          # in the future
    {"day": "not-a-date"},
    {"cost": "-1"},
    {"cost": "1.234"},                          # more than 2 decimals
    {"cost": "2000000"},                        # above the cap
    {"impressions": -5},
    {"clicks": 3_000_000_000},
    {"campaign": ""},
    {"campaign": "x" * 201},
    {"ad_group": "g" * 201},
    {"unexpected": 1},
])
async def test_bad_rows_are_422(client, token_set, db, over):
    r = await client.post(URL, json=_body(**over), headers={"X-Ad-Spend-Token": TOKEN})
    assert r.status_code == 422
    assert await _rows(db) == []


@pytest.mark.asyncio
async def test_bad_channel_and_too_many_rows_are_422(client, token_set):
    h = {"X-Ad-Spend-Token": TOKEN}
    bad = _body()
    bad["channel"] = "Google Ads!"
    assert (await client.post(URL, json=bad, headers=h)).status_code == 422
    many = {"channel": "google", "rows": _body()["rows"] * 2001}
    assert (await client.post(URL, json=many, headers=h)).status_code == 422


# --- upsert -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_maps_ad_groups_and_resend_overwrites(client, token_set, db):
    h = {"X-Ad-Spend-Token": TOKEN}
    body = {"channel": "google", "rows": [
        {"day": _day(2), "campaign": CAMPAIGN, "ad_group": "scanner", "cost": "5.00",
         "impressions": 100, "clicks": 3},
        {"day": _day(2), "campaign": CAMPAIGN, "ad_group": "claude-code", "cost": "7.50",
         "impressions": 200, "clicks": 4},
        {"day": _day(2), "campaign": CAMPAIGN, "ad_group": "Brand test", "cost": "1",
         "impressions": 10, "clicks": 0},
    ]}
    r = await client.post(URL, json=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 3
    rows = await _rows(db)
    assert {r.utm_content for r in rows} == {"rsa-scanner", "d1-automatic", "Brand test"}
    assert all(r.utm_source == "google" and r.source == "google_ads" for r in rows)

    # Google adjusts the figure; the nightly re-send overwrites, never adds a row.
    body["rows"][0]["cost"] = "6.25"
    body["rows"][0]["clicks"] = 5
    assert (await client.post(URL, json=body, headers=h)).status_code == 200
    assert (await client.post(URL, json=body, headers=h)).status_code == 200
    rows = await _rows(db)
    assert len(rows) == 3
    scanner = next(r for r in rows if r.utm_content == "rsa-scanner")
    assert scanner.spend_usd == Decimal("6.25") and scanner.clicks == 5

    audit = (await db.execute(select(AuditLog).where(
        AuditLog.action == "admin.ad_spend.ingest"))).scalars().all()
    assert audit and audit[-1].details["imported"] == 3
    assert TOKEN not in str([a.details for a in audit])


@pytest.mark.asyncio
async def test_ingest_overwrites_a_manual_google_row_but_not_another_channel(
    client, token_set, db,
):
    db.add(AdSpend(id=uuid.uuid4(), day=datetime.now(timezone.utc).date() - timedelta(days=1),
                   utm_campaign=CAMPAIGN, utm_content="rsa-scanner", utm_source="reddit",
                   spend_usd=Decimal("9.00"), source="manual"))
    await db.flush()
    r = await client.post(URL, json=_body(), headers={"X-Ad-Spend-Token": TOKEN})
    assert r.status_code == 200
    assert r.json()["imported"] == 0 and "reddit" in r.json()["skipped"][0]
    (row,) = await _rows(db)
    assert row.utm_source == "reddit" and row.spend_usd == Decimal("9.00")


@pytest.mark.asyncio
async def test_ad_tag_wins_over_ad_group(client, token_set, db):
    body = _body(ad_tag="custom-tag")
    assert (await client.post(URL, json=body, headers={"X-Ad-Spend-Token": TOKEN})
            ).status_code == 200
    (row,) = await _rows(db)
    assert row.utm_content == "custom-tag"


# --- mapping ------------------------------------------------------------------------


@pytest.mark.parametrize("channel,name,tag", [
    ("google", "scanner", "rsa-scanner"),
    ("google", "Scanner", "rsa-scanner"),
    ("google", "claude-code", "d1-automatic"),
    ("google", "Claude Code", "d1-automatic"),
    ("google", "claude_code", "d1-automatic"),
    ("google", "Something new", "Something new"),
    ("google", "rsa-scanner", "rsa-scanner"),
    ("x", "x1 - archived repos", "x1-archived"),
    ("x", "X2 automatic", "x2-automatic"),
    ("x", "x3-do-not-connect", "x3-do-not-connect"),
    ("x", "Do not connect promo", "x3-do-not-connect"),
    ("x", "Archived tools", "x1-archived"),
    ("x", "Automatic check", "x2-automatic"),
    ("x", "x10 launch", "x10 launch"),
    ("x", "Brand awareness", "Brand awareness"),
    ("twitter", "x2", "x2-automatic"),
    ("reddit", "scanner", "scanner"),
])
def test_ad_tag_for(channel, name, tag):
    assert ad_tag_for(channel, name) == tag


# --- CSV: X and Google exports ------------------------------------------------------


X_CSV = (
    "Time period,Campaign name,Ad name,Impressions,Clicks,Link clicks,Spend,Currency\n"
    "\"Nov 10, 2026\",AgentAvow test,x1 archived,5000,90,40,$10.00,USD\n"
    "\"Nov 10, 2026\",AgentAvow test,X2 automatic,3000,50,20,6.50,USD\n"
    "\"Nov 11, 2026 - Nov 11, 2026\",AgentAvow test,Do not connect,1000,10,5,2.25,USD\n"
    "\"Nov 1, 2026 - Nov 7, 2026\",AgentAvow test,x1 archived,1,1,1,1,USD\n"
)


def test_x_export_maps_ads_and_prefers_link_clicks():
    rows, errors = parse_spend_csv(X_CSV, utm_campaign="2026-11-test-x", utm_source="x")
    by = {(str(r["day"]), r["utm_content"]): r for r in rows}
    assert set(by) == {("2026-11-10", "x1-archived"), ("2026-11-10", "x2-automatic"),
                       ("2026-11-11", "x3-do-not-connect")}
    x1 = by[("2026-11-10", "x1-archived")]
    assert x1["spend_usd"] == Decimal("10.00") and x1["clicks"] == 40
    assert x1["impressions"] == 5000 and x1["utm_campaign"] == "2026-11-test-x"
    assert len(errors) == 1 and "Line 5" in errors[0] and "date" in errors[0]


@pytest.mark.parametrize("header", [
    "Date,Ad,Billed charge (USD),Impressions,URL clicks",
    "Day,Ad name,Amount spent,Impressions,Link clicks",
    "date,ad_name,billed_charge,impressions,url_clicks",
])
def test_x_header_variants(header):
    rows, errors = parse_spend_csv(f"{header}\n2026-11-12,x3 promo,4.00,100,7\n",
                                   utm_campaign="2026-11-test-x", utm_source="x")
    assert errors == []
    (row,) = rows
    assert row["utm_content"] == "x3-do-not-connect"
    assert row["spend_usd"] == Decimal("4.00") and row["clicks"] == 7


GOOGLE_CSV = (
    "Ad group report\n"
    "\"November 6, 2026 - November 12, 2026\"\n"
    "Day,Campaign,Ad group,Currency code,Impr.,Clicks,Cost\n"
    "2026-11-11,2026-11-test-google,scanner,USD,\"1,200\",30,8.40\n"
    "2026-11-11,2026-11-test-google,claude-code,USD,800,12,5.10\n"
    "Total: Campaigns,,,USD,\"2,000\",42,13.50\n"
    "Total: Account,,,USD,\"2,000\",42,13.50\n"
)


def test_google_export_skips_title_and_total_lines():
    rows, errors = parse_spend_csv(GOOGLE_CSV, utm_campaign=None, utm_source="google")
    assert errors == []
    by = {r["utm_content"]: r for r in rows}
    assert set(by) == {"rsa-scanner", "d1-automatic"}
    assert by["rsa-scanner"]["impressions"] == 1200
    assert by["rsa-scanner"]["utm_campaign"] == "2026-11-test-google"


def test_unrecognised_columns_name_what_was_expected():
    rows, errors = parse_spend_csv("Week,Thing,Money\n1,2,3\n", utm_campaign="c",
                                   utm_source="x")
    assert rows == [] and len(errors) == 1
    msg = errors[0]
    assert "Unrecognised columns" in msg and "Time period" in msg and "Billed charge" in msg
    assert '"Week"' in msg


@pytest.mark.asyncio
async def test_csv_dry_run_previews_without_saving(client, db):
    from tests.test_ad_spend import _auth, _token

    token = await _token(client, db, admin=True)
    body = {"csv": X_CSV, "utm_campaign": CAMPAIGN, "utm_source": "x", "dry_run": True}
    r = await client.post("/api/v1/admin/ad-spend/import", headers=_auth(token), json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["row_count"] == 3 and len(out["rows"]) == 3 and len(out["errors"]) == 1
    assert {row["utm_content"] for row in out["rows"]} == {
        "x1-archived", "x2-automatic", "x3-do-not-connect"}
    assert await _rows(db) == []

    body["dry_run"] = False
    r = await client.post("/api/v1/admin/ad-spend/import", headers=_auth(token), json=body)
    assert r.json()["imported"] == 3
    assert len(await _rows(db)) == 3
