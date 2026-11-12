"""Ad spend per channel (utm_source), the previous-period total, and the guard that keeps
one channel from overwriting another's spend row."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from src.api.ad_spend_router import channel_of
from tests.test_ad_spend import _auth, _token, client  # noqa: F401 (fixture)

URL = "/api/v1/admin/ad-spend"


def _day(offset: int = 0) -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=offset)).isoformat()


@pytest.mark.parametrize("raw,channel", [
    ("reddit", "reddit"), ("Reddit", "reddit"), ("twitter", "x"), ("X", "x"),
    ("google", "google"), ("  ", "(no utm_source)"), (None, "(no utm_source)"),
    ("newsletter", "newsletter"),
])
def test_channel_of(raw, channel):
    assert channel_of(raw) == channel


async def _visit(client, utm: dict, copy: bool = False) -> None:  # noqa: F811
    sid = str(uuid.uuid4())
    await client.post("/api/v1/analytics/event", json={
        "event_type": "lp_view", "session_id": sid, "page": "/claude-code", "metadata": utm})
    if copy:
        await client.post("/api/v1/analytics/event", json={
            "event_type": "cta_click", "session_id": sid, "page": "/claude-code",
            "intent": "copy_plugin_cmd"})


@pytest.mark.asyncio
async def test_cost_by_channel_lists_every_channel(client, db):  # noqa: F811
    token = await _token(client, db, admin=True)
    reddit = {"utm_source": "reddit", "utm_campaign": "2026-11-test-dev", "utm_content": "d1"}
    x = {"utm_source": "twitter", "utm_campaign": "2026-11-test-x", "utm_content": "x1"}
    for i in range(4):
        await _visit(client, reddit, copy=i < 2)
    await _visit(client, x, copy=True)
    await _visit(client, {"utm_source": "newsletter", "utm_campaign": "nl"})
    for campaign, source, spend in (("2026-11-test-dev", "reddit", "8.00"),
                                    ("2026-11-test-x", "x", "5.00")):
        r = await client.put(URL, headers=_auth(token), json={
            "day": _day(), "utm_campaign": campaign, "utm_source": source,
            "spend_usd": spend})
        assert r.status_code == 200, r.text

    out = (await client.get(f"{URL}/cost-per-action", headers=_auth(token),
                            params={"days": 7, "group_by": "source"})).json()
    rows = {r["channel"]: r for r in out["rows"]}
    assert {"reddit", "x", "google", "newsletter"} <= set(rows)
    assert rows["reddit"]["lp_view"] == 4 and rows["reddit"]["copy_plugin_cmd"] == 2
    assert rows["reddit"]["cost_per_lp_view"] == 2.0
    assert rows["reddit"]["cost_per_copy_plugin_cmd"] == 4.0
    assert rows["x"]["lp_view"] == 1 and rows["x"]["cost_per_copy_plugin_cmd"] == 5.0
    assert rows["google"]["spend_usd"] == 0 and rows["google"]["cost_per_lp_view"] is None
    assert rows["newsletter"]["spend_usd"] == 0 and rows["newsletter"]["lp_view"] == 1
    assert out["total"]["spend_usd"] == 13.0
    assert "previous" not in out

    # The default stays per ad, unchanged.
    by_ad = (await client.get(f"{URL}/cost-per-action", headers=_auth(token),
                              params={"days": 7})).json()
    assert {r["utm_content"] for r in by_ad["rows"]} >= {"d1", "x1"}


@pytest.mark.asyncio
async def test_previous_period_total(client, db):  # noqa: F811
    token = await _token(client, db, admin=True)
    for day, spend in ((_day(0), "4.00"), (_day(3), "6.00"), (_day(9), "20.00"),
                       (_day(20), "100.00")):
        await client.put(URL, headers=_auth(token), json={
            "day": day, "utm_campaign": "c", "utm_content": day, "utm_source": "reddit",
            "spend_usd": spend})
    out = (await client.get(f"{URL}/cost-per-action", headers=_auth(token),
                            params={"days": 7, "previous": "true", "campaign": "c"})).json()
    assert out["total"]["spend_usd"] == 10.0
    assert out["previous"]["spend_usd"] == 20.0
    assert out["previous"]["lp_view"] == 0


@pytest.mark.asyncio
async def test_one_channel_cannot_overwrite_another(client, db):  # noqa: F811
    token = await _token(client, db, admin=True)
    body = {"day": _day(), "utm_campaign": "shared", "utm_content": "a",
            "utm_source": "reddit", "spend_usd": "3.00"}
    assert (await client.put(URL, headers=_auth(token), json=body)).status_code == 200
    r = await client.put(URL, headers=_auth(token), json={**body, "utm_source": "google"})
    assert r.status_code == 409 and "reddit" in r.json()["detail"]
    # Same channel (any spelling) still replaces its own row.
    r = await client.put(URL, headers=_auth(token),
                         json={**body, "utm_source": "Reddit", "spend_usd": "5.00"})
    assert r.status_code == 200
    rows = (await client.get(URL, headers=_auth(token))).json()["rows"]
    assert [x["spend_usd"] for x in rows if x["utm_campaign"] == "shared"] == [5.0]

    csv = f"Date,Ad Name,Amount Spent (USD)\n{_day()},a,9.00\n{_day()},b,1.00\n"
    out = (await client.post(f"{URL}/import", headers=_auth(token), json={
        "csv": csv, "utm_campaign": "shared", "utm_source": "x"})).json()
    assert out["imported"] == 1 and any("already has spend from" in e for e in out["errors"])


@pytest.mark.asyncio
async def test_x_and_google_spend_entry_is_admin_only(client, db):  # noqa: F811
    """A read-only viewer reads the channel view but cannot enter spend."""
    from src.models import Entity

    viewer = await _token(client, db, admin=False)
    me = (await client.get("/api/v1/auth/me", headers=_auth(viewer))).json()
    entity = await db.get(Entity, uuid.UUID(me["id"]))
    entity.is_admin_viewer = True
    await db.flush()
    r = await client.get(f"{URL}/cost-per-action", headers=_auth(viewer),
                         params={"days": 7, "group_by": "source", "previous": "true"})
    assert r.status_code == 200 and "previous" in r.json()
    for source in ("x", "google"):
        r = await client.put(URL, headers=_auth(viewer), json={
            "day": _day(), "utm_campaign": f"2026-11-test-{source}", "utm_source": source,
            "spend_usd": "1.00"})
        assert r.status_code == 403
