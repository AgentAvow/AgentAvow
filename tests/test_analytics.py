from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    # A real browser string: the funnel leaves out events whose UA class is "bot",
    # and httpx's default ("python-httpx/…") is one.
    async with AsyncClient(
        transport=transport, base_url="http://test", headers={"User-Agent": BROWSER_UA},
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
HEADLESS_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/131.0.0.0 Safari/537.36"
)

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
ANALYTICS_URL = "/api/v1/analytics"

USER = {
    "email": "analyticsuser@example.com",
    "password": "Str0ngP@ss",
    "display_name": "AnalyticsUser",
}
ADMIN = {
    "email": "analyticsadmin@example.com",
    "password": "Str0ngP@ss",
    "display_name": "AnalyticsAdmin",
}


async def _setup_user(client: AsyncClient, user: dict) -> tuple[str, str]:
    await client.post(REGISTER_URL, json=user)
    resp = await client.post(
        LOGIN_URL, json={"email": user["email"], "password": user["password"]}
    )
    token = resp.json()["access_token"]
    me = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})
    return token, me.json()["id"]


async def _make_admin(db, entity_id: str):
    from src.models import Entity

    entity = await db.get(Entity, uuid.UUID(entity_id))
    entity.is_admin = True
    await db.flush()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- POST /analytics/event ---


@pytest.mark.asyncio
async def test_track_event_no_auth(client: AsyncClient):
    """POST event should succeed without authentication."""
    resp = await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_page_view",
        "session_id": str(uuid.uuid4()),
        "page": "/feed",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_track_event_with_intent(client: AsyncClient):
    """POST event with intent and referrer."""
    resp = await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_cta_click",
        "session_id": str(uuid.uuid4()),
        "page": "/feed",
        "intent": "vote",
        "referrer": "https://google.com",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_track_event_invalid_type(client: AsyncClient):
    """POST event with invalid event_type should return 422."""
    resp = await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "invalid_event",
        "session_id": str(uuid.uuid4()),
        "page": "/feed",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_track_event_missing_fields(client: AsyncClient):
    """POST event without required fields should return 422."""
    resp = await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_page_view",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_track_all_event_types(client: AsyncClient):
    """All allowed event types should be accepted."""
    session_id = str(uuid.uuid4())
    for event_type in [
        "guest_page_view",
        "guest_cta_click",
        "register_start",
        "register_complete",
        "first_action",
    ]:
        resp = await client.post(f"{ANALYTICS_URL}/event", json={
            "event_type": event_type,
            "session_id": session_id,
            "page": "/test",
        })
        assert resp.status_code == 200, f"Failed for {event_type}"


@pytest.mark.asyncio
async def test_track_event_with_metadata(client: AsyncClient):
    """POST event with custom metadata."""
    resp = await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_page_view",
        "session_id": str(uuid.uuid4()),
        "page": "/feed",
        "metadata": {"scroll_depth": 75, "time_on_page": 30},
    })
    assert resp.status_code == 200


# --- GET /analytics/conversion (admin) ---


@pytest.mark.asyncio
async def test_conversion_funnel_admin(client: AsyncClient, db):
    """Admin should see conversion funnel data."""
    admin_token, admin_id = await _setup_user(client, ADMIN)
    await _make_admin(db, admin_id)

    # Seed some events
    session_id = str(uuid.uuid4())
    for event_type in ["guest_page_view", "guest_cta_click", "register_start"]:
        await client.post(f"{ANALYTICS_URL}/event", json={
            "event_type": event_type,
            "session_id": session_id,
            "page": "/feed",
            "intent": "vote",
        })

    resp = await client.get(
        f"{ANALYTICS_URL}/conversion",
        params={"days": 30},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    assert len(data["funnel"]) == 5
    assert data["total_events"] >= 3
    assert len(data["top_pages"]) >= 1
    assert len(data["top_intents"]) >= 1

    # Verify funnel structure
    for step in data["funnel"]:
        assert "event_type" in step
        assert "count" in step
        assert "conversion_rate" in step


@pytest.mark.asyncio
async def test_conversion_funnel_non_admin(client: AsyncClient):
    """Non-admin should get 403."""
    token, _ = await _setup_user(client, USER)
    resp = await client.get(
        f"{ANALYTICS_URL}/conversion",
        headers=_auth(token),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_conversion_funnel_unauthenticated(client: AsyncClient):
    """Unauthenticated should get 401."""
    resp = await client.get(f"{ANALYTICS_URL}/conversion")
    assert resp.status_code == 401


# --- GET /analytics/conversion/daily (admin) ---


@pytest.mark.asyncio
async def test_daily_conversion_admin(client: AsyncClient, db):
    """Admin should see daily breakdown."""
    admin_token, admin_id = await _setup_user(client, ADMIN)
    await _make_admin(db, admin_id)

    # Seed an event
    await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_page_view",
        "session_id": str(uuid.uuid4()),
        "page": "/feed",
    })

    resp = await client.get(
        f"{ANALYTICS_URL}/conversion/daily",
        params={"days": 7},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 7
    assert isinstance(data["daily"], list)
    assert len(data["daily"]) >= 1
    assert "date" in data["daily"][0]
    assert "guest_page_view" in data["daily"][0]


@pytest.mark.asyncio
async def test_daily_conversion_non_admin(client: AsyncClient):
    """Non-admin should get 403."""
    token, _ = await _setup_user(client, USER)
    resp = await client.get(
        f"{ANALYTICS_URL}/conversion/daily",
        headers=_auth(token),
    )
    assert resp.status_code == 403


# --- No PII ---


@pytest.mark.asyncio
async def test_no_pii_stored(client: AsyncClient, db):
    """Analytics events should not contain PII (email, name, etc)."""
    from src.models import AnalyticsEvent

    session_id = str(uuid.uuid4())
    await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "guest_page_view",
        "session_id": session_id,
        "page": "/feed",
        "metadata": {"some_data": "test"},
    })
    await db.flush()

    from sqlalchemy import select

    result = await db.execute(
        select(AnalyticsEvent).where(AnalyticsEvent.session_id == session_id)
    )
    event = result.scalar_one_or_none()
    assert event is not None
    # Verify no PII fields — only anonymous session_id and page data
    assert event.entity_id is None  # No user linked for guest events
    assert "@" not in (event.page or "")
    assert "@" not in (event.session_id or "")


# --- Register with session_id analytics hook ---


@pytest.mark.asyncio
async def test_register_records_analytics_event(client: AsyncClient, db):
    """Registration with session_id should create register_complete event."""
    from sqlalchemy import select

    from src.models import AnalyticsEvent

    session_id = str(uuid.uuid4())
    resp = await client.post(
        f"{REGISTER_URL}?session_id={session_id}",
        json={
            "email": "analytics_hook@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AnalyticsHook",
        },
    )
    assert resp.status_code == 201
    await db.flush()

    result = await db.execute(
        select(AnalyticsEvent).where(
            AnalyticsEvent.session_id == session_id,
            AnalyticsEvent.event_type == "register_complete",
        )
    )
    event = result.scalar_one_or_none()
    assert event is not None
    assert event.entity_id is not None
    assert event.page == "/register"


def test_track_event_uses_its_own_rate_limit_bucket():
    """Page-view events must not share (and exhaust) the 20/min write bucket."""
    from src.api import analytics_router
    from src.api.rate_limit import ANALYTICS_EVENTS_PER_MINUTE, rate_limit_analytics

    route = next(r for r in analytics_router.router.routes if r.path.endswith("/event"))
    deps = [d.dependency for d in route.dependencies]
    assert rate_limit_analytics in deps
    assert ANALYTICS_EVENTS_PER_MINUTE >= 60


# --- First-party tracking events and first touch ---


async def _send(client: AsyncClient, event_type: str, session_id: str, ua: str | None = None,
                **extra):
    return await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": event_type, "session_id": session_id, "page": "/", **extra,
    }, headers={"User-Agent": ua} if ua else None)


def _utm(campaign: str = "2026-11-test-dev") -> dict:
    return {"utm_source": "reddit", "utm_medium": "paid-social", "utm_campaign": campaign,
            "utm_content": "d1-before-npx", "utm_term": "r-mcp"}


async def _first_touch(db, session_id: str):
    from src.models import AnalyticsFirstTouch

    return await db.get(AnalyticsFirstTouch, session_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", [
    "lp_view", "check_submit", "result_view", "badge_copied", "contact_submit",
])
async def test_tracking_events_are_accepted(client: AsyncClient, event_type: str):
    resp = await _send(client, event_type, str(uuid.uuid4()))
    assert resp.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("destination", [
    "copy_plugin_cmd", "open_plugin_dir", "add_claude", "add_chatgpt",
])
async def test_cta_click_accepts_each_destination(client: AsyncClient, destination: str):
    resp = await _send(client, "cta_click", str(uuid.uuid4()), intent=destination)
    assert resp.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("intent", [None, "somewhere_else"])
async def test_cta_click_rejects_unknown_destination(client: AsyncClient, intent):
    resp = await _send(client, "cta_click", str(uuid.uuid4()), intent=intent)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_first_touch_stores_all_five_tags_and_landing_page(client: AsyncClient, db):
    session_id = str(uuid.uuid4())
    await client.post(f"{ANALYTICS_URL}/event", json={
        "event_type": "lp_view", "session_id": session_id, "page": "/check", "metadata": _utm(),
    })

    touch = await _first_touch(db, session_id)
    assert (touch.utm_source, touch.utm_medium, touch.utm_campaign) == (
        "reddit", "paid-social", "2026-11-test-dev",
    )
    assert (touch.utm_content, touch.utm_term) == ("d1-before-npx", "r-mcp")
    assert touch.landing_page == "/check"


@pytest.mark.asyncio
async def test_first_touch_is_not_replaced_by_a_later_campaign(client: AsyncClient, db):
    session_id = str(uuid.uuid4())
    await _send(client, "lp_view", session_id, metadata=_utm("first"))
    await _send(client, "lp_view", session_id, metadata=_utm("second"))

    touch = await _first_touch(db, session_id)
    assert touch.utm_campaign == "first"


@pytest.mark.asyncio
async def test_first_touch_skips_events_without_usable_tags(client: AsyncClient, db):
    session_id = str(uuid.uuid4())
    await _send(client, "lp_view", session_id)
    await _send(client, "lp_view", session_id, metadata={"utm_source": 5, "utm_term": "  "})

    assert await _first_touch(db, session_id) is None


@pytest.mark.asyncio
async def test_first_touch_clips_long_tags_to_fit_its_columns(client: AsyncClient, db):
    session_id = str(uuid.uuid4())
    await _send(client, "lp_view", session_id, metadata={"utm_source": "x" * 500})

    touch = await _first_touch(db, session_id)
    assert touch.utm_source == "x" * 200


def test_first_touch_tags_strips_nul_bytes():
    from src.api.analytics_router import _first_touch_tags

    assert _first_touch_tags({"utm_source": "a\x00b", "utm_term": "\x00"}) == {"utm_source": "ab"}
    assert _first_touch_tags(None) == {}


@pytest.mark.asyncio
async def test_campaign_view_counts_a_return_visit_toward_the_first_touch(
    client: AsyncClient, db,
):
    token, entity_id = await _setup_user(client, ADMIN)
    await _make_admin(db, entity_id)

    first = str(uuid.uuid4())
    await _send(client, "lp_view", first, metadata=_utm())
    # The return visit: a new tab, so the events carry no UTM tags.
    await _send(client, "lp_view", first)
    await _send(client, "check_submit", first)
    await _send(client, "cta_click", first, intent="add_claude")
    await _send(client, "badge_copied", first, intent="badge")

    second = str(uuid.uuid4())
    await _send(client, "lp_view", second, metadata=_utm())
    await _send(client, "guest_page_view", str(uuid.uuid4()))  # no campaign: not in the view

    resp = await client.get(f"{ANALYTICS_URL}/attribution/campaigns", headers=_auth(token))
    assert resp.status_code == 200
    rows = resp.json()["campaigns"]
    assert len(rows) == 1
    row = rows[0]
    assert (row["campaign"], row["content"], row["term"]) == (
        "2026-11-test-dev", "d1-before-npx", "r-mcp",
    )
    assert row["sessions"] == 2
    assert row["lp_view"] == 2  # distinct sessions, not events
    assert row["check_submit"] == 1
    assert row["add_claude"] == 1
    assert row["add_chatgpt"] == 0
    assert row["badge_copied"] == 1


@pytest.mark.asyncio
async def test_campaign_view_is_admin_only(client: AsyncClient):
    token, _ = await _setup_user(client, USER)
    resp = await client.get(f"{ANALYTICS_URL}/attribution/campaigns", headers=_auth(token))
    assert resp.status_code == 403


# --- Bots, IP hashing (t30) ---


async def _event(db, session_id: str):
    from sqlalchemy import select

    from src.models import AnalyticsEvent

    return (await db.execute(
        select(AnalyticsEvent).where(AnalyticsEvent.session_id == session_id)
    )).scalars().first()


@pytest.mark.asyncio
@pytest.mark.parametrize("ua,expected", [
    (BROWSER_UA, "browser"), (BOT_UA, "bot"), (HEADLESS_UA, "bot"), ("", "unknown"),
])
async def test_event_stores_a_coarse_ua_class_not_the_ua(client: AsyncClient, db, ua, expected):
    sid = str(uuid.uuid4())
    resp = await _send(client, "lp_view", sid, ua=ua or " ")
    assert resp.status_code == 200
    ev = await _event(db, sid)
    assert ev.ua_class == expected
    # The UA string itself is stored nowhere on the row.
    stored = " ".join(str(v) for v in (ev.page, ev.intent, ev.referrer, ev.extra_metadata))
    assert "Googlebot" not in stored and "Chrome/131" not in stored


@pytest.mark.asyncio
async def test_event_stores_a_salted_ip_hash_not_the_ip(client: AsyncClient, db, monkeypatch):
    from src.api import metrics_dashboard_router as md

    async def fake_hash(value, length=32):
        return f"h:{value}"[:length] if value else None

    monkeypatch.setattr(md, "daily_salted_hash", fake_hash)
    sid = str(uuid.uuid4())
    await _send(client, "lp_view", sid)
    ev = await _event(db, sid)
    assert ev.ip_address is None
    assert ev.ip_hash == "h:127.0.0.1"


@pytest.mark.asyncio
async def test_no_raw_ip_when_the_salt_is_unavailable(client: AsyncClient, db, monkeypatch):
    from src.api import metrics_dashboard_router as md

    async def no_salt(value, length=32):
        return None

    monkeypatch.setattr(md, "daily_salted_hash", no_salt)
    sid = str(uuid.uuid4())
    await _send(client, "lp_view", sid)
    ev = await _event(db, sid)
    assert ev.ip_address is None and ev.ip_hash is None


@pytest.mark.asyncio
async def test_daily_salted_hash_is_stable_within_a_day_and_never_the_raw_value():
    from src.api.metrics_dashboard_router import daily_salted_hash

    a = await daily_salted_hash("203.0.113.9")
    b = await daily_salted_hash("203.0.113.9")
    if a is None:  # no Redis in this environment: the hash is withheld, never the IP
        assert b is None
        return
    assert a == b and len(a) == 32 and "203.0.113.9" not in a
    assert a != await daily_salted_hash("203.0.113.10")
    assert await daily_salted_hash(None) is None


@pytest.mark.asyncio
async def test_bots_are_left_out_of_the_campaign_funnel(client: AsyncClient, db):
    token, entity_id = await _setup_user(client, ADMIN)
    await _make_admin(db, entity_id)
    person = str(uuid.uuid4())
    await _send(client, "lp_view", person, metadata=_utm())
    await _send(client, "cta_click", person, intent="copy_plugin_cmd")
    for ua in (BOT_UA, HEADLESS_UA):
        crawler = str(uuid.uuid4())
        await _send(client, "lp_view", crawler, ua=ua, metadata=_utm())
        await _send(client, "cta_click", crawler, ua=ua, intent="copy_plugin_cmd")

    rows = (await client.get(
        f"{ANALYTICS_URL}/attribution/campaigns", headers=_auth(token))).json()["campaigns"]
    assert len(rows) == 1
    assert (rows[0]["sessions"], rows[0]["lp_view"], rows[0]["copy_plugin_cmd"]) == (1, 1, 1)

    from sqlalchemy import func, select

    from src.models import AnalyticsEvent

    all_events = await db.scalar(select(func.count()).select_from(AnalyticsEvent))
    bots = await db.scalar(select(func.count()).select_from(AnalyticsEvent).where(
        AnalyticsEvent.ua_class == "bot"))
    assert bots == 4
    conv = (await client.get(f"{ANALYTICS_URL}/conversion", headers=_auth(token))).json()
    assert conv["total_events"] == all_events - bots


@pytest.mark.asyncio
async def test_events_without_a_class_still_count(client: AsyncClient, db):
    """Rows written before t30 have no ua_class; the funnel keeps them."""
    from src.models import AnalyticsEvent, AnalyticsFirstTouch

    token, entity_id = await _setup_user(client, ADMIN)
    await _make_admin(db, entity_id)
    sid = str(uuid.uuid4())
    db.add(AnalyticsFirstTouch(session_id=sid, utm_campaign="old", landing_page="/"))
    db.add(AnalyticsEvent(event_type="lp_view", session_id=sid, page="/",
                          ip_address="198.51.100.1"))
    await db.flush()
    rows = (await client.get(
        f"{ANALYTICS_URL}/attribution/campaigns", headers=_auth(token))).json()["campaigns"]
    assert [r["lp_view"] for r in rows if r["campaign"] == "old"] == [1]
