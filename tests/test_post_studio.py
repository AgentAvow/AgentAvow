"""Post Studio: review, accept and track hand-posted marketing, with no way to publish."""
from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from src.database import get_db
from src.main import app
from src.marketing import post_studio as studio
from src.models import AnalyticsEvent, Entity

BASE = "/api/v1/admin/marketing/studio/posts"
ADMIN = {"email": "studio_admin@example.com", "password": "Str0ngP@ss!1",
         "display_name": "StudioAdmin"}
USER = {"email": "studio_user@example.com", "password": "Str0ngP@ss!2",
        "display_name": "StudioUser"}
DRAFT = {
    "platform": "linkedin", "topic": "MCPhantom",
    "content": "Nine archived reference servers now read Review before you connect.",
    "why": "A news hook.", "sources": [{"label": "Report", "url": "https://example.com/r"}],
    "checks": ["Scores rechecked today"], "campaign": "mcphantom-2026-11",
    "target_url": "https://agentavow.com/check",
}


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _token(client, db, who: dict, admin: bool) -> dict:
    await client.post("/api/v1/auth/register", json=who)
    if admin:
        await db.execute(update(Entity).where(Entity.email == who["email"])
                         .values(is_admin=True))
        await db.flush()
    resp = await client.post("/api/v1/auth/login", json={
        "email": who["email"], "password": who["password"]})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _draft(client, headers) -> dict:
    resp = await client.post(BASE, json=DRAFT, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _act(client, headers, post_id, **body):
    return await client.post(f"{BASE}/{post_id}", json=body, headers=headers)


@pytest.mark.asyncio
async def test_admin_only(client, db):
    headers = await _token(client, db, USER, admin=False)
    assert (await client.get(BASE, headers=headers)).status_code == 403
    assert (await client.post(BASE, json=DRAFT, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_full_flow_tracks_edit_link_metrics_and_visits(client, db):
    headers = await _token(client, db, ADMIN, admin=True)
    post = await _draft(client, headers)
    assert post["status"] == studio.REVIEW and post["why"] == "A news hook."

    new_text = "Nine archived servers read Review before you connect. Here is why."
    resp = await _act(client, headers, post["id"], action="accept", content=new_text)
    assert resp.json()["status"] == studio.ACCEPTED and resp.json()["edited"] is True

    resp = await _act(client, headers, post["id"], action="mark_posted",
                      url="https://www.linkedin.com/feed/update/1")
    assert resp.json()["status"] == studio.POSTED and resp.json()["posted_at"]

    resp = await _act(client, headers, post["id"], action="metrics",
                      metrics={"impressions": 500, "likes": 7})
    assert resp.json()["metrics"] == {"impressions": 500, "likes": 7}

    for session in ("a", "a", "b"):
        db.add(AnalyticsEvent(event_type="page_view", session_id=session, page="/check",
                              extra_metadata={"utm_campaign": "mcphantom-2026-11"}))
    await db.flush()
    rows = (await client.get(BASE, headers=headers)).json()
    assert rows[0]["visits"] == 2
    assert [h["action"] for h in rows[0]["history"]] == [
        "drafted", "edited", "accepted", "posted", "metrics"]


@pytest.mark.asyncio
async def test_invalid_steps_are_refused(client, db):
    headers = await _token(client, db, ADMIN, admin=True)
    post = await _draft(client, headers)
    # Cannot record a live post before it is accepted.
    resp = await _act(client, headers, post["id"], action="mark_posted",
                      url="https://x.com/a/status/1")
    assert resp.status_code == 400
    await _act(client, headers, post["id"], action="accept")
    # An accepted post needs a real link, and metrics wait until it is live.
    assert (await _act(client, headers, post["id"], action="mark_posted",
                       url="not a link")).status_code == 400
    assert (await _act(client, headers, post["id"], action="metrics",
                       metrics={"likes": 1})).status_code == 400
    # Accepted copy cannot change without going back to review.
    assert (await _act(client, headers, post["id"], action="edit",
                       content="New words for this post.")).status_code == 400
    assert (await _act(client, headers, post["id"], action="reopen")).json()["status"] == (
        studio.REVIEW)


@pytest.mark.asyncio
async def test_reject_keeps_reason_and_bad_input_is_refused(client, db):
    headers = await _token(client, db, ADMIN, admin=True)
    post = await _draft(client, headers)
    resp = await _act(client, headers, post["id"], action="reject", reason="Off tone")
    assert resp.json()["status"] == studio.REJECTED
    assert resp.json()["history"][-1]["note"] == "Off tone"
    bad = {**DRAFT, "platform": "bluesky"}
    assert (await client.post(BASE, json=bad, headers=headers)).status_code == 400


@pytest.mark.asyncio
async def test_no_path_to_a_platform(client, db):
    """Accepting must never post, even on a platform the old queue auto-posts to."""
    headers = await _token(client, db, ADMIN, admin=True)
    with patch("src.marketing.orchestrator._get_adapters", new=AsyncMock()) as adapters:
        post = await _draft(client, headers)
        await _act(client, headers, post["id"], action="accept")
        await _act(client, headers, post["id"], action="mark_posted",
                   url="https://x.com/a/status/1")
    adapters.assert_not_called()
    root = pathlib.Path(studio.__file__).parents[1]
    for path in (root / "marketing/post_studio.py", root / "api/post_studio_router.py"):
        text = path.read_text()
        assert "adapters" not in text.replace("does not import the platform adapters", "")
        assert "orchestrator" not in text


@pytest.mark.asyncio
async def test_old_queue_and_bot_cannot_touch_studio_rows(client, db):
    from src.marketing.draft_queue import approve_draft, get_pending_drafts

    headers = await _token(client, db, ADMIN, admin=True)
    post = await _draft(client, headers)
    assert post["id"] not in [str(d.id) for d in await get_pending_drafts(db)]
    assert post["id"] not in [str(d.id) for d in await get_pending_drafts(
        db, statuses=["human_review", "draft", "queued"])]
    assert await approve_draft(db, post["id"]) is None
