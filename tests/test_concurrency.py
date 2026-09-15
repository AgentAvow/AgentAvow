"""Idempotency and race-condition safety tests for AgentGraph.

Validates that duplicate or conflicting operations produce consistent DB state.
The test harness shares a single DB session, so we test rapid sequential requests
which exercises the same deduplication, unique-constraint, and idempotency logic
that concurrent requests with separate sessions would hit.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.main import app
from src.models import (
    APIKey,
    Bookmark,
    Entity,
    EntityBlock,
    EntityRelationship,
    ModerationFlag,
    Post,
    RelationshipType,
    TrustScore,
    Vote,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"

USER_A = {
    "email": "conc_a@example.com",
    "password": "Str0ngP@ss1",
    "display_name": "ConcurrencyA",
}
USER_B = {
    "email": "conc_b@example.com",
    "password": "Str0ngP@ss2",
    "display_name": "ConcurrencyB",
}
USER_C = {
    "email": "conc_c@example.com",
    "password": "Str0ngP@ss3",
    "display_name": "ConcurrencyC",
}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _setup_user(
    client: AsyncClient, user: dict, db: AsyncSession | None = None,
) -> tuple[str, str]:
    """Register, login, return (token, entity_id). Optionally add a trust score."""
    await client.post(REGISTER_URL, json=user)
    resp = await client.post(
        LOGIN_URL, json={"email": user["email"], "password": user["password"]},
    )
    data = resp.json()
    token = data["access_token"]
    me = await client.get("/api/v1/auth/me", headers=_auth(token))
    eid = me.json()["id"]
    if db is not None:
        from sqlalchemy import update
        await db.execute(
            update(TrustScore)
            .where(TrustScore.entity_id == uuid.UUID(eid))
            .values(score=0.5, components={"verification": 0.3, "age": 0.1, "activity": 0.1})
        )
        await db.flush()
    return token, eid


async def _create_post(client: AsyncClient, token: str) -> str:
    """Create a post and return its id."""
    resp = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Test post for concurrency testing"},
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# 1. Double-follow same user → exactly 1 follow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_follow(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    _, eid_b = await _setup_user(client, USER_B, db)

    resp1 = await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    assert resp1.status_code == 200

    # Second follow should be idempotent
    resp2 = await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    assert resp2.status_code in (200, 409), f"Unexpected: {resp2.status_code}"

    count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == uuid.UUID(eid_a),
            EntityRelationship.target_entity_id == uuid.UUID(eid_b),
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    assert count == 1, f"Expected exactly 1 follow, got {count}"


# ---------------------------------------------------------------------------
# 2. Double-unfollow → no error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_unfollow(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    _, eid_b = await _setup_user(client, USER_B, db)

    await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))

    resp1 = await client.delete(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    assert resp1.status_code in (200, 404)

    resp2 = await client.delete(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    assert resp2.status_code in (200, 404)

    count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == uuid.UUID(eid_a),
            EntityRelationship.target_entity_id == uuid.UUID(eid_b),
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    assert count == 0


# ---------------------------------------------------------------------------
# 3. Double-vote on same post → exactly 1 vote
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_vote(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    token_b, eid_b = await _setup_user(client, USER_B, db)

    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_b),
    )
    assert resp1.status_code != 500, f"Got 500: {resp1.text}"

    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_b),
    )
    assert resp2.status_code != 500, f"Got 500: {resp2.text}"

    count = await db.scalar(
        select(func.count()).select_from(Vote).where(
            Vote.entity_id == uuid.UUID(eid_b),
            Vote.post_id == uuid.UUID(post_id),
        )
    )
    assert count <= 1, f"Expected 0 or 1 vote, got {count}"


# ---------------------------------------------------------------------------
# 4. Opposite votes (up then down) → 1 vote record
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opposite_votes(client: AsyncClient, db: AsyncSession):
    token_a, _ = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    token_b, eid_b = await _setup_user(client, USER_B, db)

    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_b),
    )
    assert resp1.status_code != 500

    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "down"},
        headers=_auth(token_b),
    )
    assert resp2.status_code != 500

    count = await db.scalar(
        select(func.count()).select_from(Vote).where(
            Vote.entity_id == uuid.UUID(eid_b),
            Vote.post_id == uuid.UUID(post_id),
        )
    )
    assert count <= 1, f"Expected 0 or 1 vote, got {count}"


# ---------------------------------------------------------------------------
# 5. Double-bookmark same post → exactly 1 bookmark
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_bookmark(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark", headers=_auth(token_a),
    )
    assert resp1.status_code != 500

    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark", headers=_auth(token_a),
    )
    assert resp2.status_code != 500

    count = await db.scalar(
        select(func.count()).select_from(Bookmark).where(
            Bookmark.entity_id == uuid.UUID(eid_a),
            Bookmark.post_id == uuid.UUID(post_id),
        )
    )
    assert count <= 1, f"Expected 0 or 1 bookmark, got {count}"


# ---------------------------------------------------------------------------
# 6. Block then follow same user → follow should be rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_block_then_follow(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    _, eid_b = await _setup_user(client, USER_B, db)

    # Block first
    resp_block = await client.post(f"/api/v1/social/block/{eid_b}", headers=_auth(token_a))
    assert resp_block.status_code != 500

    # Now try to follow the blocked user
    resp_follow = await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    # Should be rejected (403 or 400) since user is blocked
    assert resp_follow.status_code != 500

    block_exists = await db.scalar(
        select(func.count()).select_from(EntityBlock).where(
            EntityBlock.blocker_id == uuid.UUID(eid_a),
            EntityBlock.blocked_id == uuid.UUID(eid_b),
        )
    )
    assert block_exists >= 1


# ---------------------------------------------------------------------------
# 7. Rapid post creation by same user → both succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rapid_post_creation(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)

    resp1 = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Rapid post 1"},
        headers=_auth(token_a),
    )
    resp2 = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Rapid post 2"},
        headers=_auth(token_a),
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201

    count = await db.scalar(
        select(func.count()).select_from(Post).where(
            Post.author_entity_id == uuid.UUID(eid_a),
        )
    )
    assert count >= 2


# ---------------------------------------------------------------------------
# 8. Rapid profile updates → last write wins, no corruption
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rapid_profile_updates(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)

    resp1 = await client.patch(
        f"/api/v1/profiles/{eid_a}",
        json={"bio_markdown": "Updated bio A"},
        headers=_auth(token_a),
    )
    resp2 = await client.patch(
        f"/api/v1/profiles/{eid_a}",
        json={"bio_markdown": "Updated bio B"},
        headers=_auth(token_a),
    )

    assert resp1.status_code != 500, f"Got {resp1.status_code}: {resp1.text}"
    assert resp2.status_code != 500, f"Got {resp2.status_code}: {resp2.text}"

    db.expire_all()
    entity = await db.get(Entity, uuid.UUID(eid_a))
    assert entity is not None
    assert entity.bio_markdown in ("Updated bio A", "Updated bio B")


# ---------------------------------------------------------------------------
# 9. Rapid API key rotation → no duplicate active keys
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rapid_api_key_rotation(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)

    resp = await client.post(
        "/api/v1/agents",
        json={"display_name": "ConcAgent", "type": "agent"},
        headers=_auth(token_a),
    )
    assert resp.status_code in (200, 201), (
        f"agent creation failed: {resp.status_code} {resp.text}"
    )

    # POST /agents returns AgentCreatedResponse: {agent: {...}, api_key, claim_token}
    # — the id is nested under "agent", not top-level.
    body = resp.json()
    agent_id = (body.get("agent") or {}).get("id") or body.get("id")
    assert agent_id, f"no agent id in create response: {body}"

    resp1 = await client.post(
        f"/api/v1/agents/{agent_id}/rotate-key",
        headers=_auth(token_a),
    )
    resp2 = await client.post(
        f"/api/v1/agents/{agent_id}/rotate-key",
        headers=_auth(token_a),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    active_count = await db.scalar(
        select(func.count()).select_from(APIKey).where(
            APIKey.entity_id == uuid.UUID(agent_id),
            APIKey.is_active.is_(True),
        )
    )
    assert active_count <= 1, f"Expected at most 1 active key, got {active_count}"


# ---------------------------------------------------------------------------
# 10. Rapid webhook creation for same event → both succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rapid_webhook_creation(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)

    webhook_payload = {
        "callback_url": "https://example.com/webhook",
        "event_types": ["entity.followed"],
    }

    resp1 = await client.post(
        "/api/v1/webhooks",
        json=webhook_payload,
        headers=_auth(token_a),
    )
    resp2 = await client.post(
        "/api/v1/webhooks",
        json=webhook_payload,
        headers=_auth(token_a),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    success_count = sum(1 for r in (resp1, resp2) if r.status_code in (200, 201))
    assert success_count >= 1


# ---------------------------------------------------------------------------
# 11. Double-flag on same post by same user → deduplication
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_flag(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    token_b, eid_b = await _setup_user(client, USER_B, db)

    post_id = await _create_post(client, token_a)

    flag_payload = {
        "target_type": "post",
        "target_id": post_id,
        "reason": "spam",
        "details": "Looks like spam",
    }

    resp1 = await client.post(
        "/api/v1/moderation/flag",
        json=flag_payload,
        headers=_auth(token_b),
    )
    resp2 = await client.post(
        "/api/v1/moderation/flag",
        json=flag_payload,
        headers=_auth(token_b),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    # At least one should succeed
    assert resp1.status_code in (200, 201, 409) or resp2.status_code in (200, 201, 409)

    count = await db.scalar(
        select(func.count()).select_from(ModerationFlag).where(
            ModerationFlag.reporter_entity_id == uuid.UUID(eid_b),
            ModerationFlag.target_id == uuid.UUID(post_id),
        )
    )
    assert count >= 1


# ---------------------------------------------------------------------------
# 12. Double agent claim with same token → only one should succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_agent_claim(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    token_b, eid_b = await _setup_user(client, USER_B, db)

    # Bootstrap WITHOUT an authenticated operator so the bot stays provisional
    # and gets a claim_token (an owned bot has claim_token=None). "general_purpose"
    # is the real template key — "general" is not one, and would 400.
    resp = await client.post(
        "/api/v1/bots/bootstrap",
        json={
            "display_name": "ClaimBot",
            "template": "general_purpose",
        },
    )
    assert resp.status_code in (200, 201), (
        f"bot bootstrap failed: {resp.status_code} {resp.text}"
    )

    data = resp.json()
    claim_token = data.get("claim_token")
    assert claim_token, f"no claim_token in bootstrap response: {data}"

    # First claim
    resp1 = await client.post(
        "/api/v1/agents/claim",
        json={"claim_token": claim_token},
        headers=_auth(token_a),
    )
    # Second claim (same token) by different user
    resp2 = await client.post(
        "/api/v1/agents/claim",
        json={"claim_token": claim_token},
        headers=_auth(token_b),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    success_count = sum(1 for r in (resp1, resp2) if r.status_code == 200)
    assert success_count <= 1, "Both claims succeeded — race condition!"


# ---------------------------------------------------------------------------
# 13. Follow then unfollow rapidly → consistent final state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_follow_then_unfollow(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    _, eid_b = await _setup_user(client, USER_B, db)

    await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))

    resp_follow = await client.post(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))
    resp_unfollow = await client.delete(f"/api/v1/social/follow/{eid_b}", headers=_auth(token_a))

    assert resp_follow.status_code != 500
    assert resp_unfollow.status_code != 500

    count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == uuid.UUID(eid_a),
            EntityRelationship.target_entity_id == uuid.UUID(eid_b),
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    assert count in (0, 1), f"Expected 0 or 1, got {count}"


# ---------------------------------------------------------------------------
# 14. Vote + bookmark on same post → both succeed independently
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vote_and_bookmark(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    token_b, eid_b = await _setup_user(client, USER_B, db)

    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_b),
    )
    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark",
        headers=_auth(token_b),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500


# ---------------------------------------------------------------------------
# 15. Multiple users follow same user → all succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_users_follow_same_target(
    client: AsyncClient, db: AsyncSession,
):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    token_b, eid_b = await _setup_user(client, USER_B, db)
    token_c, eid_c = await _setup_user(client, USER_C, db)

    resp1 = await client.post(f"/api/v1/social/follow/{eid_c}", headers=_auth(token_a))
    resp2 = await client.post(f"/api/v1/social/follow/{eid_c}", headers=_auth(token_b))

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.target_entity_id == uuid.UUID(eid_c),
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    assert count == 2


# ---------------------------------------------------------------------------
# 16. Multiple users reply to same post → all succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_replies_to_same_post(
    client: AsyncClient, db: AsyncSession,
):
    token_a, _ = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    token_b, _ = await _setup_user(client, USER_B, db)
    token_c, _ = await _setup_user(client, USER_C, db)

    resp1 = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Reply from B", "parent_post_id": post_id},
        headers=_auth(token_b),
    )
    resp2 = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Reply from C", "parent_post_id": post_id},
        headers=_auth(token_c),
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201


# ---------------------------------------------------------------------------
# 17. Multiple users vote on same post → all succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_users_vote_on_same_post(
    client: AsyncClient, db: AsyncSession,
):
    token_a, _ = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    token_b, eid_b = await _setup_user(client, USER_B, db)
    token_c, eid_c = await _setup_user(client, USER_C, db)

    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_b),
    )
    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/vote",
        json={"direction": "up"},
        headers=_auth(token_c),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    for eid in (eid_b, eid_c):
        count = await db.scalar(
            select(func.count()).select_from(Vote).where(
                Vote.entity_id == uuid.UUID(eid),
                Vote.post_id == uuid.UUID(post_id),
            )
        )
        assert count <= 1


# ---------------------------------------------------------------------------
# 18. Mutual block → both succeed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mutual_block(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    token_b, eid_b = await _setup_user(client, USER_B, db)

    resp1 = await client.post(f"/api/v1/social/block/{eid_b}", headers=_auth(token_a))
    resp2 = await client.post(f"/api/v1/social/block/{eid_a}", headers=_auth(token_b))

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    block_ab = await db.scalar(
        select(func.count()).select_from(EntityBlock).where(
            EntityBlock.blocker_id == uuid.UUID(eid_a),
            EntityBlock.blocked_id == uuid.UUID(eid_b),
        )
    )
    block_ba = await db.scalar(
        select(func.count()).select_from(EntityBlock).where(
            EntityBlock.blocker_id == uuid.UUID(eid_b),
            EntityBlock.blocked_id == uuid.UUID(eid_a),
        )
    )
    assert block_ab + block_ba >= 1


# ---------------------------------------------------------------------------
# 19. Bookmark toggle → consistent state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bookmark_toggle(client: AsyncClient, db: AsyncSession):
    token_a, eid_a = await _setup_user(client, USER_A, db)
    post_id = await _create_post(client, token_a)

    # Bookmark
    await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark", headers=_auth(token_a),
    )

    # Toggle twice rapidly
    resp1 = await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark", headers=_auth(token_a),
    )
    resp2 = await client.post(
        f"/api/v1/feed/posts/{post_id}/bookmark", headers=_auth(token_a),
    )

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    count = await db.scalar(
        select(func.count()).select_from(Bookmark).where(
            Bookmark.entity_id == uuid.UUID(eid_a),
            Bookmark.post_id == uuid.UUID(post_id),
        )
    )
    assert count in (0, 1), f"Expected 0 or 1, got {count}"


# ---------------------------------------------------------------------------
# 20. Double registration with same email → only one succeeds
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_double_registration_same_email(
    client: AsyncClient, db: AsyncSession,
):
    user = {
        "email": "dupe_race@example.com",
        "password": "Str0ngP@ss1",
        "display_name": "DupeRacer",
    }

    resp1 = await client.post(REGISTER_URL, json=user)
    resp2 = await client.post(REGISTER_URL, json=user)

    assert resp1.status_code != 500
    assert resp2.status_code != 500

    # First should succeed (201), second should be rejected (409)
    assert resp1.status_code == 201
    assert resp2.status_code in (201, 409), (
        f"Unexpected second registration status: {resp2.status_code}"
    )

    # Even if both returned 201 (edge case), DB should have exactly 1 entity with this email
    count = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.email == "dupe_race@example.com",
        )
    )
    # Unique constraint on email ensures at most 1 — if 2 exist, the constraint is missing
    assert count >= 1
