"""Tests for the embeddable trust badge endpoint."""
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
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"

USER = {
    "email": "embed_badge_user@example.com",
    "password": "Str0ngP@ss",
    "display_name": "EmbedBadgeUser",
}


async def _setup_user(client: AsyncClient) -> tuple:
    """Register + login, return (token, entity_id)."""
    await client.post(REGISTER_URL, json=USER)
    resp = await client.post(
        LOGIN_URL,
        json={"email": USER["email"], "password": USER["password"]},
    )
    token = resp.json()["access_token"]
    me = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    return token, me.json()["id"]


async def _set_trust_score(db, entity_id: str, score: float) -> None:
    from sqlalchemy import update as _sa_update

    from src.models import TrustScore

    await db.execute(
        _sa_update(TrustScore)
        .where(TrustScore.entity_id == uuid.UUID(entity_id))
        .values(score=score, components={"verification": 1.0, "age": 0.5})
    )
    await db.flush()


# --- SVG format tests ---


@pytest.mark.asyncio
async def test_embed_badge_svg_default(client, db):
    """Default format returns SVG with entity name and score."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.75)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    body = resp.text
    assert "<svg" in body
    assert "AgentAvow" in body
    assert "EmbedBadgeUser" in body
    assert "75" in body  # 0.75 displayed as 75 (0-100 scale)


@pytest.mark.asyncio
async def test_embed_badge_svg_explicit(client, db):
    """?format=svg returns SVG."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.50)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}?format=svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    assert "<svg" in resp.text


@pytest.mark.asyncio
async def test_embed_badge_svg_has_cache_control(client, db):
    """SVG badge has a cache-control header set."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.50)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}")
    assert resp.status_code == 200
    assert "cache-control" in resp.headers


# --- JSON format tests ---


@pytest.mark.asyncio
async def test_embed_badge_json(client, db):
    """?format=json returns structured badge data."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.85)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}?format=json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_id"] == entity_id
    assert data["entity_name"] == "EmbedBadgeUser"
    assert data["trust_score"] == 0.85
    # trust_tier is the 0-100 tier word (dual-mark); 85 → Trusted, green
    assert data["trust_tier"] == "Trusted"
    assert isinstance(data["is_verified"], bool)
    assert data["badge_color"] == "#22C55E"
    assert data["schema_version"] == 1


@pytest.mark.asyncio
async def test_embed_badge_json_trust_tiers(client, db):
    """JSON format returns correct tier labels for different score ranges."""
    _, entity_id = await _setup_user(client)

    # Trusted tier (>= 80)
    await _set_trust_score(db, entity_id, 0.90)
    resp = await client.get(f"/api/v1/badges/embed/{entity_id}?format=json")
    assert resp.json()["trust_tier"] == "Trusted"


# --- Edge cases ---


@pytest.mark.asyncio
async def test_embed_badge_nonexistent_entity(client):
    """Requesting a badge for a nonexistent entity returns 404."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/badges/embed/{fake_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_embed_badge_no_trust_score(client, db):
    """Entity with no trust score gets 0.00 in badge."""
    _, entity_id = await _setup_user(client)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}?format=json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 0.0
    # Score 0 → Blocked (dual-mark tier word)
    assert data["trust_tier"] == "Blocked"


@pytest.mark.asyncio
async def test_embed_badge_invalid_format(client, db):
    """Invalid format query param returns 422."""
    _, entity_id = await _setup_user(client)

    resp = await client.get(f"/api/v1/badges/embed/{entity_id}?format=png")
    assert resp.status_code == 422
