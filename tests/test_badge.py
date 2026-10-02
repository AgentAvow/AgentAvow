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
    "email": "trust_badge_user@example.com",
    "password": "Str0ngP@ss",
    "display_name": "TrustBadgeUser",
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
    from sqlalchemy import update

    from src.models import TrustScore

    await db.execute(
        update(TrustScore)
        .where(TrustScore.entity_id == uuid.UUID(entity_id))
        .values(
            score=score,
            components={"verification": 1.0, "age": 0.5, "activity": 0.5,
                         "reputation": 0.5, "community": 0.5},
        )
    )
    await db.flush()


# --- Tests ---


@pytest.mark.asyncio
async def test_trust_badge_svg_valid_entity(client, db):
    """A valid entity returns an SVG badge with correct content type."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.85)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"

    body = resp.text
    assert "<svg" in body
    assert "AgentAvow Trust" in body
    assert "85/100" in body  # numbers-only: 0.85 → "85/100" (dual-mark pivot)


@pytest.mark.asyncio
async def test_trust_badge_svg_nonexistent_entity(client):
    """Requesting a badge for a nonexistent entity returns 404."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/badges/trust/{fake_id}.svg")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_trust_badge_svg_no_trust_score(client, db):
    """An entity with no trust score record gets a badge showing 0."""
    _, entity_id = await _setup_user(client)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    body = resp.text
    # Numbers-only: score 0 renders the value text "0/100" (no letter grade)
    assert ">0/100<" in body


@pytest.mark.asyncio
async def test_trust_badge_color_gray(client, db):
    """Trust score 15 is the 'Restricted' tier (11-30) → orange; 5 is 'Blocked' → red."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.15)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert "#F97316" in resp.text  # Restricted — orange (11-30)

    await _set_trust_score(db, entity_id, 0.05)
    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert "#EF4444" in resp.text  # Blocked — red (0-10)


@pytest.mark.asyncio
async def test_trust_badge_color_amber(client, db):
    """Trust score 45 is the 'Minimal' tier (31-50) → amber."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.45)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert "#F59E0B" in resp.text  # Minimal — amber (31-50)


@pytest.mark.asyncio
async def test_trust_badge_color_teal(client, db):
    """Trust score 70 is the 'Standard' tier (51-80) → lighter green."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.70)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    # Six-tier floors (src/trust_tiers.py): 51-80 = Standard = #5BBF3A
    assert "#5BBF3A" in resp.text


@pytest.mark.asyncio
async def test_trust_badge_color_bright_teal(client, db):
    """Trust score 90 is the 'Trusted' tier (81-95) → green; 97 is 'Verified' → deeper green."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.90)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert "#22C55E" in resp.text  # Trusted — green (81-95)

    await _set_trust_score(db, entity_id, 0.97)
    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    assert "#16A34A" in resp.text  # Verified — deeper green (96+)


@pytest.mark.asyncio
async def test_trust_badge_value_text(client, db):
    """Score 0.50 renders the numeric value '50/100' in the badge (no letter)."""
    _, entity_id = await _setup_user(client)
    await _set_trust_score(db, entity_id, 0.50)

    resp = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert resp.status_code == 200
    # Numbers-only badge: value text is "50/100"
    assert ">50/100<" in resp.text
