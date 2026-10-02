"""Tests for A2A Agent Card enrichment endpoints."""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.main import app
from src.models import Entity, EntityType, TrustScore


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

OPERATOR = {
    "email": f"a2a_op_{uuid.uuid4().hex[:6]}@test.com",
    "password": "Str0ngP@ss",
    "display_name": "A2AOperator",
}


async def _setup_operator(client: AsyncClient) -> tuple[str, str]:
    """Register + login, return (token, entity_id)."""
    await client.post(REGISTER_URL, json=OPERATOR)
    resp = await client.post(
        LOGIN_URL, json={"email": OPERATOR["email"], "password": OPERATOR["password"]}
    )
    token = resp.json()["access_token"]
    me = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    return token, me.json()["id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def agent_with_trust(db: AsyncSession) -> Entity:
    """Create an agent entity with a trust score."""
    eid = uuid.uuid4()
    agent = Entity(
        id=eid,
        email=f"a2a_card_{uuid.uuid4().hex[:6]}@test.com",
        display_name="CardTestAgent",
        type=EntityType.AGENT,
        is_active=True,
        did_web=f"did:web:agentgraph.co:agents:{eid}",
        capabilities=["chat", "code-review"],
        framework_source="pydantic_ai",
        framework_trust_modifier=0.90,
        bio_markdown="A test agent for A2A cards",
    )
    db.add(agent)
    ts = TrustScore(id=uuid.uuid4(), entity_id=eid, score=0.75)
    db.add(ts)
    await db.flush()
    return agent


@pytest_asyncio.fixture
async def provisional_agent(db: AsyncSession) -> Entity:
    """Create a provisional agent."""
    eid = uuid.uuid4()
    agent = Entity(
        id=eid,
        email=f"a2a_prov_{uuid.uuid4().hex[:6]}@test.com",
        display_name="ProvisionalBot",
        type=EntityType.AGENT,
        is_active=True,
        did_web=f"did:web:agentgraph.co:agents:{eid}",
        capabilities=["chat"],
        framework_source="openclaw",
        framework_trust_modifier=0.65,
        is_provisional=True,
    )
    db.add(agent)
    ts = TrustScore(id=uuid.uuid4(), entity_id=eid, score=0.25)
    db.add(ts)
    await db.flush()
    return agent


@pytest.mark.asyncio
async def test_get_agent_card(client: AsyncClient, agent_with_trust: Entity):
    """Get an enriched A2A Agent Card."""
    resp = await client.get(f"/api/v1/a2a/agent-card/{agent_with_trust.id}")
    assert resp.status_code == 200
    data = resp.json()

    # A2A standard fields
    assert data["name"] == "CardTestAgent"
    assert data["capabilities"] == ["chat", "code-review"]
    assert "agentavow.com" in data["url"]

    # Trust enrichment
    assert data["trust"]["score"] == 0.75
    assert data["trust"]["tier"] == "established"
    assert data["trust"]["framework_source"] == "pydantic_ai"
    assert data["trust"]["framework_modifier"] == 0.90
    assert data["trust"]["is_provisional"] is False

    # Identity
    assert data["did"] is not None
    assert data["entity_id"] == str(agent_with_trust.id)


@pytest.mark.asyncio
async def test_get_agent_card_not_found(client: AsyncClient):
    """404 for nonexistent agent."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/a2a/agent-card/{fake_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_provisional_agent_card(
    client: AsyncClient, provisional_agent: Entity
):
    """Provisional agents show correct status in card."""
    resp = await client.get(f"/api/v1/a2a/agent-card/{provisional_agent.id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["trust"]["is_provisional"] is True
    assert data["trust"]["tier"] == "new"
    assert data["trust"]["score"] == 0.25
    assert data["trust"]["framework_source"] == "openclaw"


@pytest.mark.asyncio
async def test_trust_tier_mapping(client: AsyncClient, db: AsyncSession):
    """Verify trust tier boundaries."""
    # Create agents at different trust levels
    tiers = [
        (0.85, "trusted"),
        (0.65, "established"),
        (0.40, "developing"),
        (0.10, "new"),
    ]
    for score, expected_tier in tiers:
        eid = uuid.uuid4()
        agent = Entity(
            id=eid,
            display_name=f"Tier{expected_tier}",
            type=EntityType.AGENT,
            is_active=True,
            did_web=f"did:web:agentgraph.co:agents:{eid}",
        )
        db.add(agent)
        ts = TrustScore(id=uuid.uuid4(), entity_id=eid, score=score)
        db.add(ts)
        await db.flush()

        resp = await client.get(f"/api/v1/a2a/agent-card/{eid}")
        assert resp.status_code == 200
        assert resp.json()["trust"]["tier"] == expected_tier, (
            f"Score {score} should be tier '{expected_tier}'"
        )


@pytest.mark.asyncio
async def test_agent_card_no_trust_score(
    client: AsyncClient, db: AsyncSession
):
    """Agent without trust score shows unrated tier."""
    eid = uuid.uuid4()
    agent = Entity(
        id=eid,
        display_name="NoScoreBot",
        type=EntityType.AGENT,
        is_active=True,
        did_web=f"did:web:agentgraph.co:agents:{eid}",
    )
    db.add(agent)
    await db.flush()

    resp = await client.get(f"/api/v1/a2a/agent-card/{eid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["trust"]["score"] is None
    assert data["trust"]["tier"] == "unrated"


@pytest.mark.asyncio
async def test_list_agent_cards(
    client: AsyncClient, agent_with_trust: Entity, provisional_agent: Entity
):
    """List all agent cards."""
    resp = await client.get("/api/v1/a2a/agent-cards")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    assert isinstance(data["agents"], list)


@pytest.mark.asyncio
async def test_list_agent_cards_filter_framework(
    client: AsyncClient, agent_with_trust: Entity, provisional_agent: Entity
):
    """Filter agent cards by framework."""
    resp = await client.get("/api/v1/a2a/agent-cards?framework=pydantic_ai")
    assert resp.status_code == 200
    data = resp.json()
    for card in data["agents"]:
        assert card["trust"]["framework_source"] == "pydantic_ai"


@pytest.mark.asyncio
async def test_list_agent_cards_filter_min_trust(
    client: AsyncClient, agent_with_trust: Entity, provisional_agent: Entity
):
    """Filter agent cards by minimum trust score."""
    resp = await client.get("/api/v1/a2a/agent-cards?min_trust=0.5")
    assert resp.status_code == 200
    data = resp.json()
    for card in data["agents"]:
        assert (card["trust"]["score"] or 0) >= 0.5


@pytest.mark.asyncio
async def test_list_agent_cards_pagination(
    client: AsyncClient, db: AsyncSession
):
    """Pagination works correctly."""
    # Create several agents
    for i in range(5):
        eid = uuid.uuid4()
        agent = Entity(
            id=eid,
            display_name=f"PaginateBot{i}",
            type=EntityType.AGENT,
            is_active=True,
            did_web=f"did:web:agentgraph.co:agents:{eid}",
        )
        db.add(agent)
    await db.flush()

    resp = await client.get("/api/v1/a2a/agent-cards?limit=2&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["agents"]) <= 2
    assert data["has_more"] is True


@pytest.mark.asyncio
async def test_agent_card_includes_interaction_counts(
    client: AsyncClient, agent_with_trust: Entity
):
    """Agent card includes interaction summary."""
    resp = await client.get(f"/api/v1/a2a/agent-card/{agent_with_trust.id}")
    assert resp.status_code == 200
    interactions = resp.json()["interactions"]
    assert "endorsement_count" in interactions
    assert "follower_count" in interactions
    assert "following_count" in interactions
