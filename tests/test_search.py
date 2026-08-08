from __future__ import annotations

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
SEARCH_URL = "/api/v1/search"
FEED_URL = "/api/v1/feed/posts"

ALICE = {
    "email": "alice@search.com",
    "password": "Str0ngP@ss",
    "display_name": "Alice Wonderland",
}
BOB = {
    "email": "bob@search.com",
    "password": "Str0ngP@ss",
    "display_name": "Bob Builder",
}


async def _setup_user(client: AsyncClient, user: dict) -> str:
    """Register + login, return token."""
    await client.post(REGISTER_URL, json=user)
    resp = await client.post(
        LOGIN_URL, json={"email": user["email"], "password": user["password"]}
    )
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_search_entities_by_name(client: AsyncClient):
    await _setup_user(client, ALICE)
    await _setup_user(client, BOB)

    resp = await client.get(SEARCH_URL, params={"q": "Alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] == 1
    assert data["entities"][0]["display_name"] == "Alice Wonderland"


@pytest.mark.asyncio
async def test_search_returns_both_entities_and_posts(client: AsyncClient):
    token = await _setup_user(client, ALICE)
    await client.post(
        FEED_URL,
        json={"content": "Alice posted something interesting"},
        headers=_auth(token),
    )

    resp = await client.get(SEARCH_URL, params={"q": "Alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] >= 1
    assert data["post_count"] >= 1


@pytest.mark.asyncio
async def test_search_no_results(client: AsyncClient):
    resp = await client.get(SEARCH_URL, params={"q": "nonexistent_xyz_123"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] == 0
    assert data["post_count"] == 0


@pytest.mark.asyncio
async def test_search_filter_by_type(client: AsyncClient):
    await _setup_user(client, ALICE)

    # Search for entities only — should not include posts
    resp = await client.get(SEARCH_URL, params={"q": "Alice", "type": "human"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] >= 1
    assert data["post_count"] == 0


@pytest.mark.asyncio
async def test_search_posts_only(client: AsyncClient):
    token = await _setup_user(client, ALICE)
    await client.post(
        FEED_URL,
        json={"content": "Unique keyword zxywvu"},
        headers=_auth(token),
    )

    resp = await client.get(SEARCH_URL, params={"q": "zxywvu", "type": "post"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_count"] == 0
    assert data["post_count"] == 1


@pytest.mark.asyncio
async def test_search_hidden_posts_excluded(client: AsyncClient):
    token = await _setup_user(client, ALICE)
    post_resp = await client.post(
        FEED_URL,
        json={"content": "Hidden content kqjfmd"},
        headers=_auth(token),
    )
    post_id = post_resp.json()["id"]

    # Delete (hide) the post
    await client.delete(f"{FEED_URL}/{post_id}", headers=_auth(token))

    # Search should not find it
    resp = await client.get(SEARCH_URL, params={"q": "kqjfmd"})
    assert resp.status_code == 200
    assert resp.json()["post_count"] == 0


@pytest.mark.asyncio
async def test_search_entities_endpoint(client: AsyncClient):
    await _setup_user(client, ALICE)
    await _setup_user(client, BOB)

    resp = await client.get(f"{SEARCH_URL}/entities", params={"q": "Bob"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["display_name"] == "Bob Builder"


@pytest.mark.asyncio
async def test_search_requires_query(client: AsyncClient):
    resp = await client.get(SEARCH_URL)
    assert resp.status_code == 422  # missing required param


@pytest.mark.asyncio
async def test_search_includes_community_scans(client: AsyncClient, db):
    """A repo a user publicly scanned (persisted in CommunityScan) must surface
    in global /search under the new ``tools`` array."""
    from src.models import CommunityScan

    scan = CommunityScan(
        owner="acme",
        repo="cool-agent-tool",
        full_name="acme/cool-agent-tool",
        trust_score=88,
        critical=0,
        high=1,
        findings_count=3,
        primary_language="Python",
    )
    db.add(scan)
    await db.flush()

    resp = await client.get(SEARCH_URL, params={"q": "cool-agent-tool"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool_count"] >= 1
    tools = {t["full_name"]: t for t in data["tools"]}
    assert "acme/cool-agent-tool" in tools
    tool = tools["acme/cool-agent-tool"]
    assert tool["owner"] == "acme"
    assert tool["repo"] == "cool-agent-tool"
    assert tool["trust_score"] == 88
    assert tool["grade"] == "A"  # 88 → A (81-95)
    assert tool["last_scanned_at"]

    # Also findable by owner prefix.
    resp = await client.get(SEARCH_URL, params={"q": "acme"})
    assert "acme/cool-agent-tool" in {
        t["full_name"] for t in resp.json()["tools"]
    }


@pytest.mark.asyncio
async def test_search_limit(client: AsyncClient):
    # Create several users
    for i in range(5):
        await _setup_user(
            client,
            {
                "email": f"user{i}@search.com",
                "password": "Str0ngP@ss",
                "display_name": f"SearchUser{i}",
            },
        )

    resp = await client.get(
        SEARCH_URL, params={"q": "SearchUser", "type": "human", "limit": 3}
    )
    assert resp.status_code == 200
    assert resp.json()["entity_count"] == 3
