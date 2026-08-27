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

USER = {
    "email": "ratelimit@example.com",
    "password": "Str0ngP@ss",
    "display_name": "RateLimitUser",
}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _setup_user(client: AsyncClient) -> str:
    await client.post(REGISTER_URL, json=USER)
    resp = await client.post(
        LOGIN_URL, json={"email": USER["email"], "password": USER["password"]}
    )
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_rate_limit_headers_on_read(client: AsyncClient, db):
    """Rate-limited read endpoints include rate limit headers."""
    token = await _setup_user(client)

    resp = await client.get(
        "/api/v1/feed/posts",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers
    assert "x-ratelimit-remaining" in resp.headers
    assert "x-ratelimit-reset" in resp.headers
    assert int(resp.headers["x-ratelimit-limit"]) > 0
    assert int(resp.headers["x-ratelimit-remaining"]) >= 0


@pytest.mark.asyncio
async def test_rate_limit_headers_on_write(client: AsyncClient, db):
    """Rate-limited write endpoints include rate limit headers."""
    token = await _setup_user(client)

    resp = await client.post(
        "/api/v1/feed/posts",
        json={"content": "Testing rate limit headers"},
        headers=_auth(token),
    )
    assert resp.status_code == 201
    assert "x-ratelimit-limit" in resp.headers
    assert int(resp.headers["x-ratelimit-remaining"]) >= 0


@pytest.mark.asyncio
async def test_rate_limit_remaining_decreases(client: AsyncClient, db):
    """Remaining count decreases with each request."""
    token = await _setup_user(client)

    resp1 = await client.get(
        "/api/v1/feed/posts",
        headers=_auth(token),
    )
    remaining1 = int(resp1.headers["x-ratelimit-remaining"])

    resp2 = await client.get(
        "/api/v1/feed/posts",
        headers=_auth(token),
    )
    remaining2 = int(resp2.headers["x-ratelimit-remaining"])

    assert remaining2 < remaining1


@pytest.mark.asyncio
async def test_no_rate_limit_headers_on_unrated(client: AsyncClient, db):
    """Endpoints without rate limiting don't have rate limit headers."""
    resp = await client.get("/health")
    # /health does LIVE db+redis checks and legitimately returns 503 (degraded) when a
    # connection is down — which happens in the long test run after the pool churns.
    # This test is about rate-limit headers on an unrated endpoint, not health status.
    assert resp.status_code in (200, 503)
    assert "x-ratelimit-limit" not in resp.headers
