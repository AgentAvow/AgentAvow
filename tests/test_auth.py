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
REFRESH_URL = "/api/v1/auth/refresh"
ME_URL = "/api/v1/auth/me"

VALID_USER = {
    "email": "alice@example.com",
    "password": "Str0ngP@ss",
    "display_name": "Alice",
}


# --- Registration tests ---


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    resp = await client.post(REGISTER_URL, json=VALID_USER)
    assert resp.status_code == 201
    assert "Registration successful" in resp.json()["message"]


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    resp = await client.post(REGISTER_URL, json=VALID_USER)
    # Returns 201 with generic message to prevent email enumeration
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_register_weak_password(client: AsyncClient):
    resp = await client.post(
        REGISTER_URL,
        json={"email": "bob@example.com", "password": "weak", "display_name": "Bob"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_no_uppercase(client: AsyncClient):
    resp = await client.post(
        REGISTER_URL,
        json={"email": "bob@example.com", "password": "nouppercase1", "display_name": "Bob"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(client: AsyncClient):
    resp = await client.post(
        REGISTER_URL,
        json={"email": "not-an-email", "password": "Str0ngP@ss", "display_name": "Bad"},
    )
    assert resp.status_code == 422


# --- Login tests ---


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    resp = await client.post(
        LOGIN_URL,
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900  # 15 min * 60


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    resp = await client.post(
        LOGIN_URL,
        json={"email": VALID_USER["email"], "password": "WrongP@ss1"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_email(client: AsyncClient):
    resp = await client.post(
        LOGIN_URL,
        json={"email": "nobody@example.com", "password": "Str0ngP@ss"},
    )
    assert resp.status_code == 401


# --- Token refresh tests ---


@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    login_resp = await client.post(
        LOGIN_URL,
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    refresh_token = login_resp.json()["refresh_token"]

    resp = await client.post(REFRESH_URL, json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_refresh_with_access_token_fails(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    login_resp = await client.post(
        LOGIN_URL,
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    access_token = login_resp.json()["access_token"]

    resp = await client.post(REFRESH_URL, json={"refresh_token": access_token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_invalid_token_fails(client: AsyncClient):
    resp = await client.post(REFRESH_URL, json={"refresh_token": "garbage"})
    assert resp.status_code == 401


# --- Protected endpoint tests ---


@pytest.mark.asyncio
async def test_me_authenticated(client: AsyncClient):
    await client.post(REGISTER_URL, json=VALID_USER)
    login_resp = await client.post(
        LOGIN_URL,
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    token = login_resp.json()["access_token"]

    resp = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == VALID_USER["email"]
    assert data["display_name"] == VALID_USER["display_name"]
    assert data["type"] == "human"
    assert data["did_web"].startswith("did:web:agentgraph.co:users:")


@pytest.mark.asyncio
async def test_me_unauthenticated(client: AsyncClient):
    resp = await client.get(ME_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_invalid_token(client: AsyncClient):
    resp = await client.get(ME_URL, headers={"Authorization": "Bearer invalid"})
    assert resp.status_code == 401


# --- Password hashing cost ---------------------------------------------------
# Production hashes at a fixed cost; tests/conftest.py swaps in a cost-4 hasher
# for the suite only.


def test_production_password_cost_is_12():
    from src.api import auth_service

    assert auth_service.PASSWORD_HASH_ROUNDS == 12


def test_suite_hashes_at_low_cost():
    from src.api.auth_service import hash_password

    assert hash_password("Str0ngP@ss").startswith("$2b$04$")


def test_hash_of_production_cost_still_verifies():
    from pwdlib.hashers.bcrypt import BcryptHasher

    from src.api.auth_service import verify_password

    hashed = BcryptHasher(rounds=12).hash("Str0ngP@ss")
    assert verify_password("Str0ngP@ss", hashed)
