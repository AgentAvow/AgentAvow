"""POST /public/scan-catalog/refresh rebuilds the in-memory catalog from disk; until
2026-10-02 it had no auth and sat behind nginx's /api/v1/ proxy, so anyone could make
the backend re-read every scan file. It is admin-only now."""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app

URL = "/api/v1/public/scan-catalog/refresh"


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _login(client: AsyncClient, email: str) -> tuple[str, str]:
    user = {"email": email, "password": "Str0ngP@ss", "display_name": email.split("@")[0]}
    await client.post("/api/v1/auth/register", json=user)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": user["password"]}
    )
    token = resp.json()["access_token"]
    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    return token, me.json()["id"]


@pytest.mark.asyncio
async def test_refresh_is_refused_without_a_session(client):
    resp = await client.post(URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_is_refused_for_a_regular_user(client):
    token, _ = await _login(client, "catalog-user@example.com")
    resp = await client.post(URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_refresh_works_for_an_admin(client, db, monkeypatch):
    import src.api.scan_catalog_router as m

    token, entity_id = await _login(client, "catalog-admin@example.com")
    from src.models import Entity

    entity = await db.get(Entity, uuid.UUID(entity_id))
    entity.is_admin = True
    await db.flush()

    # Don't read the real catalog from disk in a unit test.
    monkeypatch.setattr(
        m, "_get_catalog",
        lambda: {"summary": type("S", (), {"total_scans": 7})(), "rows": []},
    )
    resp = await client.post(URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "rebuilt", "total_scans": 7}
