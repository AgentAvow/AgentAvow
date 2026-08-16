"""End-to-end test for POST /account/private-scan — the authenticated, token-based
private-repo scan (the flow a dev uses on a private repo). Verifies it returns real
findings AND never persists to the public catalog."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from src.database import get_db
from src.main import app
from src.models import CommunityScan
from src.scanner.local_scan import scan_local


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: AsyncClient) -> str:
    user = {
        "email": "privscan@example.com",
        "password": "Str0ngP@ss",
        "display_name": "PrivScanUser",
    }
    await client.post("/api/v1/auth/register", json=user)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_private_scan_returns_findings_and_does_not_persist(
    client, db, tmp_path, monkeypatch,
):
    # A real (offline) scan result stands in for the GitHub-backed scan_repo, so
    # the endpoint's serialization + response shape are exercised without network.
    (tmp_path / "app.py").write_text(
        "import os\ndef run(cmd):\n    os.system(cmd)\n"
    )

    async def fake_scan_repo(full_name, *a, **k):
        # token must reach the scanner — assert the endpoint forwards it
        assert k.get("token") == "transient-fine-grained-token-abc123"
        return scan_local(tmp_path, name=full_name)

    monkeypatch.setattr("src.scanner.scan.scan_repo", fake_scan_repo)

    token = await _login(client)
    full_name = "someorg/private-repo"

    resp = await client.post(
        "/api/v1/account/private-scan",
        json={"owner": "someorg", "repo": "private-repo",
              "token": "transient-fine-grained-token-abc123"},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["private"] is True
    assert body["repo"] == full_name
    # real findings came back (the unsafe os.system)
    assert body["findings"]["total"] >= 1
    assert "trust_score" in body

    # crucially: a private scan must NOT reach the public catalog
    count = await db.scalar(
        select(func.count()).select_from(CommunityScan)
        .where(CommunityScan.full_name == full_name)
    )
    assert count == 0


@pytest.mark.asyncio
async def test_private_scan_requires_auth(client):
    resp = await client.post(
        "/api/v1/account/private-scan",
        json={"owner": "x", "repo": "y", "token": "sometoken"},
    )
    assert resp.status_code in (401, 403)
