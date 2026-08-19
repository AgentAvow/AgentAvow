from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app
from src.models import TrustAttestation, TrustScore


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
ME_URL = "/api/v1/auth/me"
AGENTS_URL = "/api/v1/agents"
CREDS_URL = "/api/v1/credentials"

USER_A = {
    "email": "cred-a@test.com",
    "password": "Str0ngP@ss",
    "display_name": "CredUserA",
}
USER_B = {
    "email": "cred-b@test.com",
    "password": "Str0ngP@ss",
    "display_name": "CredUserB",
}


async def _setup_user(client: AsyncClient, user: dict) -> tuple[str, str]:
    await client.post(REGISTER_URL, json=user)
    resp = await client.post(
        LOGIN_URL, json={"email": user["email"], "password": user["password"]},
    )
    token = resp.json()["access_token"]
    me = await client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})
    return token, me.json()["id"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_export_trust_credential(client, db):
    """Export trust score as verifiable credential."""
    token, uid = await _setup_user(client, USER_A)

    # Update trust score
    from sqlalchemy import update
    await db.execute(
        update(TrustScore)
        .where(TrustScore.entity_id == uuid.UUID(uid))
        .values(score=0.82, components={"verification": 0.3, "activity": 0.52})
    )
    await db.flush()

    resp = await client.get(
        f"{CREDS_URL}/export/{uid}?types=trust",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["credentials"]) == 1
    cred = data["credentials"][0]
    assert "TrustScoreCredential" in cred["type"]
    assert cred["credentialSubject"]["trust_score"] == pytest.approx(0.82, abs=0.01)
    assert cred["proof"]["type"] == "JsonWebSignature2020"
    assert cred["proof"]["jws"].count(".") == 2  # real Ed25519 JWS
    assert cred["issuer"] == "did:web:agentgraph.co"


@pytest.mark.asyncio
async def test_export_attestation_credential(client, db):
    """Export attestation summary as verifiable credential."""
    token_a, uid_a = await _setup_user(client, USER_A)
    _, uid_b = await _setup_user(client, USER_B)

    # B attests about A
    db.add(TrustAttestation(
        id=uuid.uuid4(),
        attester_entity_id=uuid.UUID(uid_b),
        target_entity_id=uuid.UUID(uid_a),
        attestation_type="competent",
        weight=0.7,
    ))
    db.add(TrustAttestation(
        id=uuid.uuid4(),
        attester_entity_id=uuid.UUID(uid_b),
        target_entity_id=uuid.UUID(uid_a),
        attestation_type="reliable",
        weight=0.7,
    ))
    await db.flush()

    resp = await client.get(
        f"{CREDS_URL}/export/{uid_a}?types=attestation",
        headers=_auth(token_a),
    )
    assert resp.status_code == 200
    cred = resp.json()["credentials"][0]
    assert "AttestationSummaryCredential" in cred["type"]
    assert cred["credentialSubject"]["attestation_count"] == 2
    assert set(cred["credentialSubject"]["attestation_types"]) == {"competent", "reliable"}


@pytest.mark.asyncio
async def test_export_activity_credential(client, db):
    """Export activity summary as verifiable credential."""
    token, uid = await _setup_user(client, USER_A)

    # Create a post to generate activity
    await client.post(
        "/api/v1/feed/posts",
        json={"content": "Hello from credential test"},
        headers=_auth(token),
    )

    resp = await client.get(
        f"{CREDS_URL}/export/{uid}?types=activity",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    creds = resp.json()["credentials"]
    assert len(creds) == 1
    activity = creds[0]["credentialSubject"]["activity_summary"]
    assert activity["posts"] >= 1


@pytest.mark.asyncio
async def test_export_all_credentials(client, db):
    """Export all credential types at once."""
    token, uid = await _setup_user(client, USER_A)

    from sqlalchemy import update
    await db.execute(
        update(TrustScore)
        .where(TrustScore.entity_id == uuid.UUID(uid))
        .values(score=0.5)
    )
    await db.flush()

    # Create a post
    await client.post(
        "/api/v1/feed/posts",
        json={"content": "Activity for all export"},
        headers=_auth(token),
    )

    resp = await client.get(
        f"{CREDS_URL}/export/{uid}",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    data = resp.json()
    # Should have trust + activity at minimum
    types_found = set()
    for cred in data["credentials"]:
        for t in cred["type"]:
            types_found.add(t)
    assert "TrustScoreCredential" in types_found
    assert "ActivityCredential" in types_found


@pytest.mark.asyncio
async def test_export_forbidden_for_other_user(client, db):
    """Cannot export another user's credentials."""
    token_a, uid_a = await _setup_user(client, USER_A)
    _, uid_b = await _setup_user(client, USER_B)

    resp = await client.get(
        f"{CREDS_URL}/export/{uid_b}",
        headers=_auth(token_a),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_export_evolution_credential_agent(client, db):
    """Agent gets evolution credential with capabilities."""
    token, _ = await _setup_user(client, USER_A)

    # Create agent
    agent_resp = await client.post(
        AGENTS_URL,
        json={
            "display_name": "CredBot",
            "capabilities": ["chat", "search"],
            "autonomy_level": 3,
        },
        headers=_auth(token),
    )
    agent_id = agent_resp.json()["agent"]["id"]

    # Create evolution record
    await client.post(
        "/api/v1/evolution",
        json={
            "entity_id": agent_id,
            "version": "1.0.0",
            "change_type": "initial",
            "change_summary": "Initial release",
            "capabilities_snapshot": ["chat", "search"],
        },
        headers=_auth(token),
    )

    # Export as operator
    resp = await client.get(
        f"{CREDS_URL}/export/{agent_id}?types=evolution",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    creds = resp.json()["credentials"]
    assert len(creds) == 1
    assert "EvolutionCredential" in creds[0]["type"]
    assert creds[0]["credentialSubject"]["current_version"] == "1.0.0"
    assert "chat" in creds[0]["credentialSubject"]["capabilities"]


@pytest.mark.asyncio
async def test_verify_trust_credential(client, db):
    """Verify a trust credential proof against current data."""
    token, uid = await _setup_user(client, USER_A)

    from sqlalchemy import update
    await db.execute(
        update(TrustScore)
        .where(TrustScore.entity_id == uuid.UUID(uid))
        .values(score=0.75, components={"verification": 0.25, "activity": 0.5})
    )
    await db.flush()

    # Export
    export_resp = await client.get(
        f"{CREDS_URL}/export/{uid}?types=trust",
        headers=_auth(token),
    )
    cred = export_resp.json()["credentials"][0]
    proof_value = cred["proof"]["proofValue"]

    # Verify
    verify_resp = await client.get(
        f"{CREDS_URL}/verify",
        params={
            "entity_id": uid,
            "credential_type": "TrustScoreCredential",
            "proof_value": proof_value,
        },
        headers=_auth(token),
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_list_credential_types(client, db):
    """List available credential types."""
    token, _ = await _setup_user(client, USER_A)

    resp = await client.get(
        f"{CREDS_URL}/types",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    data = resp.json()
    type_names = [t["type"] for t in data["credential_types"]]
    assert "TrustScoreCredential" in type_names
    assert "AttestationSummaryCredential" in type_names
    assert "ActivityCredential" in type_names
    assert "EvolutionCredential" in type_names


@pytest.mark.asyncio
async def test_export_no_data_returns_empty(client, db):
    """Export with minimal data returns at most the registration trust credential."""
    token, uid = await _setup_user(client, USER_A)

    resp = await client.get(
        f"{CREDS_URL}/export/{uid}?types=trust",
        headers=_auth(token),
    )
    assert resp.status_code == 200
    # Registration may create an initial trust score credential
    assert len(resp.json()["credentials"]) <= 1
