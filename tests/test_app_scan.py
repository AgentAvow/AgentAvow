"""Tests for scheduled GitHub-App private-repo scanning (src/jobs/app_scan.py)
and the stored private-report view endpoint.

Fully offline — mints/repos/scan are mocked so no network or GitHub creds are
needed. Verifies that scan_installation:
  - stores a PrivateScanResult (owner-scoped),
  - ensures a VERIFIED RepoClaim (the App install is the ownership proof),
  - fires a "watch_alert" drop notification when the score falls;
and that GET /account/private-report/{owner}/{repo}:
  - returns the owner's stored json,
  - 404s for a repo the caller doesn't own.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from src.database import get_db
from src.main import app
from src.models import (
    Entity,
    GitHubAppInstallation,
    Notification,
    PrivateScanResult,
    RepoClaim,
)
from tests.conftest import DB_URL


@pytest_asyncio.fixture(scope="module", autouse=True)
async def _ensure_tables():
    """Ensure the App/claims/private-scan tables exist on the test DB (migrations
    may not have run there). Additive, committed once per module."""
    engine = create_async_engine(DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS github_app_installations ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  installation_id VARCHAR(32) NOT NULL,"
            "  account_login VARCHAR(255),"
            "  account_type VARCHAR(20),"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  revoked_at TIMESTAMPTZ,"
            "  CONSTRAINT uq_gh_app_installation UNIQUE (entity_id, installation_id)"
            ")"
        ))
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS repo_claims ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  owner VARCHAR(255) NOT NULL,"
            "  repo VARCHAR(255) NOT NULL,"
            "  full_name VARCHAR(512) NOT NULL,"
            "  status VARCHAR(20) NOT NULL DEFAULT 'pending',"
            "  verify_code VARCHAR(64) NOT NULL,"
            "  is_private BOOLEAN NOT NULL DEFAULT false,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  verified_at TIMESTAMPTZ,"
            "  CONSTRAINT uq_repo_claim_target UNIQUE (entity_id, owner, repo)"
            ")"
        ))
        # A test DB from before the `is_private` column exists needs it added.
        await conn.execute(text(
            "ALTER TABLE repo_claims "
            "ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT false"
        ))
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS private_scan_results ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  owner VARCHAR(255) NOT NULL,"
            "  repo VARCHAR(255) NOT NULL,"
            "  full_name VARCHAR(512) NOT NULL,"
            "  trust_score INTEGER,"
            "  grade VARCHAR(4),"
            "  result_json JSONB,"
            "  prev_score INTEGER,"
            "  source VARCHAR(16) NOT NULL DEFAULT 'app',"
            "  published BOOLEAN NOT NULL DEFAULT false,"
            "  scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT uq_private_scan_target UNIQUE (entity_id, owner, repo)"
            ")"
        ))
        # A test DB from before the `published` column exists needs it added.
        await conn.execute(text(
            "ALTER TABLE private_scan_results "
            "ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT false"
        ))
    await engine.dispose()


def _fake_scan_result(trust_score: int, critical: int = 0) -> SimpleNamespace:
    """Minimal stand-in for a ScanResult with the fields _scan_result_to_dict reads."""
    return SimpleNamespace(
        error=None,
        trust_score=trust_score,
        critical_count=critical,
        high_count=0,
        medium_count=0,
        findings=[],
        suppressed_count=0,
        positive_signals=[],
        files_scanned=3,
        primary_language="Python",
        has_readme=True,
        has_license=False,
        has_tests=False,
    )


async def _make_entity(db: AsyncSession) -> Entity:
    eid = uuid.uuid4()
    ent = Entity(
        id=eid,
        email=f"appscan_{eid.hex[:8]}@test.com",
        display_name="AppScanOwner",
        type="human",
        is_active=True,
        did_web=f"did:web:agentgraph.co:humans:{eid}",
    )
    db.add(ent)
    await db.flush()
    return ent


def _patch_gh(monkeypatch, repos, scan_result):
    import src.api.github_app_router as gh
    import src.github_auth as ga
    import src.scanner.scan as scan_mod

    monkeypatch.setattr(ga, "mint_installation_token", AsyncMock(return_value="inst-tok"))
    monkeypatch.setattr(gh, "_installation_repos", AsyncMock(return_value=repos))
    monkeypatch.setattr(scan_mod, "scan_repo", AsyncMock(return_value=scan_result))


@pytest.mark.asyncio
async def test_scan_installation_stores_verifies_and_alerts(db: AsyncSession, monkeypatch):
    ent = await _make_entity(db)
    inst = GitHubAppInstallation(
        id=uuid.uuid4(),
        entity_id=ent.id,
        installation_id="99001",
        account_login="me",
        account_type="User",
    )
    db.add(inst)
    # The repo is already CLAIMED — scan_installation only re-scans claimed repos.
    db.add(RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="repo",
        full_name="me/repo", status="verified", verify_code="pre", verified_at=func.now(),
    ))
    # Prior scan at 90 so the fresh 50 is a clear drop (>5) → watch_alert.
    db.add(PrivateScanResult(
        entity_id=ent.id,
        owner="me",
        repo="repo",
        full_name="me/repo",
        trust_score=90,
        grade="A",
        result_json={"trust_score": 90},
        source="app",
    ))
    await db.flush()

    _patch_gh(
        monkeypatch,
        repos=[{"full_name": "me/repo", "private": True}],
        scan_result=_fake_scan_result(trust_score=50, critical=1),
    )

    from src.jobs.app_scan import scan_installation

    summary = await scan_installation(db, inst)

    assert summary["scanned"] == 1
    assert summary["failed"] == 0
    assert summary["alerts"] == 1

    # PrivateScanResult upserted: new score + previous score retained.
    row = (await db.execute(
        select(PrivateScanResult).where(
            PrivateScanResult.entity_id == ent.id,
            PrivateScanResult.owner == "me",
            PrivateScanResult.repo == "repo",
        )
    )).scalar_one()
    assert row.trust_score == 50
    assert row.prev_score == 90
    assert row.grade == "C"
    assert row.source == "app"
    assert row.result_json["trust_score"] == 50

    # A VERIFIED RepoClaim was created (App install = ownership proof).
    claim = (await db.execute(
        select(RepoClaim).where(
            RepoClaim.entity_id == ent.id,
            RepoClaim.owner == "me",
            RepoClaim.repo == "repo",
        )
    )).scalar_one()
    assert claim.status == "verified"
    assert claim.verified_at is not None

    # A drop alert notification was fired.
    notifs = (await db.execute(
        select(Notification).where(
            Notification.entity_id == ent.id,
            Notification.kind == "watch_alert",
        )
    )).scalars().all()
    assert len(notifs) == 1
    assert "me/repo" in notifs[0].title


@pytest.mark.asyncio
async def test_scan_installation_first_scan_no_alert(db: AsyncSession, monkeypatch):
    """A first-ever scan (no prior score) stores a row + verified claim but does
    NOT alert (nothing to compare against)."""
    ent = await _make_entity(db)
    inst = GitHubAppInstallation(
        id=uuid.uuid4(),
        entity_id=ent.id,
        installation_id="99002",
        account_login="me",
        account_type="User",
    )
    db.add(inst)
    await db.flush()

    _patch_gh(
        monkeypatch,
        repos=[{"full_name": "me/fresh", "private": True}],
        scan_result=_fake_scan_result(trust_score=88),
    )

    from src.jobs.app_scan import scan_one_repo

    # The per-repo claim path scans one repo, stores it, and ensures a verified claim.
    alerts = await scan_one_repo(db, "99002", ent.id, "me", "fresh")
    assert alerts == 0

    row = (await db.execute(
        select(PrivateScanResult).where(PrivateScanResult.entity_id == ent.id)
    )).scalar_one()
    assert row.trust_score == 88
    assert row.prev_score is None
    claim = (await db.execute(
        select(RepoClaim).where(RepoClaim.entity_id == ent.id)
    )).scalar_one()
    assert claim.status == "verified"


@pytest.mark.asyncio
async def test_delete_private_claim_unlists_from_search(
    db: AsyncSession, client: AsyncClient,
):
    """Removing a PRIVATE claim also deletes its public CommunityScan row (unlists
    from Browse/search) and its stored PrivateScanResult. A PUBLIC claim's catalog
    row is left intact."""
    from src.models import CommunityScan

    token = await _register(client, "del_owner@test.com")
    ent = (await db.execute(
        select(Entity).where(Entity.email == "del_owner@test.com")
    )).scalar_one()
    priv = RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="priv",
        full_name="me/priv", status="verified", verify_code="a",
        is_private=True, verified_at=func.now(),
    )
    pub = RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="pubrepo",
        full_name="me/pubrepo", status="verified", verify_code="b",
        is_private=False, verified_at=func.now(),
    )
    db.add_all([priv, pub])
    db.add(PrivateScanResult(
        entity_id=ent.id, owner="me", repo="priv", full_name="me/priv",
        trust_score=80, grade="B", result_json={"trust_score": 80},
        source="app", published=True,
    ))
    db.add(CommunityScan(owner="me", repo="priv", full_name="me/priv", trust_score=80))
    db.add(CommunityScan(owner="me", repo="pubrepo", full_name="me/pubrepo", trust_score=90))
    await db.flush()

    # Remove the private claim.
    r1 = await client.delete(
        f"/api/v1/account/claims/{priv.id}", headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 204
    cs_priv = (await db.execute(select(CommunityScan).where(
        CommunityScan.owner == "me", CommunityScan.repo == "priv"))).scalar_one_or_none()
    assert cs_priv is None
    psr = (await db.execute(select(PrivateScanResult).where(
        PrivateScanResult.entity_id == ent.id,
        PrivateScanResult.repo == "priv"))).scalar_one_or_none()
    assert psr is None

    # Remove the public claim — its catalog row survives (public regardless of owner).
    r2 = await client.delete(
        f"/api/v1/account/claims/{pub.id}", headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 204
    cs_pub = (await db.execute(select(CommunityScan).where(
        CommunityScan.owner == "me", CommunityScan.repo == "pubrepo"))).scalar_one_or_none()
    assert cs_pub is not None


@pytest.mark.asyncio
async def test_ensure_verified_claim_records_is_private(db: AsyncSession):
    """_ensure_verified_claim persists is_private on create and never downgrades a
    True flag on a later re-scan (which passes is_private=None)."""
    from src.jobs.app_scan import _ensure_verified_claim

    ent = await _make_entity(db)
    await _ensure_verified_claim(db, ent.id, "me", "secret", "me/secret", is_private=True)
    claim = (await db.execute(
        select(RepoClaim).where(RepoClaim.entity_id == ent.id, RepoClaim.repo == "secret")
    )).scalar_one()
    assert claim.is_private is True
    assert claim.status == "verified"

    # A re-scan (is_private omitted) must not clear the flag.
    await _ensure_verified_claim(db, ent.id, "me", "secret", "me/secret")
    await db.refresh(claim)
    assert claim.is_private is True


# ── View endpoint ─────────────────────────────────────────────────────────

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
REPORT_URL = "/api/v1/account/private-report"


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _register(client: AsyncClient, email: str) -> str:
    await client.post(REGISTER_URL, json={
        "email": email, "password": "Str0ngP@ss", "display_name": "Owner",
    })
    resp = await client.post(LOGIN_URL, json={"email": email, "password": "Str0ngP@ss"})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_private_report_returns_owner_json_and_404s_for_others(
    db: AsyncSession, client: AsyncClient,
):
    token_a = await _register(client, "owner_a@test.com")
    token_b = await _register(client, "owner_b@test.com")

    # Resolve owner A's entity id and store a report under it.
    ent_a = (await db.execute(
        select(Entity).where(Entity.email == "owner_a@test.com")
    )).scalar_one()
    db.add(PrivateScanResult(
        entity_id=ent_a.id,
        owner="me",
        repo="secret",
        full_name="me/secret",
        trust_score=72,
        grade="B",
        result_json={"trust_score": 72, "scan_result": "clean", "findings": {"total": 0}},
        prev_score=70,
        source="app",
    ))
    await db.flush()

    # Owner A can read their stored report.
    resp = await client.get(
        f"{REPORT_URL}/me/secret", headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo"] == "me/secret"
    assert body["private"] is True
    assert body["grade"] == "B"
    assert body["prev_score"] == 70
    assert body["trust_score"] == 72
    assert body["scan_result"] == "clean"

    # Owner B does NOT own it → 404 (owner-scoped).
    resp_b = await client.get(
        f"{REPORT_URL}/me/secret", headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_b.status_code == 404


@pytest.mark.asyncio
async def test_unpublish_removes_catalog_row_and_clears_flag(
    db: AsyncSession, client: AsyncClient,
):
    """Unpublishing a previously-published private repo deletes its CommunityScan
    row (drops out of Browse/search/badge) and clears `published`; the private
    result itself stays (still scanned + watched)."""
    from src.models import CommunityScan

    token = await _register(client, "unpub_owner@test.com")
    ent = (await db.execute(
        select(Entity).where(Entity.email == "unpub_owner@test.com")
    )).scalar_one()
    db.add(PrivateScanResult(
        entity_id=ent.id, owner="me", repo="pub", full_name="me/pub",
        trust_score=80, grade="B", result_json={"trust_score": 80},
        source="app", published=True,
    ))
    db.add(CommunityScan(owner="me", repo="pub", full_name="me/pub", trust_score=80))
    await db.flush()

    resp = await client.post(
        f"{REPORT_URL}/me/pub/unpublish", headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["published"] is False

    # The private row survives but is no longer flagged published.
    row = (await db.execute(
        select(PrivateScanResult).where(PrivateScanResult.entity_id == ent.id)
    )).scalar_one()
    assert row.published is False
    # The public catalog row is gone.
    cs = (await db.execute(
        select(CommunityScan).where(CommunityScan.owner == "me", CommunityScan.repo == "pub")
    )).scalar_one_or_none()
    assert cs is None


@pytest.mark.asyncio
async def test_list_claims_carries_private_published_flags(
    db: AsyncSession, client: AsyncClient,
):
    """GET /account/claims tags each claim from the AUTHORITATIVE is_private flag:
    a private repo reports private=True + scanned/published state; a public repo
    reports private=False regardless of any stray scan rows."""
    token = await _register(client, "flags_owner@test.com")
    ent = (await db.execute(
        select(Entity).where(Entity.email == "flags_owner@test.com")
    )).scalar_one()
    # A private, published claim.
    db.add(RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="priv",
        full_name="me/priv", status="verified", verify_code="a",
        is_private=True, verified_at=func.now(),
    ))
    db.add(PrivateScanResult(
        entity_id=ent.id, owner="me", repo="priv", full_name="me/priv",
        trust_score=90, grade="A", result_json={"trust_score": 90},
        source="app", published=True,
    ))
    # A private claim NOT yet scanned (no PrivateScanResult) — scanned=False.
    db.add(RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="fresh",
        full_name="me/fresh", status="verified", verify_code="c",
        is_private=True, verified_at=func.now(),
    ))
    # A public claim (private=False even if a stray scan row exists).
    db.add(RepoClaim(
        id=uuid.uuid4(), entity_id=ent.id, owner="me", repo="pubrepo",
        full_name="me/pubrepo", status="verified", verify_code="b",
        is_private=False, verified_at=func.now(),
    ))
    await db.flush()

    resp = await client.get(
        "/api/v1/account/claims", headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    by_name = {c["full_name"]: c for c in resp.json()["claims"]}
    assert by_name["me/priv"]["private"] is True
    assert by_name["me/priv"]["scanned"] is True
    assert by_name["me/priv"]["published"] is True
    assert by_name["me/fresh"]["private"] is True
    assert by_name["me/fresh"]["scanned"] is False
    assert by_name["me/fresh"]["published"] is False
    assert by_name["me/pubrepo"]["private"] is False
