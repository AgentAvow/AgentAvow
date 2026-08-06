"""Repo ownership claims + private-repo scanning.

Claim: prove you own a public repo by adding a GitHub topic — no token stored.
Private scan: scan a private repo you can access using a GitHub token you supply
transiently (never persisted). Both require a signed-in account.
"""
from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_scans, rate_limit_writes
from src.database import get_db
from src.models import Entity, RepoClaim

router = APIRouter(prefix="/account", tags=["account"])

_VALID = "abcdefghijklmnopqrstuvwxyz0123456789-._"


def _valid_repo(owner: str, repo: str) -> bool:
    return bool(owner) and bool(repo) and all(c.lower() in _VALID for c in owner + repo)


class ClaimRequest(BaseModel):
    owner: str = Field(..., max_length=255)
    repo: str = Field(..., max_length=255)


def _serialize(c: RepoClaim) -> dict:
    return {
        "id": str(c.id),
        "owner": c.owner,
        "repo": c.repo,
        "full_name": c.full_name,
        "status": c.status,
        "topic": f"agentavow-verify-{c.verify_code}",
        "verified_at": c.verified_at.isoformat() if c.verified_at else None,
    }


@router.get("/claims")
async def list_claims(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    result = await db.execute(
        select(RepoClaim)
        .where(RepoClaim.entity_id == entity.id)
        .order_by(RepoClaim.created_at.desc())
    )
    return {"claims": [_serialize(c) for c in result.scalars().all()]}


@router.post("/claims", status_code=201)
async def create_claim(
    body: ClaimRequest,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Start a claim — returns the GitHub topic to add to prove ownership."""
    if not _valid_repo(body.owner, body.repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo")
    existing = (await db.execute(
        select(RepoClaim).where(
            RepoClaim.entity_id == entity.id,
            RepoClaim.owner == body.owner,
            RepoClaim.repo == body.repo,
        )
    )).scalar_one_or_none()
    if existing is not None:
        return _serialize(existing)
    claim = RepoClaim(
        entity_id=entity.id,
        owner=body.owner,
        repo=body.repo,
        full_name=f"{body.owner}/{body.repo}",
        status="pending",
        verify_code=secrets.token_hex(8),
    )
    db.add(claim)
    await db.flush()
    await db.refresh(claim)
    return _serialize(claim)


@router.post("/claims/{claim_id}/verify")
async def verify_claim(
    claim_id: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Check the repo's public GitHub topics for the verification topic."""
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")
    expected = f"agentavow-verify-{claim.verify_code}"
    try:
        import httpx

        from src.github_auth import get_github_token

        headers = {"Accept": "application/vnd.github+json"}
        token = await get_github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{claim.owner}/{claim.repo}/topics", headers=headers
            )
        topics = resp.json().get("names", []) if resp.status_code == 200 else []
    except Exception:
        topics = []
    if expected in topics:
        from sqlalchemy import func as safunc

        claim.status = "verified"
        claim.verified_at = safunc.now()
        await db.flush()
        await db.refresh(claim)
        return {"verified": True, **_serialize(claim)}
    return {
        "verified": False,
        "topic": expected,
        "detail": "Topic not found yet — add it to the repo and retry.",
    }


@router.delete("/claims/{claim_id}", status_code=204)
async def delete_claim(
    claim_id: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")
    await db.delete(claim)
    await db.flush()


class PrivateScanRequest(BaseModel):
    owner: str = Field(..., max_length=255)
    repo: str = Field(..., max_length=255)
    token: str = Field(..., min_length=8, max_length=255)


@router.post("/private-scan")
async def private_scan(
    body: PrivateScanRequest,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_scans),
):
    """Scan a private repo using a GitHub token the user supplies. The token is used
    transiently for this scan only — never stored or logged. Results are returned to
    the caller and NOT added to the public catalog."""
    if not _valid_repo(body.owner, body.repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo")
    full_name = f"{body.owner}/{body.repo}"
    try:
        from src.api.public_scan_router import _scan_result_to_dict
        from src.scanner.scan import scan_repo

        result = await scan_repo(full_name, token=body.token)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan failed: {e}") from e
    if result.error:
        raise HTTPException(
            status_code=404 if "not found" in (result.error or "").lower() else 502,
            detail=f"Scan error: {result.error}",
        )
    data = _scan_result_to_dict(result)
    return {"repo": full_name, "private": True, **data}
