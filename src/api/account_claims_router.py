"""Repo ownership claims + private-repo scanning.

Claim: prove you own a public repo by adding a GitHub topic — no token stored.
Private scan: scan a private repo you can access using a GitHub token you supply
transiently (never persisted). Both require a signed-in account.
"""
from __future__ import annotations

import logging
import secrets
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_scans, rate_limit_writes
from src.database import get_db
from src.models import Entity, PrivateScanResult, RepoClaim

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/account", tags=["account"])

_VALID = "abcdefghijklmnopqrstuvwxyz0123456789-._"


async def _repo_accessible_with_token(owner: str, repo: str, token: str) -> bool:
    """True if the supplied GitHub token can read the repo. For a PRIVATE repo
    this is the ownership proof — our scanner token can't read a private repo's
    topics, so the topic method can't verify private repos. The token is used
    transiently here and never stored or logged."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                },
            )
        return resp.status_code == 200
    except Exception:
        return False


async def _scan_into_catalog(owner: str, repo: str) -> None:
    """Best-effort public scan of a just-claimed repo so it enters the catalog +
    search (claiming a repo should make it discoverable). Fire-and-forget: any
    failure is swallowed — a claim must never fail because the scan did."""
    try:
        from src.api.public_scan_router import public_scan
        from src.database import async_session

        async with async_session() as db:
            await public_scan(owner=owner, repo=repo, force=False, db=db)
    except Exception:
        logger.debug("claim auto-scan failed for %s/%s", owner, repo, exc_info=True)


def _valid_repo(owner: str, repo: str) -> bool:
    return bool(owner) and bool(repo) and all(c.lower() in _VALID for c in owner + repo)


class ClaimRequest(BaseModel):
    owner: str = Field(..., max_length=255)
    repo: str = Field(..., max_length=255)
    # Optional: a read token proving access. When present + valid the claim is
    # verified immediately (the path for PRIVATE repos, which can't use a topic).
    token: str | None = Field(None, max_length=255)


class VerifyRequest(BaseModel):
    # Optional read token — supply it to verify a PRIVATE repo (proves access).
    # Omit it to verify a public repo via its GitHub topic.
    token: str | None = Field(None, max_length=255)


def _serialize(c: RepoClaim, meta: dict | None = None) -> dict:
    # `private` is AUTHORITATIVE on the claim (set at claim time): public
    # topic-proof claims are False; GitHub-App claims of private repos are True.
    # `meta` maps full_name -> {scanned, published, grade, score} so the unified
    # "Your tools" list can show a grade + state without a per-row fetch.
    m = (meta or {}).get(c.full_name) or {}
    return {
        "id": str(c.id),
        "owner": c.owner,
        "repo": c.repo,
        "full_name": c.full_name,
        "status": c.status,
        "topic": f"agentavow-verify-{c.verify_code}",
        "verified_at": c.verified_at.isoformat() if c.verified_at else None,
        "private": bool(c.is_private),
        "scanned": bool(m.get("scanned", False)),
        "published": bool(m.get("published", False)),
        "grade": m.get("grade"),
        "score": m.get("score"),
    }


@router.get("/claims")
async def list_claims(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    from src.api.public_scan_router import _grade_from_score
    from src.models import CommunityScan

    result = await db.execute(
        select(RepoClaim)
        .where(RepoClaim.entity_id == entity.id)
        .order_by(RepoClaim.created_at.desc())
    )
    claims = result.scalars().all()

    # Build a per-repo meta map (keyed by full_name) so each row carries its grade
    # + state. Private repos read from the owner's PrivateScanResult; public repos
    # read the latest catalog grade from CommunityScan.
    meta: dict[str, dict] = {}
    priv_rows = (await db.execute(
        select(
            PrivateScanResult.full_name, PrivateScanResult.published,
            PrivateScanResult.grade, PrivateScanResult.trust_score,
        ).where(PrivateScanResult.entity_id == entity.id)
    )).all()
    for fn, pub, grade, score in priv_rows:
        meta[fn] = {"scanned": True, "published": bool(pub), "grade": grade, "score": score}

    pub_names = [c.full_name for c in claims if not c.is_private]
    if pub_names:
        cs_rows = (await db.execute(
            select(CommunityScan.full_name, CommunityScan.trust_score)
            .where(CommunityScan.full_name.in_(pub_names))
        )).all()
        for fn, score in cs_rows:
            if fn in meta:
                continue
            meta[fn] = {
                "scanned": True,
                "published": True,  # public repos are inherently listed
                "grade": _grade_from_score(score) if score is not None else None,
                "score": score,
            }

    return {"claims": [_serialize(c, meta) for c in claims]}


@router.post("/claims", status_code=201)
async def create_claim(
    body: ClaimRequest,
    background: BackgroundTasks,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Start a claim — returns the GitHub topic to add to prove ownership. Also
    kicks off a best-effort public scan so the claimed repo shows up in the
    catalog + search (claiming ≠ scanning otherwise)."""
    if not _valid_repo(body.owner, body.repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo")

    token = (body.token or "").strip()

    # Public-claim path (no token): if we can't read the repo publicly it's private
    # (or doesn't exist) — the topic method can't work, so steer the owner to the
    # GitHub App flow instead of creating a claim that would sit pending forever.
    if not token:
        try:
            import httpx

            from src.github_auth import get_github_token

            gh = await get_github_token()
            headers = {"Accept": "application/vnd.github+json"}
            if gh:
                headers["Authorization"] = f"Bearer {gh}"
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{body.owner}/{body.repo}",
                    headers=headers,
                )
            if resp.status_code != 200:
                return {
                    "needs_private_flow": True,
                    "detail": (
                        "We can't read this repo publicly. If it's private, connect the "
                        "GitHub App below to claim + scan it. If it's public, double-check "
                        "the owner / repo."
                    ),
                }
        except Exception:
            pass  # transient network issue — fall through and create as usual

    # Make the claimed repo discoverable — scan it into the catalog in the
    # background (public repos only; private repos use the App / private-scan).
    background.add_task(_scan_into_catalog, body.owner, body.repo)

    # A token proving repo access verifies the claim immediately — the ONLY way
    # to verify a private repo (topics aren't readable there). Used transiently.
    token_verified = bool(token) and await _repo_accessible_with_token(
        body.owner, body.repo, token,
    )

    existing = (await db.execute(
        select(RepoClaim).where(
            RepoClaim.entity_id == entity.id,
            RepoClaim.owner == body.owner,
            RepoClaim.repo == body.repo,
        )
    )).scalar_one_or_none()
    if existing is not None:
        if token_verified and existing.status != "verified":
            from sqlalchemy import func as safunc
            existing.status = "verified"
            existing.verified_at = safunc.now()
            await db.flush()
            await db.refresh(existing)
        # Commit before the background scan runs (see claim-repo note) so the row
        # lock releases immediately instead of being held for the whole scan.
        payload = _serialize(existing)
        await db.commit()
        return payload
    claim = RepoClaim(
        entity_id=entity.id,
        owner=body.owner,
        repo=body.repo,
        full_name=f"{body.owner}/{body.repo}",
        status="verified" if token_verified else "pending",
        verify_code=secrets.token_hex(8),
    )
    if token_verified:
        from sqlalchemy import func as safunc
        claim.verified_at = safunc.now()
    db.add(claim)
    await db.flush()
    await db.refresh(claim)
    payload = _serialize(claim)
    await db.commit()  # release the lock before the background catalog scan
    return payload


@router.post("/claims/{claim_id}/verify")
async def verify_claim(
    claim_id: uuid.UUID,
    body: VerifyRequest | None = None,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Verify a claim. Public repos: check the GitHub topic. Private repos: pass a
    read token (proves access — topics aren't readable there). Token is transient."""
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")

    # Token path — the private-repo route.
    token = (body.token.strip() if body and body.token else "")
    if token:
        if await _repo_accessible_with_token(claim.owner, claim.repo, token):
            from sqlalchemy import func as safunc
            claim.status = "verified"
            claim.verified_at = safunc.now()
            await db.flush()
            await db.refresh(claim)
            return {"verified": True, **_serialize(claim)}
        return {
            "verified": False,
            "detail": "That token can't read this repo — check it has read access to it.",
        }

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
    # Removing a PRIVATE claim also withdraws it from public search (delete the
    # CommunityScan row) and drops the owner-scoped stored report — otherwise an
    # unclaimed private repo would linger in Browse/search. Public repos stay in
    # the catalog (they're public regardless of who claims them).
    if claim.is_private:
        from sqlalchemy import delete as sa_delete

        from src.models import CommunityScan
        await db.execute(sa_delete(CommunityScan).where(
            CommunityScan.owner == claim.owner, CommunityScan.repo == claim.repo,
        ))
        await db.execute(sa_delete(PrivateScanResult).where(
            PrivateScanResult.entity_id == entity.id,
            PrivateScanResult.owner == claim.owner,
            PrivateScanResult.repo == claim.repo,
        ))
    await db.delete(claim)
    await db.flush()


@router.get("/private-report/{owner}/{repo}")
async def private_report(
    owner: str,
    repo: str,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    """Return the caller's stored private-repo scan report (from the scheduled
    GitHub App scan). Backs the frontend "View report" for a connected private
    repo — re-renders from the stored ``result_json`` without re-scanning.

    Owner-scoped: only the account that owns the scan can read it. 404 if there
    is no stored report for this owner/repo under the caller's account."""
    row = (
        await db.execute(
            select(PrivateScanResult).where(
                PrivateScanResult.entity_id == entity.id,
                PrivateScanResult.owner == owner,
                PrivateScanResult.repo == repo,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No private report for this repo")
    return {
        "repo": row.full_name,
        "private": True,
        "grade": row.grade,
        "prev_score": row.prev_score,
        "source": row.source,
        "published": bool(row.published),
        "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
        **(row.result_json or {}),
    }


@router.post("/private-report/{owner}/{repo}/publish")
async def publish_private_report(
    owner: str,
    repo: str,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Owner opt-in: publish a connected private repo's stored grade to the public
    catalog + search. Unlike the one-time /private-scan/publish (which re-scans
    with a token), this publishes the ALREADY-STORED App scan result — no token
    needed. Makes the repo's grade + name public; the owner's explicit choice."""
    row = (
        await db.execute(
            select(PrivateScanResult).where(
                PrivateScanResult.entity_id == entity.id,
                PrivateScanResult.owner == owner,
                PrivateScanResult.repo == repo,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No private report to publish")
    try:
        from src.api.public_scan_router import _capture_community_scan
        await _capture_community_scan(owner, repo, row.result_json or {}, db)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Publish failed: {e}") from e
    row.published = True
    await db.flush()
    return {
        "published": True,
        "full_name": row.full_name,
        "trust_score": row.trust_score,
        "grade": row.grade,
    }


@router.post("/private-report/{owner}/{repo}/unpublish")
async def unpublish_private_report(
    owner: str,
    repo: str,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Owner opt-out: remove a previously-published private repo from the public
    catalog + search. Deletes the CommunityScan row (so it drops out of Browse /
    search / badge) and clears the stored `published` flag. The repo stays scanned
    and watched privately — only its public listing is withdrawn. Idempotent."""
    from sqlalchemy import delete as sa_delete

    from src.models import CommunityScan

    row = (
        await db.execute(
            select(PrivateScanResult).where(
                PrivateScanResult.entity_id == entity.id,
                PrivateScanResult.owner == owner,
                PrivateScanResult.repo == repo,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No private report for this repo")
    # Drop it from the public catalog (Browse/search/badge all read CommunityScan).
    await db.execute(
        sa_delete(CommunityScan).where(
            CommunityScan.owner == owner, CommunityScan.repo == repo
        )
    )
    row.published = False
    await db.flush()
    return {"published": False, "full_name": row.full_name}


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


@router.post("/private-scan/publish")
async def publish_private_scan(
    body: PrivateScanRequest,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_scans),
):
    """Owner-gated opt-in: publish a private repo's grade to the public catalog + search.

    Private scans (POST /account/private-scan) deliberately never reach the public
    catalog. This endpoint lets the repo owner choose to make a private repo's grade
    public and searchable. The supplied GitHub ``token`` proving read access to the
    repo IS the authorization — a private repo can't be topic-claimed (our PAT can't
    read its topics), so access-via-token is the ownership proof.

    Re-scans the repo with the token (transient — never stored or logged, matching the
    private_scan guarantees), then upserts the result into CommunityScan so it appears
    in the browse catalog and global search. On scan failure / no access → 502/404.
    """
    if not _valid_repo(body.owner, body.repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo")
    full_name = f"{body.owner}/{body.repo}"
    try:
        from src.api.public_scan_router import (
            _capture_community_scan,
            _grade_from_score,
            _scan_result_to_dict,
        )
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
    # Upsert into CommunityScan — the SAME upsert public_scan_router uses — so the
    # owner-published grade grows the catalog + search dataset (latest scan wins).
    await _capture_community_scan(body.owner, body.repo, data, db)
    return {
        "published": True,
        "full_name": full_name,
        "trust_score": data["trust_score"],
        "grade": _grade_from_score(data["trust_score"]),
    }
