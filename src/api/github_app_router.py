"""GitHub App connect flow — opt-in scoped access for scheduled PRIVATE-repo
scanning. The owner installs the AgentAvow App on their repos; GitHub mints
short-lived, auto-rotating installation tokens on demand, so no long-lived secret
is stored and the owner can revoke in GitHub anytime.

Flow:
  1. GET  /account/github-app/install-url  -> the github.com/apps/<slug>/installations/new URL
  2. (owner installs the App on GitHub, is redirected to the Setup URL)
  3. GET  /account/github-app/setup         -> 302 to the frontend with ?gh_installation_id=
  4. POST /account/github-app/connect       -> associate the installation with the signed-in owner
  5. GET  /account/github-app/status        -> connected installations + their repos
  6. DELETE /account/github-app/{id}        -> disconnect (mark revoked)

SECURITY NOTE (pre-enable follow-up): step 4 trusts the signed-in owner who just
completed the install. Before this is enabled in prod, add identity matching
(GitHub App user-authorization / OAuth) so a user can't associate an installation
id that isn't theirs. Tracked in the action plan.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.config import settings
from src.database import get_db
from src.models import Entity, GitHubAppInstallation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/account/github-app", tags=["account"])


async def _scan_installation_bg(installation_pk: uuid.UUID) -> None:
    """Best-effort: scan a freshly-connected installation in its own session so
    connecting immediately scans + verified-claims the owner's repos. Fire-and-
    forget — any failure is swallowed (a connect must never fail because the scan
    did). Runs after the response, so the installation row is already committed."""
    try:
        from src.database import async_session
        from src.jobs.app_scan import scan_installation

        async with async_session() as db:
            inst = await db.get(GitHubAppInstallation, installation_pk)
            if inst is None or inst.revoked_at is not None:
                return
            await scan_installation(db, inst)
            await db.commit()
    except Exception:
        logger.debug("connect auto-scan failed for %s", installation_pk, exc_info=True)


def _serialize(i: GitHubAppInstallation) -> dict:
    return {
        "id": str(i.id),
        "installation_id": i.installation_id,
        "account_login": i.account_login,
        "account_type": i.account_type,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "revoked": i.revoked_at is not None,
    }


async def _installation_repos(installation_id: str) -> list[dict]:
    """List the repos an installation can access (via a freshly-minted token)."""
    import httpx

    from src.github_auth import mint_installation_token

    token = await mint_installation_token(installation_id)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            "https://api.github.com/installation/repositories?per_page=100",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    if resp.status_code != 200:
        return []
    return [
        {"full_name": r["full_name"], "private": r.get("private", False)}
        for r in resp.json().get("repositories", [])
    ]


async def _verify_installation_claims(db, entity_id, installation_id: str) -> None:
    """Synchronously create a VERIFIED RepoClaim for each repo an installation can
    access — the install itself is the ownership proof. Fast (list + upsert, no
    scan) so the repos show in 'Your repos' the moment connect returns; the actual
    scan/result runs in the background task. Best-effort."""
    try:
        from src.jobs.app_scan import _ensure_verified_claim

        repos = await _installation_repos(installation_id)
        for r in repos[:25]:
            fn = (r or {}).get("full_name")
            if not fn or "/" not in fn:
                continue
            owner, repo = fn.split("/", 1)
            await _ensure_verified_claim(db, entity_id, owner, repo, fn)
    except Exception:
        logger.debug(
            "verify-claims-on-connect failed for %s", installation_id, exc_info=True
        )


@router.get("/install-url")
async def install_url(
    entity: Entity = Depends(get_current_entity),
    _: None = Depends(rate_limit_reads),
):
    """The GitHub URL where the owner installs the App on their repos."""
    slug = getattr(settings, "github_app_slug", None)
    if not slug:
        raise HTTPException(status_code=503, detail="GitHub App not configured yet")
    return {"url": f"https://github.com/apps/{slug}/installations/new"}


@router.get("/setup")
async def setup_callback(installation_id: str | None = None, setup_action: str | None = None):
    """GitHub redirects here after an install. Bounce to the frontend (which holds
    the auth token) so it can POST /connect to associate the installation."""
    # The live (cutover) site serves the rebrand at root, so the My Tools page is
    # /tools — NOT /rebrand/tools (which falls through to the homepage catch-all,
    # where the connect handler isn't mounted → the install id is dropped).
    base = settings.base_url.rstrip("/")
    if not installation_id:
        return RedirectResponse(url=f"{base}/tools?gh_setup=error", status_code=302)
    _action = setup_action or "install"
    return RedirectResponse(
        url=f"{base}/tools?gh_installation_id={installation_id}&gh_setup={_action}",
        status_code=302,
    )


class ConnectRequest(BaseModel):
    installation_id: str = Field(..., max_length=32)


@router.post("/connect", status_code=201)
async def connect(
    body: ConnectRequest,
    background: BackgroundTasks,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Associate a just-created installation with the signed-in owner. Verifies the
    installation is real + reachable by minting a token for it."""
    inst_id = body.installation_id.strip()
    if not inst_id.isdigit():
        raise HTTPException(status_code=400, detail="Invalid installation id")

    # Prove the App can actually use this installation (and grab its account).
    try:
        import httpx

        from src.github_auth import _mint_app_jwt

        app_jwt = _mint_app_jwt()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://api.github.com/app/installations/{inst_id}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {app_jwt}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
    except Exception as e:  # pragma: no cover - network
        raise HTTPException(status_code=502, detail=f"Could not verify installation: {e}") from e
    if resp.status_code != 200:
        raise HTTPException(status_code=404, detail="Installation not found")
    acct = resp.json().get("account") or {}

    existing = (await db.execute(
        select(GitHubAppInstallation).where(
            GitHubAppInstallation.entity_id == entity.id,
            GitHubAppInstallation.installation_id == inst_id,
        )
    )).scalar_one_or_none()
    if existing is not None:
        existing.revoked_at = None
        existing.account_login = acct.get("login")
        existing.account_type = acct.get("type")
        await db.flush()
        await db.refresh(existing)
        await _verify_installation_claims(db, entity.id, inst_id)
        # The full scan (result + alerts) runs in the background — slow for private
        # repos, so it must NOT gate the connect response.
        background.add_task(_scan_installation_bg, existing.id)
        return _serialize(existing)

    inst = GitHubAppInstallation(
        entity_id=entity.id,
        installation_id=inst_id,
        account_login=acct.get("login"),
        account_type=acct.get("type"),
    )
    db.add(inst)
    await db.flush()
    await db.refresh(inst)
    await _verify_installation_claims(db, entity.id, inst_id)
    # Scan immediately so connecting scans + verified-claims the repos right away.
    background.add_task(_scan_installation_bg, inst.id)
    return _serialize(inst)


@router.get("/status")
async def status(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    """The owner's connected installations + the repos each can scan."""
    rows = (await db.execute(
        select(GitHubAppInstallation)
        .where(
            GitHubAppInstallation.entity_id == entity.id,
            GitHubAppInstallation.revoked_at.is_(None),
        )
        .order_by(GitHubAppInstallation.created_at.desc())
    )).scalars().all()
    out = []
    for i in rows:
        info = _serialize(i)
        try:
            info["repos"] = await _installation_repos(i.installation_id)
        except Exception:
            info["repos"] = []
        out.append(info)
    return {
        "installations": out,
        "app_configured": bool(getattr(settings, "github_app_slug", None)),
    }


@router.delete("/{installation_pk}", status_code=204)
async def disconnect(
    installation_pk: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Forget an installation locally (the owner should also uninstall in GitHub).
    Also removes the App-derived verified claims + stored private results for this
    installation's repos, so they drop out of 'Your repos' on disconnect."""
    from sqlalchemy import delete as sa_delete
    from sqlalchemy import func as safunc

    from src.models import PrivateScanResult, RepoClaim

    inst = await db.get(GitHubAppInstallation, installation_pk)
    if inst is None or inst.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Not found")

    # Best-effort cleanup: list the install's repos (token usually still valid at
    # disconnect) and drop their claims + private results under this owner. If the
    # token is already dead (uninstalled in GitHub first), just mark it revoked.
    try:
        repos = await _installation_repos(inst.installation_id)
        for r in repos:
            fn = (r or {}).get("full_name")
            if not fn or "/" not in fn:
                continue
            owner, repo = fn.split("/", 1)
            await db.execute(sa_delete(PrivateScanResult).where(
                PrivateScanResult.entity_id == entity.id,
                PrivateScanResult.owner == owner,
                PrivateScanResult.repo == repo,
            ))
            await db.execute(sa_delete(RepoClaim).where(
                RepoClaim.entity_id == entity.id,
                RepoClaim.owner == owner,
                RepoClaim.repo == repo,
            ))
    except Exception:
        logger.debug(
            "disconnect cleanup skipped for %s (token unavailable)",
            inst.installation_id, exc_info=True,
        )

    inst.revoked_at = safunc.now()
    await db.flush()
