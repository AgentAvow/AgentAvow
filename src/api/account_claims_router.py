"""Repo ownership claims + private-repo scanning.

Claim: prove you own a public repo by adding a GitHub topic — no token stored.
Private scan: scan a private repo you can access using a GitHub token you supply
transiently (never persisted). Both require a signed-in account.
"""
from __future__ import annotations

import json
import logging
import re
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


_SURFACES = ("github", "npm", "pypi", "mcp", "openclaw")


def _claim_coord(surface: str, owner: str, repo: str) -> tuple[str, str, str] | None:
    """Map a request to stored (owner, repo, full_name), mirroring ToolWatch coords:
    github/openclaw → owner/repo · npm/pypi → owner=surface, repo=pkg · mcp →
    owner='mcp', repo=url. Returns None if the coordinate is invalid for the surface."""
    s = (surface or "github").lower()
    owner = (owner or "").strip()
    repo = (repo or "").strip()
    if s in ("github", "openclaw"):
        o, r = owner.strip("/"), repo.strip("/")
        return (o, r, f"{o}/{r}") if _valid_repo(o, r) else None
    if s in ("npm", "pypi"):
        # package name incl. npm scoped @scope/name
        if not repo or not re.fullmatch(r"@?[\w.-]+(?:/[\w.-]+)?", repo):
            return None
        return (s, repo, f"{s}:{repo}")
    if s == "mcp":
        try:
            from src.ssrf import validate_url_https
            validate_url_https(repo, field_name="endpoint")
        except Exception:
            return None
        return ("mcp", repo, repo)
    return None


def _norm_github_repo(url: str | None) -> str | None:
    """Normalize any GitHub URL/spec (git+https, ssh, or a bare 'owner/repo') to
    lowercase 'owner/repo'. Returns None for non-GitHub hosts — we only cross-check
    a package's source against GitHub/skill claims."""
    if not url or not isinstance(url, str):
        return None
    m = re.search(r"github\.com[/:]+([\w.-]+)/([\w.-]+)", url, re.IGNORECASE)
    if m:
        owner, repo = m.group(1), m.group(2)
    else:
        s = url.strip().strip("/")
        mm = re.fullmatch(r"([\w.-]+)/([\w.-]+)", s)
        if not mm:
            return None
        owner, repo = mm.group(1), mm.group(2)
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}".lower()


async def _declared_repo(surface: str, name: str) -> str | None:
    """The GitHub repo a package DECLARES as its source (npm package.json
    `repository`; PyPI project_urls / home_page). Self-asserted, so only trusted
    when the user independently owns that repo. Cheap registry-metadata fetch."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            if surface == "npm":
                r = await client.get(f"https://registry.npmjs.org/{name}")
                if r.status_code != 200:
                    return None
                doc = r.json()
                repo = doc.get("repository")
                url = repo.get("url") if isinstance(repo, dict) else repo
                if not url:
                    latest = (doc.get("dist-tags") or {}).get("latest")
                    ver = (doc.get("versions") or {}).get(latest) or {}
                    rr = ver.get("repository")
                    url = rr.get("url") if isinstance(rr, dict) else rr
                return _norm_github_repo(url)
            if surface == "pypi":
                r = await client.get(f"https://pypi.org/pypi/{name}/json")
                if r.status_code != 200:
                    return None
                info = (r.json() or {}).get("info") or {}
                urls = info.get("project_urls") or {}
                for key in ("Source", "Source Code", "Repository", "Code",
                            "GitHub", "Homepage", "Home"):
                    n = _norm_github_repo(urls.get(key))
                    if n:
                        return n
                return _norm_github_repo(info.get("home_page"))
    except Exception:
        return None
    return None


async def _provenance_repo(surface: str, name: str) -> str | None:
    """The GitHub repo cryptographically BOUND to the published artifact via
    Sigstore/PEP-740 provenance (the strongest link). Runs the canonical package
    scan and reads the verified binding. None if no verified provenance."""
    try:
        from src.scanner.scan import scan_package

        r = await scan_package(surface, name)
        prov = getattr(r, "provenance", None)
        if isinstance(prov, dict) and prov.get("verified"):
            return _norm_github_repo((prov.get("binding") or {}).get("repo"))
    except Exception:
        return None
    return None


async def _user_owns_repo(db: AsyncSession, entity_id, full_name: str) -> bool:
    """True if this user holds a VERIFIED github/openclaw claim for `owner/repo`."""
    from sqlalchemy import func as safunc

    row = (await db.execute(
        select(RepoClaim.id).where(
            RepoClaim.entity_id == entity_id,
            RepoClaim.status == "verified",
            RepoClaim.surface.in_(("github", "openclaw")),
            safunc.lower(RepoClaim.full_name) == full_name.lower(),
        ).limit(1)
    )).first()
    return row is not None


async def _ensure_watch(
    db: AsyncSession, entity_id, surface: str, owner: str, repo: str, is_private: bool,
) -> None:
    """A verified owner of a PUBLIC tool auto-watches it — rug-pull early warning on
    their own tool, delivered by the existing per-surface re-scan loop (which already
    dispatches via scan_watch_target). Private GitHub repos already get continuous
    App re-scans, so skip them. Best-effort: never fails the claim."""
    if is_private:
        return
    try:
        from src.models import ToolWatch

        existing = (await db.execute(
            select(ToolWatch).where(
                ToolWatch.watcher_id == entity_id,
                ToolWatch.surface == surface,
                ToolWatch.owner == owner,
                ToolWatch.repo == repo,
            )
        )).scalar_one_or_none()
        if existing is not None:
            if not existing.active:
                existing.active = True
            return
        # last_score left None → the first re-scan populates the baseline and can't
        # false-alert (a "dropped" alert needs a prior score).
        db.add(ToolWatch(watcher_id=entity_id, surface=surface, owner=owner, repo=repo))
    except Exception:
        logger.debug("auto-watch on claim failed for %s %s/%s", surface, owner, repo, exc_info=True)


async def _package_grant(
    db: AsyncSession, entity_id, surface: str, name: str,
) -> tuple[bool, str | None]:
    """Auto-grant an npm/PyPI claim by linking back to a repo the user owns. Checks
    the cheap declared-repo link first, then the (heavier) provenance binding.
    Returns (granted, proof_method)."""
    decl = await _declared_repo(surface, name)
    if decl and await _user_owns_repo(db, entity_id, decl):
        return True, "declared-repo"
    prov = await _provenance_repo(surface, name)
    if prov and await _user_owns_repo(db, entity_id, prov):
        return True, "provenance"
    return False, None


async def _keyword_challenge_ok(surface: str, name: str, code: str) -> bool:
    """Fallback proof for a repo-less package: the maintainer published a version
    carrying keyword/classifier `agentavow-verify-<code>` (only a publisher can)."""
    token = f"agentavow-verify-{code}"
    import httpx

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            if surface == "npm":
                r = await client.get(f"https://registry.npmjs.org/{name}")
                if r.status_code != 200:
                    return False
                doc = r.json()
                kws: set[str] = set()
                if isinstance(doc.get("keywords"), list):
                    kws.update(str(k).lower() for k in doc["keywords"])
                latest = (doc.get("dist-tags") or {}).get("latest")
                ver = (doc.get("versions") or {}).get(latest) or {}
                if isinstance(ver.get("keywords"), list):
                    kws.update(str(k).lower() for k in ver["keywords"])
                return token in kws
            if surface == "pypi":
                r = await client.get(f"https://pypi.org/pypi/{name}/json")
                if r.status_code != 200:
                    return False
                info = (r.json() or {}).get("info") or {}
                blob = " ".join([
                    str(info.get("keywords") or ""),
                    " ".join(info.get("classifiers") or []),
                    " ".join(str(v) for v in (info.get("project_urls") or {}).values()),
                ]).lower()
                return token in blob
    except Exception:
        return False
    return False


async def _mcp_challenge_ok(url: str, code: str) -> bool:
    """Proof of MCP-endpoint control: the server returns `agentavow-verify-<code>` —
    as an `X-AgentAvow-Verify` response header or anywhere in its serverInfo — read
    on a fresh initialize handshake. SSRF-guarded; fail-closed."""
    token = f"agentavow-verify-{code}"
    try:
        import httpx

        from src.ssrf import validate_url_https

        safe = validate_url_https(url, field_name="endpoint")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "AgentAvow-Claim-Verify",
        }
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "AgentAvow", "version": "1.0"},
            },
        }
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            resp = await client.post(safe, headers=headers, json=body)
        hv = resp.headers.get("x-agentavow-verify")
        if hv and hv.strip() == token:
            return True
        from src.scanner.mcp_scan import _parse_jsonrpc_body

        doc = _parse_jsonrpc_body(resp.text)
        info = ((doc or {}).get("result") or {}).get("serverInfo") or {}
        return token in json.dumps(info).lower() or token in (resp.text or "").lower()[:8000]
    except Exception:
        return False


class ClaimRequest(BaseModel):
    # Surface of the tool being claimed. github/openclaw send owner+repo; npm/pypi
    # send the package name in `repo`; mcp sends the endpoint URL in `repo`.
    surface: str = Field("github", max_length=16)
    owner: str = Field("", max_length=255)
    repo: str = Field(..., max_length=512)
    # Optional: a read token proving access. When present + valid the claim is
    # verified immediately (the path for PRIVATE github repos, which can't use a topic).
    token: str | None = Field(None, max_length=255)


class VerifyRequest(BaseModel):
    # Optional read token — supply it to verify a PRIVATE github repo (proves access).
    # Omit it to verify via the surface's native proof (topic/keyword/mcp-challenge).
    token: str | None = Field(None, max_length=255)


def _serialize(c: RepoClaim, meta: dict | None = None) -> dict:
    # `private` is AUTHORITATIVE on the claim (set at claim time): public
    # topic-proof claims are False; GitHub-App claims of private repos are True.
    # `meta` maps full_name -> {scanned, published, grade, score} so the unified
    # "Your tools" list can show a grade + state without a per-row fetch.
    m = (meta or {}).get(c.full_name) or {}
    surface = getattr(c, "surface", "github") or "github"
    code = c.verify_code
    verify_token = f"agentavow-verify-{code}"
    # Per-surface proof instruction the UI renders (what the owner must do to verify).
    if surface in ("github", "openclaw"):
        proof = {"kind": "topic", "topic": verify_token}
    elif surface in ("npm", "pypi"):
        proof = {"kind": "keyword", "keyword": verify_token, "registry": surface}
    elif surface == "mcp":
        proof = {"kind": "mcp-challenge", "header": "X-AgentAvow-Verify", "value": verify_token}
    else:
        proof = {"kind": "topic", "topic": verify_token}
    return {
        "id": str(c.id),
        "surface": surface,
        "owner": c.owner,
        "repo": c.repo,
        "full_name": c.full_name,
        "status": c.status,
        "topic": verify_token,  # back-compat (github topic)
        "proof": proof,
        "proof_method": getattr(c, "proof_method", None),
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


@router.get("/claim-status")
async def claim_status(
    surface: str = "github",
    owner: str = "",
    repo: str = "",
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    """PUBLIC: has this tool been claimed by a verified owner? Powers the
    'maintainer-claimed' trust badge on the public report. Returns only a boolean —
    never who claimed it. Coordinates match the claim/watch convention per surface."""
    s = (surface or "github").strip().lower()
    coord = _claim_coord(s, owner, repo)
    if coord is None:
        return {"claimed": False, "surface": s}
    o, r, _fn = coord
    row = (await db.execute(
        select(RepoClaim.id).where(
            RepoClaim.surface == s,
            RepoClaim.owner == o,
            RepoClaim.repo == r,
            RepoClaim.status == "verified",
        ).limit(1)
    )).first()
    return {"claimed": row is not None, "surface": s}


@router.post("/claims", status_code=201)
async def create_claim(
    body: ClaimRequest,
    background: BackgroundTasks,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Start a claim across any surface. Ownership proof is per-surface:
      github/openclaw → add the topic (or supply a read token for a private repo)
      npm/pypi        → auto-granted if it links back to a repo you own, else add
                        the keyword and re-verify
      mcp             → have the endpoint return the challenge, then re-verify."""
    surface = (body.surface or "github").strip().lower()
    if surface not in _SURFACES:
        raise HTTPException(status_code=400, detail="unsupported surface")
    coord = _claim_coord(surface, body.owner, body.repo)
    if coord is None:
        raise HTTPException(status_code=400, detail="Invalid coordinate for surface")
    owner, repo, full_name = coord
    token = (body.token or "").strip()

    # --- GitHub / OpenClaw skill: a skill IS a repo, so the repo proof applies. ---
    if surface in ("github", "openclaw"):
        # Public-claim path (no token): if we can't read the repo publicly it's
        # private (or missing) — the topic method can't work, so steer the owner to
        # the GitHub App flow instead of a claim that sits pending forever.
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
                        f"https://api.github.com/repos/{owner}/{repo}", headers=headers,
                    )
                if resp.status_code != 200:
                    return {
                        "needs_private_flow": True,
                        "detail": (
                            "We can't read this repo publicly. If it's private, connect "
                            "the GitHub App below to claim + scan it. If it's public, "
                            "double-check the owner / repo."
                        ),
                    }
            except Exception:
                pass  # transient network issue — fall through and create as usual
        # Make a claimed GitHub repo discoverable (skills aren't in the catalog yet).
        if surface == "github":
            background.add_task(_scan_into_catalog, owner, repo)
        verified = bool(token) and await _repo_accessible_with_token(owner, repo, token)
        proof_method = "token" if verified else None
    # --- npm / PyPI: try to auto-grant by linking to a repo you own. ---
    elif surface in ("npm", "pypi"):
        verified, proof_method = await _package_grant(db, entity.id, surface, repo)
    # --- MCP: always starts pending — the endpoint must return the challenge. ---
    else:  # mcp
        verified, proof_method = False, None

    existing = (await db.execute(
        select(RepoClaim).where(
            RepoClaim.entity_id == entity.id,
            RepoClaim.surface == surface,
            RepoClaim.owner == owner,
            RepoClaim.repo == repo,
        )
    )).scalar_one_or_none()
    if existing is not None:
        if verified and existing.status != "verified":
            from sqlalchemy import func as safunc
            existing.status = "verified"
            existing.verified_at = safunc.now()
            existing.proof_method = proof_method
            await _ensure_watch(db, entity.id, surface, owner, repo, existing.is_private)
            await db.flush()
            await db.refresh(existing)
        payload = _serialize(existing)
        await db.commit()
        return payload
    claim = RepoClaim(
        entity_id=entity.id,
        surface=surface,
        owner=owner,
        repo=repo,
        full_name=full_name,
        status="verified" if verified else "pending",
        verify_code=secrets.token_hex(8),
        proof_method=proof_method,
    )
    if verified:
        from sqlalchemy import func as safunc
        claim.verified_at = safunc.now()
        await _ensure_watch(db, entity.id, surface, owner, repo, claim.is_private)
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
    """Verify a claim via its surface's proof:
      github/openclaw → GitHub topic (or a read token for a private repo)
      npm/pypi        → repo-link (provenance/declared) or the published keyword
      mcp             → the endpoint returns the challenge (header / serverInfo)."""
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")
    surface = getattr(claim, "surface", "github") or "github"

    async def _mark_verified(proof_method: str) -> dict:
        from sqlalchemy import func as safunc
        claim.status = "verified"
        claim.verified_at = safunc.now()
        claim.proof_method = proof_method
        # Owning a public tool auto-watches it (rug-pull alerts on your own tool).
        await _ensure_watch(db, entity.id, surface, claim.owner, claim.repo, claim.is_private)
        await db.flush()
        await db.refresh(claim)
        return {"verified": True, **_serialize(claim)}

    # --- npm / PyPI: re-check the repo-link auto-grant, then the keyword challenge.
    if surface in ("npm", "pypi"):
        granted, pm = await _package_grant(db, entity.id, surface, claim.repo)
        if granted:
            return await _mark_verified(pm)
        if await _keyword_challenge_ok(surface, claim.repo, claim.verify_code):
            return await _mark_verified("keyword")
        return {
            "verified": False,
            "keyword": f"agentavow-verify-{claim.verify_code}",
            "detail": (
                "Not verified yet. Either claim the package's source repo first "
                "(we auto-link it), or add the keyword above and publish a new version."
            ),
        }

    # --- MCP: the endpoint must return the challenge.
    if surface == "mcp":
        if await _mcp_challenge_ok(claim.repo, claim.verify_code):
            return await _mark_verified("mcp-challenge")
        return {
            "verified": False,
            "header": "X-AgentAvow-Verify",
            "value": f"agentavow-verify-{claim.verify_code}",
            "detail": (
                "Challenge not seen yet — have the server return the value above as an "
                "X-AgentAvow-Verify response header (or in its serverInfo), then retry."
            ),
        }

    # --- GitHub / OpenClaw skill: token path (private) then topic path.
    token = (body.token.strip() if body and body.token else "")
    if token:
        if await _repo_accessible_with_token(claim.owner, claim.repo, token):
            return await _mark_verified("token")
        return {
            "verified": False,
            "detail": "That token can't read this repo — check it has read access to it.",
        }

    expected = f"agentavow-verify-{claim.verify_code}"
    try:
        import httpx

        from src.github_auth import get_github_token

        headers = {"Accept": "application/vnd.github+json"}
        gh = await get_github_token()
        if gh:
            headers["Authorization"] = f"Bearer {gh}"
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{claim.owner}/{claim.repo}/topics", headers=headers
            )
        topics = resp.json().get("names", []) if resp.status_code == 200 else []
    except Exception:
        topics = []
    if expected in topics:
        return await _mark_verified("topic")
    return {
        "verified": False,
        "topic": expected,
        "detail": "Topic not found yet — add it to the repo and retry.",
    }


async def _scan_surface_for_publish(surface: str, owner: str, repo: str):
    """Scan a non-GitHub surface and return its catalog-ready dict (findings, grade,
    trust_score) via the shared _scan_result_to_dict. Raises HTTPException on error."""
    from src.api.public_scan_router import _scan_result_to_dict
    from src.scanner.scan import scan_mcp, scan_package, scan_skill

    if surface in ("npm", "pypi"):
        result = await scan_package(surface, repo)
    elif surface == "mcp":
        result = await scan_mcp(repo)
    elif surface == "openclaw":
        result = await scan_skill(owner, repo)
    else:
        raise HTTPException(status_code=400, detail="Unsupported surface for publish")
    if getattr(result, "error", None):
        raise HTTPException(status_code=502, detail=f"Scan failed: {result.error}")
    return _scan_result_to_dict(result)


@router.post("/claims/{claim_id}/publish")
async def publish_claim(
    claim_id: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_scans),
):
    """Publish a verified NON-GitHub claim (npm/pypi/mcp/skill) into the public
    browse catalog under its real surface. GitHub public repos are auto-listed on
    claim; private GitHub repos use /private-report/.../publish."""
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")
    if claim.status != "verified":
        raise HTTPException(status_code=400, detail="Verify ownership first")
    surface = getattr(claim, "surface", "github") or "github"
    if surface == "github":
        raise HTTPException(status_code=400, detail="GitHub repos are listed automatically")
    from src.api.public_scan_router import _capture_community_scan

    data = await _scan_surface_for_publish(surface, claim.owner, claim.repo)
    await _capture_community_scan(claim.owner, claim.repo, data, db, surface=surface)
    return {
        "published": True, "surface": surface, "full_name": claim.full_name,
        "grade": data.get("grade"), "trust_score": data.get("trust_score"),
    }


@router.post("/claims/{claim_id}/unpublish")
async def unpublish_claim(
    claim_id: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Withdraw a claimed non-GitHub tool from the public catalog (delete its
    community_scans row). Idempotent. The claim + its watch stay."""
    claim = await db.get(RepoClaim, claim_id)
    if claim is None or claim.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Claim not found")
    from sqlalchemy import delete as sa_delete

    from src.models import CommunityScan
    surface = getattr(claim, "surface", "github") or "github"
    await db.execute(sa_delete(CommunityScan).where(
        CommunityScan.surface == surface,
        CommunityScan.owner == claim.owner,
        CommunityScan.repo == claim.repo,
    ))
    return {"published": False}


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
    from sqlalchemy import delete as sa_delete

    from src.models import CommunityScan
    # A non-GitHub claim's catalog listing is tied to the claim (unlike a public
    # GitHub repo, which is public regardless of claimant) — withdraw it on remove.
    surface = getattr(claim, "surface", "github") or "github"
    if surface != "github":
        await db.execute(sa_delete(CommunityScan).where(
            CommunityScan.surface == surface,
            CommunityScan.owner == claim.owner,
            CommunityScan.repo == claim.repo,
        ))
    # Removing a PRIVATE claim also withdraws it from public search (delete the
    # CommunityScan row) and drops the owner-scoped stored report — otherwise an
    # unclaimed private repo would linger in Browse/search. Public repos stay in
    # the catalog (they're public regardless of who claims them).
    if claim.is_private:
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
    # Count one-time (ephemeral, token-based) private scans for the metrics
    # dashboard — these aren't persisted, so the GitHub-App count can't see them.
    try:
        from src.api.metrics_dashboard_router import bump_metric
        await bump_metric("private_scan_onetime")
    except Exception:
        pass
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
