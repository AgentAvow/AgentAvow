"""Connector Preflight + registry-snippet endpoints — the developer app-store surface.

* ``GET /public/preflight/{owner}/{repo}`` — repo readiness for the app stores.
* ``GET /public/preflight/mcp?endpoint=`` — live MCP server readiness.
* ``GET /public/registry-snippet/{owner}/{repo}`` — the signed-score ``_meta`` block
  a developer pastes into their ``server.json`` so the score travels into the MCP
  registry record itself (portable, offline-recomputable).

All reuse the existing scan pipeline + public-scan attestation; the gate logic lives
in ``src.preflight.gates`` (pure).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src import cache
from src.api.rate_limit import rate_limit_reads, rate_limit_scans
from src.database import get_db
from src.preflight.gates import evaluate_gates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public", tags=["preflight"])

_TTL = 3600
JWKS_URL = "https://agentgraph.co/.well-known/jwks.json"
KID = "agentgraph-security-v1"
ISSUER = "did:web:agentgraph.co"
SCHEMA = "https://schema.agentgraph.co/attestation/security/v1"
_META_KEY = "io.modelcontextprotocol.registry/publisher-provided"


class Gate(BaseModel):
    id: str
    label: str
    status: str          # pass | fail | warn | unknown | na
    severity: str        # blocker | warning
    detail: str
    stores: list[str]


class PreflightResponse(BaseModel):
    target: str
    surface: str         # mcp | repo
    directory_ready: bool
    headline: str
    trust_score: int
    trust_tier: str
    grade: str
    certified: bool
    gates: list[Gate]
    summary: dict
    signed: dict         # {jws, kid, jwks_url, report_url}
    cached: bool
    scanned_at: str


async def _cache_get(key: str) -> dict | None:
    try:
        return await cache.get(key)
    except Exception:
        return None


async def _cache_set(key: str, value: dict) -> None:
    try:
        await cache.set(key, value, ttl=_TTL)
    except Exception:
        pass


def _sign(subject_full: str, data: dict) -> str:
    from src.api.public_scan_router import _build_scan_payload
    from src.signing import canonicalize, create_jws

    return create_jws(canonicalize(_build_scan_payload(subject_full, data)))


def _report_url(surface: str, target: str) -> str:
    if surface == "mcp":
        return "https://agentavow.com/check/mcp"
    return f"https://agentavow.com/check/{target}"


def _build_preflight(
    target: str, surface: str, data: dict, auth: dict | None, cached: bool,
) -> PreflightResponse:
    report = evaluate_gates(data, surface=surface, auth=auth)
    subject_full = f"mcp:{target}" if surface == "mcp" else target
    jws = _sign(subject_full, data)
    return PreflightResponse(
        target=target,
        surface=surface,
        directory_ready=report["directory_ready"],
        headline=report["headline"],
        trust_score=int(data.get("trust_score") or 0),
        trust_tier=str(data.get("trust_tier") or ""),
        grade=str(data.get("grade") or ""),
        certified=bool((data.get("certified") or {}).get("eligible")),
        gates=[Gate(**g) for g in report["gates"]],
        summary=report["summary"],
        signed={
            "jws": jws,
            "kid": KID,
            "jwks_url": JWKS_URL,
            "report_url": _report_url(surface, target),
        },
        cached=cached,
        scanned_at=str(data.get("scanned_at") or ""),
    )


@router.get(
    "/preflight/mcp",
    response_model=PreflightResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def preflight_mcp(
    endpoint: str = Query(..., description="The MCP server's Streamable-HTTP URL"),
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
) -> PreflightResponse:
    """Check a LIVE MCP server against the Anthropic + OpenAI submission gates."""
    from src.api.public_scan_router import _scan_result_to_dict
    from src.ssrf import validate_url_https

    try:
        url = validate_url_https(endpoint, field_name="endpoint")
    except Exception:
        raise HTTPException(400, "endpoint must be a valid https:// URL")

    key = "preflight:mcp:" + hashlib.sha256(url.encode()).hexdigest()[:22]
    if not force:
        cached = await _cache_get(key)
        if cached:
            return _build_preflight(url, "mcp", cached["data"], cached.get("auth"), cached=True)

    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)

    from src.preflight.auth_probe import probe_mcp_auth
    from src.scanner.scan import scan_mcp

    try:
        result = await asyncio.wait_for(scan_mcp(url), timeout=45)
    except asyncio.TimeoutError:
        raise HTTPException(503, "MCP handshake timed out — please retry shortly.",
                            headers={"Retry-After": "20"})
    if result.error:
        raise HTTPException(422, f"Scan error: {result.error}")

    data = _scan_result_to_dict(result)
    auth = await probe_mcp_auth(url)
    await _cache_set(key, {"data": data, "auth": auth})
    return _build_preflight(url, "mcp", data, auth, cached=False)


@router.get(
    "/preflight/{owner}/{repo}",
    response_model=PreflightResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def preflight_repo(
    owner: str,
    repo: str,
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
) -> PreflightResponse:
    """Check a GitHub repo (an MCP server / agent tool) against the submission gates."""
    from src.api.public_scan_router import _scan_result_to_dict

    if not owner.replace("-", "").replace("_", "").replace(".", "").isalnum() or \
       not repo.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "Invalid owner/repo")
    full = f"{owner}/{repo}"

    key = f"preflight:repo:{full}"
    if not force:
        cached = await _cache_get(key)
        if cached:
            return _build_preflight(full, "repo", cached["data"], None, cached=True)

    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)

    from src.github_auth import get_github_token
    from src.scanner.scan import scan_repo

    token = await get_github_token()
    try:
        result = await asyncio.wait_for(scan_repo(full_name=full, token=token), timeout=90)
    except asyncio.TimeoutError:
        raise HTTPException(503, "Scan timed out — please retry shortly.",
                            headers={"Retry-After": "20"})
    if getattr(result, "error", None):
        raise HTTPException(422, f"Scan error: {result.error}")

    data = _scan_result_to_dict(result)
    await _cache_set(key, {"data": data})
    return _build_preflight(full, "repo", data, None, cached=False)


def _registry_meta(subject_id: str, subject_full: str, data: dict) -> dict:
    """Build the compact ``_meta`` publisher-provided trust block (§ server.json).

    Shaped as a W3C Verifiable Credential (VC Data Model v2 context + type) so it rides
    the same DID/VC standard the identity-registry players use — the safety SCORE none of
    them issue, carried in the credential format they already consume. The Ed25519 JWS in
    ``proof`` is offline-verifiable against our JWKS; the score is recomputable from the
    findings. Only the SAFETY score is signed here — adoption is not a credentialed claim.
    """
    jws = _sign(subject_full, data)
    trust = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust/v1",
        ],
        "type": ["VerifiableCredential", "TrustScoreCredential"],
        "issuer": ISSUER,
        "credentialSubject": {
            "id": subject_id,
            "trustScore": int(data.get("trust_score") or 0),
            "trustTier": str(data.get("trust_tier") or ""),
            "grade": str(data.get("grade") or ""),
            "certified": bool((data.get("certified") or {}).get("eligible")),
        },
        "proof": {
            "type": "JsonWebSignature2020",
            "verificationMethod": f"{ISSUER}#{KID}",
            "jwks": JWKS_URL,
            "jws": jws,
        },
        "schema": SCHEMA,
        "report": _report_url("repo" if subject_id.startswith("github:") else "mcp",
                              subject_full.replace("mcp:", "")),
    }
    return {"_meta": {_META_KEY: {"com.agentavow/trust": trust}}}


@router.get(
    "/registry-snippet/{owner}/{repo}",
    dependencies=[Depends(rate_limit_reads)],
)
async def registry_snippet(owner: str, repo: str):
    """Return the signed ``server.json`` ``_meta`` block to paste into an MCP registry
    record, so the AgentAvow score travels with the connector (offline-recomputable)."""
    import json

    from src.api.public_scan_router import _scan_result_to_dict
    from src.github_auth import get_github_token
    from src.scanner.scan import scan_repo

    full = f"{owner}/{repo}"
    key = f"preflight:repo:{full}"
    cached = await _cache_get(key)
    if cached:
        data = cached["data"]
    else:
        try:
            token = await get_github_token()
            result = await asyncio.wait_for(scan_repo(full_name=full, token=token), timeout=90)
        except asyncio.TimeoutError:
            raise HTTPException(503, "Scan timed out — please retry shortly.")
        if getattr(result, "error", None):
            raise HTTPException(422, f"Scan error: {result.error}")
        data = _scan_result_to_dict(result)
        await _cache_set(key, {"data": data})

    meta = _registry_meta(f"github:{full}", full, data)
    return {
        "server_json_meta": meta,
        "snippet": json.dumps(meta, indent=2),
        "note": "Merge this _meta block into your server.json. The attestation JWS is "
                "self-verifying: recompute the score offline and check the EdDSA signature "
                f"against {JWKS_URL}.",
    }


# ── Recompute-on-release drift feed ──────────────────────────────────────────
DRIFT_SCHEMA = "https://schema.agentgraph.co/attestation/drift/v1"


async def _drift_payload(full_name: str, subject_id: str, db: AsyncSession) -> dict:
    from src.models import ScanHistory
    from src.signing import canonicalize, create_jws

    rows = (await db.execute(
        select(ScanHistory)
        .where(ScanHistory.full_name == full_name)
        .order_by(desc(ScanHistory.scanned_at))
        .limit(50)
    )).scalars().all()
    if not rows:
        raise HTTPException(404, "No scan history yet for this tool — scan it first, "
                                 "then re-scan on your next release to build the feed.")

    points = [{
        "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
        "trust_score": r.trust_score,
        "grade": r.grade,
        "certified": r.certified,
        "critical": r.critical,
        "high": r.high,
        "score_delta": r.score_delta,
        "manifest_drift": r.manifest_drift,
    } for r in rows]
    latest = rows[0]
    drift_events = sum(1 for r in rows if r.manifest_drift or (r.score_delta or 0) != 0)

    now = datetime.now(timezone.utc).isoformat()
    signed_payload = {
        "@context": DRIFT_SCHEMA,
        "type": "ScoreDriftAttestation",
        "issuer": {"id": ISSUER, "name": "AgentAvow"},
        "subject": {"id": subject_id, "fullName": full_name},
        "issuedAt": now,
        "latest": {
            "trustScore": latest.trust_score,
            "certified": latest.certified,
            "toolManifestDigest": latest.tool_manifest_digest,
            "scannedAt": latest.scanned_at.isoformat() if latest.scanned_at else None,
        },
        "history": [{
            "scannedAt": p["scanned_at"], "trustScore": p["trust_score"],
            "scoreDelta": p["score_delta"], "manifestDrift": p["manifest_drift"],
        } for p in points],
    }
    jws = create_jws(canonicalize(signed_payload))
    return {
        "subject": subject_id,
        "full_name": full_name,
        "current_score": latest.trust_score,
        "certified": latest.certified,
        "summary": {
            "points": len(points),
            "drift_events": drift_events,
            "first_seen": points[-1]["scanned_at"],
            "last_change": points[0]["scanned_at"],
        },
        "history": points,
        "signed": {"jws": jws, "kid": KID, "jwks_url": JWKS_URL},
    }


@router.get("/drift/pkg/{surface}/{name:path}", dependencies=[Depends(rate_limit_reads)])
async def drift_pkg(surface: str, name: str, db: AsyncSession = Depends(get_db)):
    """Signed score/definition drift timeline for a package (npm/pypi/crates/…)."""
    surface = surface.lower()
    full_name = f"{surface}:{name}"
    return await _drift_payload(full_name, f"{surface}:{name}", db)


@router.get("/drift/{owner}/{repo}", dependencies=[Depends(rate_limit_reads)])
async def drift_repo(owner: str, repo: str, db: AsyncSession = Depends(get_db)):
    """Signed score/definition drift timeline for a GitHub repo — the recompute-on-
    release feed: every version bump that moved the score or drifted the signed
    tool definition, offline-recomputable against our JWKS."""
    full_name = f"{owner}/{repo}"
    return await _drift_payload(full_name, f"github:{full_name}", db)
