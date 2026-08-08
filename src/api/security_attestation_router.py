"""Signed security posture attestations (A2A trust.signals[] compatible)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.rate_limit import rate_limit_reads
from src.attestation.composed_slot import (
    ScanInputs,
    build_agentgraph_slot,
    compute_evidence_hash,
)
from src.database import get_db
from src.models import Entity, FrameworkSecurityScan, TrustScore
from src.signing import KID, canonicalize, create_jws

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attestations"])

# ── response models ───────────────────────────────────────────────────


class AttestationIssuer(BaseModel):
    id: str
    name: str
    url: str


class AttestationSubject(BaseModel):
    id: str
    entity_id: str
    display_name: str


class ScanFindings(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    total: int = 0


class ScanChecks(BaseModel):
    no_critical_findings: bool = True
    no_high_findings: bool = True
    has_readme: bool = False
    has_license: bool = False
    has_tests: bool = False


class ScanData(BaseModel):
    result: str
    scanned_at: str
    framework: str
    trust_score: int = 0
    findings: ScanFindings
    positive_signals: list[str] = []
    checks: ScanChecks
    files_scanned: int = 0
    files_total: int = 0
    sampled: bool = False
    primary_language: str = ""


class TrustData(BaseModel):
    overall: float | None = None
    scan_component: float | None = None


class AttestationPayload(BaseModel):
    context: str
    type: str
    issuer: AttestationIssuer
    subject: AttestationSubject
    issued_at: str
    expires_at: str
    scan: ScanData
    trust: TrustData


class SecurityAttestationResponse(BaseModel):
    jws: str
    payload: dict
    algorithm: str = "EdDSA"
    key_id: str = KID
    jwks_url: str = "https://agentgraph.co/.well-known/jwks.json"


# ── helpers ───────────────────────────────────────────────────────────

def _build_payload(
    entity: Entity,
    scan: FrameworkSecurityScan,
    trust: TrustScore | None,
) -> dict:
    """Build the attestation payload dict."""
    now = datetime.now(timezone.utc)
    vulns = scan.vulnerabilities if isinstance(scan.vulnerabilities, dict) else {}

    # Extract finding counts — handle both dict and list formats
    critical = vulns.get("critical_count", 0)
    high = vulns.get("high_count", 0)
    medium = vulns.get("medium_count", 0)

    # If vulnerabilities is a list of findings, count by severity
    if isinstance(scan.vulnerabilities, list):
        findings = [
            f for f in scan.vulnerabilities if isinstance(f, dict)
        ]
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

    total = critical + high + medium

    did_uri = f"did:web:agentgraph.co:entities:{entity.id}"

    return {
        "@context": "https://schema.agentgraph.co/attestation/security/v1",
        "type": "SecurityPostureAttestation",
        "issuer": {
            "id": "did:web:agentgraph.co",
            "name": "AgentGraph",
            "url": "https://agentgraph.co",
        },
        "subject": {
            "id": did_uri,
            "entity_id": str(entity.id),
            "display_name": entity.display_name,
        },
        "scannedAt": scan.scanned_at.isoformat() if scan.scanned_at else now.isoformat(),
        "issuedAt": now.isoformat(),
        "expiresAt": (now + timedelta(hours=24)).isoformat(),
        "scan": {
            "result": scan.scan_result,
            "framework": scan.framework,
            "trustScore": vulns.get("trust_score", 0) if isinstance(vulns, dict) else 0,
            "findings": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "total": total,
            },
            "positiveSignals": vulns.get("positive_signals", []) if isinstance(vulns, dict) else [],
            "checks": {
                "no_critical_findings": critical == 0,
                "no_high_findings": high == 0,
                "has_readme": vulns.get("has_readme", False) if isinstance(vulns, dict) else False,
                "has_license": (
                    vulns.get("has_license", False)
                    if isinstance(vulns, dict) else False
                ),
                "has_tests": vulns.get("has_tests", False) if isinstance(vulns, dict) else False,
            },
            "filesScanned": vulns.get("files_scanned", 0) if isinstance(vulns, dict) else 0,
            # Coverage disclosure (#4): total scannable files + whether the grade is a
            # sample. Signed into the payload so partial coverage is never presented as
            # an authoritative whole-repo verdict. Defaults degrade gracefully when a
            # stored scan predates these fields.
            "filesTotal": (
                vulns.get("total_scannable_files", vulns.get("files_scanned", 0))
                if isinstance(vulns, dict) else 0
            ),
            "sampled": vulns.get("sampled", False) if isinstance(vulns, dict) else False,
            "primaryLanguage": vulns.get("primary_language", "") if isinstance(vulns, dict) else "",
        },
        "trust": {
            "overall": round(trust.score, 4) if trust else None,
            "scanComponent": (
                round((trust.components or {}).get("scan_score", 0), 4)
                if trust else None
            ),
        },
    }


# ── endpoint ──────────────────────────────────────────────────────────


@router.get(
    "/entities/{entity_id}/attestation/security",
    response_model=SecurityAttestationResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_security_attestation(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> SecurityAttestationResponse:
    """Return a signed security posture attestation for *entity_id*.

    The response follows the insumer multi-attestation format and can be
    verified using the public key at ``/.well-known/jwks.json``.
    """
    # Look up entity
    result = await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.is_active.is_(True)),
    )
    entity = result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Latest security scan
    scan_result = await db.execute(
        select(FrameworkSecurityScan)
        .where(FrameworkSecurityScan.entity_id == entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(1),
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No security scan available for this entity",
        )

    # Trust score (optional — attestation still valid without it)
    trust_result = await db.execute(
        select(TrustScore).where(TrustScore.entity_id == entity_id),
    )
    trust = trust_result.scalar_one_or_none()

    # Build & sign as compact JWS (RFC 7515)
    payload = _build_payload(entity, scan, trust)
    payload_bytes = canonicalize(payload)
    jws = create_jws(payload_bytes)

    return SecurityAttestationResponse(
        jws=jws,
        payload=payload,
        algorithm="EdDSA",
        key_id=KID,
        jwks_url="https://agentgraph.co/.well-known/jwks.json",
    )


# ── composed-slot v1 (APS interop) ────────────────────────────────────
#
# This is the *published interop shape* for the three-signal composition
# (APS composed-v1 envelope — coordinated on A2A #1734 / agentid-aps-interop#5).
#
# Distinct from the native attestation above: native includes the full rubric
# output (positive_signals, etc.). The slot exposes only the locked contract
# fields. overall_grade stays proprietary; consumers MAY treat it as opaque.

@router.get(
    "/entities/{entity_id}/attestation/composed-slot",
    dependencies=[Depends(rate_limit_reads)],
)
async def get_composed_slot(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return the ``agentgraph-scan-v1-structural`` slot for *entity_id*.

    Designed to be dropped into the APS composed-v1 envelope as the
    ``static_analysis`` signal. Does NOT expose AgentGraph's internal
    scoring weights — only the published gate vocabulary + letter grade.
    """
    # Look up entity
    result = await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.is_active.is_(True)),
    )
    entity = result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Latest security scan
    scan_result = await db.execute(
        select(FrameworkSecurityScan)
        .where(FrameworkSecurityScan.entity_id == entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(1),
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No security scan available for this entity",
        )

    vulns = scan.vulnerabilities if isinstance(scan.vulnerabilities, dict) else {}

    # Trust score (for overall_grade)
    trust_result = await db.execute(
        select(TrustScore).where(TrustScore.entity_id == entity_id),
    )
    trust = trust_result.scalar_one_or_none()
    # Scanner emits 0-100; TrustScore.score is 0-1. Prefer scan trust_score.
    trust_0_to_100 = int(vulns.get("trust_score", 0))
    if not trust_0_to_100 and trust:
        trust_0_to_100 = int(round((trust.score or 0) * 100))

    # Category scores (public fraction-of-100 per gate)
    category_scores = vulns.get("category_scores") or {}

    # Flat findings counts (scanner already rolls these up)
    findings_counts = {
        "critical": int(vulns.get("critical_count", 0)),
        "high": int(vulns.get("high_count", 0)),
        "medium": int(vulns.get("medium_count", 0)),
        "secrets": int(vulns.get("secret_count", 0)),
        "dep_critical": int(vulns.get("dep_critical_count", 0)),
        "dep_high": int(vulns.get("dep_high_count", 0)),
        "static_analysis": int(vulns.get("static_analysis_count", 0)),
    }

    # Evidence hash — canonical hash over the native attestation payload,
    # so the slot's evidence_hash references a replayable, signed artifact.
    native_payload = _build_payload(entity, scan, trust)
    evidence_hash = compute_evidence_hash(canonicalize(native_payload))
    evidence_url = (
        f"https://agentgraph.co/api/v1/entities/{entity.id}/attestation/security"
    )

    inputs = ScanInputs(
        entity_id=str(entity.id),
        entity_did=None,  # Derive from entity_id; external DIDs handled in future
        source_url=entity.source_url or "",
        source_type=entity.source_type,
        framework=scan.framework,
        artifact_ref=vulns.get("artifact_ref") or "",
        scanned_at=scan.scanned_at,
        scanner_version=str(vulns.get("scanner_version", "unknown")),
        trust_score_0_to_100=trust_0_to_100,
        category_scores=category_scores,
        findings=findings_counts,
        evidence_hash=evidence_hash,
        evidence_url=evidence_url,
        # Phase 0: pass through the recompute-discipline coverage block if the
        # stored scan carries one (older scans simply omit it — additive).
        coverage=(vulns.get("coverage") or None),
    )
    return build_agentgraph_slot(inputs)
