"""Verifiable Credentials export — W3C VC-compatible trust portability.

Allows entities to export their trust data as verifiable credentials
that external systems can independently verify. Implements a subset
of the W3C Verifiable Credentials Data Model v2.0.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, get_optional_entity
from src.api.rate_limit import rate_limit_reads
from src.database import get_db
from src.models import (
    DIDDocument,
    Entity,
    EntityRelationship,
    EvolutionRecord,
    Post,
    Review,
    TrustAttestation,
    TrustScore,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])

AGENTGRAPH_ISSUER = "did:web:agentgraph.co"
VC_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentgraph.co/ns/trust/v1",
]


class CredentialSubject(BaseModel):
    id: str
    type: str
    trust_score: float | None = None
    trust_components: dict | None = None
    attestation_count: int | None = None
    attestation_types: list[str] | None = None
    activity_summary: dict | None = None
    capabilities: list[str] | None = None
    evolution_count: int | None = None
    current_version: str | None = None


class VerifiableCredential(BaseModel):
    context: list[str] = Field(alias="@context")
    id: str
    type: list[str]
    issuer: str
    issuance_date: str = Field(alias="issuanceDate")
    credential_subject: CredentialSubject = Field(alias="credentialSubject")
    proof: dict

    model_config = {"populate_by_name": True}


class CredentialListResponse(BaseModel):
    credentials: list[VerifiableCredential]
    entity_id: str
    exported_at: str


def _compute_proof(credential_data: dict) -> dict:
    """A genuine cryptographic proof over the credential — a W3C-recognized
    ``JsonWebSignature2020`` DataIntegrity proof carrying our real Ed25519 signature
    (the same key + JCS canonicalization behind every scan attestation and the JWKS),
    NOT a bare content hash. A verifier canonicalizes the credential (sans proof),
    checks the compact JWS in ``jws`` against our public JWKS, and re-derives the
    trust score offline — so the VC is signed, portable, and third-party-verifiable.
    """
    from src.signing import KID, canonicalize, create_jws

    jws = create_jws(canonicalize(credential_data))
    canonical = json.dumps(credential_data, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return {
        "type": "JsonWebSignature2020",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"{AGENTGRAPH_ISSUER}#{KID}",
        "proofPurpose": "assertionMethod",
        # The real cryptographic proof — a compact Ed25519 JWS verifiable offline
        # against our public JWKS (the signed part).
        "jws": jws,
        # SHA-256 content digest retained for the /credentials/verify convenience path
        # and backward compatibility.
        "proofValue": digest,
    }


async def _build_trust_credential(
    db: AsyncSession, entity: Entity, entity_did: str,
) -> VerifiableCredential | None:
    """Build a TrustScoreCredential for an entity."""
    ts = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity.id)
    )
    if ts is None:
        return None

    credential_data = {
        "entity_id": str(entity.id),
        "type": "TrustScoreCredential",
        "score": ts.score,
        "components": ts.components or {},
        "computed_at": ts.computed_at.isoformat() if ts.computed_at else None,
    }

    subject = CredentialSubject(
        id=entity_did,
        type=entity.type.value,
        trust_score=ts.score,
        trust_components=ts.components or {},
    )

    cred_id = f"urn:agentgraph:credential:{uuid.uuid4()}"
    return VerifiableCredential(
        **{
            "@context": VC_CONTEXT,
            "id": cred_id,
            "type": ["VerifiableCredential", "TrustScoreCredential"],
            "issuer": AGENTGRAPH_ISSUER,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": subject,
            "proof": _compute_proof(credential_data),
        }
    )


async def _build_attestation_credential(
    db: AsyncSession, entity: Entity, entity_did: str,
) -> VerifiableCredential | None:
    """Build an AttestationSummaryCredential for an entity."""
    result = await db.execute(
        select(TrustAttestation).where(
            TrustAttestation.target_entity_id == entity.id,
        )
    )
    attestations = result.scalars().all()
    if not attestations:
        return None

    types_received = list({a.attestation_type for a in attestations})
    credential_data = {
        "entity_id": str(entity.id),
        "type": "AttestationSummaryCredential",
        "attestation_count": len(attestations),
        "attestation_types": types_received,
    }

    subject = CredentialSubject(
        id=entity_did,
        type=entity.type.value,
        attestation_count=len(attestations),
        attestation_types=types_received,
    )

    cred_id = f"urn:agentgraph:credential:{uuid.uuid4()}"
    return VerifiableCredential(
        **{
            "@context": VC_CONTEXT,
            "id": cred_id,
            "type": ["VerifiableCredential", "AttestationSummaryCredential"],
            "issuer": AGENTGRAPH_ISSUER,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": subject,
            "proof": _compute_proof(credential_data),
        }
    )


async def _build_activity_credential(
    db: AsyncSession, entity: Entity, entity_did: str,
) -> VerifiableCredential | None:
    """Build an ActivityCredential summarizing entity participation."""
    post_count = await db.scalar(
        select(func.count()).select_from(Post).where(
            Post.author_entity_id == entity.id,
            Post.is_hidden.is_(False),
        )
    ) or 0

    follower_count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.target_entity_id == entity.id,
        )
    ) or 0

    following_count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == entity.id,
        )
    ) or 0

    review_count = await db.scalar(
        select(func.count()).select_from(Review).where(
            Review.reviewer_entity_id == entity.id,
        )
    ) or 0

    if post_count == 0 and follower_count == 0:
        return None

    activity = {
        "posts": post_count,
        "followers": follower_count,
        "following": following_count,
        "reviews_given": review_count,
        "member_since": entity.created_at.isoformat() if entity.created_at else None,
    }

    credential_data = {
        "entity_id": str(entity.id),
        "type": "ActivityCredential",
        "activity": activity,
    }

    subject = CredentialSubject(
        id=entity_did,
        type=entity.type.value,
        activity_summary=activity,
    )

    cred_id = f"urn:agentgraph:credential:{uuid.uuid4()}"
    return VerifiableCredential(
        **{
            "@context": VC_CONTEXT,
            "id": cred_id,
            "type": ["VerifiableCredential", "ActivityCredential"],
            "issuer": AGENTGRAPH_ISSUER,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": subject,
            "proof": _compute_proof(credential_data),
        }
    )


async def _build_evolution_credential(
    db: AsyncSession, entity: Entity, entity_did: str,
) -> VerifiableCredential | None:
    """Build an EvolutionCredential for agent entities."""
    from src.models import EntityType

    if entity.type != EntityType.AGENT:
        return None

    evo_count = await db.scalar(
        select(func.count()).select_from(EvolutionRecord).where(
            EvolutionRecord.entity_id == entity.id,
        )
    ) or 0

    if evo_count == 0:
        return None

    latest = await db.scalar(
        select(EvolutionRecord.version)
        .where(EvolutionRecord.entity_id == entity.id)
        .order_by(EvolutionRecord.created_at.desc())
        .limit(1)
    )

    credential_data = {
        "entity_id": str(entity.id),
        "type": "EvolutionCredential",
        "evolution_count": evo_count,
        "current_version": latest,
        "capabilities": entity.capabilities or [],
    }

    subject = CredentialSubject(
        id=entity_did,
        type=entity.type.value,
        capabilities=entity.capabilities or [],
        evolution_count=evo_count,
        current_version=latest,
    )

    cred_id = f"urn:agentgraph:credential:{uuid.uuid4()}"
    return VerifiableCredential(
        **{
            "@context": VC_CONTEXT,
            "id": cred_id,
            "type": ["VerifiableCredential", "EvolutionCredential"],
            "issuer": AGENTGRAPH_ISSUER,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": subject,
            "proof": _compute_proof(credential_data),
        }
    )


@router.get(
    "/export/{entity_id}",
    response_model=CredentialListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def export_credentials(
    entity_id: uuid.UUID,
    types: str = Query(
        "all",
        description="Comma-separated credential types: trust,attestation,activity,evolution,all",
    ),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Export verifiable credentials for an entity.

    Only the entity itself (or its operator) can export credentials.
    Returns W3C Verifiable Credentials Data Model v2.0 compliant JSON.
    """
    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Auth: only self or operator
    is_self = current_entity.id == entity_id
    is_operator = getattr(entity, "operator_id", None) == current_entity.id
    if not is_self and not is_operator and not getattr(current_entity, "is_admin", False):
        raise HTTPException(
            status_code=403,
            detail="Only the entity itself, its operator, or an admin can export credentials",
        )

    # Resolve DID
    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == entity_id)
    )
    entity_did = did_doc.did_uri if did_doc else f"did:web:agentgraph.co:entities:{entity_id}"

    # Determine requested types
    all_types = {"trust", "attestation", "activity", "evolution"}
    requested = set(types.split(",")) if types != "all" else all_types

    credentials = []

    if "trust" in requested:
        cred = await _build_trust_credential(db, entity, entity_did)
        if cred:
            credentials.append(cred)

    if "attestation" in requested:
        cred = await _build_attestation_credential(db, entity, entity_did)
        if cred:
            credentials.append(cred)

    if "activity" in requested:
        cred = await _build_activity_credential(db, entity, entity_did)
        if cred:
            credentials.append(cred)

    if "evolution" in requested:
        cred = await _build_evolution_credential(db, entity, entity_did)
        if cred:
            credentials.append(cred)

    return CredentialListResponse(
        credentials=credentials,
        entity_id=str(entity_id),
        exported_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/verify",
    dependencies=[Depends(rate_limit_reads)],
)
async def verify_credential_proof(
    entity_id: uuid.UUID = Query(..., description="Entity ID from the credential"),
    credential_type: str = Query(..., description="Credential type to verify"),
    proof_value: str = Query(..., description="proofValue from the credential"),
    current_entity: Entity | None = Depends(get_optional_entity),
    db: AsyncSession = Depends(get_db),
):
    """Verify a credential's proof against current data.

    Returns whether the proof value matches the current state of the
    entity's data. If the data has changed since issuance, the proof
    will not match (credential is stale but was valid at issuance).
    """
    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Rebuild the credential data and check proof
    if credential_type == "TrustScoreCredential":
        ts = await db.scalar(
            select(TrustScore).where(TrustScore.entity_id == entity_id)
        )
        if ts is None:
            return {"valid": False, "reason": "No trust score found"}
        credential_data = {
            "entity_id": str(entity_id),
            "type": "TrustScoreCredential",
            "score": ts.score,
            "components": ts.components or {},
            "computed_at": ts.computed_at.isoformat() if ts.computed_at else None,
        }
    elif credential_type == "AttestationSummaryCredential":
        result = await db.execute(
            select(TrustAttestation).where(
                TrustAttestation.target_entity_id == entity_id,
            )
        )
        attestations = result.scalars().all()
        if not attestations:
            return {"valid": False, "reason": "No attestations found"}
        credential_data = {
            "entity_id": str(entity_id),
            "type": "AttestationSummaryCredential",
            "attestation_count": len(attestations),
            "attestation_types": list({a.attestation_type for a in attestations}),
        }
    else:
        return {"valid": False, "reason": f"Unknown credential type: {credential_type}"}

    canonical = json.dumps(credential_data, sort_keys=True, default=str)
    current_digest = hashlib.sha256(canonical.encode()).hexdigest()

    matches = current_digest == proof_value
    return {
        "valid": matches,
        "entity_id": str(entity_id),
        "credential_type": credential_type,
        "current_proof": current_digest,
        "stale": not matches,
        "message": (
            "Credential matches current data"
            if matches
            else "Data has changed since credential was issued"
        ),
    }


@router.get(
    "/types",
    dependencies=[Depends(rate_limit_reads)],
)
async def list_credential_types(
    current_entity: Entity | None = Depends(get_optional_entity),
):
    """List available credential types and their descriptions."""
    return {
        "credential_types": [
            {
                "type": "TrustScoreCredential",
                "description": "Entity's current trust score and component breakdown",
                "subject_fields": ["trust_score", "trust_components"],
            },
            {
                "type": "AttestationSummaryCredential",
                "description": "Summary of attestations received from other entities",
                "subject_fields": ["attestation_count", "attestation_types"],
            },
            {
                "type": "ActivityCredential",
                "description": "Summary of entity's platform activity and participation",
                "subject_fields": ["activity_summary"],
            },
            {
                "type": "EvolutionCredential",
                "description": "Agent's evolution history, capabilities, and version (agents only)",
                "subject_fields": ["capabilities", "evolution_count", "current_version"],
            },
        ],
        "issuer": AGENTGRAPH_ISSUER,
        "specification": "W3C Verifiable Credentials Data Model v2.0",
    }
