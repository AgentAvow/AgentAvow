"""DID (Decentralized Identifier) document management endpoints.

Provides resolution and management of DID:web documents for entities.
DID documents contain public keys, service endpoints, and verification
methods following the W3C DID Core specification.

Includes a PROVISIONAL/FULL/REVOKED state machine for DID status:
- New agent registrations start with PROVISIONAL DID status
- Transition to FULL via trust score >= 0.3, operator attestation, or admin promotion
- PROVISIONAL DIDs cannot issue attestations or create marketplace listings
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.audit import log_action
from src.database import get_db
from src.models import DIDDocument, DIDStatus, Entity, FormalAttestation, TrustScore
from src.ssrf import validate_url_https

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/did", tags=["did"])

# Trust score threshold for automatic DID promotion
DID_PROMOTION_TRUST_THRESHOLD = 0.3


class ServiceEndpoint(BaseModel):
    id: str = Field(..., max_length=200)
    type: str = Field(..., max_length=100)
    serviceEndpoint: str = Field(  # noqa: N815 — W3C DID spec field name
        ..., max_length=2000,
    )

    @field_validator("serviceEndpoint")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        return validate_url_https(v, field_name="serviceEndpoint")


class UpdateDIDRequest(BaseModel):
    service: list[ServiceEndpoint] | None = None


class DIDStatusResponse(BaseModel):
    did_uri: str
    did_status: str
    is_provisional: bool
    promoted_at: datetime | None = None
    promoted_by: str | None = None
    promotion_reason: str | None = None
    created_at: datetime | None = None


class PromoteDIDRequest(BaseModel):
    reason: str = Field(
        "admin_approval",
        max_length=200,
        description="Reason for promoting the DID to FULL status.",
    )


class PromoteDIDResponse(BaseModel):
    did_uri: str
    old_status: str
    new_status: str
    promotion_reason: str
    promoted_at: datetime
    message: str


# --- Helpers ---


def _build_did_document(entity: Entity, did_doc: DIDDocument | None) -> dict:
    """Build a W3C DID document from entity + stored doc."""
    did = entity.did_web
    base_doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
            }
        ],
        "authentication": [f"{did}#key-1"],
        "service": [
            {
                "id": f"{did}#agentgraph",
                "type": "AgentGraphProfile",
                "serviceEndpoint": f"https://agentgraph.co/entities/{entity.id}",
            }
        ],
    }

    # Merge stored document data if exists
    if did_doc and did_doc.document:
        stored = did_doc.document
        if "service" in stored:
            base_doc["service"].extend(stored["service"])
        if did_doc.created_at:
            base_doc["created"] = did_doc.created_at.isoformat()
        if did_doc.updated_at:
            base_doc["updated"] = did_doc.updated_at.isoformat()

    # Include DID status metadata
    if did_doc:
        base_doc["didStatus"] = did_doc.did_status.value if did_doc.did_status else "full"
    else:
        base_doc["didStatus"] = "full"

    return base_doc


async def _get_or_create_did_doc(
    db: AsyncSession,
    entity: Entity,
    initial_status: DIDStatus = DIDStatus.FULL,
) -> DIDDocument:
    """Get existing DID document or create one with the given initial status."""
    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == entity.id)
    )
    if did_doc is None:
        did_doc = DIDDocument(
            id=uuid.uuid4(),
            entity_id=entity.id,
            did_uri=entity.did_web,
            document={},
            did_status=initial_status,
        )
        db.add(did_doc)
        await db.flush()
    return did_doc


async def _resolve_entity_by_did(
    db: AsyncSession, did_uri: str
) -> tuple[Entity, DIDDocument | None]:
    """Resolve entity and optional DID doc by DID URI.

    Raises HTTPException(404) if not found.
    """
    entity = await db.scalar(
        select(Entity).where(Entity.did_web == did_uri, Entity.is_active.is_(True))
    )
    if entity is None:
        raise HTTPException(status_code=404, detail="DID not found")

    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == entity.id)
    )
    return entity, did_doc


async def promote_did_to_full(
    db: AsyncSession,
    did_doc: DIDDocument,
    reason: str,
    promoted_by: uuid.UUID | None = None,
) -> None:
    """Transition a DID document from PROVISIONAL to FULL.

    Also clears the provisional flag on the entity and upgrades API key scopes.
    """
    did_doc.did_status = DIDStatus.FULL
    did_doc.promoted_at = datetime.now(timezone.utc)
    did_doc.promoted_by = promoted_by
    did_doc.promotion_reason = reason

    # Also clear the entity's is_provisional flag
    entity = await db.get(Entity, did_doc.entity_id)
    if entity and entity.is_provisional:
        entity.is_provisional = False
        entity.claim_token = None
        entity.provisional_expires_at = None

        # Upgrade API key scopes
        from src.models import APIKey

        key_result = await db.execute(
            select(APIKey).where(
                APIKey.entity_id == entity.id,
                APIKey.is_active.is_(True),
            )
        )
        for key in key_result.scalars().all():
            key.scopes = ["agent:read", "agent:write", "webhooks:manage"]

    await db.flush()


async def check_auto_promotion(
    db: AsyncSession,
    entity: Entity,
) -> str | None:
    """Check if a PROVISIONAL DID should be auto-promoted to FULL.

    Returns the promotion reason if criteria met, None otherwise.

    Auto-promotion criteria (any one is sufficient):
    1. Trust score >= 0.3
    2. Received an operator_verified attestation
    """
    # Check trust score
    trust = await db.scalar(
        select(TrustScore.score).where(TrustScore.entity_id == entity.id)
    )
    if trust is not None and trust >= DID_PROMOTION_TRUST_THRESHOLD:
        return f"trust_score_threshold ({trust:.2f} >= {DID_PROMOTION_TRUST_THRESHOLD})"

    # Check for operator_verified attestation
    has_operator_attestation = await db.scalar(
        select(FormalAttestation.id).where(
            FormalAttestation.subject_entity_id == entity.id,
            FormalAttestation.attestation_type == "operator_verified",
            FormalAttestation.is_revoked.is_(False),
        )
    )
    if has_operator_attestation:
        return "operator_attestation_received"

    return None


# --- Endpoints ---


@router.get("/resolve", dependencies=[Depends(rate_limit_reads)])
async def resolve_did(
    uri: str = Query(..., description="DID URI to resolve"),
    db: AsyncSession = Depends(get_db),
):
    """Resolve a DID:web identifier to its DID document."""
    entity, did_doc = await _resolve_entity_by_did(db, uri)
    return _build_did_document(entity, did_doc)


@router.get("/entity/{entity_id}", dependencies=[Depends(rate_limit_reads)])
async def get_entity_did(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the DID document for an entity by ID."""
    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == entity.id)
    )

    return _build_did_document(entity, did_doc)


@router.patch("/entity/{entity_id}", dependencies=[Depends(rate_limit_writes)])
async def update_did_document(
    entity_id: uuid.UUID,
    body: UpdateDIDRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Update service endpoints on an entity's DID document. Owner only."""
    if current_entity.id != entity_id:
        raise HTTPException(status_code=403, detail="Can only update your own DID document")

    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == entity_id)
    )

    document_data = {}
    if body.service is not None:
        document_data["service"] = [s.model_dump() for s in body.service]

    if did_doc is None:
        did_doc = DIDDocument(
            id=uuid.uuid4(),
            entity_id=entity_id,
            did_uri=current_entity.did_web,
            document=document_data,
        )
        db.add(did_doc)
    else:
        did_doc.document = (
            {**did_doc.document, **document_data}
            if did_doc.document
            else document_data
        )

    await log_action(
        db,
        action="did.update",
        entity_id=current_entity.id,
        resource_type="did_document",
        resource_id=did_doc.id,
    )
    await db.flush()

    return _build_did_document(current_entity, did_doc)


@router.get(
    "/{did_uri:path}/status",
    response_model=DIDStatusResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_did_status(
    did_uri: str,
    db: AsyncSession = Depends(get_db),
):
    """Check the current DID status (PROVISIONAL, FULL, or REVOKED).

    The did_uri path parameter should be a DID:web identifier, e.g.
    ``did:web:agentgraph.co:agents:<uuid>``.
    """
    entity, did_doc = await _resolve_entity_by_did(db, did_uri)

    if did_doc is None:
        # No stored DID doc means it hasn't been explicitly managed yet;
        # derive status from entity's is_provisional flag.
        current_status = (
            DIDStatus.PROVISIONAL if entity.is_provisional else DIDStatus.FULL
        )
        return DIDStatusResponse(
            did_uri=entity.did_web,
            did_status=current_status.value,
            is_provisional=current_status == DIDStatus.PROVISIONAL,
        )

    return DIDStatusResponse(
        did_uri=did_doc.did_uri,
        did_status=did_doc.did_status.value,
        is_provisional=did_doc.did_status == DIDStatus.PROVISIONAL,
        promoted_at=did_doc.promoted_at,
        promoted_by=str(did_doc.promoted_by) if did_doc.promoted_by else None,
        promotion_reason=did_doc.promotion_reason,
        created_at=did_doc.created_at,
    )


@router.post(
    "/{did_uri:path}/promote",
    response_model=PromoteDIDResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def promote_did(
    did_uri: str,
    body: PromoteDIDRequest | None = None,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Promote a PROVISIONAL DID to FULL status. Admin only.

    The did_uri path parameter should be a DID:web identifier, e.g.
    ``did:web:agentgraph.co:agents:<uuid>``.
    """
    require_admin(current_entity)

    entity, did_doc = await _resolve_entity_by_did(db, did_uri)

    # Ensure a DID document exists
    if did_doc is None:
        initial_status = (
            DIDStatus.PROVISIONAL if entity.is_provisional else DIDStatus.FULL
        )
        did_doc = await _get_or_create_did_doc(db, entity, initial_status)

    old_status = did_doc.did_status.value

    if did_doc.did_status == DIDStatus.FULL:
        raise HTTPException(
            status_code=400,
            detail="DID is already in FULL status",
        )

    if did_doc.did_status == DIDStatus.REVOKED:
        raise HTTPException(
            status_code=400,
            detail="Cannot promote a REVOKED DID. It must be reinstated first.",
        )

    reason = body.reason if body else "admin_approval"

    await promote_did_to_full(db, did_doc, reason=reason, promoted_by=current_entity.id)

    await log_action(
        db,
        action="did.promote",
        entity_id=current_entity.id,
        resource_type="did_document",
        resource_id=did_doc.id,
        details={
            "old_status": old_status,
            "new_status": "full",
            "reason": reason,
            "entity_id": str(entity.id),
        },
    )
    await db.flush()

    logger.info(
        "DID promoted: %s -> FULL by admin %s (reason: %s)",
        did_doc.did_uri,
        current_entity.id,
        reason,
    )

    return PromoteDIDResponse(
        did_uri=did_doc.did_uri,
        old_status=old_status,
        new_status="full",
        promotion_reason=reason,
        promoted_at=did_doc.promoted_at,
        message=f"DID {did_doc.did_uri} promoted from {old_status} to full.",
    )
