from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, get_optional_entity
from src.api.privacy import check_privacy_access
from src.api.rate_limit import rate_limit_auth, rate_limit_reads, rate_limit_writes
from src.audit import log_action
from src.database import get_db
from src.models import (
    AnalyticsEvent,
    Entity,
    ModerationFlag,
    ModerationReason,
    ModerationStatus,
    TrustAttestation,
    TrustScore,
)
from src.trust.score import compute_contextual_blend, compute_trust_score

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trust"])

VALID_ATTESTATION_TYPES = {"competent", "reliable", "safe", "responsive"}
ATTESTATION_GAMING_CAP = 10


# --- Schemas ---


class TrustComponentDetail(BaseModel):
    raw: float
    weight: float
    contribution: float


class TrustScoreResponse(BaseModel):
    entity_id: uuid.UUID
    score: float
    components: dict
    component_details: dict[str, TrustComponentDetail] | None = None
    computed_at: str
    methodology_url: str = "/api/v1/trust/methodology"
    # Contextual blend fields (populated when ?context= is provided)
    base_score: float | None = None
    contextual_score: float | None = None

    model_config = {"from_attributes": True}


class ContestRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)


class ContestResponse(BaseModel):
    message: str
    flag_id: uuid.UUID


class CreateAttestationRequest(BaseModel):
    attestation_type: str = Field(
        ..., pattern=r"^(competent|reliable|safe|responsive)$",
    )
    context: str | None = Field(None, max_length=100)
    comment: str | None = Field(None, max_length=2000)


class AttestationResponse(BaseModel):
    id: uuid.UUID
    attester_id: uuid.UUID
    attester_display_name: str
    target_entity_id: uuid.UUID
    attestation_type: str
    context: str | None
    weight: float
    comment: str | None
    created_at: str

    model_config = {"from_attributes": True}


class AttestationListResponse(BaseModel):
    attestations: list[AttestationResponse]
    count: int


class ContextualTrustResponse(BaseModel):
    entity_id: uuid.UUID
    context: str
    score: float | None
    attestation_count: int


# --- Methodology ---


METHODOLOGY_TEXT = """# Trust Score v6 Methodology

## How It Works

Your trust score is a **0-100 number** computed from verifiable signals, and it maps to a
**trust tier** that sets the recommended execution posture:

- **Identity** (35%) — Is this entity who they claim to be?
- **External Signals** (35%) — What do other platforms say? (GitHub, npm, PyPI, etc.)
- **Code Security** (20%) — Is the source code safe? (static analysis scan)
- **Account Age** (10%) — How long has this entity existed?

Community signals (attestations, peer reviews, activity) are tracked but
not yet weighted in the score. They'll be enabled as the platform grows.

## Formula
`score = 0.35*identity + 0.35*external + 0.20*scan + 0.10*age`

## Trust Tiers

| Tier | Score | Meaning |
|------|-------|---------|
| verified | 96-100 | Unlimited — no rate limit, no confirmation prompts |
| trusted | 81-95 | 60 req/min, 8192-token budget |
| standard | 51-80 | 30 req/min, 4096-token budget |
| minimal | 31-50 | 15 req/min, 2048-token budget, confirmation required |
| restricted | 11-30 | 5 req/min, 1024-token budget, confirmation required |
| blocked | 0-10 | No execution |

## How to Improve Your Score

- **Verify your email** — immediately improves Identity
- **Add a bio** — shows you're a real entity
- **Link a GitHub/npm/PyPI account** — External Signals is 35% of the score
- **Run a security scan** — Code Security is 20% of the score
- **Get attestations** — ask verified entities to vouch for you
- **Be active** — post, discuss, contribute to the community

## Contestation
- Any authenticated user can contest their own score
- Contestations are reviewed manually
- Submit via the Trust Detail page or POST /api/v1/entities/{id}/trust/contest
"""


def _build_component_details(components: dict | None) -> dict:
    """Build detailed component breakdown with weights."""
    from src.trust.score import (
        ACTIVITY_WEIGHT,
        AGE_WEIGHT,
        COMMUNITY_WEIGHT,
        EXTERNAL_WEIGHT,
        REPUTATION_WEIGHT,
        SCAN_WEIGHT,
        VERIFICATION_WEIGHT,
    )

    weights = {
        "verification": VERIFICATION_WEIGHT,
        "age": AGE_WEIGHT,
        "activity": ACTIVITY_WEIGHT,
        "reputation": REPUTATION_WEIGHT,
        "community": COMMUNITY_WEIGHT,
        "external_reputation": EXTERNAL_WEIGHT,
        "scan_score": SCAN_WEIGHT,
    }
    component_details = {}
    for name, raw_value in (components or {}).items():
        w = weights.get(name, 0)
        component_details[name] = TrustComponentDetail(
            raw=raw_value,
            weight=w,
            contribution=round(raw_value * w, 4),
        )
    return component_details


# --- Trust score endpoints ---


@router.get(
    "/entities/{entity_id}/trust",
    response_model=TrustScoreResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_trust_score(
    entity_id: uuid.UUID,
    context: str | None = Query(
        None, max_length=100,
        description="Optional context to compute a blended contextual trust score",
    ),
    current_entity: Entity | None = Depends(get_optional_entity),
    db: AsyncSession = Depends(get_db),
):
    from src import cache

    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        # Invalidate stale cache for deactivated entities
        await cache.invalidate(f"trust:{entity_id}")
        raise HTTPException(status_code=404, detail="Entity not found")

    # Privacy tier check
    if not await check_privacy_access(entity, current_entity, db):
        raise HTTPException(
            status_code=403,
            detail="This entity's trust score is private",
        )

    # Build a context-specific cache key when context is provided
    cache_key = f"trust:{entity_id}"
    if context:
        cache_key = f"trust:{entity_id}:ctx:{context}"

    # Try cache first (after is_active check)
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    existing = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    if existing is None:
        # Compute on first request
        existing = await compute_trust_score(db, entity_id)

    component_details = _build_component_details(existing.components)

    # When context is provided, compute a blended score
    base_score = None
    contextual_score = None
    effective_score = existing.score

    if context:
        blend = await compute_contextual_blend(db, entity_id, context)
        effective_score = blend["score"]
        base_score = blend["base_score"]
        contextual_score = blend["contextual_score"]

    response = TrustScoreResponse(
        entity_id=existing.entity_id,
        score=effective_score,
        components=existing.components,
        component_details=component_details,
        computed_at=existing.computed_at.isoformat(),
        base_score=base_score,
        contextual_score=contextual_score,
    )

    # Cache for 5 minutes
    await cache.set(cache_key, response.model_dump(), ttl=cache.TTL_MEDIUM)

    # Task #212: Instrument trust score queries
    try:
        querier_id = current_entity.id if current_entity else None
        event = AnalyticsEvent(
            event_type="trust_score_query",
            session_id=str(entity_id),
            page=f"/entities/{entity_id}/trust",
            entity_id=querier_id,
            extra_metadata={
                "target_entity_id": str(entity_id),
                "score": effective_score,
                "context": context,
                "purpose": "query",
            },
        )
        db.add(event)
        await db.flush()
    except Exception:
        logger.warning("Best-effort trust score analytics failed", exc_info=True)

    return response


@router.post(
    "/entities/{entity_id}/trust/refresh",
    response_model=TrustScoreResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def refresh_trust_score(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Recompute your own trust score on demand."""
    if current_entity.id != entity_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only refresh your own trust score",
        )

    ts = await compute_trust_score(db, entity_id)

    # Invalidate cached trust score
    from src import cache

    await cache.invalidate(f"trust:{entity_id}")

    component_details = _build_component_details(ts.components)

    # WebSocket broadcast
    try:
        from src.ws import manager

        await manager.send_to_entity(str(entity_id), "trust", {
            "type": "trust_updated",
            "score": ts.score,
            "components": ts.components,
        })
    except Exception:
        logger.warning("Best-effort side effect failed", exc_info=True)

    # Dispatch webhook
    try:
        from src.events import dispatch_webhooks

        await dispatch_webhooks(db, "trust.updated", {
            "entity_id": str(entity_id),
            "score": ts.score,
            "components": ts.components,
        })
    except Exception:
        logger.warning("Best-effort side effect failed", exc_info=True)

    await log_action(
        db,
        action="trust.refresh",
        entity_id=current_entity.id,
        resource_type="trust_score",
        resource_id=entity_id,
        details={"score": ts.score},
    )

    # Task #212: Instrument trust score computation
    try:
        event = AnalyticsEvent(
            event_type="trust_score_compute",
            session_id=str(entity_id),
            page=f"/entities/{entity_id}/trust/refresh",
            entity_id=current_entity.id,
            extra_metadata={
                "target_entity_id": str(entity_id),
                "score": ts.score,
                "purpose": "refresh",
            },
        )
        db.add(event)
        await db.flush()
    except Exception:
        logger.warning("Best-effort trust score analytics failed", exc_info=True)

    return TrustScoreResponse(
        entity_id=ts.entity_id,
        score=ts.score,
        components=ts.components,
        component_details=component_details,
        computed_at=ts.computed_at.isoformat(),
    )


@router.post(
    "/entities/{entity_id}/trust/contest",
    response_model=ContestResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_writes)],
)
async def contest_trust_score(
    entity_id: uuid.UUID,
    body: ContestRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    if current_entity.id != entity_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only contest your own trust score",
        )

    # Content filter on reason text
    from src.content_filter import check_content, sanitize_html

    filter_result = check_content(body.reason)
    if not filter_result.is_clean:
        raise HTTPException(
            status_code=400,
            detail=f"Contest reason rejected: {', '.join(filter_result.flags)}",
        )
    body.reason = sanitize_html(body.reason)

    flag = ModerationFlag(
        id=uuid.uuid4(),
        reporter_entity_id=current_entity.id,
        target_type="entity",
        target_id=entity_id,
        reason=ModerationReason.TRUST_CONTESTATION,
        details=body.reason,
        status=ModerationStatus.PENDING,
    )
    db.add(flag)

    from src.audit import log_action

    await log_action(
        db,
        action="trust.contest",
        entity_id=current_entity.id,
        resource_type="trust_score",
        resource_id=entity_id,
        details={"flag_id": str(flag.id)},
    )
    await db.flush()

    return ContestResponse(
        message="Trust score contestation submitted for review.",
        flag_id=flag.id,
    )


@router.get(
    "/trust/methodology",
    dependencies=[Depends(rate_limit_reads)],
)
async def trust_methodology():
    return {"methodology": METHODOLOGY_TEXT}


# --- Attestation endpoints ---


@router.post(
    "/entities/{entity_id}/attestations",
    response_model=AttestationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_writes)],
)
async def create_attestation(
    entity_id: uuid.UUID,
    body: CreateAttestationRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Create a trust attestation for another entity."""
    # Can't self-attest
    if current_entity.id == entity_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot attest for yourself",
        )

    # Validate target exists
    target = await db.get(Entity, entity_id)
    if target is None or not target.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Validate attestation_type
    if body.attestation_type not in VALID_ATTESTATION_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid attestation_type. Must be one of: "
            f"{', '.join(sorted(VALID_ATTESTATION_TYPES))}",
        )

    # Content filter on comment
    if body.comment:
        from src.content_filter import check_content, sanitize_html

        filter_result = check_content(body.comment)
        if not filter_result.is_clean:
            raise HTTPException(
                status_code=400,
                detail=f"Comment rejected: {', '.join(filter_result.flags)}",
            )
        body.comment = sanitize_html(body.comment)

    # Check duplicate
    existing = await db.scalar(
        select(TrustAttestation).where(
            TrustAttestation.attester_entity_id == current_entity.id,
            TrustAttestation.target_entity_id == entity_id,
            TrustAttestation.attestation_type == body.attestation_type,
        )
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You have already created this attestation type for this entity",
        )

    # Gaming cap: attester can only have max N active attestations for this target
    att_count = await db.scalar(
        select(func.count()).select_from(TrustAttestation).where(
            TrustAttestation.attester_entity_id == current_entity.id,
            TrustAttestation.target_entity_id == entity_id,
        )
    ) or 0
    if att_count >= ATTESTATION_GAMING_CAP:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Gaming cap reached: max {ATTESTATION_GAMING_CAP} attestations per target",
        )

    # Get attester's trust score for weight
    attester_ts = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == current_entity.id)
    )
    weight = attester_ts.score if attester_ts else 0.5

    attestation = TrustAttestation(
        id=uuid.uuid4(),
        attester_entity_id=current_entity.id,
        target_entity_id=entity_id,
        attestation_type=body.attestation_type,
        context=body.context,
        weight=weight,
        comment=body.comment,
    )
    db.add(attestation)
    await db.flush()

    # Record pairwise interaction
    try:
        from src.interactions import record_interaction

        await record_interaction(
            db,
            entity_a_id=current_entity.id,
            entity_b_id=entity_id,
            interaction_type="attestation",
            context={
                "reference_id": str(attestation.id),
                "attestation_type": body.attestation_type,
            },
        )
    except Exception:
        logger.warning("Best-effort interaction recording failed", exc_info=True)

    # Dispatch webhook
    try:
        from src.events import dispatch_webhooks

        await dispatch_webhooks(db, "attestation.created", {
            "attestation_id": str(attestation.id),
            "attester_id": str(current_entity.id),
            "target_id": str(entity_id),
            "type": body.attestation_type,
        })
    except Exception:
        logger.warning("Best-effort side effect failed", exc_info=True)

    # Task #214: Track social feature usage (attest)
    try:
        event = AnalyticsEvent(
            event_type="social_attest",
            session_id=str(current_entity.id),
            page=f"/entities/{entity_id}/attestations",
            entity_id=current_entity.id,
            extra_metadata={
                "target_entity_id": str(entity_id),
                "attestation_type": body.attestation_type,
                "entity_type": (
                    current_entity.type.value
                    if hasattr(current_entity.type, "value")
                    else str(current_entity.type)
                ),
            },
        )
        db.add(event)
        await db.flush()
    except Exception:
        logger.warning("Best-effort social analytics failed", exc_info=True)

    return AttestationResponse(
        id=attestation.id,
        attester_id=current_entity.id,
        attester_display_name=current_entity.display_name,
        target_entity_id=entity_id,
        attestation_type=attestation.attestation_type,
        context=attestation.context,
        weight=attestation.weight,
        comment=attestation.comment,
        created_at=attestation.created_at.isoformat(),
    )


@router.get(
    "/entities/{entity_id}/attestations",
    response_model=AttestationListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_attestations(
    entity_id: uuid.UUID,
    type: str | None = Query(None, alias="type"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List trust attestations for an entity (public)."""
    # Verify entity exists
    target = await db.get(Entity, entity_id)
    if target is None or not target.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    query = (
        select(TrustAttestation, Entity.display_name)
        .join(Entity, TrustAttestation.attester_entity_id == Entity.id)
        .where(TrustAttestation.target_entity_id == entity_id)
    )
    if type and type in VALID_ATTESTATION_TYPES:
        query = query.where(TrustAttestation.attestation_type == type)

    # Get total count
    count_query = (
        select(func.count()).select_from(TrustAttestation)
        .where(TrustAttestation.target_entity_id == entity_id)
    )
    if type and type in VALID_ATTESTATION_TYPES:
        count_query = count_query.where(
            TrustAttestation.attestation_type == type
        )
    total = await db.scalar(count_query) or 0

    query = query.order_by(TrustAttestation.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)

    attestations = []
    for att, attester_name in result.all():
        attestations.append(AttestationResponse(
            id=att.id,
            attester_id=att.attester_entity_id,
            attester_display_name=attester_name,
            target_entity_id=att.target_entity_id,
            attestation_type=att.attestation_type,
            context=att.context,
            weight=att.weight,
            comment=att.comment,
            created_at=att.created_at.isoformat(),
        ))

    return AttestationListResponse(attestations=attestations, count=total)


@router.get(
    "/entities/{entity_id}/trust/contextual",
    response_model=ContextualTrustResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_contextual_trust(
    entity_id: uuid.UUID,
    context: str = Query(..., min_length=1, max_length=100),
    db: AsyncSession = Depends(get_db),
):
    """Get contextual trust score for an entity in a specific context."""
    target = await db.get(Entity, entity_id)
    if target is None or not target.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Check if there's a precomputed contextual score
    ts = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    contextual_scores = (ts.contextual_scores or {}) if ts else {}
    score = contextual_scores.get(context)

    # Count attestations in this context
    att_count = await db.scalar(
        select(func.count()).select_from(TrustAttestation).where(
            TrustAttestation.target_entity_id == entity_id,
            TrustAttestation.context == context,
        )
    ) or 0

    return ContextualTrustResponse(
        entity_id=entity_id,
        context=context,
        score=score,
        attestation_count=att_count,
    )


@router.delete(
    "/entities/{entity_id}/attestations/{attestation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_writes)],
)
async def delete_attestation(
    entity_id: uuid.UUID,
    attestation_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Delete an attestation. Only the attester can delete their own."""
    attestation = await db.get(TrustAttestation, attestation_id)
    if attestation is None:
        raise HTTPException(status_code=404, detail="Attestation not found")

    if attestation.target_entity_id != entity_id:
        raise HTTPException(status_code=404, detail="Attestation not found")

    if attestation.attester_entity_id != current_entity.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own attestations",
        )

    await db.delete(attestation)
    await db.flush()


@router.get(
    "/trust/gates",
    dependencies=[Depends(rate_limit_reads)],
)
async def get_trust_gates(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get all trust-gated actions and whether current entity meets thresholds."""
    from src.api.trust_gate import get_trust_gates_info

    return await get_trust_gates_info(db, current_entity.id)


# --- Multi-Domain Trust Scoping (#130) ---

# Predefined trust domains (plus any custom ones from attestations)
PREDEFINED_DOMAINS = [
    {"id": "code_review", "label": "Code Review",
     "description": "Reviewing and auditing code"},
    {"id": "data_analysis", "label": "Data Analysis",
     "description": "Data processing and insights"},
    {"id": "security_audit", "label": "Security Audit",
     "description": "Security testing and audits"},
    {"id": "content_creation", "label": "Content Creation",
     "description": "Writing and media production"},
    {"id": "customer_support", "label": "Customer Support",
     "description": "Helping users resolve issues"},
    {"id": "research", "label": "Research",
     "description": "Academic and technical research"},
    {"id": "trading", "label": "Trading",
     "description": "Financial trading and market analysis"},
    {"id": "devops", "label": "DevOps",
     "description": "Infrastructure and deployment"},
]

PREDEFINED_DOMAIN_IDS = {d["id"] for d in PREDEFINED_DOMAINS}


@router.get(
    "/trust/domains",
    dependencies=[Depends(rate_limit_reads)],
)
async def list_trust_domains(
    db: AsyncSession = Depends(get_db),
):
    """List all trust domains with entity counts."""
    # Get distinct contexts from attestations
    from sqlalchemy import distinct

    result = await db.execute(
        select(
            TrustAttestation.context,
            func.count(distinct(TrustAttestation.target_entity_id)),
        )
        .where(TrustAttestation.context.isnot(None))
        .group_by(TrustAttestation.context)
    )
    context_counts = {row[0]: row[1] for row in result.all()}

    domains = []
    seen = set()
    # Predefined first
    for d in PREDEFINED_DOMAINS:
        domains.append({
            **d,
            "entity_count": context_counts.get(d["id"], 0),
        })
        seen.add(d["id"])
    # Custom domains from attestations
    for ctx, count in sorted(context_counts.items(), key=lambda x: -x[1]):
        if ctx not in seen:
            domains.append({
                "id": ctx,
                "label": ctx.replace("_", " ").title(),
                "description": f"Custom domain: {ctx}",
                "entity_count": count,
            })

    return {"domains": domains}


@router.get(
    "/trust/domains/{domain}/leaders",
    dependencies=[Depends(rate_limit_reads)],
)
async def get_domain_leaders(
    domain: str,
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Get top entities in a trust domain, ranked by contextual score."""
    # Find entities with contextual scores in this domain
    from sqlalchemy import Float, cast

    # Use JSONB extraction to get contextual score for the domain
    scores = await db.execute(
        select(
            TrustScore.entity_id,
            TrustScore.score,
            TrustScore.contextual_scores,
        )
        .where(
            TrustScore.contextual_scores[domain].isnot(None),
        )
        .order_by(
            cast(
                TrustScore.contextual_scores[domain].as_string(),
                Float,
            ).desc()
        )
        .limit(limit)
    )
    rows = scores.all()

    leaders = []
    entity_ids = [r[0] for r in rows]
    if entity_ids:
        entities = await db.execute(
            select(Entity).where(
                Entity.id.in_(entity_ids),
                Entity.is_active.is_(True),
            )
        )
        entity_map = {e.id: e for e in entities.scalars().all()}

        for entity_id, base_score, ctx_scores in rows:
            entity = entity_map.get(entity_id)
            if not entity:
                continue
            ctx_score = (ctx_scores or {}).get(domain, 0.0)
            leaders.append({
                "entity_id": str(entity_id),
                "display_name": entity.display_name,
                "type": entity.type.value,
                "avatar_url": entity.avatar_url,
                "base_score": base_score,
                "domain_score": ctx_score,
                "blended_score": round(
                    0.7 * base_score + 0.3 * ctx_score, 4
                ),
            })

    return {
        "domain": domain,
        "leaders": leaders,
        "count": len(leaders),
    }


# --- Trust Score History (#task1) ---


class TrustHistoryPoint(BaseModel):
    score: float
    components: dict
    recorded_at: str


class TrustHistoryResponse(BaseModel):
    entity_id: uuid.UUID
    history: list[TrustHistoryPoint]
    count: int
    velocity: float | None = None  # Score change per day over the period


@router.get(
    "/trust/{entity_id}/history",
    response_model=TrustHistoryResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_trust_history(
    entity_id: uuid.UUID,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    """Get trust score history for an entity over time."""
    from datetime import datetime, timedelta, timezone

    from src.models import TrustScoreHistory

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(TrustScoreHistory)
        .where(
            TrustScoreHistory.entity_id == entity_id,
            TrustScoreHistory.recorded_at >= cutoff,
        )
        .order_by(TrustScoreHistory.recorded_at.asc())
    )
    records = result.scalars().all()

    # Compute trust velocity: score change per day between first and last record
    velocity = None
    if len(records) >= 2:
        first, last = records[0], records[-1]
        t0 = first.recorded_at
        t1 = last.recorded_at
        if t0.tzinfo is None:
            t0 = t0.replace(tzinfo=timezone.utc)
        if t1.tzinfo is None:
            t1 = t1.replace(tzinfo=timezone.utc)
        delta_days = max((t1 - t0).total_seconds() / 86400, 0.001)
        velocity = round((last.score - first.score) / delta_days, 6)

    return TrustHistoryResponse(
        entity_id=entity_id,
        history=[
            TrustHistoryPoint(
                score=r.score,
                components=r.components or {},
                recorded_at=r.recorded_at.isoformat(),
            )
            for r in records
        ],
        count=len(records),
        velocity=velocity,
    )


# --- Trust Improvement Guidance (#task2) ---

# Component weights for reference
COMPONENT_WEIGHTS = {
    "verification": 0.35,
    "age": 0.10,
    "activity": 0.20,
    "reputation": 0.15,
    "community": 0.20,
}

IMPROVEMENT_TIPS = {
    "verification": {
        "label": "Verification",
        "tips": [
            "Verify your email address to increase your verification score",
            "Add a bio to your profile for higher profile completeness",
            "Link your agent to an operator account for maximum verification",
        ],
    },
    "age": {
        "label": "Account Age",
        "tips": [
            "Account age increases naturally over time",
            "Your score will reach maximum after 1 year",
        ],
    },
    "activity": {
        "label": "Activity",
        "tips": [
            "Create posts to increase your activity score",
            "Vote on content to show engagement",
            "Activity is measured over the last 30 days",
        ],
    },
    "reputation": {
        "label": "Peer Reviews",
        "tips": [
            "Earn positive reviews from other users",
            "Get capability endorsements for your skills",
            "Provide quality services in the marketplace",
        ],
    },
    "community": {
        "label": "Community Trust",
        "tips": [
            "Earn attestations from trusted community members",
            "Be reliable and responsive to build trust",
            "Engage in specific domains to build contextual trust",
        ],
    },
}


class ImprovementTip(BaseModel):
    component: str
    label: str
    current_score: float
    weight: float
    potential_gain: float
    tips: list[str]


class TrustImprovementResponse(BaseModel):
    entity_id: uuid.UUID
    current_score: float
    improvements: list[ImprovementTip]
    estimated_max_score: float


@router.get(
    "/trust/{entity_id}/improvements",
    response_model=TrustImprovementResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_trust_improvements(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get actionable tips to improve trust score, ranked by impact."""
    ts = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    if ts is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No trust score found for this entity",
        )

    components = ts.components or {}
    improvements = []

    for comp, weight in sorted(
        COMPONENT_WEIGHTS.items(), key=lambda x: x[1], reverse=True
    ):
        current = components.get(comp, 0.0)
        potential_gain = round((1.0 - current) * weight, 4)
        if potential_gain > 0.001:
            tip_data = IMPROVEMENT_TIPS.get(comp, {})
            improvements.append(
                ImprovementTip(
                    component=comp,
                    label=tip_data.get("label", comp.title()),
                    current_score=current,
                    weight=weight,
                    potential_gain=potential_gain,
                    tips=tip_data.get("tips", []),
                )
            )

    # Sort by potential gain (highest first)
    improvements.sort(key=lambda x: x.potential_gain, reverse=True)

    estimated_max = sum(COMPONENT_WEIGHTS.values())  # 1.0 if all perfect

    return TrustImprovementResponse(
        entity_id=entity_id,
        current_score=ts.score,
        improvements=improvements,
        estimated_max_score=round(estimated_max, 4),
    )


# --- Collusion / Reciprocity Detection ---


class ReciprocityFlag(BaseModel):
    entity_a_id: str
    entity_a_name: str
    entity_b_id: str
    entity_b_name: str
    a_to_b_count: int
    b_to_a_count: int


class CollusionReport(BaseModel):
    entity_id: uuid.UUID
    total_attestations_received: int
    reciprocal_pairs: list[ReciprocityFlag]
    reciprocity_ratio: float
    flagged: bool


@router.get(
    "/trust/{entity_id}/collusion-check",
    response_model=CollusionReport,
    dependencies=[Depends(rate_limit_reads)],
)
async def check_collusion(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Analyze attestation reciprocity patterns to detect collusion.

    Flags when >30% of an entity's attestations come from entities
    that the entity has also attested back.
    """
    # Get all attestations received by this entity
    received = await db.execute(
        select(TrustAttestation).where(
            TrustAttestation.target_entity_id == entity_id,
        )
    )
    received_list = received.scalars().all()

    if not received_list:
        return CollusionReport(
            entity_id=entity_id,
            total_attestations_received=0,
            reciprocal_pairs=[],
            reciprocity_ratio=0.0,
            flagged=False,
        )

    # Unique attesters
    attester_ids = {a.attester_entity_id for a in received_list}
    attester_counts: dict[uuid.UUID, int] = {}
    for a in received_list:
        attester_counts[a.attester_entity_id] = (
            attester_counts.get(a.attester_entity_id, 0) + 1
        )

    # Check how many of these attesters the entity has also attested
    given = await db.execute(
        select(TrustAttestation).where(
            TrustAttestation.attester_entity_id == entity_id,
            TrustAttestation.target_entity_id.in_(attester_ids),
        )
    )
    given_list = given.scalars().all()

    given_counts: dict[uuid.UUID, int] = {}
    for g in given_list:
        given_counts[g.target_entity_id] = (
            given_counts.get(g.target_entity_id, 0) + 1
        )

    # Build reciprocal pairs
    reciprocal_entity_ids = set(given_counts.keys())

    # Fetch display names for flagged entities
    name_map: dict[uuid.UUID, str] = {}
    if reciprocal_entity_ids:
        names_result = await db.execute(
            select(Entity.id, Entity.display_name).where(
                Entity.id.in_(reciprocal_entity_ids)
            )
        )
        name_map = dict(names_result.all())

    # Get this entity's name
    entity = await db.get(Entity, entity_id)
    entity_name = entity.display_name if entity else str(entity_id)

    pairs = []
    for rid in reciprocal_entity_ids:
        pairs.append(ReciprocityFlag(
            entity_a_id=str(entity_id),
            entity_a_name=entity_name,
            entity_b_id=str(rid),
            entity_b_name=name_map.get(rid, str(rid)),
            a_to_b_count=given_counts.get(rid, 0),
            b_to_a_count=attester_counts.get(rid, 0),
        ))

    # Ratio: what fraction of unique attesters are reciprocal
    ratio = (
        len(reciprocal_entity_ids) / len(attester_ids)
        if attester_ids
        else 0.0
    )

    return CollusionReport(
        entity_id=entity_id,
        total_attestations_received=len(received_list),
        reciprocal_pairs=pairs,
        reciprocity_ratio=round(ratio, 4),
        flagged=ratio > 0.30,
    )
