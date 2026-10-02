"""A2A Agent Card enrichment endpoints.

Provides A2A-compatible Agent Card data enriched with AgentGraph trust
metadata. This plugs into the A2A discovery flow — when any A2A agent
discovers another agent, the enriched Agent Card gives them trust signals
to decide whether to interact.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src import cache
from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import (
    Entity,
    EntityRelationship,
    EntityType,
    RelationshipType,
    TrustAttestation,
    TrustScore,
)

router = APIRouter(tags=["a2a"])


# --- Response Schemas ---


class TrustInfo(BaseModel):
    score: float | None = None
    tier: str = "unknown"
    framework_modifier: float | None = None
    framework_source: str | None = None
    is_provisional: bool = False
    operator_verified: bool = False
    operator_id: str | None = None


class InteractionSummary(BaseModel):
    endorsement_count: int = 0
    follower_count: int = 0
    following_count: int = 0


class AgentCardResponse(BaseModel):
    """A2A Agent Card enriched with AgentGraph trust data."""

    # A2A standard fields
    name: str
    description: str = ""
    url: str = ""
    capabilities: list[str] = Field(default_factory=list)
    version: str = "1.0.0"

    # AgentGraph identity
    entity_id: str
    did: str | None = None
    entity_type: str = "agent"
    avatar_url: str | None = None

    # AgentGraph trust enrichment
    trust: TrustInfo
    interactions: InteractionSummary

    # Agent health
    agent_status: str | None = None
    last_seen_at: str | None = None


class AgentCardListResponse(BaseModel):
    agents: list[AgentCardResponse]
    total: int
    has_more: bool = False


# --- Endpoints ---


@router.get(
    "/agent-card/{entity_id}",
    response_model=AgentCardResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_agent_card(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get an A2A-compatible Agent Card enriched with trust data.

    This endpoint returns agent metadata in a format compatible with
    A2A Agent Card discovery, enriched with AgentAvow trust scores,
    verification status, and interaction history.
    """
    cache_key = f"a2a:card:{entity_id}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Agent not found")

    card = await _build_agent_card(db, entity)

    await cache.set(cache_key, card, ttl=cache.TTL_SHORT)
    return card


@router.get(
    "/agent-cards",
    response_model=AgentCardListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_agent_cards(
    framework: str | None = Query(None, description="Filter by framework"),
    min_trust: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List A2A Agent Cards with optional filters.

    Useful for A2A discovery — agents can browse available peers
    filtered by framework and minimum trust score.
    """
    stmt = (
        select(Entity)
        .where(
            Entity.is_active.is_(True),
            Entity.type == EntityType.AGENT,
        )
        .order_by(Entity.created_at.desc())
    )

    if framework:
        stmt = stmt.where(Entity.framework_source == framework.lower())

    # Count total before pagination
    count_stmt = (
        select(func.count())
        .select_from(Entity)
        .where(
            Entity.is_active.is_(True),
            Entity.type == EntityType.AGENT,
        )
    )
    if framework:
        count_stmt = count_stmt.where(
            Entity.framework_source == framework.lower()
        )
    total = await db.scalar(count_stmt) or 0

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    entities = result.scalars().all()

    cards = []
    for entity in entities:
        card = await _build_agent_card(db, entity)
        # Apply trust filter after building (score comes from TrustScore table)
        trust_score = card["trust"]["score"] or 0.0
        if trust_score >= min_trust:
            cards.append(card)

    return {
        "agents": cards,
        "total": total,
        "has_more": (offset + limit) < total,
    }


# --- Internal ---


async def _build_agent_card(
    db: AsyncSession, entity: Entity
) -> dict:
    """Build an enriched A2A Agent Card for an entity."""
    # Fetch trust score
    trust_row = await db.scalar(
        select(TrustScore.score).where(TrustScore.entity_id == entity.id)
    )
    trust_score = trust_row if trust_row is not None else None

    # Determine trust tier
    tier = _trust_tier(trust_score)

    # Check if operator is verified (has email_verified=True)
    operator_verified = False
    if entity.operator_id:
        operator = await db.get(Entity, entity.operator_id)
        if operator and getattr(operator, "email_verified", False):
            operator_verified = True

    # Get interaction counts
    endorsement_count = await db.scalar(
        select(func.count()).select_from(TrustAttestation).where(
            TrustAttestation.target_entity_id == entity.id
        )
    ) or 0

    follower_count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.target_entity_id == entity.id,
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    ) or 0

    following_count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == entity.id,
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    ) or 0

    return {
        "name": entity.display_name,
        "description": entity.bio_markdown or "",
        "url": f"https://agentavow.com/agent/{entity.id}",
        "capabilities": entity.capabilities or [],
        "version": "1.0.0",
        "entity_id": str(entity.id),
        "did": entity.did_web,
        "entity_type": entity.type.value if entity.type else "agent",
        "avatar_url": entity.avatar_url,
        "trust": {
            "score": trust_score,
            "tier": tier,
            "framework_modifier": entity.framework_trust_modifier,
            "framework_source": entity.framework_source,
            "is_provisional": getattr(entity, "is_provisional", False) or False,
            "operator_verified": operator_verified,
            "operator_id": str(entity.operator_id) if entity.operator_id else None,
        },
        "interactions": {
            "endorsement_count": endorsement_count,
            "follower_count": follower_count,
            "following_count": following_count,
        },
        "agent_status": entity.agent_status,
        "last_seen_at": (
            entity.last_seen_at.isoformat() if entity.last_seen_at else None
        ),
    }


def _trust_tier(score: float | None) -> str:
    """Map trust score to human-readable tier."""
    if score is None:
        return "unrated"
    if score >= 0.8:
        return "trusted"
    if score >= 0.6:
        return "established"
    if score >= 0.3:
        return "developing"
    return "new"


# --- A2A Import ---


class A2AImportRequest(BaseModel):
    card_url: str = Field(..., max_length=1000)


@router.post(
    "/agent-card/import",
    status_code=201,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_a2a_agent_card(
    body: A2AImportRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity = Depends(get_current_entity),
):
    """Import an agent from an A2A Agent Card URL.

    Delegates to the source import system with the card URL.
    """
    from src.api.agent_service import register_agent_direct
    from src.content_filter import sanitize_html, sanitize_text
    from src.source_import.resolver import resolve_source

    try:
        result = await resolve_source(body.card_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    display_name = sanitize_text(result.display_name)
    bio = sanitize_html(result.bio or "")

    agent, plaintext_key = await register_agent_direct(
        db=db,
        display_name=display_name,
        capabilities=result.capabilities,
        bio_markdown=bio,
        framework_source=result.detected_framework,
        registration_ip=request.client.host if request.client else None,
    )

    # Set source fields
    from datetime import datetime, timezone
    agent.source_url = result.source_url
    agent.source_type = result.source_type
    agent.source_verified_at = datetime.now(timezone.utc)

    onboarding = agent.onboarding_data or {}
    onboarding["import_source"] = {
        "url": result.source_url,
        "type": result.source_type,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "community_signals": result.community_signals,
    }
    agent.onboarding_data = onboarding
    await db.flush()

    return {
        "agent_id": str(agent.id),
        "did": agent.did_web,
        "api_key": plaintext_key,
        "source_type": result.source_type,
        "display_name": agent.display_name,
    }
