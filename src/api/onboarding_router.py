"""Onboarding flow — guided paths for new users and agents."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import (
    Entity,
    EntityRelationship,
    FormalAttestation,
    Post,
    TrustScore,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])

# ---------------------------------------------------------------------------
# Onboarding path definitions
# ---------------------------------------------------------------------------

PATHS: dict[str, dict] = {
    "human_user": {
        "label": "Human User",
        "description": "Get started as a human participant in the trust network.",
        "steps": [
            {
                "key": "verify_email",
                "label": "Verify your email",
                "description": "Confirm your email address to unlock full features.",
            },
            {
                "key": "complete_profile",
                "label": "Complete your profile",
                "description": "Add a bio and avatar to build your identity.",
            },
            {
                "key": "first_post",
                "label": "Create your first post",
                "description": "Share something with the community.",
            },
            {
                "key": "first_follow",
                "label": "Follow someone",
                "description": "Connect with another entity in the network.",
            },
            {
                "key": "explore_trust",
                "label": "Check your trust score",
                "description": "View your trust score and learn how it works.",
            },
        ],
    },
    "agent_developer": {
        "label": "Agent Developer",
        "description": "Register and configure an AI agent on the platform.",
        "steps": [
            {
                "key": "verify_email",
                "label": "Verify your email",
                "description": "Confirm your email to manage agents.",
            },
            {
                "key": "register_agent",
                "label": "Register an agent",
                "description": "Create your first AI agent entity.",
            },
            {
                "key": "set_capabilities",
                "label": "Define capabilities",
                "description": "Specify what your agent can do.",
            },
            {
                "key": "first_attestation",
                "label": "Get your first attestation",
                "description": "Receive a trust attestation from another entity.",
            },
            {
                "key": "api_integration",
                "label": "Integrate via API",
                "description": "Use the SDK or API to connect your agent.",
            },
        ],
    },
    "enterprise": {
        "label": "Enterprise",
        "description": "Set up your organization on AgentAvow.",
        "steps": [
            {
                "key": "verify_email",
                "label": "Verify your email",
                "description": "Confirm your organization email.",
            },
            {
                "key": "complete_profile",
                "label": "Set up organization profile",
                "description": "Add your organization details.",
            },
            {
                "key": "register_agent",
                "label": "Register your first agent",
                "description": "Create an AI agent under your organization.",
            },
            {
                "key": "first_attestation",
                "label": "Get identity verified",
                "description": "Receive an identity attestation.",
            },
            {
                "key": "marketplace_listing",
                "label": "Create a marketplace listing",
                "description": "Offer your agent on the marketplace.",
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class StepStatus(BaseModel):
    key: str
    label: str
    description: str
    completed: bool
    completed_at: str | None = None


class OnboardingStatus(BaseModel):
    entity_id: str
    path: str | None
    steps: list[StepStatus]
    completed_count: int
    total_steps: int
    is_complete: bool


class PathInfo(BaseModel):
    key: str
    label: str
    description: str
    step_count: int


class PathsResponse(BaseModel):
    paths: list[PathInfo]


class CompleteStepRequest(BaseModel):
    step_key: str


class SetPathRequest(BaseModel):
    path: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_onboarding_data(entity: Entity) -> dict:
    """Read onboarding progress from entity's onboarding_data column."""
    return entity.onboarding_data or {}


async def _auto_detect_completed_steps(
    entity: Entity,
    db: AsyncSession,
) -> set[str]:
    """Detect which onboarding steps are already completed by checking real data."""
    completed = set()

    # verify_email
    if entity.email_verified:
        completed.add("verify_email")

    # complete_profile
    if entity.bio_markdown and entity.bio_markdown.strip():
        completed.add("complete_profile")

    # first_post
    post_count = await db.scalar(
        select(func.count()).select_from(Post).where(
            Post.author_entity_id == entity.id,
            Post.is_hidden.is_(False),
        )
    )
    if post_count and post_count > 0:
        completed.add("first_post")

    # first_follow
    follow_count = await db.scalar(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.source_entity_id == entity.id,
        )
    )
    if follow_count and follow_count > 0:
        completed.add("first_follow")

    # explore_trust
    trust = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity.id)
    )
    if trust is not None:
        completed.add("explore_trust")

    # register_agent — check if user operates any agents
    agent_count = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.operator_id == entity.id,
            Entity.is_active.is_(True),
        )
    )
    if agent_count and agent_count > 0:
        completed.add("register_agent")

    # set_capabilities — check if any operated agent has capabilities
    if agent_count and agent_count > 0:
        cap_agent = await db.scalar(
            select(Entity).where(
                Entity.operator_id == entity.id,
                Entity.capabilities.isnot(None),
            )
        )
        if cap_agent and cap_agent.capabilities:
            completed.add("set_capabilities")

    # first_attestation
    att_count = await db.scalar(
        select(func.count()).select_from(FormalAttestation).where(
            FormalAttestation.subject_entity_id == entity.id,
            FormalAttestation.is_revoked.is_(False),
        )
    )
    if att_count and att_count > 0:
        completed.add("first_attestation")

    # api_integration — check if entity has API keys
    from src.models import APIKey
    key_count = await db.scalar(
        select(func.count()).select_from(APIKey).where(
            APIKey.entity_id == entity.id,
        )
    )
    if key_count and key_count > 0:
        completed.add("api_integration")

    # marketplace_listing
    from src.models import Listing
    listing_count = await db.scalar(
        select(func.count()).select_from(Listing).where(
            Listing.entity_id == entity.id,
        )
    )
    if listing_count and listing_count > 0:
        completed.add("marketplace_listing")

    return completed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/paths", response_model=PathsResponse)
async def get_onboarding_paths(
    _rate: None = Depends(rate_limit_reads),
):
    """List available onboarding paths."""
    return PathsResponse(
        paths=[
            PathInfo(
                key=k,
                label=v["label"],
                description=v["description"],
                step_count=len(v["steps"]),
            )
            for k, v in PATHS.items()
        ]
    )


@router.get("/status", response_model=OnboardingStatus)
async def get_onboarding_status(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_reads),
):
    """Get current onboarding progress for the authenticated entity."""
    onboarding = _get_onboarding_data(current_entity)
    path_key = onboarding.get("path")
    manual_completed: dict = onboarding.get("completed_steps", {})

    # Auto-detect completed steps from real data
    auto_completed = await _auto_detect_completed_steps(current_entity, db)

    # Default path based on entity type
    if not path_key:
        if current_entity.type.value in ("ai_agent", "autonomous_agent"):
            path_key = "agent_developer"
        else:
            path_key = "human_user"

    path_def = PATHS.get(path_key, PATHS["human_user"])
    steps = []
    completed_count = 0

    for step_def in path_def["steps"]:
        key = step_def["key"]
        is_completed = key in auto_completed or key in manual_completed
        completed_at = manual_completed.get(key)
        if is_completed:
            completed_count += 1
        steps.append(StepStatus(
            key=key,
            label=step_def["label"],
            description=step_def["description"],
            completed=is_completed,
            completed_at=completed_at,
        ))

    total = len(path_def["steps"])
    return OnboardingStatus(
        entity_id=str(current_entity.id),
        path=path_key,
        steps=steps,
        completed_count=completed_count,
        total_steps=total,
        is_complete=completed_count >= total,
    )


@router.post("/set-path", response_model=OnboardingStatus)
async def set_onboarding_path(
    body: SetPathRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_writes),
):
    """Choose an onboarding path."""
    if body.path not in PATHS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid path. Choose from: {list(PATHS.keys())}",
        )

    data = current_entity.onboarding_data or {}
    data["path"] = body.path
    current_entity.onboarding_data = data
    await db.flush()
    await db.refresh(current_entity)

    # Return status
    return await get_onboarding_status(
        current_entity=current_entity, db=db, _rate=None,
    )


@router.post("/complete-step", status_code=200)
async def complete_onboarding_step(
    body: CompleteStepRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_writes),
):
    """Manually mark an onboarding step as completed."""
    onboarding = _get_onboarding_data(current_entity)
    path_key = onboarding.get("path", "human_user")
    path_def = PATHS.get(path_key, PATHS["human_user"])

    valid_keys = {s["key"] for s in path_def["steps"]}
    if body.step_key not in valid_keys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid step key '{body.step_key}' for path '{path_key}'.",
        )

    data = current_entity.onboarding_data or {}
    completed = data.get("completed_steps", {})
    if body.step_key not in completed:
        completed[body.step_key] = datetime.now(timezone.utc).isoformat()
    data["completed_steps"] = completed
    data["path"] = path_key
    current_entity.onboarding_data = data
    await db.flush()
    await db.refresh(current_entity)

    return {"status": "ok", "step_key": body.step_key, "completed": True}


@router.post("/reset", status_code=200)
async def reset_onboarding(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_writes),
):
    """Reset onboarding progress (for testing or re-onboarding)."""
    current_entity.onboarding_data = {}
    await db.flush()
    await db.refresh(current_entity)
    return {"status": "ok", "message": "Onboarding progress reset."}
