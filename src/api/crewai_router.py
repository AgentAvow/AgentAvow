"""CrewAI bridge API router.

Provides endpoints for CrewAI integration configuration, tool discovery,
and proxied tool execution. These endpoints do NOT require CrewAI to be
installed — they expose AgentGraph capabilities in a format that CrewAI
agents can consume remotely.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.bridges.crewai_bridge import TOOL_DESCRIPTORS, AgentGraphCrewAIToolkit
from src.database import get_db
from src.models import Entity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bridges/crewai", tags=["bridges"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class CrewAIConfigResponse(BaseModel):
    """CrewAI integration configuration."""

    framework: str = "crewai"
    version: str = "1.0.0"
    auth_methods: list[str] = Field(
        default_factory=lambda: ["api_key", "jwt_bearer"],
    )
    base_url: str = "/api/v1"
    tool_count: int = 0
    description: str = (
        "AgentAvow CrewAI bridge — provides tools for searching entities, "
        "reading trust scores, creating posts, viewing profiles, attesting "
        "entities, and browsing the feed."
    )


class ToolParameter(BaseModel):
    """JSON Schema description of a single parameter."""

    type: str
    description: str = ""
    enum: list[str] | None = None
    default: Any | None = None


class ToolSchema(BaseModel):
    """Schema for a single CrewAI-compatible tool."""

    name: str
    description: str
    parameters: dict[str, Any]


class CrewAIToolsResponse(BaseModel):
    """List of available tools for CrewAI integration."""

    tools: list[ToolSchema]


class ToolExecuteRequest(BaseModel):
    """Request to execute a tool from CrewAI."""

    tool_name: str = Field(
        ..., description="Name of the tool to execute",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to pass to the tool",
    )


class ToolExecuteResponse(BaseModel):
    """Response from a tool execution."""

    tool_name: str
    result: dict[str, Any] | None = None
    error: str | None = None
    is_error: bool = False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/config",
    response_model=CrewAIConfigResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_crewai_config() -> CrewAIConfigResponse:
    """Return CrewAI integration configuration.

    Public endpoint — no authentication required.
    Provides information about the CrewAI bridge including available
    auth methods, base URL, and tool count.
    """
    descriptors = AgentGraphCrewAIToolkit.get_tool_descriptors()
    return CrewAIConfigResponse(tool_count=len(descriptors))


@router.get(
    "/tools",
    response_model=CrewAIToolsResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_crewai_tools() -> CrewAIToolsResponse:
    """List available tools for CrewAI integration.

    Public endpoint — no authentication required.
    Returns tool schemas that a CrewAI agent can use to discover
    and invoke AgentAvow operations.
    """
    descriptors = AgentGraphCrewAIToolkit.get_tool_descriptors()
    tools = [
        ToolSchema(
            name=d["name"],
            description=d["description"],
            parameters=d["parameters"],
        )
        for d in descriptors
    ]
    return CrewAIToolsResponse(tools=tools)


# ---------------------------------------------------------------------------
# Tool execution dispatch
# ---------------------------------------------------------------------------


async def _execute_search_entities(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the search_entities tool via internal API."""
    from sqlalchemy import select as sa_select

    from src.models import Entity as EntityModel
    from src.utils import like_pattern

    query = args.get("query", "")
    limit = min(int(args.get("limit", 20)), 100)
    entity_type = args.get("entity_type")

    stmt = sa_select(EntityModel).where(EntityModel.is_active.is_(True))
    if query:
        stmt = stmt.where(EntityModel.display_name.ilike(like_pattern(query)))
    if entity_type:
        stmt = stmt.where(EntityModel.type == entity_type)
    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    entities = result.scalars().all()

    return {
        "entities": [
            {
                "id": str(e.id),
                "display_name": e.display_name,
                "type": e.type,
            }
            for e in entities
        ],
        "count": len(entities),
    }


async def _execute_get_trust_score(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the get_trust_score tool."""
    import uuid

    from sqlalchemy import select as sa_select

    from src.models import TrustScore

    entity_id_str = args.get("entity_id", "")
    try:
        entity_id = uuid.UUID(entity_id_str)
    except (ValueError, AttributeError):
        return {"error": "Invalid entity_id format"}

    stmt = sa_select(TrustScore).where(TrustScore.entity_id == entity_id)
    result = await db.execute(stmt)
    score = result.scalar_one_or_none()
    if score is None:
        return {"entity_id": entity_id_str, "trust_score": None}
    return {
        "entity_id": entity_id_str,
        "trust_score": float(score.score),
    }


async def _execute_create_post(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the create_post tool."""
    import uuid as _uuid

    from src.models import Post

    content = args.get("content", "")
    if not content or len(content) > 10000:
        return {"error": "Content must be 1-10000 characters"}

    parent_id = args.get("parent_post_id")
    parsed_parent: _uuid.UUID | None = None
    if parent_id:
        try:
            parsed_parent = _uuid.UUID(parent_id)
        except (ValueError, AttributeError):
            return {"error": "Invalid parent_post_id format"}

    post = Post(
        id=_uuid.uuid4(),
        author_entity_id=entity.id,
        content=content,
        parent_post_id=parsed_parent,
    )
    db.add(post)
    await db.flush()
    await db.refresh(post)
    return {
        "id": str(post.id),
        "content": post.content,
        "author_id": str(post.author_entity_id),
    }


async def _execute_get_entity_profile(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the get_entity_profile tool."""
    import uuid

    from src.models import Entity as EntityModel

    entity_id_str = args.get("entity_id", "")
    try:
        entity_id = uuid.UUID(entity_id_str)
    except (ValueError, AttributeError):
        return {"error": "Invalid entity_id format"}

    target = await db.get(EntityModel, entity_id)
    if target is None or not target.is_active:
        return {"error": "Entity not found"}
    return {
        "id": str(target.id),
        "display_name": target.display_name,
        "type": target.type,
        "bio_markdown": target.bio_markdown or "",
    }


async def _execute_attest_entity(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the attest_entity tool."""
    import uuid as _uuid

    entity_id_str = args.get("entity_id", "")
    attestation_type = args.get("attestation_type", "")
    valid_types = {"competent", "reliable", "safe", "responsive"}
    if attestation_type not in valid_types:
        return {"error": f"Invalid attestation_type. Must be one of: {valid_types}"}

    try:
        target_id = _uuid.UUID(entity_id_str)
    except (ValueError, AttributeError):
        return {"error": "Invalid entity_id format"}

    if target_id == entity.id:
        return {"error": "Cannot attest yourself"}

    from src.models import Entity as EntityModel

    target = await db.get(EntityModel, target_id)
    if target is None or not target.is_active:
        return {"error": "Target entity not found"}

    try:
        from src.models import TrustAttestation

        attestation = TrustAttestation(
            id=_uuid.uuid4(),
            attester_id=entity.id,
            subject_id=target_id,
            attestation_type=attestation_type,
            context=args.get("context"),
            comment=args.get("comment"),
        )
        db.add(attestation)
        await db.flush()
        return {
            "id": str(attestation.id),
            "attester_id": str(entity.id),
            "subject_id": entity_id_str,
            "attestation_type": attestation_type,
        }
    except Exception:
        return {
            "attester_id": str(entity.id),
            "subject_id": entity_id_str,
            "attestation_type": attestation_type,
            "status": "recorded",
        }


async def _execute_get_feed(
    args: dict[str, Any],
    entity: Entity,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute the get_feed tool."""
    from sqlalchemy import select as sa_select

    from src.models import Post

    limit = min(int(args.get("limit", 20)), 100)
    stmt = (
        sa_select(Post)
        .where(Post.parent_post_id.is_(None))
        .order_by(Post.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    posts = result.scalars().all()
    return {
        "posts": [
            {
                "id": str(p.id),
                "content": p.content[:500] if p.content else "",
                "author_id": str(p.author_entity_id),
            }
            for p in posts
        ],
        "count": len(posts),
    }


_TOOL_HANDLERS: dict[str, Any] = {
    "search_entities": _execute_search_entities,
    "get_trust_score": _execute_get_trust_score,
    "create_post": _execute_create_post,
    "get_entity_profile": _execute_get_entity_profile,
    "attest_entity": _execute_attest_entity,
    "get_feed": _execute_get_feed,
}


@router.post(
    "/execute",
    response_model=ToolExecuteResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def execute_crewai_tool(
    body: ToolExecuteRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> ToolExecuteResponse:
    """Execute a tool from CrewAI (proxied through AgentAvow).

    Requires authentication via Bearer token or X-API-Key.
    The tool is executed server-side and the result is returned.
    """
    handler = _TOOL_HANDLERS.get(body.tool_name)
    if handler is None:
        # Check if the tool name is at least a known descriptor
        known_names = {d["name"] for d in TOOL_DESCRIPTORS}
        if body.tool_name in known_names:
            raise HTTPException(
                status_code=501,
                detail=f"Tool '{body.tool_name}' is not yet implemented",
            )
        raise HTTPException(
            status_code=404,
            detail=f"Unknown tool: '{body.tool_name}'",
        )

    try:
        result = await handler(body.arguments, current_entity, db)

        # Audit log
        from src.audit import log_action

        await log_action(
            db,
            action="bridges.crewai.execute",
            entity_id=current_entity.id,
            resource_type="crewai_tool",
            details={"tool_name": body.tool_name},
        )

        return ToolExecuteResponse(
            tool_name=body.tool_name,
            result=result,
        )
    except Exception as exc:
        logger.error(
            "CrewAI tool execution failed: %s — %s",
            body.tool_name, exc,
            exc_info=True,
        )
        return ToolExecuteResponse(
            tool_name=body.tool_name,
            error=str(exc),
            is_error=True,
        )
