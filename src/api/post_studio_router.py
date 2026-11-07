"""Admin API for Post Studio. See src/marketing/post_studio.py; nothing here publishes."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, get_db, require_admin
from src.marketing import post_studio as studio
from src.marketing.models import MarketingPost
from src.models import AnalyticsEvent, Entity

router = APIRouter(prefix="/admin/marketing/studio", tags=["admin"])


class Source(BaseModel):
    label: str = Field(..., max_length=200)
    url: str = Field(..., max_length=1000)


class CreateRequest(BaseModel):
    platform: str
    content: str = Field(..., min_length=1, max_length=40000)
    topic: str = Field(..., min_length=1, max_length=200)
    why: str = Field("", max_length=4000)
    sources: list[Source] = []
    checks: list[str] = []
    campaign: str = Field("", max_length=100)
    target_url: str = Field("", max_length=1000)


class ActionRequest(BaseModel):
    action: Literal["edit", "accept", "reject", "reopen", "mark_posted", "metrics"]
    content: str | None = Field(None, max_length=40000)
    reason: str = Field("", max_length=1000)
    url: str = Field("", max_length=1000)
    metrics: dict = {}


class PostResponse(BaseModel):
    id: uuid.UUID
    platform: str
    topic: str | None
    content: str
    status: str
    why: str
    sources: list[dict]
    checks: list[str]
    campaign: str
    target_url: str
    edited: bool
    history: list[dict]
    external_url: str | None
    metrics: dict
    visits: int
    created_at: str
    posted_at: str | None


async def _visits(db: AsyncSession, campaigns: set[str]) -> dict[str, int]:
    """Distinct site sessions per utm_campaign, from first-party analytics only."""
    if not campaigns:
        return {}
    name = AnalyticsEvent.extra_metadata["utm_campaign"].as_string()
    rows = await db.execute(
        select(name, func.count(func.distinct(AnalyticsEvent.session_id)))
        .where(name.in_(campaigns)).group_by(name),
    )
    return {campaign: count for campaign, count in rows.all()}


def _response(post: MarketingPost, visits: dict[str, int]) -> PostResponse:
    data = studio.meta(post)
    campaign = data.get("campaign") or ""
    return PostResponse(
        id=post.id, platform=post.platform, topic=post.topic, content=post.content,
        status=post.status, why=data.get("why") or "", sources=data.get("sources") or [],
        checks=data.get("checks") or [], campaign=campaign,
        target_url=data.get("target_url") or "",
        edited=post.content != data.get("original_content", post.content),
        history=data.get("history") or [],
        external_url=(post.utm_params or {}).get("external_url"),
        metrics=post.metrics_json or {}, visits=visits.get(campaign, 0),
        created_at=post.created_at.isoformat(),
        posted_at=post.posted_at.isoformat() if post.posted_at else None,
    )


def _who(entity: Entity) -> str:
    return entity.display_name or "admin"


@router.get("/posts", response_model=list[PostResponse])
async def list_studio_posts(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> list[PostResponse]:
    require_admin(current_entity)
    posts = await studio.list_posts(db)
    campaigns = {studio.meta(p).get("campaign") for p in posts} - {None, ""}
    visits = await _visits(db, campaigns)
    return [_response(p, visits) for p in posts]


@router.post("/posts", response_model=PostResponse)
async def create_studio_post(
    req: CreateRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> PostResponse:
    require_admin(current_entity)
    try:
        post = await studio.create_post(
            db, **req.model_dump(exclude={"sources"}),
            sources=[s.model_dump() for s in req.sources], by=_who(current_entity),
        )
    except studio.StudioError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await db.commit()
    await db.refresh(post)
    return _response(post, {})


@router.post("/posts/{post_id}", response_model=PostResponse)
async def act_on_studio_post(
    post_id: uuid.UUID,
    req: ActionRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> PostResponse:
    require_admin(current_entity)
    post = await studio.get_post(db, post_id)
    if not post:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Post not found")
    by = _who(current_entity)
    try:
        if req.action == "edit":
            studio.edit(post, req.content or "", by)
        elif req.action == "accept":
            studio.accept(post, by, req.content)
        elif req.action == "reject":
            studio.reject(post, by, req.reason)
        elif req.action == "reopen":
            studio.reopen(post, by)
        elif req.action == "mark_posted":
            studio.mark_posted(post, by, req.url)
        else:
            studio.set_metrics(post, by, req.metrics)
    except studio.StudioError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await db.commit()
    await db.refresh(post)
    campaign = studio.meta(post).get("campaign")
    return _response(post, await _visits(db, {campaign} if campaign else set()))
