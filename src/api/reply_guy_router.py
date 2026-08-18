"""Admin API for the Reply Guy engagement system."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import get_current_entity, require_admin
from src.database import get_db
from src.models import Entity, ReplyOpportunity, ReplyTarget

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/engagement", tags=["engagement"])


# --- Schemas ---


class TargetCreate(BaseModel):
    platform: str
    handle: str
    display_name: str | None = None
    follower_count: int = 0
    priority_tier: int = 2
    topics: list = []


class TargetUpdate(BaseModel):
    display_name: str | None = None
    follower_count: int | None = None
    priority_tier: int | None = None
    topics: list | None = None
    is_active: bool | None = None


class OpportunityAction(BaseModel):
    action: str  # approve, skip, edit
    draft_content: str | None = None  # for edit action


# --- Target endpoints ---


@router.get("/targets")
async def list_targets(
    platform: str | None = None,
    active_only: bool = True,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List all reply targets."""
    require_admin(current_entity)

    q = select(ReplyTarget).order_by(
        ReplyTarget.priority_tier, ReplyTarget.handle,
    )
    if platform:
        q = q.where(ReplyTarget.platform == platform)
    if active_only:
        q = q.where(ReplyTarget.is_active.is_(True))
    targets = (await db.scalars(q)).all()
    return [
        {
            "id": str(t.id),
            "platform": t.platform,
            "handle": t.handle,
            "display_name": t.display_name,
            "follower_count": t.follower_count,
            "priority_tier": t.priority_tier,
            "topics": t.topics or [],
            "is_active": t.is_active,
            "last_checked_at": (
                t.last_checked_at.isoformat() if t.last_checked_at else None
            ),
            "created_at": t.created_at.isoformat(),
        }
        for t in targets
    ]


@router.post("/targets", status_code=201)
async def create_target(
    body: TargetCreate,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Add a new reply target account."""
    require_admin(current_entity)

    target = ReplyTarget(
        platform=body.platform,
        handle=body.handle,
        display_name=body.display_name,
        follower_count=body.follower_count,
        priority_tier=body.priority_tier,
        topics=body.topics,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return {"id": str(target.id), "message": f"Target {body.handle} added"}


@router.patch("/targets/{target_id}")
async def update_target(
    target_id: uuid.UUID,
    body: TargetUpdate,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Update a reply target."""
    require_admin(current_entity)

    target = await db.get(ReplyTarget, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    for field, val in body.dict(exclude_unset=True).items():
        setattr(target, field, val)
    await db.commit()
    await db.refresh(target)
    return {"id": str(target.id), "message": "Updated"}


@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Delete a target and all its opportunities."""
    require_admin(current_entity)

    await db.execute(
        delete(ReplyOpportunity).where(
            ReplyOpportunity.target_id == target_id,
        ),
    )
    await db.execute(delete(ReplyTarget).where(ReplyTarget.id == target_id))
    await db.commit()
    return {"message": "Deleted"}


# --- Opportunity endpoints ---


@router.get("/queue")
async def get_queue(
    status: str = "drafted",
    platform: str | None = None,
    limit: int = 20,
    offset: int = 0,
    sort: str = "urgency",  # "urgency" (default, legacy) | "recent" (newest first)
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get reply opportunities queue. Sorted by urgency by default; ``sort=recent``
    orders newest-first (by posted_at for sent replies, else created_at)."""
    require_admin(current_entity)

    if sort == "recent":
        order = (
            ReplyOpportunity.posted_at.desc().nullslast()
            if status == "posted"
            else ReplyOpportunity.created_at.desc()
        )
    else:
        order = ReplyOpportunity.urgency_score.desc()
    q = (
        select(ReplyOpportunity)
        .options(selectinload(ReplyOpportunity.target))
        .where(ReplyOpportunity.status == status)
        .order_by(order)
        .offset(offset)
        .limit(limit)
    )
    if platform:
        q = q.where(ReplyOpportunity.platform == platform)
    opps = (await db.scalars(q)).all()

    count_q = select(func.count(ReplyOpportunity.id)).where(
        ReplyOpportunity.status == status,
    )
    if platform:
        count_q = count_q.where(ReplyOpportunity.platform == platform)
    total = await db.scalar(count_q)

    return {
        "items": [
            {
                "id": str(o.id),
                "platform": o.platform,
                "post_uri": o.post_uri,
                "post_content": o.post_content,
                "post_timestamp": (
                    o.post_timestamp.isoformat() if o.post_timestamp else None
                ),
                "status": o.status,
                "draft_content": o.draft_content,
                "drafted_at": (
                    o.drafted_at.isoformat() if o.drafted_at else None
                ),
                "posted_at": (
                    o.posted_at.isoformat() if o.posted_at else None
                ),
                "reply_url": o.reply_url,
                "urgency_score": round(o.urgency_score or 0, 2),
                "engagement_count": o.engagement_count,
                "target": {
                    "handle": o.target.handle if o.target else None,
                    "display_name": (
                        o.target.display_name if o.target else None
                    ),
                    "platform": o.target.platform if o.target else None,
                    "priority_tier": (
                        o.target.priority_tier if o.target else None
                    ),
                    "follower_count": (
                        o.target.follower_count if o.target else 0
                    ),
                },
            }
            for o in opps
        ],
        "total": total or 0,
    }


@router.post("/queue/{opp_id}/action")
async def opportunity_action(
    opp_id: uuid.UUID,
    body: OpportunityAction,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Approve, skip, or edit a reply opportunity."""
    require_admin(current_entity)

    opp = await db.get(ReplyOpportunity, opp_id)
    if not opp:
        raise HTTPException(404, "Opportunity not found")

    if body.action == "skip":
        opp.status = "skipped"
        await db.commit()
        return {"message": "Skipped"}

    if body.action == "edit":
        if body.draft_content:
            opp.draft_content = body.draft_content
        await db.commit()
        return {"message": "Draft updated"}

    if body.action == "approve":
        # Post the reply via platform adapter
        target = await db.get(ReplyTarget, opp.target_id)
        if not target:
            raise HTTPException(400, "Target not found")

        try:
            result = await _post_reply(opp, target)
        except Exception as exc:
            logger.exception("Failed to post reply for %s", opp_id)
            raise HTTPException(500, f"Failed to post: {exc}") from exc

        opp.status = "posted"
        opp.posted_at = datetime.now(timezone.utc)
        if result:
            opp.reply_url = result
        await db.commit()
        return {"message": "Posted", "reply_url": result}

    raise HTTPException(400, f"Unknown action: {body.action}")


@router.get("/stats")
async def get_stats(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get engagement stats."""
    require_admin(current_entity)

    # Count by status
    status_counts = {}
    for st in ["new", "drafted", "approved", "posted", "skipped"]:
        count = await db.scalar(
            select(func.count(ReplyOpportunity.id)).where(
                ReplyOpportunity.status == st,
            ),
        )
        status_counts[st] = count or 0

    # Today's posts
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0,
    )
    posted_today = await db.scalar(
        select(func.count(ReplyOpportunity.id)).where(
            ReplyOpportunity.status == "posted",
            ReplyOpportunity.posted_at >= today_start,
        ),
    )

    # Total targets
    total_targets = await db.scalar(
        select(func.count(ReplyTarget.id)).where(
            ReplyTarget.is_active.is_(True),
        ),
    )

    return {
        "status_counts": status_counts,
        "posted_today": posted_today or 0,
        "active_targets": total_targets or 0,
        "queue_size": (
            status_counts.get("drafted", 0) + status_counts.get("new", 0)
        ),
    }


async def _post_reply(
    opp: ReplyOpportunity, target: ReplyTarget,
) -> str | None:
    """Post a reply via the appropriate platform adapter."""
    content = opp.draft_content
    if not content:
        return None

    if opp.platform == "bluesky":
        from src.marketing.adapters.bluesky import BlueskyAdapter

        adapter = BlueskyAdapter()
        result = await adapter.reply(opp.post_uri, content)
        return result.url if result.success else None

    if opp.platform == "twitter":
        from src.marketing.adapters.twitter import TwitterAdapter

        # Free tier can't reply to tweets we're not mentioned in.
        # Use quote tweet instead: post content + original tweet URL.
        # Twitter auto-renders the URL as an embedded quote tweet.
        # URLs count as 23 chars on Twitter, so budget accordingly.
        tweet_url = opp.post_uri
        max_text = 280 - 23 - 2  # 2 for "\n\n" separator
        truncated = content[:max_text].rstrip()
        quote_content = f"{truncated}\n\n{tweet_url}"

        adapter = TwitterAdapter()
        result = await adapter.post(quote_content)
        return result.url if result.success else None

    return None
