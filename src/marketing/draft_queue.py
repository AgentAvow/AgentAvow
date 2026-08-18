"""Human-in-the-loop draft queue for HN, Product Hunt, and other
platforms where bot posting would get flagged or banned.

Posts go to status='human_review' and wait for admin approval.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.marketing.content.engine import content_hash, content_quality_issue
from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)


async def enqueue_draft(
    db: AsyncSession,
    platform: str,
    content: str,
    topic: str,
    post_type: str = "proactive",
    llm_model: str | None = None,
    llm_tokens_in: int = 0,
    llm_tokens_out: int = 0,
    llm_cost_usd: float = 0.0,
    utm_params: dict | None = None,
    campaign_id: uuid.UUID | None = None,
) -> MarketingPost:
    """Create a draft post awaiting human review.

    Bulletproof quality gate: if ``content`` is an unfilled brief/placeholder
    (LLM scaffolding, not finished copy) it is recorded as ``failed`` instead of
    ``human_review`` — so garbage is auditable but never clutters the review
    queue or gets approved by mistake.
    """
    issue = content_quality_issue(content)
    status = "human_review"
    error_message = None
    if issue:
        status = "failed"
        error_message = f"Auto-rejected (quality gate): {issue}"
        logger.warning(
            "Draft auto-rejected for %s (topic=%s): %s | %s",
            platform, topic, issue, (content or "")[:80],
        )

    post = MarketingPost(
        id=uuid.uuid4(),
        campaign_id=campaign_id,
        platform=platform,
        content=content,
        content_hash=content_hash(content),
        post_type=post_type,
        topic=topic,
        status=status,
        error_message=error_message,
        llm_model=llm_model,
        llm_tokens_in=llm_tokens_in,
        llm_tokens_out=llm_tokens_out,
        llm_cost_usd=llm_cost_usd,
        utm_params=utm_params,
    )
    db.add(post)
    await db.flush()
    if issue:
        logger.info("Draft gated for %s: %s (topic=%s)", platform, post.id, topic)
    else:
        logger.info("Draft enqueued for %s: %s (topic=%s)", platform, post.id, topic)
    return post


async def get_pending_drafts(
    db: AsyncSession,
    platform: str | None = None,
    statuses: list[str] | None = None,
    limit: int = 50,
) -> list[MarketingPost]:
    """Get drafts awaiting human review (or matching given statuses)."""
    allowed = statuses or ["human_review"]
    q = (
        select(MarketingPost)
        .options(selectinload(MarketingPost.campaign))
        .where(MarketingPost.status.in_(allowed))
        .order_by(MarketingPost.created_at.desc())
        .limit(limit)
    )

    if platform:
        q = q.where(MarketingPost.platform == platform)

    result = await db.execute(q)
    return list(result.scalars().all())


_ACTIONABLE_STATUSES = ("human_review", "draft", "queued")


async def approve_draft(db: AsyncSession, post_id: uuid.UUID) -> MarketingPost | None:
    """Approve a draft — moves it to 'queued' for posting."""
    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.id == post_id,
            MarketingPost.status.in_(_ACTIONABLE_STATUSES),
        ),
    )
    post = result.scalar_one_or_none()
    if not post:
        return None

    post.status = "queued"
    await db.flush()
    logger.info("Draft approved: %s (%s)", post.id, post.platform)
    return post


async def reject_draft(
    db: AsyncSession, post_id: uuid.UUID, reason: str = "",
) -> MarketingPost | None:
    """Reject a draft — marks it as 'failed'."""
    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.id == post_id,
            MarketingPost.status.in_(_ACTIONABLE_STATUSES),
        ),
    )
    post = result.scalar_one_or_none()
    if not post:
        return None

    post.status = "failed"
    post.error_message = f"Rejected: {reason}" if reason else "Rejected by admin"
    await db.flush()
    logger.info("Draft rejected: %s (%s)", post.id, post.platform)
    return post


async def edit_and_approve(
    db: AsyncSession, post_id: uuid.UUID, new_content: str,
) -> MarketingPost | None:
    """Edit a draft's content and approve it."""
    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.id == post_id,
            MarketingPost.status.in_(_ACTIONABLE_STATUSES),
        ),
    )
    post = result.scalar_one_or_none()
    if not post:
        return None

    original = post.content or ""
    post.content = new_content
    post.content_hash = content_hash(new_content)
    post.status = "queued"
    await db.flush()
    logger.info("Draft edited and approved: %s (%s)", post.id, post.platform)
    # No-slop learning: what the human edited OUT is a labeled slop signal → propose it.
    try:
        from src.marketing.content.slop_learning import propose_from_edit
        await propose_from_edit(original, new_content)
    except Exception:
        pass
    return post


async def edit_content(
    db: AsyncSession, post_id: uuid.UUID, new_content: str,
) -> MarketingPost | None:
    """Edit a post's content WITHOUT changing its status — for scheduled/planned
    campaign posts the user wants to tweak but keep on schedule."""
    post = (await db.execute(
        select(MarketingPost).where(
            MarketingPost.id == post_id,
            MarketingPost.status.in_(("human_review", "draft", "queued", "planned")),
        ),
    )).scalar_one_or_none()
    if not post:
        return None
    original = post.content or ""
    post.content = new_content
    post.content_hash = content_hash(new_content)
    await db.flush()
    try:
        from src.marketing.content.slop_learning import propose_from_edit
        await propose_from_edit(original, new_content)
    except Exception:
        pass
    return post


async def mark_manually_posted(
    db: AsyncSession,
    post_id: uuid.UUID,
    posted_url: str | None = None,
) -> MarketingPost | None:
    """Mark a draft as manually posted (for platforms like Reddit)."""
    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.id == post_id,
            MarketingPost.status.in_(_ACTIONABLE_STATUSES),
        ),
    )
    post = result.scalar_one_or_none()
    if not post:
        return None

    post.status = "posted"
    post.posted_at = datetime.now(timezone.utc)
    if posted_url:
        post.utm_params = {
            **(post.utm_params or {}),
            "external_url": posted_url,
        }
    await db.flush()
    logger.info("Draft marked as manually posted: %s (%s)", post.id, post.platform)
    return post
