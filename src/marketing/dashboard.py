"""Admin dashboard data aggregation for marketing system."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.llm.cost_tracker import get_daily_spend, get_monthly_spend
from src.marketing.models import MarketingCampaign, MarketingPost

logger = logging.getLogger(__name__)

# Platform-specific URL patterns for external_id → URL mapping
_URL_PATTERNS: dict[str, str] = {
    "twitter": "https://x.com/i/status/{id}",
    "reddit": "https://reddit.com/comments/{id}",
    "linkedin": "https://linkedin.com/feed/update/{id}",
    "devto": "https://dev.to/agentavow/{id}",
    "hashnode": "https://agentavow.hashnode.dev/{id}",
}


def _post_url(
    platform: str, external_id: str | None,
) -> str | None:
    """Construct a URL to the external post from its ID."""
    if not external_id:
        return None

    # Bluesky AT URIs need special handling
    if platform == "bluesky" and external_id.startswith("at://"):
        # at://did:plc:xxx/app.bsky.feed.post/yyy → bsky.app URL
        parts = external_id.split("/")
        if len(parts) >= 5:
            rkey = parts[-1]
            return (
                "https://bsky.app/profile/"
                "agentavow.bsky.social"
                f"/post/{rkey}"
            )
        return None

    pattern = _URL_PATTERNS.get(platform)
    if pattern:
        return pattern.format(id=external_id)

    return None


async def get_dashboard_data(db: AsyncSession) -> dict:
    """Aggregate marketing data for the admin dashboard."""
    now = datetime.now(timezone.utc)
    month_ago = now - timedelta(days=30)

    # Posts by platform
    platform_stats_q = await db.execute(
        select(
            MarketingPost.platform,
            func.count(MarketingPost.id).label("total"),
            func.count(MarketingPost.id).filter(
                MarketingPost.status == "posted",
            ).label("posted"),
            func.count(MarketingPost.id).filter(
                MarketingPost.status == "failed",
            ).label("failed"),
            func.count(MarketingPost.id).filter(
                MarketingPost.status == "human_review",
            ).label("pending_review"),
        ).group_by(MarketingPost.platform),
    )
    platform_stats = [
        {
            "platform": row.platform,
            "total": row.total,
            "posted": row.posted,
            "failed": row.failed,
            "pending_review": row.pending_review,
        }
        for row in platform_stats_q.all()
    ]

    # Posts by topic
    topic_stats_q = await db.execute(
        select(
            MarketingPost.topic,
            func.count(MarketingPost.id).label("count"),
        ).where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= month_ago,
        ).group_by(MarketingPost.topic),
    )
    topic_stats = [
        {"topic": row.topic, "count": row.count}
        for row in topic_stats_q.all()
    ]

    # Posts by type
    type_stats_q = await db.execute(
        select(
            MarketingPost.post_type,
            func.count(MarketingPost.id).label("count"),
        ).where(MarketingPost.status == "posted").group_by(MarketingPost.post_type),
    )
    type_stats = [
        {"type": row.post_type, "count": row.count}
        for row in type_stats_q.all()
    ]

    # Engagement totals (from metrics_json)
    posted_posts_q = await db.execute(
        select(MarketingPost.metrics_json).where(
            MarketingPost.status == "posted",
            MarketingPost.metrics_json.isnot(None),
            MarketingPost.posted_at >= month_ago,
        ),
    )
    total_likes = 0
    total_comments = 0
    total_shares = 0
    total_impressions = 0
    for row in posted_posts_q.all():
        m = row[0] or {}
        total_likes += m.get("likes", 0)
        total_comments += m.get("comments", 0)
        total_shares += m.get("shares", 0)
        total_impressions += m.get("impressions", 0)

    # LLM cost — ALL from the same source (cost_tracker Redis counters) so the
    # per-model breakdown reconciles with the monthly total. This captures every
    # LLM call (reply-guy drafts + campaign planning included), unlike the old
    # breakdown which summed only stored MarketingPosts and undercounted.
    from src.marketing.llm.cost_tracker import get_monthly_breakdown
    daily_spend = await get_daily_spend()
    monthly_spend = await get_monthly_spend()
    cost_breakdown = await get_monthly_breakdown()
    # Fallback: if the Redis per-model counters are empty (e.g. fresh deploy before
    # any generation this month), show the DB post-attributed breakdown so the table
    # isn't blank.
    if not cost_breakdown:
        cost_q = await db.execute(
            select(
                MarketingPost.llm_model,
                func.count(MarketingPost.id).label("calls"),
                func.coalesce(func.sum(MarketingPost.llm_cost_usd), 0.0).label("cost"),
            ).where(
                MarketingPost.llm_model.isnot(None),
                MarketingPost.created_at >= month_ago,
            ).group_by(MarketingPost.llm_model),
        )
        cost_breakdown = [
            {"model": row.llm_model, "calls": row.calls, "cost_usd": round(float(row.cost), 4)}
            for row in cost_q.all()
        ]

    # Recent posts
    recent_q = await db.execute(
        select(MarketingPost).where(
            MarketingPost.status == "posted",
        ).order_by(MarketingPost.posted_at.desc()).limit(10),
    )
    recent_posts = [
        {
            "id": str(p.id),
            "platform": p.platform,
            "topic": p.topic,
            "content": p.content[:200],
            "url": _post_url(p.platform, p.external_id),
            "posted_at": (
                (p.posted_at or p.created_at).isoformat()
                if (p.posted_at or p.created_at) else None
            ),
            "metrics": p.metrics_json,
            "llm_model": p.llm_model,
            "llm_cost_usd": p.llm_cost_usd,
        }
        for p in recent_q.scalars().all()
    ]

    # Pending drafts count
    drafts_q = await db.execute(
        select(func.count(MarketingPost.id)).where(
            MarketingPost.status == "human_review",
        ),
    )
    pending_drafts = drafts_q.scalar() or 0

    # Active campaigns
    campaigns_q = await db.execute(
        select(MarketingCampaign).where(
            MarketingCampaign.status == "active",
        ).order_by(MarketingCampaign.created_at.desc()).limit(10),
    )
    campaigns = [
        {
            "id": str(c.id),
            "name": c.name,
            "topic": c.topic,
            "platforms": c.platforms,
            "status": c.status,
        }
        for c in campaigns_q.scalars().all()
    ]

    return {
        "platform_stats": platform_stats,
        "topic_stats": topic_stats,
        "type_stats": type_stats,
        "engagement": {
            "total_likes": total_likes,
            "total_comments": total_comments,
            "total_shares": total_shares,
            "total_impressions": total_impressions,
        },
        "cost": {
            "breakdown": cost_breakdown,
            "daily_spend_usd": round(daily_spend, 4),
            "monthly_spend_usd": round(monthly_spend, 4),
        },
        "recent_posts": recent_posts,
        "pending_drafts": pending_drafts,
        "campaigns": campaigns,
    }
