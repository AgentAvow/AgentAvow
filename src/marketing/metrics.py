"""Engagement metric refresh — pulls stats from platform APIs.

Runs every 2 hours, updates marketing_posts.metrics_json for
recent posts (last 7 days).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.adapters.base import AbstractPlatformAdapter
from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)


def _get_all_adapters() -> dict[str, AbstractPlatformAdapter]:
    """Load all adapters for metric fetching."""
    from src.marketing.adapters.bluesky import BlueskyAdapter
    from src.marketing.adapters.devto import DevtoAdapter
    from src.marketing.adapters.discord_bot import DiscordAdapter
    from src.marketing.adapters.github_discussions import GitHubDiscussionsAdapter
    from src.marketing.adapters.hashnode import HashnodeAdapter
    from src.marketing.adapters.huggingface import HuggingFaceAdapter
    from src.marketing.adapters.linkedin import LinkedInAdapter
    from src.marketing.adapters.reddit import RedditAdapter
    from src.marketing.adapters.telegram_bot import TelegramAdapter
    from src.marketing.adapters.twitter import TwitterAdapter

    return {
        "twitter": TwitterAdapter(),
        "reddit": RedditAdapter(),
        "bluesky": BlueskyAdapter(),
        "devto": DevtoAdapter(),
        "linkedin": LinkedInAdapter(),
        "hashnode": HashnodeAdapter(),
        "discord": DiscordAdapter(),
        "telegram": TelegramAdapter(),
        "github_discussions": GitHubDiscussionsAdapter(),
        "huggingface": HuggingFaceAdapter(),
    }


async def refresh_metrics(db: AsyncSession) -> dict:
    """Refresh engagement metrics for recent posted content."""
    adapters = _get_all_adapters()
    window = datetime.now(timezone.utc) - timedelta(days=7)

    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= window,
            MarketingPost.external_id.isnot(None),
        ).order_by(MarketingPost.metrics_updated_at.asc().nullsfirst()).limit(50),
    )
    posts = list(result.scalars().all())

    updated = 0
    errors = 0

    for post in posts:
        adapter = adapters.get(post.platform)
        if not adapter or not await adapter.is_configured():
            continue

        try:
            metrics = await adapter.fetch_metrics(post.external_id)
            post.metrics_json = {
                "likes": metrics.likes,
                "comments": metrics.comments,
                "shares": metrics.shares,
                "impressions": metrics.impressions,
                "clicks": metrics.clicks,
            }
            if metrics.extra:
                post.metrics_json["extra"] = metrics.extra
            post.metrics_updated_at = datetime.now(timezone.utc)
            updated += 1
        except Exception:
            logger.debug("Metric refresh failed for %s/%s", post.platform, post.id)
            errors += 1

    await db.flush()

    logger.info("Metrics refreshed: %d updated, %d errors", updated, errors)
    return {"updated": updated, "errors": errors, "total_checked": len(posts)}


def _reply_post_id(platform: str, url: str | None) -> str | None:
    """Best-effort platform post id from a reply's URL (for metric lookup)."""
    if not url:
        return None
    # Twitter/X: https://x.com/i/status/<id> (or /<user>/status/<id>)
    if platform == "twitter" and "status/" in url:
        return url.rstrip("/").split("status/")[-1].split("?")[0]
    return None  # bluesky needs its at:// uri — tracked separately, skip for now


async def refresh_reply_metrics(db: AsyncSession) -> dict:
    """Pull engagement for recently auto-posted reply-guy replies into
    ``ReplyOpportunity.engagement_count`` (likes + comments + shares).

    Reply engagement was never tracked — the metrics job only covered proactive
    posts. This closes that gap for Twitter (Bluesky reply metrics need the at-uri
    and are deferred). Best-effort; never raises into the scheduler."""
    from src.models import ReplyOpportunity
    adapters = _get_all_adapters()
    window = datetime.now(timezone.utc) - timedelta(days=7)
    rows = list((await db.execute(
        select(ReplyOpportunity).where(
            ReplyOpportunity.status == "posted",
            ReplyOpportunity.posted_at >= window,
            ReplyOpportunity.reply_url.isnot(None),
        ).order_by(ReplyOpportunity.posted_at.desc()).limit(50),
    )).scalars().all())

    updated = 0
    for opp in rows:
        adapter = adapters.get(opp.platform)
        if not adapter or not await adapter.is_configured():
            continue
        pid = _reply_post_id(opp.platform, opp.reply_url)
        if not pid:
            continue
        try:
            m = await adapter.fetch_metrics(pid)
            opp.engagement_count = (m.likes or 0) + (m.comments or 0) + (m.shares or 0)
            updated += 1
        except Exception:
            logger.debug("Reply metric refresh failed for %s", opp.id)

    await db.flush()
    logger.info("Reply metrics refreshed: %d/%d", updated, len(rows))
    return {"updated": updated, "checked": len(rows)}
