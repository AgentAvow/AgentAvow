"""Marketing recap generator — posts a summary of recent social media
activity to the AgentAvow feed twice per week (Monday and Thursday).

Uses the MarketingBot entity to post, matching the bot posting pattern
from ``src/bots/engine._post_as_bot``.
"""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.bots.definitions import BOT_BY_KEY
from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)

# Redis key for tracking last recap time
_LAST_RECAP_KEY = "ag:mktg:last_recap"

# Days to look back for recap content
_LOOKBACK_DAYS = 4

# Platform URL builders
_PLATFORM_URL_BUILDERS: dict[str, object] = {}


def _build_twitter_url(external_id: str) -> str:
    """Build a Twitter/X post URL from external ID."""
    return f"https://x.com/i/status/{external_id}"


def _build_bluesky_url(external_id: str) -> str:
    """Build a Bluesky post URL from an AT URI or rkey."""
    # AT URI format: at://did:plc:xxx/app.bsky.feed.post/rkey
    if external_id.startswith("at://"):
        parts = external_id.split("/")
        if len(parts) >= 5:
            rkey = parts[-1]
            return f"https://bsky.app/profile/agentavow.bsky.social/post/{rkey}"
    # If it's just a bare rkey
    return f"https://bsky.app/profile/agentavow.bsky.social/post/{external_id}"


def _build_devto_url(external_id: str) -> str:
    """Build a Dev.to article URL."""
    # external_id might be a numeric ID or slug
    return f"https://dev.to/agentavow/{external_id}"


def _build_reddit_url(external_id: str) -> str:
    """Build a Reddit post URL."""
    return f"https://reddit.com/comments/{external_id}"


def _build_linkedin_url(external_id: str) -> str:
    """Build a LinkedIn post URL."""
    return f"https://linkedin.com/feed/update/{external_id}"


def _build_hashnode_url(external_id: str) -> str:
    """Build a Hashnode article URL."""
    return f"https://agentavow.hashnode.dev/{external_id}"


def _build_discord_url(external_id: str) -> str:
    """Discord messages don't have public URLs."""
    return ""


def _build_telegram_url(external_id: str) -> str:
    """Telegram messages don't have reliable public URLs."""
    return ""


_URL_BUILDERS: dict[str, object] = {
    "twitter": _build_twitter_url,
    "bluesky": _build_bluesky_url,
    "devto": _build_devto_url,
    "reddit": _build_reddit_url,
    "linkedin": _build_linkedin_url,
    "hashnode": _build_hashnode_url,
    "discord": _build_discord_url,
    "telegram": _build_telegram_url,
}

# Display names for platforms
_PLATFORM_NAMES: dict[str, str] = {
    "twitter": "Twitter/X",
    "bluesky": "Bluesky",
    "devto": "Dev.to",
    "reddit": "Reddit",
    "linkedin": "LinkedIn",
    "hashnode": "Hashnode",
    "discord": "Discord",
    "telegram": "Telegram",
    "huggingface": "HuggingFace",
    "github_discussions": "GitHub Discussions",
    "hackernews": "Hacker News",
    "producthunt": "Product Hunt",
}


async def _get_recent_posted(
    db: AsyncSession, lookback_days: int = _LOOKBACK_DAYS,
) -> list[MarketingPost]:
    """Fetch marketing posts with status='posted' from the last N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    result = await db.execute(
        select(MarketingPost)
        .where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= cutoff,
        )
        .order_by(MarketingPost.posted_at.asc()),
    )
    return list(result.scalars().all())


def _build_url(platform: str, external_id: str | None) -> str:
    """Build a URL for a marketing post given platform and external_id."""
    if not external_id:
        return ""
    builder = _URL_BUILDERS.get(platform)
    if builder is None:
        return ""
    return builder(external_id)  # type: ignore[operator]


_OPENERS = [
    "We've been busy building trust infrastructure for AI agents.",
    "Another week pushing agent security forward.",
    "Here's what the AgentAvow bot has been up to.",
    "Spreading the word about verifiable agent identity.",
    "Building in public — here's our latest across the web.",
]


def _format_recap(
    posts_by_platform: dict[str, list[MarketingPost]],
) -> str:
    """Format the recap as an engaging feed post."""
    import random

    lines: list[str] = []
    opener = random.choice(_OPENERS)  # noqa: S311
    lines.append(opener)
    lines.append("")

    total = 0
    for platform, posts in sorted(posts_by_platform.items()):
        count = len(posts)
        total += count
        display_name = _PLATFORM_NAMES.get(platform, platform.title())

        # Pick the best post to highlight (longest content = most effort)
        best = max(posts, key=lambda p: len(p.content or ""))
        snippet = (best.content or "")[:80].strip()
        if len(best.content or "") > 80:
            snippet += "..."

        # Build links
        links: list[str] = []
        for p in posts:
            url = _build_url(platform, p.external_id)
            if url:
                links.append(url)

        platform_line = f"{display_name} ({count})"
        if snippet:
            platform_line += f' — "{snippet}"'
        lines.append(platform_line)

        if links:
            lines.append("  " + " ".join(links[:3]))
            if len(links) > 3:
                lines.append(f"  +{len(links) - 3} more")
        lines.append("")

    lines.append(
        f"{total} posts, {len(posts_by_platform)} platforms. "
        "More at https://agentavow.com"
    )

    return "\n".join(lines)


async def generate_recap_content(
    db: AsyncSession, lookback_days: int = _LOOKBACK_DAYS,
) -> str | None:
    """Generate recap post content. Returns None if no activity."""
    posts = await _get_recent_posted(db, lookback_days)
    if not posts:
        logger.info("No marketing posts found for recap (last %d days)", lookback_days)
        return None

    # Group by platform
    by_platform: dict[str, list[MarketingPost]] = defaultdict(list)
    for post in posts:
        by_platform[post.platform].append(post)

    return _format_recap(by_platform)


async def post_recap_to_feed(db: AsyncSession, content: str) -> uuid.UUID | None:
    """Post the recap content to the AgentAvow feed as MarketingBot.

    Returns the post ID or None on failure.
    """
    from src.bots.engine import _post_as_bot

    marketing_bot = BOT_BY_KEY.get("marketingbot")
    if not marketing_bot:
        logger.error("MarketingBot not found in bot definitions")
        return None

    post = await _post_as_bot(
        db,
        marketing_bot["id"],
        content,
        flair="announcement",
    )
    if post:
        logger.info("Posted marketing recap to feed: post_id=%s", post.id)
        return post.id
    return None


async def _is_recap_due() -> bool:
    """Check if it's time for a recap (Monday or Thursday, not already sent today)."""
    now = datetime.now(timezone.utc)
    # Monday = 0, Thursday = 3
    if now.weekday() not in (0, 3):
        return False

    try:
        from src.redis_client import get_redis

        r = get_redis()
        last_recap = await r.get(_LAST_RECAP_KEY)
        if last_recap:
            last_time = float(last_recap)
            # Don't post if we already posted within the last 20 hours
            if (now.timestamp() - last_time) < 72000:  # 20 hours
                return False
    except Exception:
        # Redis unavailable — check day only
        pass

    return True


async def _record_recap_time() -> None:
    """Record that a recap was just posted."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        await r.set(
            _LAST_RECAP_KEY,
            str(datetime.now(timezone.utc).timestamp()),
            ex=86400 * 7,  # 7 day TTL
        )
    except Exception:
        logger.debug("Failed to record recap time in Redis")


async def maybe_post_recap(db: AsyncSession) -> dict:
    """Check if it's time for a recap and post it if so.

    Called from the scheduler or orchestrator tick.
    Returns a dict with status info.
    """
    if not await _is_recap_due():
        return {"status": "not_due"}

    content = await generate_recap_content(db)
    if not content:
        return {"status": "no_activity"}

    post_id = await post_recap_to_feed(db, content)
    if post_id:
        await _record_recap_time()
        return {"status": "posted", "post_id": str(post_id)}

    return {"status": "failed"}


async def trigger_recap(db: AsyncSession) -> dict:
    """Manually trigger a recap post (bypasses day-of-week check).

    Used by the admin API endpoint.
    """
    content = await generate_recap_content(db)
    if not content:
        return {
            "status": "no_activity",
            "message": "No posted marketing content found in the last 4 days",
        }

    post_id = await post_recap_to_feed(db, content)
    if post_id:
        await _record_recap_time()
        return {"status": "posted", "post_id": str(post_id), "content": content}

    return {"status": "failed", "message": "Failed to create feed post"}
