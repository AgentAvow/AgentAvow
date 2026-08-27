"""Monitor target accounts for new posts to reply to."""
from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from src.database import async_session
from src.models import ReplyOpportunity, ReplyTarget

logger = logging.getLogger(__name__)

# Permanent do-not-reply blocklist. Handles here are NEVER monitored or replied to,
# even if a matching ReplyTarget row is (re-)added or marked active. This is the durable
# guarantee behind an opt-out request — someone who asks us to stop must stay stopped.
# Normalize entries lowercase, no leading '@'. (Xe iaso asked us to stop, 2026-08-20.)
_HANDLE_BLOCKLIST = {
    "xeiaso.net",
}


def _is_blocklisted(handle: str) -> bool:
    return (handle or "").strip().lower().lstrip("@") in _HANDLE_BLOCKLIST


# Keywords that boost relevance score when found in a post
_RELEVANCE_KEYWORDS = [
    "ai agent", "mcp server", "agent trust", "autonomous agent",
    "tool use", "agentic", "agent identity", "did", "verifiable",
    "agent framework", "langchain", "crewai", "autogen", "agent orchestration",
    "trust score", "agent verification",
]


def is_relevant(text: str) -> bool:
    """True if the post is actually on-topic for us. When
    ``reply_guy_require_relevance`` is on, we only reply to these — no more replying
    to a target's off-topic posts (birds, pinball) just because they're on the list."""
    low = (text or "").lower()
    return any(kw in low for kw in _RELEVANCE_KEYWORDS)


async def monitor_all_targets() -> dict:
    """Check all active targets for new posts. Returns stats."""
    async with async_session() as db:
        targets = (
            await db.scalars(
                select(ReplyTarget)
                .where(ReplyTarget.is_active.is_(True))
                .order_by(
                    ReplyTarget.priority_tier,
                    ReplyTarget.last_checked_at.asc().nullsfirst(),
                )
            )
        ).all()

    stats: dict = {"checked": 0, "new_opportunities": 0, "errors": 0}
    for target in targets:
        try:
            count = await _check_target(target)
            stats["checked"] += 1
            stats["new_opportunities"] += count
        except Exception:
            logger.exception(
                "Error checking target %s/%s", target.platform, target.handle,
            )
            stats["errors"] += 1

    logger.info("Reply monitor: %s", stats)
    return stats


async def _check_target(target: ReplyTarget) -> int:
    """Check a single target for new posts. Returns number of new opportunities."""
    # Permanent opt-out: never monitor or reply to a blocklisted handle, whatever the
    # ReplyTarget row says. Belt-and-suspenders behind deactivating the row itself.
    if _is_blocklisted(target.handle):
        logger.info("Skipping blocklisted handle %s (%s)", target.handle, target.platform)
        return 0

    # Per-target cooldown: never pester the same account more than once per window.
    from src.config import settings
    cooldown_h = getattr(settings, "reply_guy_target_cooldown_hours", 0)
    if cooldown_h > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=cooldown_h)
        async with async_session() as db:
            last_posted = await db.scalar(
                select(ReplyOpportunity.posted_at)
                .where(
                    ReplyOpportunity.target_id == target.id,
                    ReplyOpportunity.status == "posted",
                    ReplyOpportunity.posted_at.is_not(None),
                )
                .order_by(ReplyOpportunity.posted_at.desc())
                .limit(1)
            )
        if last_posted is not None:
            lp = last_posted if last_posted.tzinfo else last_posted.replace(tzinfo=timezone.utc)
            if lp > cutoff:
                logger.debug(
                    "Target %s in cooldown (last reply %s)", target.handle, lp,
                )
                return 0

    since = target.last_checked_at or (
        datetime.now(timezone.utc) - timedelta(hours=24)
    )

    if target.platform == "bluesky":
        posts = await _fetch_bluesky_posts(target.handle, since)
        if posts is None:
            # Permanent getAuthorFeed 400 (profile not found) — retire the dead target
            # so it stops erroring every cycle. Real accounts are unaffected.
            async with async_session() as db:
                await db.execute(
                    update(ReplyTarget)
                    .where(ReplyTarget.id == target.id)
                    .values(is_active=False)
                )
                await db.commit()
            logger.warning(
                "Retired dead bluesky target %s (%s) — getAuthorFeed 400",
                target.id, target.handle,
            )
            return 0
    elif target.platform == "twitter":
        posts = await _fetch_twitter_posts(target.handle, since)
    else:
        return 0

    new_count = 0
    async with async_session() as db:
        with db.no_autoflush:
            for post in posts:
                # Dedup check — no_autoflush prevents premature flush
                existing = await db.scalar(
                    select(ReplyOpportunity).where(
                        ReplyOpportunity.platform == target.platform,
                        ReplyOpportunity.post_uri == post["uri"],
                    )
                )
                if existing:
                    continue

                urgency = _calculate_urgency(post, target)
                opp = ReplyOpportunity(
                    target_id=target.id,
                    platform=target.platform,
                    post_uri=post["uri"],
                    post_content=post.get("text", ""),
                    post_timestamp=post["timestamp"],
                    status="new",
                    urgency_score=urgency,
                    engagement_count=post.get("likes", 0),
                )
                db.add(opp)
                new_count += 1

        # Update last_checked_at
        await db.execute(
            update(ReplyTarget)
            .where(ReplyTarget.id == target.id)
            .values(last_checked_at=datetime.now(timezone.utc))
        )
        try:
            await db.commit()
        except Exception:
            # Unique constraint race — another worker inserted same post
            await db.rollback()
            logger.debug("Duplicate post_uri during commit, rolled back")

    return new_count


def _calculate_urgency(post: dict, target: ReplyTarget) -> float:
    """Calculate urgency score for a reply opportunity.

    Higher = should reply sooner.
    Components: time decay, priority tier, topic relevance, engagement.
    """
    now = datetime.now(timezone.utc)
    post_time = post["timestamp"]
    if post_time.tzinfo is None:
        post_time = post_time.replace(tzinfo=timezone.utc)

    hours_since = (now - post_time).total_seconds() / 3600
    # Exponential decay: 15min=~1.0, 1hr=~0.6, 4hr=~0.13
    time_decay = math.exp(-0.5 * max(hours_since, 0))

    tier_multiplier = {1: 3.0, 2: 2.0, 3: 1.0}.get(target.priority_tier, 1.0)

    # Topic relevance
    text_lower = post.get("text", "").lower()
    relevance = 0.5 if any(kw in text_lower for kw in _RELEVANCE_KEYWORDS) else 0.0

    # Engagement boost (capped)
    engagement = min(1.0, post.get("likes", 0) / 100)

    return time_decay * tier_multiplier + relevance + engagement


async def _fetch_bluesky_posts(handle: str, since: datetime) -> list | None:
    """Fetch recent posts from a Bluesky account.

    Returns a list of posts, or ``None`` if the account is permanently
    unfetchable (getAuthorFeed 400 — profile not found / deactivated), which
    signals the caller to retire the target.
    """
    try:
        import httpx

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",
                params={
                    "actor": handle,
                    "limit": 30,
                    "filter": "posts_no_replies",
                },
                timeout=15,
            )
            if resp.status_code != 200:
                logger.warning(
                    "Bluesky getAuthorFeed failed for %s: %s",
                    handle,
                    resp.status_code,
                )
                # 400 = permanent (deactivated / no profile / bad actor). Signal the
                # caller to retire the target so we stop hammering a dead handle.
                if resp.status_code == 400:
                    return None
                return []
            data = resp.json()

        posts = []
        for item in data.get("feed", []):
            post_data = item.get("post", {})
            record = post_data.get("record", {})
            created_str = record.get("createdAt", "")
            if not created_str:
                continue
            # Parse ISO timestamp. Bluesky can return NANOSECOND precision (e.g.
            # …43.791082215+00:00 — 9 fractional digits), which datetime.fromisoformat
            # on py3.9 rejects. Truncate fractional seconds to 6 digits; skip on any
            # remaining parse error rather than failing the whole target.
            iso = re.sub(r"(\.\d{6})\d+", r"\1", created_str.replace("Z", "+00:00"))
            try:
                created = datetime.fromisoformat(iso)
            except ValueError:
                continue
            if created <= since:
                continue
            text = (record.get("text") or "").strip()
            # Image/link-only posts carry empty text. Skip them: handing an empty
            # post to the LLM produced meta-refusals ("the post appears empty, could
            # you share what they wrote…") that got auto-posted as replies.
            if not text:
                continue
            posts.append({
                "uri": post_data.get("uri", ""),
                "text": text,
                "timestamp": created,
                "likes": post_data.get("likeCount", 0),
            })
        return posts
    except Exception:
        logger.exception("Failed to fetch Bluesky posts for %s", handle)
        return []


async def _fetch_twitter_posts(handle: str, since: datetime) -> list:
    """Fetch recent posts from a Twitter account using API v2.

    Uses the TWITTER_BEARER_TOKEN for app-only auth (read timelines).
    Returns list of dicts with: uri, text, timestamp, likes.
    """
    import os
    import urllib.parse

    import httpx

    bearer = os.environ.get("TWITTER_BEARER_TOKEN")
    if not bearer:
        logger.debug("TWITTER_BEARER_TOKEN not set, skipping %s", handle)
        return []
    # URL-decode in case the token was stored with %2F/%2B encoding
    bearer = urllib.parse.unquote(bearer)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Step 1: resolve handle → user ID
            user_resp = await client.get(
                f"https://api.twitter.com/2/users/by/username/{handle}",
                headers={"Authorization": f"Bearer {bearer}"},
            )
            if user_resp.status_code != 200:
                logger.info("Twitter user lookup failed for %s: %s", handle, user_resp.status_code)
                return []

            user_id = user_resp.json().get("data", {}).get("id")
            if not user_id:
                return []

            # Step 2: fetch recent tweets
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            tweets_resp = await client.get(
                f"https://api.twitter.com/2/users/{user_id}/tweets",
                headers={"Authorization": f"Bearer {bearer}"},
                params={
                    "max_results": 10,
                    "start_time": since_str,
                    "tweet.fields": "created_at,public_metrics,text",
                    "exclude": "retweets,replies",
                },
            )
            if tweets_resp.status_code != 200:
                logger.info("Twitter timeline failed for %s: %s", handle, tweets_resp.status_code)
                return []

            tweets = tweets_resp.json().get("data", [])
            posts = []
            for tweet in tweets:
                created = tweet.get("created_at", "")
                metrics = tweet.get("public_metrics", {})
                posts.append({
                    "uri": f"https://x.com/{handle}/status/{tweet['id']}",
                    "text": tweet.get("text", ""),
                    "timestamp": (
                        datetime.fromisoformat(
                            re.sub(r"(\.\d{6})\d+", r"\1", created.replace("Z", "+00:00"))
                        )
                        if created else datetime.now(timezone.utc)
                    ),
                    "likes": metrics.get("like_count", 0),
                })

            logger.info("Twitter: fetched %d posts for %s", len(posts), handle)
            return posts

    except Exception:
        logger.warning("Twitter fetch failed for %s", handle, exc_info=True)
        return []
