"""One-time backfill: populate reply_opportunities.our_engagement for Bluesky replies.

our_engagement was added 2026-08-21 to hold OUR reply's real engagement (the dashboard
had been ranking targets by engagement_count = the SOURCE post's likes). This backfills
it for existing posted Bluesky replies by matching them to the bot's own author feed
(which carries the real like/reply/repost counts), keyed by post rkey.

Idempotent + read-only against Bluesky (public API). Run from repo root:
    docker exec agentgraph-backend-1 python3 scripts/backfill_reply_engagement.py
"""
from __future__ import annotations

import asyncio

import httpx
from sqlalchemy import select, update

from src.database import async_session
from src.models import ReplyOpportunity

_ACTOR = "agentavow.bsky.social"
_FEED = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"


def _rkey(url: str | None) -> str | None:
    """Post rkey from either a bsky.app web URL or an at:// URI (last path segment)."""
    if not url:
        return None
    return url.rstrip("/").split("/")[-1] or None


async def _fetch_engagement_by_rkey() -> dict[str, int]:
    """Walk the bot's author feed and map rkey -> (likes+replies+reposts) for our replies."""
    by_rkey: dict[str, int] = {}
    cursor: str | None = None
    async with httpx.AsyncClient(timeout=20) as client:
        for _ in range(40):  # up to ~4000 posts
            params = {"actor": _ACTOR, "limit": 100, "filter": "posts_with_replies"}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(_FEED, params=params)
            if resp.status_code != 200:
                break
            data = resp.json()
            for item in data.get("feed", []):
                post = item.get("post", {})
                uri = post.get("uri", "")
                rk = _rkey(uri)
                if not rk:
                    continue
                by_rkey[rk] = (
                    (post.get("likeCount", 0) or 0)
                    + (post.get("replyCount", 0) or 0)
                    + (post.get("repostCount", 0) or 0)
                )
            cursor = data.get("cursor")
            if not cursor:
                break
    return by_rkey


async def main() -> None:
    eng = await _fetch_engagement_by_rkey()
    print(f"fetched engagement for {len(eng)} of the bot's own posts")
    updated = 0
    async with async_session() as db:
        rows = list((await db.execute(
            select(ReplyOpportunity.id, ReplyOpportunity.reply_url).where(
                ReplyOpportunity.platform == "bluesky",
                ReplyOpportunity.status == "posted",
                ReplyOpportunity.reply_url.isnot(None),
            ),
        )).all())
        for opp_id, url in rows:
            rk = _rkey(url)
            if rk and rk in eng:
                await db.execute(
                    update(ReplyOpportunity)
                    .where(ReplyOpportunity.id == opp_id)
                    .values(our_engagement=eng[rk]),
                )
                updated += 1
        await db.commit()
    print(f"backfilled our_engagement on {updated} of {len(rows)} posted bluesky replies")


if __name__ == "__main__":
    asyncio.run(main())
