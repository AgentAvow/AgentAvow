"""Post Studio: posts Claude drafts and Kenne reviews, accepts and posts by hand.

This module never publishes anything. It does not import the platform adapters, and
it uses its own statuses, so neither the marketing bot's poster cycle nor the legacy
draft queue can pick these rows up. The only way a Studio post reaches a platform is
a person pasting it there and recording the link with ``mark_posted``.

Add drafts from the host with:
    python -m src.marketing.post_studio add < drafts.json
"""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.content.engine import content_hash, content_quality_issue
from src.marketing.models import MarketingPost

POST_TYPE = "studio"
REVIEW = "studio_review"
ACCEPTED = "studio_accepted"
REJECTED = "studio_rejected"
POSTED = "posted"
STATUSES = (REVIEW, ACCEPTED, REJECTED, POSTED)
PLATFORMS = ("x", "linkedin", "reddit", "github", "hackernews", "other")
METRIC_KEYS = ("impressions", "likes", "comments", "shares", "clicks")


class StudioError(ValueError):
    """The action is not valid for this post, or its input is unusable."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def meta(post: MarketingPost) -> dict:
    return dict((post.utm_params or {}).get("studio") or {})


def _save_meta(post: MarketingPost, studio: dict, **top: object) -> None:
    # Reassign the whole dict so SQLAlchemy sees the JSONB change.
    post.utm_params = {**(post.utm_params or {}), **top, "studio": studio}


def _log(post: MarketingPost, action: str, by: str, note: str = "") -> None:
    studio = meta(post)
    entry = {"at": _now(), "action": action, "by": by}
    if note:
        entry["note"] = note
    studio["history"] = [*(studio.get("history") or []), entry]
    _save_meta(post, studio)


def _set_content(post: MarketingPost, content: str) -> None:
    text = content.strip()
    issue = content_quality_issue(text)
    if issue or not text:
        raise StudioError(f"Content failed the quality check: {issue or 'empty'}")
    post.content = text
    post.content_hash = content_hash(text)


async def create_post(
    db: AsyncSession,
    *,
    platform: str,
    content: str,
    topic: str,
    why: str = "",
    sources: list[dict] | None = None,
    checks: list[str] | None = None,
    campaign: str = "",
    target_url: str = "",
    by: str = "claude",
) -> MarketingPost:
    if platform not in PLATFORMS:
        raise StudioError(f"Unknown platform: {platform}")
    post = MarketingPost(
        id=uuid.uuid4(), platform=platform, post_type=POST_TYPE, topic=topic[:200],
        status=REVIEW, content="", content_hash="",
    )
    _set_content(post, content)
    _save_meta(post, {
        "why": why, "sources": sources or [], "checks": checks or [],
        "campaign": campaign, "target_url": target_url,
        "original_content": post.content, "history": [],
    })
    _log(post, "drafted", by)
    db.add(post)
    await db.flush()
    return post


async def get_post(db: AsyncSession, post_id: uuid.UUID) -> MarketingPost | None:
    return (await db.execute(select(MarketingPost).where(
        MarketingPost.id == post_id, MarketingPost.post_type == POST_TYPE,
    ))).scalar_one_or_none()


async def list_posts(db: AsyncSession, limit: int = 200) -> list[MarketingPost]:
    return list((await db.execute(
        select(MarketingPost).where(MarketingPost.post_type == POST_TYPE)
        .order_by(MarketingPost.created_at.desc()).limit(limit),
    )).scalars().all())


def _need(post: MarketingPost, *allowed: str) -> None:
    if post.status not in allowed:
        raise StudioError(f"Not allowed while the post is {post.status}")


def edit(post: MarketingPost, content: str, by: str) -> None:
    _need(post, REVIEW)
    _set_content(post, content)
    _log(post, "edited", by)


def accept(post: MarketingPost, by: str, content: str | None = None) -> None:
    _need(post, REVIEW)
    if content is not None and content.strip() != post.content:
        _set_content(post, content)
        _log(post, "edited", by)
    post.status = ACCEPTED
    _log(post, "accepted", by)


def reject(post: MarketingPost, by: str, reason: str = "") -> None:
    _need(post, REVIEW, ACCEPTED)
    post.status = REJECTED
    _log(post, "rejected", by, reason)


def reopen(post: MarketingPost, by: str) -> None:
    _need(post, ACCEPTED, REJECTED)
    post.status = REVIEW
    _log(post, "reopened", by)


def mark_posted(post: MarketingPost, by: str, url: str) -> None:
    _need(post, ACCEPTED)
    link = url.strip()
    if not link.startswith("https://"):
        raise StudioError("Add the https link to the live post")
    post.status = POSTED
    post.posted_at = datetime.now(timezone.utc)
    _save_meta(post, meta(post), external_url=link)
    _log(post, "posted", by)


def set_metrics(post: MarketingPost, by: str, metrics: dict) -> None:
    _need(post, POSTED)
    clean = {}
    for key in METRIC_KEYS:
        value = metrics.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise StudioError(f"{key} must be a whole number")
        clean[key] = value
    post.metrics_json = {**(post.metrics_json or {}), **clean}
    post.metrics_updated_at = datetime.now(timezone.utc)
    _log(post, "metrics", by)


async def _cli_add() -> int:
    from src.database import async_session

    items = json.load(sys.stdin)
    items = items if isinstance(items, list) else [items]
    async with async_session() as db:
        created = [await create_post(db, **item) for item in items]
        await db.commit()
    for post in created:
        print(post.id, post.platform, post.topic)
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["add"]:
        sys.exit("usage: python -m src.marketing.post_studio add < drafts.json")
    sys.exit(asyncio.run(_cli_add()))
