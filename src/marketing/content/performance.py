"""Self-learning loop — feed real engagement back into generation.

The content engine improves by *measuring what worked and doing more of it*:

- ``get_performance_context`` mines recently-posted content + its engagement metrics
  (likes/comments/shares) and returns a prompt block naming the winning topics/angles,
  so the generator leans toward what earns engagement.
- ``get_overused_phrases`` finds openings/phrases the bot has repeated lately and tells
  it to vary them — a continuous, data-driven no-slop improvement (repetition is a top
  AI-tell the rule detector can't catch on its own).

Both are best-effort and return "" on no data, so generation is never blocked.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)


def _engagement(metrics: dict | None) -> int:
    if not metrics:
        return 0
    return int((metrics.get("likes") or 0) + (metrics.get("comments") or 0)
               + (metrics.get("shares") or 0))


async def get_performance_context(
    db: AsyncSession, platform: str | None = None, days: int = 45,
) -> str:
    """Prompt block naming the best-performing recent topics/angles to lean into."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(MarketingPost).where(
        MarketingPost.status == "posted",
        MarketingPost.posted_at >= since,
        MarketingPost.metrics_json.isnot(None),
    )
    if platform:
        q = q.where(MarketingPost.platform == platform)
    try:
        posts = list((await db.execute(q.limit(300))).scalars().all())
    except Exception:
        return ""

    scored = [(p, _engagement(p.metrics_json)) for p in posts]
    scored = [(p, e) for p, e in scored if e > 0]
    if len(scored) < 3:
        return ""  # not enough signal yet

    # Winning topics (avg engagement per topic, min 2 posts)
    by_topic: dict[str, list[int]] = {}
    for p, e in scored:
        if p.topic:
            by_topic.setdefault(p.topic, []).append(e)
    topic_avg = {t: sum(v) / len(v) for t, v in by_topic.items() if len(v) >= 2}
    top_topics = sorted(topic_avg.items(), key=lambda x: x[1], reverse=True)[:3]

    # Top individual posts (as concrete exemplars of what lands)
    top_posts = sorted(scored, key=lambda x: x[1], reverse=True)[:2]

    parts = ["\n- WHAT'S EARNED ENGAGEMENT LATELY (learn from this — do more of it):"]
    if top_topics:
        parts.append(
            "  Best topics by avg engagement: "
            + ", ".join(f"{t} (~{int(a)})" for t, a in top_topics) + "."
        )
    for p, e in top_posts:
        snippet = re.sub(r"\s+", " ", (p.content or "")).strip()[:140]
        parts.append(f"  A post that landed ({e} engagements): \"{snippet}…\"")
    parts.append("  Echo the angle/voice of what worked; don't copy it verbatim.")
    return "\n".join(parts) + "\n"


async def get_overused_phrases(
    db: AsyncSession, platform: str | None = None, days: int = 21,
) -> str:
    """Tell the generator to vary phrases it's leaned on too hard recently (anti-repetition)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(MarketingPost.content).where(
        MarketingPost.status == "posted",
        MarketingPost.posted_at >= since,
    )
    if platform:
        q = q.where(MarketingPost.platform == platform)
    try:
        contents = [c for (c,) in (await db.execute(q.limit(200))).all() if c]
    except Exception:
        return ""
    if len(contents) < 6:
        return ""

    # Repeated openers (first 5 words) + repeated 4-grams.
    openers = Counter()
    grams = Counter()
    for c in contents:
        words = re.sub(r"\s+", " ", c.strip()).split()
        if len(words) >= 5:
            openers[" ".join(words[:5]).lower()] += 1
        for i in range(len(words) - 3):
            grams[" ".join(words[i:i + 4]).lower()] += 1

    overused = [p for p, n in openers.most_common(3) if n >= 3]
    overused += [g for g, n in grams.most_common(5) if n >= 4 and not g.startswith("http")]
    overused = list(dict.fromkeys(overused))[:5]
    if not overused:
        return ""
    return (
        "\n- AVOID REPEATING (you've overused these lately — say it a fresh way): "
        + "; ".join(f"\"{p}\"" for p in overused) + ".\n"
    )


async def get_learning_context(db: AsyncSession, platform: str | None = None) -> str:
    """Combined self-learning block injected into generation prompts."""
    perf = await get_performance_context(db, platform)
    avoid = await get_overused_phrases(db, platform)
    return perf + avoid


async def get_reply_learning_context(db: AsyncSession, platform: str | None = None) -> str:
    """What replies have earned engagement — injected into the reply drafter so it does
    more of what lands. Replies are the best-performing channel, so this matters most."""
    from src.models import ReplyOpportunity
    since = datetime.now(timezone.utc) - timedelta(days=30)
    q = select(ReplyOpportunity).where(
        ReplyOpportunity.status == "posted",
        ReplyOpportunity.posted_at >= since,
        ReplyOpportunity.engagement_count > 0,
    )
    if platform:
        q = q.where(ReplyOpportunity.platform == platform)
    try:
        rows = list((await db.execute(q.order_by(
            ReplyOpportunity.engagement_count.desc()).limit(3))).scalars().all())
    except Exception:
        return ""
    if not rows:
        return ""
    parts = ["\n- REPLIES THAT EARNED ENGAGEMENT (echo this voice, don't copy):"]
    for r in rows:
        snippet = re.sub(r"\s+", " ", (r.draft_content or "")).strip()[:160]
        parts.append(f"  ({r.engagement_count} engagements) \"{snippet}\"")
    return "\n".join(parts) + "\n"
