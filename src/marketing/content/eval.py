"""Marketing eval + alerts — the 'is the learning loop actually working?' layer.

Online eval (the real signal): engagement-per-post over 7d vs 30d (trend), the no-slop
first-draft pass rate, and reply-guy engagement — all in one place, feeding both the
admin view and the alerting. Best-effort; never raises into a request/scheduler.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)


def _eng(m: dict | None) -> int:
    if not m:
        return 0
    return int((m.get("likes") or 0) + (m.get("comments") or 0) + (m.get("shares") or 0))


async def _avg_engagement(db: AsyncSession, days: int) -> tuple[float, int]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = list((await db.execute(
        select(MarketingPost.metrics_json).where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= since,
            MarketingPost.metrics_json.isnot(None),
        ),
    )).all())
    if not rows:
        return 0.0, 0
    total = sum(_eng(r[0]) for r in rows)
    return round(total / len(rows), 2), len(rows)


async def _slop_pass_rate(days: int = 7) -> float | None:
    """First-draft no-slop pass rate over the window (from Redis counters)."""
    try:
        from src.redis_client import get_redis
        r = get_redis()
        now = datetime.now(timezone.utc)
        days_str = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)]
        tot = sum(int(await r.get(f"ag:mktg:slop:total:{d}") or 0) for d in days_str)
        passed = sum(int(await r.get(f"ag:mktg:slop:pass:{d}") or 0) for d in days_str)
        return round(passed / tot, 3) if tot else None
    except Exception:
        return None


async def _reply_engagement(db: AsyncSession, days: int = 7) -> tuple[float, int]:
    from src.models import ReplyOpportunity
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = list((await db.execute(
        select(ReplyOpportunity.engagement_count).where(
            ReplyOpportunity.status == "posted",
            ReplyOpportunity.posted_at >= since,
        ),
    )).all())
    if not rows:
        return 0.0, 0
    total = sum(int(r[0] or 0) for r in rows)
    return round(total / len(rows), 2), len(rows)


async def get_marketing_eval(db: AsyncSession) -> dict:
    """The eval snapshot + any active alerts."""
    eng7, n7 = await _avg_engagement(db, 7)
    eng30, n30 = await _avg_engagement(db, 30)
    slop7 = await _slop_pass_rate(7)
    reply7, rn7 = await _reply_engagement(db, 7)
    trend = round(((eng7 - eng30) / eng30) * 100, 1) if eng30 > 0 else None

    alerts: list[dict] = []
    reply_wins = reply7 > eng7 and reply7 > 0
    # Engagement regression: 7d meaningfully below the 30d baseline (need enough posts).
    if eng30 > 0 and n7 >= 3 and eng7 < eng30 * 0.6:
        alerts.append({
            "level": "warn",
            "message": f"Engagement down {abs(trend or 0)}% vs 30-day baseline "
                       f"({eng7} vs {eng30}/post). The learning loop may be drifting.",
            "action": ("Replies are outperforming broadcasts — shift effort to reply-guy "
                       if reply_wins else "Review recent topics; lean into what's working ")
                      + "and check the phrases-to-approve queue.",
            "cta": {"label": "Reply-guy →", "tab": "marketing"},
        })
    # No-slop first-pass rate dropping (bot writing more slop that needs a retry).
    if slop7 is not None and slop7 < 0.6:
        alerts.append({
            "level": "warn",
            "message": f"No-slop first-draft pass rate is {int(slop7 * 100)}% "
                       f"(retries rising) — voice guidance may need a refresh.",
            "action": "Approve the learned slop phrases below to tighten the voice, and "
                      "consider trimming overused angles.",
            "cta": {"label": "Review phrases →", "anchor": "slop"},
        })
    # Almost-zero engagement across the board (reach problem, worth flagging).
    if n7 >= 5 and eng7 == 0:
        alerts.append({
            "level": "info",
            "message": "Zero engagement across broadcast posts — reach, not quality, is the "
                       "bottleneck.",
            "action": (f"Your replies average {reply7}/post vs 0 for broadcasts — put effort "
                       "into reply-guy (widen targeting) over broadcast volume."
                       if reply_wins else
                       "Try targeting/timing over volume; consider more replies."),
            "cta": {"label": "Reply-guy →", "tab": "marketing"},
        })

    return {
        "engagement_per_post_7d": eng7,
        "engagement_per_post_30d": eng30,
        "trend_pct": trend,
        "posts_7d": n7,
        "posts_30d": n30,
        "slop_pass_rate_7d": slop7,
        "reply_engagement_per_post_7d": reply7,
        "replies_7d": rn7,
        "alerts": alerts,
    }
