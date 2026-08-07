"""Weekly marketing digest — emailed to admin every Sunday midnight UTC."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.marketing.models import MarketingPost

logger = logging.getLogger(__name__)


async def get_digest_data(db: AsyncSession) -> dict:
    """Gather weekly digest data for dashboard and email."""
    now = datetime.now(timezone.utc)
    week_start = now - timedelta(days=7)

    # Posts by platform
    platform_q = await db.execute(
        select(
            MarketingPost.platform,
            func.count(MarketingPost.id).label("count"),
        ).where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= week_start,
        ).group_by(MarketingPost.platform),
    )
    platforms = [
        {"platform": row.platform, "posts": row.count}
        for row in platform_q.all()
    ]

    # Cost by model
    cost_q = await db.execute(
        select(
            MarketingPost.llm_model,
            func.count(MarketingPost.id).label("calls"),
            func.coalesce(
                func.sum(MarketingPost.llm_tokens_in + MarketingPost.llm_tokens_out),
                0,
            ).label("tokens"),
            func.coalesce(func.sum(MarketingPost.llm_cost_usd), 0.0).label("cost"),
        ).where(
            MarketingPost.llm_model.isnot(None),
            MarketingPost.created_at >= week_start,
        ).group_by(MarketingPost.llm_model),
    )
    cost_breakdown = [
        {
            "model": row.llm_model,
            "calls": row.calls,
            "tokens": row.tokens,
            "cost_usd": round(float(row.cost), 4),
        }
        for row in cost_q.all()
    ]

    total_cost = sum(c["cost_usd"] for c in cost_breakdown)

    # Top performing posts
    top_q = await db.execute(
        select(MarketingPost).where(
            MarketingPost.status == "posted",
            MarketingPost.posted_at >= week_start,
            MarketingPost.metrics_json.isnot(None),
        ).order_by(MarketingPost.posted_at.desc()).limit(5),
    )
    top_posts = []
    for post in top_q.scalars().all():
        m = post.metrics_json or {}
        engagement = m.get("likes", 0) + m.get("comments", 0) + m.get("shares", 0)
        top_posts.append({
            "platform": post.platform,
            "content": post.content[:120],
            "engagement": engagement,
            "likes": m.get("likes", 0),
            "comments": m.get("comments", 0),
            "shares": m.get("shares", 0),
        })

    total_posts = sum(p["posts"] for p in platforms)

    # Failure summary for the week
    from src.marketing.alerts import get_failure_summary

    failures = await get_failure_summary(db, hours=7 * 24)

    # Reddit scout — cached data only (no live HTTP requests to Reddit).
    # The news-digest on the Windows server handles Reddit scanning and
    # pushes results to Redis.
    reddit_threads: list[dict] = []
    try:
        from src.marketing.reddit_scout import get_cached_threads

        threads = await get_cached_threads()
        reddit_threads = [t.to_dict() for t in threads[:15]]
    except Exception:
        logger.debug("Reddit scout cache read failed", exc_info=True)

    return {
        "week_start": week_start.strftime("%B %d, %Y"),
        "week_end": now.strftime("%B %d, %Y"),
        "platforms": platforms,
        "total_posts": total_posts,
        "cost_breakdown": cost_breakdown,
        "total_cost_usd": round(total_cost, 4),
        "top_posts": top_posts,
        "failures": failures,
        "reddit_threads": reddit_threads,
    }


async def generate_weekly_digest(db: AsyncSession) -> dict:
    """Generate digest data (used by dashboard API)."""
    return await get_digest_data(db)


async def send_weekly_digest_email(db: AsyncSession) -> bool:
    """Generate and email the weekly digest to admin.

    Called by the scheduler every Sunday midnight UTC.
    Returns True if email was sent successfully.
    """
    from src.email import send_email
    from src.models import Entity

    data = await get_digest_data(db)

    # Find admin
    result = await db.execute(
        select(Entity).where(
            Entity.email == settings.admin_email,
            Entity.is_active.is_(True),
        ).limit(1),
    )
    admin = result.scalar_one_or_none()
    if not admin:
        logger.warning("No admin entity found for weekly digest email")
        return False

    html = _render_digest_email(data)
    subject = (
        f"AgentAvow Marketing Digest — "
        f"Week of {data['week_start']}"
    )

    sent = await send_email(admin.email, subject, html)
    if sent:
        logger.info("Weekly digest email sent to %s", admin.email)
    else:
        logger.error("Failed to send weekly digest email")
    return sent


def _render_digest_email(data: dict) -> str:
    """Render the weekly digest as an HTML email."""
    from src.email import _load_template

    # Platform rows
    platform_rows = ""
    for p in data["platforms"]:
        platform_rows += (
            "<tr>"
            "<td style='padding:8px 12px;"
            "border-bottom:1px solid #e2e8f0;color:#1e293b;'>"
            f"{p['platform']}</td>"
            "<td style='padding:8px 12px;"
            "border-bottom:1px solid #e2e8f0;"
            f"text-align:center;color:#1e293b;'>{p['posts']}</td>"
            "</tr>"
        )
    if not platform_rows:
        platform_rows = (
            "<tr><td colspan='2' style='padding:8px 12px;"
            "color:#64748b;'>No posts this week</td></tr>"
        )

    # Cost rows
    cost_rows = ""
    for c in data["cost_breakdown"]:
        cost_rows += (
            "<tr>"
            "<td style='padding:8px 12px;"
            "border-bottom:1px solid #e2e8f0;color:#1e293b;'>"
            f"{c['model']}</td>"
            "<td style='padding:8px 12px;"
            "border-bottom:1px solid #e2e8f0;"
            f"text-align:center;color:#1e293b;'>{c['calls']}</td>"
            "<td style='padding:8px 12px;"
            "border-bottom:1px solid #e2e8f0;"
            f"text-align:right;color:#1e293b;'>${c['cost_usd']:.4f}</td>"
            "</tr>"
        )
    if not cost_rows:
        cost_rows = (
            "<tr><td colspan='3' style='padding:8px 12px;"
            "color:#64748b;'>No LLM usage this week</td></tr>"
        )

    # Top posts
    top_posts_html = ""
    for tp in data["top_posts"]:
        top_posts_html += (
            "<div style='padding:12px;background:#f1f5f9;"
            "border-radius:8px;margin-bottom:8px;"
            "border:1px solid #e2e8f0;'>"
            "<div style='color:#6366f1;font-size:12px;"
            f"margin-bottom:4px;font-weight:600;'>{tp['platform']}</div>"
            "<div style='color:#1e293b;font-size:14px;'>"
            f"{tp['content']}</div>"
            "<div style='color:#64748b;font-size:12px;"
            f"margin-top:6px;'>{tp['engagement']} engagements "
            f"({tp['likes']} likes, {tp['comments']} comments, "
            f"{tp['shares']} shares)</div>"
            "</div>"
        )
    if not top_posts_html:
        top_posts_html = (
            "<p style='color:#64748b;'>"
            "No posts with metrics this week</p>"
        )

    # Failures section
    failures = data.get("failures", {})
    failures_section = ""
    total_failures = (
        failures.get("total_failed", 0)
        + failures.get("total_permanently_failed", 0)
    )
    if total_failures > 0:
        failure_rows = ""
        for platform, counts in failures.get(
            "by_platform", {},
        ).items():
            failed = counts.get("failed", 0)
            perm = counts.get("permanently_failed", 0)
            failure_rows += (
                "<tr>"
                "<td style='padding:8px 12px;"
                "border-bottom:1px solid #e2e8f0;"
                f"color:#1e293b;'>{platform}</td>"
                "<td style='padding:8px 12px;"
                "border-bottom:1px solid #e2e8f0;"
                f"text-align:center;color:#dc2626;'>{failed}</td>"
                "<td style='padding:8px 12px;"
                "border-bottom:1px solid #e2e8f0;"
                f"text-align:center;color:#b91c1c;'>{perm}</td>"
                "</tr>"
            )

        recent_error_html = ""
        for err in failures.get("recent_errors", [])[:5]:
            recent_error_html += (
                "<div style='padding:6px 10px;"
                "background:#fef2f2;border-radius:4px;"
                "margin-bottom:4px;font-size:12px;"
                "border:1px solid #fecaca;'>"
                "<span style='color:#6366f1;font-weight:600;'>"
                f"{err['platform']}</span>"
                "<span style='color:#64748b;'> — </span>"
                "<span style='color:#dc2626;'>"
                f"{err['error']}</span>"
                "</div>"
            )

        failures_section = (
            "<tr><td style='padding-bottom:24px;'>"
            "<h2 style='color:#dc2626;font-size:16px;"
            "margin:0 0 12px;'>"
            f"Failures ({total_failures})</h2>"
            "<table width='100%' cellpadding='0' "
            "cellspacing='0' "
            "style='background:#f8fafc;"
            "border-radius:8px;border:1px solid #e2e8f0;'>"
            "<tr>"
            "<th style='padding:8px 12px;text-align:left;"
            "color:#64748b;font-size:12px;"
            "border-bottom:1px solid #e2e8f0;'>Platform</th>"
            "<th style='padding:8px 12px;text-align:center;"
            "color:#64748b;font-size:12px;"
            "border-bottom:1px solid #e2e8f0;'>Failed</th>"
            "<th style='padding:8px 12px;text-align:center;"
            "color:#64748b;font-size:12px;"
            "border-bottom:1px solid #e2e8f0;'>Permanent</th>"
            "</tr>"
            f"{failure_rows}"
            "</table>"
            f"{recent_error_html}"
            "</td></tr>"
        )

    # Reddit threads section
    reddit_threads = data.get("reddit_threads", [])
    reddit_section = ""
    if reddit_threads:
        thread_cards = ""
        for t in reddit_threads:
            kw_tags = ", ".join(t.get("keywords_matched", [])[:3])
            preview = (t.get("selftext_preview", "") or "")[:120]
            if len(t.get("selftext_preview", "") or "") > 120:
                preview += "..."
            thread_cards += (
                "<div style='padding:12px;background:#f1f5f9;"
                "border-radius:8px;margin-bottom:8px;"
                "border:1px solid #e2e8f0;'>"
                "<div style='color:#6366f1;font-size:12px;"
                f"margin-bottom:4px;font-weight:600;'>r/{t['subreddit']} "
                f"&middot; {t['score']} pts "
                f"&middot; {t['num_comments']} comments</div>"
                "<a href='" + t["url"] + "' style='color:#1e293b;"
                "font-size:14px;text-decoration:none;'>"
                f"{t['title']}</a>"
            )
            if preview:
                thread_cards += (
                    "<div style='color:#64748b;font-size:12px;"
                    f"margin-top:4px;'>{preview}</div>"
                )
            if kw_tags:
                thread_cards += (
                    "<div style='color:#6366f1;font-size:11px;"
                    f"margin-top:4px;'>Keywords: {kw_tags}</div>"
                )
            thread_cards += "</div>"

        reddit_section = (
            "<tr><td style='padding-bottom:24px;'>"
            "<h2 style='color:#1e293b;font-size:16px;"
            "margin:0 0 12px;'>"
            f"Reddit Scout ({len(reddit_threads)} threads)</h2>"
            "<p style='color:#64748b;font-size:13px;"
            "margin:0 0 12px;'>Relevant threads discovered "
            "across AI/agent subreddits this week:</p>"
            f"{thread_cards}"
            "</td></tr>"
        )

    return _load_template(
        "marketing_digest.html",
        week_start=data["week_start"],
        week_end=data["week_end"],
        total_posts=str(data["total_posts"]),
        total_cost=f"${data['total_cost_usd']:.2f}",
        fallback=(
            f"Marketing Digest: {data['total_posts']} posts, "
            f"${data['total_cost_usd']:.2f} spend"
        ),
        _raw={
            "platform_rows": platform_rows,
            "cost_rows": cost_rows,
            "top_posts": top_posts_html,
            "failures_section": failures_section,
            "reddit_section": reddit_section,
        },
    )
