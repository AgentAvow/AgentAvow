"""Send email notification when marketing drafts need approval.

Fires after the proactive cycle generates human-review drafts for
platforms like Dev.to, LinkedIn, Hashnode, and Reddit.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


async def notify_pending_drafts(drafts: list[dict]) -> bool:
    """Send an email listing new drafts that need human review.

    Args:
        drafts: List of dicts with keys: platform, topic

    Returns True if the email was sent.
    """
    if not drafts:
        return False

    # Guard: don't send more than once per 6 hours
    try:
        from src.redis_client import get_redis

        r = get_redis()
        key = "ag:mktg:draft_notify"
        already = await r.get(key)
        if already:
            logger.debug("Draft notification already sent recently")
            return False
    except Exception:
        pass

    from src.marketing.config import marketing_settings

    platforms = ", ".join(
        d.get("platform", "unknown").title() for d in drafts
    )
    topics = ", ".join(
        d.get("topic", "general") for d in drafts
    )
    today = datetime.now(timezone.utc).strftime("%A, %B %d")

    from src.email import _load_template, send_email

    html = _load_template(
        "marketing_draft_notify.html",
        today_date=today,
        platforms=platforms,
        topics=topics,
        draft_count=str(len(drafts)),
        dashboard_url="https://agentavow.com/admin",
        fallback=(
            f"{len(drafts)} marketing draft(s) need review: {platforms}. "
            "Visit https://agentavow.com/admin"
        ),
    )

    sent = await send_email(
        marketing_settings.marketing_notify_email,
        f"AgentAvow \u2014 {len(drafts)} draft(s) need approval",
        html,
    )

    if sent:
        logger.info("Draft approval notification sent (%d drafts)", len(drafts))
        try:
            from src.redis_client import get_redis

            r = get_redis()
            await r.set(key, "1", ex=21600)  # 6hr cooldown
        except Exception:
            pass

    return sent


async def notify_post_failure(
    platform: str, content_preview: str, error: str,
) -> bool:
    """Send an email when an approved marketing post fails to publish.

    Has a 1-hour per-platform cooldown via Redis to avoid spamming.

    Returns True if the email was sent.
    """
    # Cooldown: 1 hour per platform
    cooldown_key = f"ag:mktg:fail_notify:{platform}"
    try:
        from src.redis_client import get_redis

        r = get_redis()
        already = await r.get(cooldown_key)
        if already:
            logger.debug(
                "Post-failure notification for %s already sent recently",
                platform,
            )
            return False
    except Exception:
        pass

    from src.email import _load_template, send_email
    from src.marketing.config import marketing_settings

    preview = content_preview[:200]
    html = _load_template(
        "marketing_post_failure.html",
        platform=platform.title(),
        content_preview=preview,
        error=error,
        dashboard_url="https://agentavow.com/admin",
        fallback=(
            f"Marketing post failed on {platform.title()}: {error}. "
            f"Content: {preview}. Visit https://agentavow.com/admin"
        ),
    )

    sent = await send_email(
        marketing_settings.marketing_notify_email,
        f"AgentAvow \u2014 Post failed on {platform.title()}",
        html,
    )

    if sent:
        logger.info("Post-failure notification sent for %s", platform)
        try:
            from src.redis_client import get_redis

            r = get_redis()
            await r.set(cooldown_key, "1", ex=3600)  # 1hr cooldown
        except Exception:
            pass

    return sent
