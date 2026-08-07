"""Weekly marketing plan reminder email.

Sends a reminder email to the admin on Sundays prompting them to
review and approve the upcoming week's marketing plan.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)

_DASHBOARD_URL = "https://agentavow.com/admin"


def _is_sunday() -> bool:
    """Return True if today is Sunday (UTC weekday == 6)."""
    return datetime.now(timezone.utc).weekday() == 6


async def send_plan_reminder(db: AsyncSession) -> bool:
    """Send a weekly marketing plan reminder email to the admin.

    Returns True if the email was sent, False otherwise.
    Only sends on Sunday (UTC).  Uses a Redis key to guard against
    duplicate sends within the same day.
    """
    if not _is_sunday():
        logger.debug("Not Sunday, skipping plan reminder")
        return False

    # Guard against duplicate sends via Redis
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sent_key = f"ag:mktg:plan_reminder:{today_str}"

    try:
        from src.redis_client import get_redis

        r = get_redis()
        already_sent = await r.get(sent_key)
        if already_sent:
            logger.debug("Plan reminder already sent today")
            return False
    except Exception:
        # If Redis is down, proceed (better to double-send than miss)
        pass

    # Render the email template
    from src.email import _load_template, send_email

    today_date = datetime.now(timezone.utc).strftime("%A, %B %d, %Y")
    html = _load_template(
        "marketing_plan_reminder.html",
        today_date=today_date,
        dashboard_url=_DASHBOARD_URL,
        fallback=(
            "Time to review and approve this week's marketing plan. "
            f"Visit {_DASHBOARD_URL}"
        ),
    )

    sent = await send_email(
        marketing_settings.marketing_notify_email,
        "AgentAvow \u2014 Weekly marketing plan",
        html,
    )

    if sent:
        logger.info("Plan reminder email sent to %s", marketing_settings.marketing_notify_email)
        # Mark as sent for today
        try:
            from src.redis_client import get_redis

            r = get_redis()
            await r.set(sent_key, "1", ex=86400)
        except Exception:
            pass
    else:
        logger.warning("Failed to send plan reminder email")

    return sent
