"""Expire raw client IPs on old first-party analytics events.

Since t30 (2026-11-11) analytics events store a daily-salted hash of the IP
(``analytics_events.ip_hash``) and leave ``ip_address`` empty. Rows written before
that still hold the raw IP. The privacy policy promises those are deleted once a row
is 30 days old; this job keeps that promise. It runs once a day from the scheduler's
expired-token cleanup (Job 13 in ``src/jobs/scheduler.py``).

Only the IP is cleared: the event itself stays, so funnel counts do not change.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import AnalyticsEvent

RAW_IP_RETENTION_DAYS = 30


async def expire_raw_analytics_ips(
    session: AsyncSession, now: datetime | None = None,
) -> int:
    """Set ``ip_address`` to NULL on analytics events older than 30 days.

    Returns the number of rows changed. The caller owns the transaction."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RAW_IP_RETENTION_DAYS)
    result = await session.execute(
        update(AnalyticsEvent)
        .where(AnalyticsEvent.ip_address.isnot(None), AnalyticsEvent.created_at < cutoff)
        .values(ip_address=None)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount or 0
