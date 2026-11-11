"""Raw IPs on analytics events are cleared once a row is 30 days old (privacy policy,
section 5). Rows from before t30 hold the raw IP; newer rows store only a hash."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from src.api.legal_router import _PRIVACY_CLAUSES
from src.jobs.analytics_ip_expiry import RAW_IP_RETENTION_DAYS, expire_raw_analytics_ips
from src.models import AnalyticsEvent


async def test_clears_raw_ip_only_on_rows_older_than_30_days(db):
    now = datetime.now(timezone.utc)
    old = AnalyticsEvent(event_type="lp_view", session_id="s-old", page="/",
                         ip_address="198.51.100.7", created_at=now - timedelta(days=31))
    edge = AnalyticsEvent(event_type="lp_view", session_id="s-edge", page="/",
                          ip_address="198.51.100.8", created_at=now - timedelta(days=29))
    new = AnalyticsEvent(event_type="lp_view", session_id="s-new", page="/",
                         ip_address="198.51.100.9", created_at=now)
    db.add_all([old, edge, new])
    await db.flush()

    assert await expire_raw_analytics_ips(db, now) == 1
    rows = {r.session_id: r for r in (await db.execute(
        select(AnalyticsEvent).where(AnalyticsEvent.session_id.in_(
            ["s-old", "s-edge", "s-new"])).execution_options(populate_existing=True)
    )).scalars()}
    # The event stays (funnel counts unchanged); only its IP goes.
    assert set(rows) == {"s-old", "s-edge", "s-new"}
    assert rows["s-old"].ip_address is None
    assert rows["s-edge"].ip_address == "198.51.100.8"
    assert rows["s-new"].ip_address == "198.51.100.9"

    # Idempotent: a second run the same day changes nothing.
    assert await expire_raw_analytics_ips(db, now) == 0


def test_policy_states_the_same_window():
    assert RAW_IP_RETENTION_DAYS == 30
    text = " ".join(b for _, b in _PRIVACY_CLAUSES)
    assert "deleted once the record is 30 days old" in text


def test_runs_from_the_daily_cleanup_job():
    import inspect

    from src.jobs import scheduler

    assert "expire_raw_analytics_ips(session, _now)" in inspect.getsource(
        scheduler._scheduler_loop)
