"""Production-ready scheduler for periodic jobs.

Runs multiple jobs on the same interval (default 6 hours):
1. Trust recomputation — recalculate all trust scores with attestation decay
2. Provisional agent expiry — deactivate expired provisional agents and revoke keys
3. External reputation sync (linked accounts)
4. Bot scheduled posts — official platform bots post content on a cycle
5. Token blacklist cleanup (expired entries)
6. Source import verification sync
7. Marketing bot orchestrator (after 18:00 UTC)
8. Weekly marketing digest email (Sunday)
9. [REMOVED] Moltbook auto-import — synthetic data removed March 2026
10. Marketing metrics refresh
11. Marketing watchdog checks
12. Marketing recap to feed (Monday + Thursday)
13. Expired token cleanup — email verifications + password reset tokens (daily)
14. Reply Guy monitor — check reply targets for new posts
15. Reply Guy drafter — generate LLM reply drafts for new opportunities
16. Bluesky starter pack refresh — recreate starter pack every 30 days
17. Agent cleanup — hard-delete soft-deleted agents after grace period
18. Auto-follow — follow active Bluesky reply targets daily
19. Security re-scan — weekly re-scan of agents with GitHub source URLs
20. API health check — ping registered API endpoints every 15 minutes

Started via a startup hook in ``src/main.py`` when the ``ENABLE_SCHEDULER``
config flag is set.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

# Default interval: 6 hours (in seconds)
SCHEDULER_INTERVAL = 6 * 60 * 60

_scheduler_task: asyncio.Task | None = None
_reply_monitor_task: asyncio.Task | None = None
_reply_drafter_task: asyncio.Task | None = None
_starter_pack_task: asyncio.Task | None = None
_reply_poster_task: asyncio.Task | None = None
_auto_follow_task: asyncio.Task | None = None
_security_scan_task: asyncio.Task | None = None
_api_health_task: asyncio.Task | None = None
_github_budget_task: asyncio.Task | None = None
_lock_refresh_task: asyncio.Task | None = None

# Redis distributed lock — prevents multiple workers from running the scheduler
SCHEDULER_LOCK_KEY = "ag:scheduler:lock"
SCHEDULER_LOCK_TTL = 60  # seconds — auto-expires if worker dies
SCHEDULER_LOCK_REFRESH = 45  # refresh interval (must be < TTL)

# Reply Guy intervals (in seconds)
REPLY_MONITOR_INTERVAL = 15 * 60   # 15 minutes
REPLY_DRAFTER_INTERVAL = 30 * 60   # 30 minutes
REPLY_POSTER_INTERVAL = 10 * 60    # 10 minutes

# Bluesky starter pack refresh interval (30 days in seconds)
STARTER_PACK_INTERVAL = 30 * 24 * 60 * 60

# Auto-follow interval (24 hours)
AUTO_FOLLOW_INTERVAL = 24 * 60 * 60

# Weekly marketing sync (runs every 6 hours, but only generates on Fridays)
MARKETING_SYNC_INTERVAL = 6 * 60 * 60


async def _marketing_sync_loop(interval: int = MARKETING_SYNC_INTERVAL) -> None:
    """Job 22: Weekly marketing digest — generates Fridays, consumed by content engine."""
    logger.info("Marketing sync started (interval=%ds, runs Saturdays)", interval)
    while True:
        try:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            # Only generate on Saturdays (weekday 5), afternoon UTC (covers US afternoon)
            if now.weekday() == 5 and now.hour >= 18:
                from src.jobs.weekly_marketing_sync import generate_weekly_digest
                digest = await generate_weekly_digest()
                logger.info(
                    "Weekly marketing digest generated: %d commits, %d scan repos",
                    digest.get("key_metrics", {}).get("commits_this_week", 0),
                    digest.get("scan_stats", {}).get("repos_scanned", 0),
                )
        except Exception:
            logger.exception("Marketing sync failed")
        await asyncio.sleep(interval)


async def _scheduler_loop(interval: int = SCHEDULER_INTERVAL) -> None:
    """Periodically run all scheduled jobs in the background."""
    from src.database import async_session

    logger.info(
        "Background scheduler started (interval=%ds)", interval,
    )

    while True:
        # Job 1: Trust recomputation
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.jobs.trust_recompute import run_trust_recompute

                    summary = await run_trust_recompute(session)
                    logger.info(
                        "Scheduled trust recompute completed: %s", summary,
                    )
        except Exception:
            logger.exception("Scheduled trust recompute failed")

        # Job 2: Provisional agent expiry
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.jobs.expire_provisional import (
                        expire_provisional_agents,
                    )

                    summary = await expire_provisional_agents(session)
                    if summary["expired_count"] > 0:
                        logger.info(
                            "Scheduled provisional expiry completed: %s",
                            summary,
                        )
                    else:
                        logger.debug("Provisional expiry: nothing to expire")
        except Exception:
            logger.exception("Scheduled provisional expiry failed")

        # Job 3: External reputation sync (linked accounts)
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.jobs.sync_linked_accounts import sync_stale_linked_accounts

                    summary = await sync_stale_linked_accounts(session)
                    if summary["synced"] > 0:
                        logger.info(
                            "Scheduled linked account sync completed: %s",
                            summary,
                        )
                    else:
                        logger.debug("Linked account sync: nothing to sync")
        except Exception:
            logger.exception("Scheduled linked account sync failed")

        # Job 4: Bot scheduled posts
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.bots.engine import run_scheduled_posts

                    summary = await run_scheduled_posts(session)
                    if summary["posted"]:
                        logger.info(
                            "Scheduled bot posts completed: %s", summary,
                        )
        except Exception:
            logger.exception("Scheduled bot posts failed")

        # Job 5: Token blacklist cleanup (expired entries)
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.api.auth_service import cleanup_expired_blacklist

                    removed = await cleanup_expired_blacklist(session)
                    if removed > 0:
                        logger.info(
                            "Token blacklist cleanup: removed %d expired entries",
                            removed,
                        )
                    else:
                        logger.debug("Token blacklist cleanup: nothing to remove")
        except Exception:
            logger.exception("Token blacklist cleanup failed")

        # Job 6: Source import verification sync
        try:
            async with async_session() as session:
                async with session.begin():
                    from src.jobs.sync_source_imports import sync_stale_source_imports

                    summary = await sync_stale_source_imports(session)
                    if summary["synced"] > 0:
                        logger.info(
                            "Scheduled source import sync completed: %s",
                            summary,
                        )
                    else:
                        logger.debug("Source import sync: nothing to sync")
        except Exception:
            logger.exception("Scheduled source import sync failed")

        # Job 7: Marketing bot orchestrator
        # Runs every scheduler tick. Individual tasks (reddit reminder,
        # digest email, etc.) have their own daily dedup via Redis keys.
        try:
            from src.config import settings as _settings

            if _settings.marketing_enabled:
                async with async_session() as session:
                    async with session.begin():
                        from src.marketing.orchestrator import run_marketing_tick

                        summary = await run_marketing_tick(session)
                        if summary.get("status") != "disabled":
                            logger.info(
                                "Marketing tick completed: %s", summary,
                            )
        except Exception:
            logger.exception("Marketing tick failed")

        # Job 8: Weekly marketing digest email (Sunday midnight UTC)
        try:
            from datetime import datetime, timezone

            now_utc = datetime.now(timezone.utc)
            if now_utc.weekday() == 6:  # Sunday
                from src.config import settings as _digest_settings

                if _digest_settings.marketing_enabled:
                    # Only send once per Sunday (check Redis flag)
                    _digest_sent = False
                    try:
                        from src.redis_client import get_redis as _get_redis

                        _r = _get_redis()
                        _digest_key = f"ag:mktg:digest_sent:{now_utc.strftime('%Y-%m-%d')}"
                        _digest_sent = bool(await _r.get(_digest_key))
                        if not _digest_sent:
                            await _r.set(_digest_key, "1", ex=86400 * 2)
                    except Exception:
                        logger.warning(
                            "Redis unavailable for digest tracking, skipping",
                            exc_info=True,
                        )

                    if not _digest_sent:
                        async with async_session() as session:
                            from src.marketing.digest import send_weekly_digest_email

                            sent = await send_weekly_digest_email(session)
                            if sent:
                                logger.info("Weekly marketing digest email sent")
                            else:
                                logger.warning("Weekly marketing digest email failed")
        except Exception:
            logger.exception("Weekly digest email job failed")

        # Job 10: Marketing metrics refresh
        try:
            from src.config import settings as _metrics_settings

            if _metrics_settings.marketing_enabled:
                async with async_session() as session:
                    async with session.begin():
                        from src.marketing.metrics import (
                            refresh_metrics,
                        )

                        summary = await refresh_metrics(session)
                        if summary.get("updated", 0) > 0:
                            logger.info(
                                "Marketing metrics refresh: %s",
                                summary,
                            )
                        else:
                            logger.debug(
                                "Marketing metrics: nothing to update",
                            )
        except Exception:
            logger.exception("Marketing metrics refresh failed")

        # Job 11: Marketing watchdog checks (auth, zero-post, staleness)
        try:
            from src.config import settings as _watchdog_settings

            if _watchdog_settings.marketing_enabled:
                async with async_session() as session:
                    async with session.begin():
                        from src.marketing.alerts import (
                            run_watchdog_checks,
                        )

                        wd_results = await run_watchdog_checks(
                            session,
                        )
                        logger.debug(
                            "Marketing watchdog: %s", wd_results,
                        )
        except Exception:
            logger.exception("Marketing watchdog checks failed")

        # Job 12: Marketing recap to feed (Monday + Thursday)
        try:
            from src.config import settings as _recap_settings

            if _recap_settings.marketing_enabled:
                async with async_session() as session:
                    async with session.begin():
                        from src.marketing.recap import maybe_post_recap

                        recap_result = await maybe_post_recap(session)
                        if recap_result.get("status") == "posted":
                            logger.info(
                                "Marketing recap posted: %s",
                                recap_result,
                            )
                        else:
                            logger.debug(
                                "Marketing recap: %s",
                                recap_result.get("status", "skipped"),
                            )
        except Exception:
            logger.exception("Marketing recap job failed")

        # Job 13: Expired token cleanup — email verifications + password reset tokens (daily)
        try:
            from datetime import datetime, timedelta, timezone

            from sqlalchemy import text

            _now = datetime.now(timezone.utc)
            # Run once per day — use Redis flag to avoid re-running each tick
            _cleanup_ran = False
            try:
                from src.redis_client import get_redis as _get_redis_cleanup

                _rc = _get_redis_cleanup()
                _cleanup_key = f"ag:jobs:token_cleanup:{_now.strftime('%Y-%m-%d')}"
                _cleanup_ran = bool(await _rc.get(_cleanup_key))
                if not _cleanup_ran:
                    await _rc.set(_cleanup_key, "1", ex=86400 * 2)
            except Exception:
                logger.warning(
                    "Redis unavailable for token cleanup tracking, skipping",
                    exc_info=True,
                )

            if not _cleanup_ran:
                _cutoff = _now - timedelta(days=30)

                async with async_session() as session:
                    async with session.begin():
                        # 1. Remove used email verifications older than 30 days
                        r1 = await session.execute(
                            text(
                                "DELETE FROM email_verifications "
                                "WHERE is_used = true AND created_at < :cutoff"
                            ),
                            {"cutoff": _cutoff},
                        )
                        # 2. Remove expired email verifications
                        r2 = await session.execute(
                            text(
                                "DELETE FROM email_verifications "
                                "WHERE expires_at < :now"
                            ),
                            {"now": _now},
                        )
                        # 3. Remove password reset tokens older than 30 days
                        r3 = await session.execute(
                            text(
                                "DELETE FROM password_reset_tokens "
                                "WHERE created_at < :cutoff"
                            ),
                            {"cutoff": _cutoff},
                        )
                        ev_total = r1.rowcount + r2.rowcount
                        prt_total = r3.rowcount
                        total = ev_total + prt_total
                        if total > 0:
                            logger.info(
                                "Token cleanup: removed %d email verifications, "
                                "%d password reset tokens",
                                ev_total,
                                prt_total,
                            )
                        else:
                            logger.debug("Token cleanup: nothing to remove")
        except Exception:
            logger.exception("Token cleanup failed")

        # Job 17: Hard-delete soft-deleted agents (daily)
        # Agents are soft-deleted (is_active=false) on user request;
        # this job does the actual CASCADE delete off the hot path.
        try:
            from datetime import datetime, timedelta, timezone

            from sqlalchemy import text

            _now_del = datetime.now(timezone.utc)
            _del_ran = False
            try:
                from src.redis_client import get_redis as _get_redis_del

                _rc_del = _get_redis_del()
                _del_key = f"ag:jobs:agent_cleanup:{_now_del.strftime('%Y-%m-%d')}"
                _del_ran = bool(await _rc_del.get(_del_key))
                if not _del_ran:
                    await _rc_del.set(_del_key, "1", ex=86400 * 2)
            except Exception:
                pass

            if not _del_ran:
                # Delete agents inactive for at least 5 minutes (grace period)
                _del_cutoff = _now_del - timedelta(minutes=5)
                async with async_session() as session:
                    async with session.begin():
                        r = await session.execute(
                            text(
                                "DELETE FROM entities "
                                "WHERE type = 'AGENT' "
                                "AND is_active = false "
                                "AND updated_at < :cutoff"
                            ),
                            {"cutoff": _del_cutoff},
                        )
                        if r.rowcount > 0:
                            logger.info(
                                "Agent cleanup: hard-deleted %d inactive agents",
                                r.rowcount,
                            )
                        else:
                            logger.debug("Agent cleanup: nothing to remove")
        except Exception:
            logger.exception("Agent cleanup failed")

        # Job 9: [REMOVED] Moltbook auto-import — synthetic data removed March 2026

        # Job 10: [DISABLED] GitHub issue outreach — killed March 2026.
        # Issue-based outreach was perceived as spam by maintainers.
        # Discovery code kept in src/recruitment/ for potential future
        # reuse with a different channel (email, discussions, etc.).

        await asyncio.sleep(interval)


async def _reply_monitor_loop(interval: int = REPLY_MONITOR_INTERVAL) -> None:
    """Job 14: Check reply targets for new posts on a fast loop."""
    logger.info("Reply guy monitor started (interval=%ds)", interval)
    while True:
        try:
            from src.config import settings as _rg_settings

            if _rg_settings.reply_guy_enabled:
                from src.marketing.reply_guy.monitor import monitor_all_targets

                stats = await monitor_all_targets()
                if stats.get("new_opportunities", 0) > 0:
                    logger.info("Reply guy monitor: %s", stats)
                else:
                    logger.debug("Reply guy monitor: %s", stats)
        except Exception:
            logger.exception("Reply guy monitor failed")
        await asyncio.sleep(interval)


async def _reply_drafter_loop(interval: int = REPLY_DRAFTER_INTERVAL) -> None:
    """Job 15: Generate LLM reply drafts for new opportunities on a fast loop."""
    logger.info("Reply guy drafter started (interval=%ds)", interval)
    while True:
        try:
            from src.config import settings as _rg_settings

            if _rg_settings.reply_guy_enabled:
                from src.marketing.reply_guy.drafter import generate_drafts

                stats = await generate_drafts(limit=20)
                if stats.get("drafted", 0) > 0:
                    logger.info("Reply guy drafter: %s", stats)
                else:
                    logger.debug("Reply guy drafter: %s", stats)
        except Exception:
            logger.exception("Reply guy drafter failed")
        await asyncio.sleep(interval)


async def _reply_poster_loop(interval: int = REPLY_POSTER_INTERVAL) -> None:
    """Job 21: Auto-post drafted replies (no manual approval needed)."""
    logger.info("Reply guy auto-poster started (interval=%ds)", interval)
    while True:
        try:
            from src.config import settings as _rg_settings

            if _rg_settings.reply_guy_enabled and _rg_settings.reply_guy_auto_post:
                from src.database import async_session

                async with async_session() as session:
                    from datetime import datetime, timezone

                    import sqlalchemy as sa

                    from src.models import ReplyOpportunity, ReplyTarget

                    # Fetch drafted replies, newest first, limit to 5 per cycle
                    result = await session.execute(
                        sa.select(ReplyOpportunity)
                        .where(ReplyOpportunity.status == "drafted")
                        .order_by(ReplyOpportunity.drafted_at.desc())
                        .limit(5)
                    )
                    opps = result.scalars().all()

                    if not opps:
                        logger.debug("Reply guy poster: no drafted replies")
                    else:
                        # Check daily limit
                        today_start = datetime.now(timezone.utc).replace(
                            hour=0, minute=0, second=0, microsecond=0,
                        )
                        posted_today_result = await session.execute(
                            sa.select(sa.func.count()).where(
                                ReplyOpportunity.status == "posted",
                                ReplyOpportunity.posted_at >= today_start,
                            )
                        )
                        posted_today = posted_today_result.scalar() or 0

                        remaining = _rg_settings.reply_guy_max_daily - posted_today

                        # Pacing: spread the daily batch instead of bursting at the
                        # 00:00 UTC reset. Only post inside the active UTC window, and
                        # only once enough time has passed since the last reply.
                        now = datetime.now(timezone.utc)
                        in_window = now.hour >= _rg_settings.reply_guy_active_start_hour_utc
                        last_posted = (
                            await session.execute(
                                sa.select(sa.func.max(ReplyOpportunity.posted_at))
                                .where(ReplyOpportunity.status == "posted")
                            )
                        ).scalar()
                        gap_ok = last_posted is None or (
                            now - last_posted
                        ).total_seconds() >= _rg_settings.reply_guy_min_gap_minutes * 60

                        if remaining <= 0:
                            logger.info(
                                "Reply guy poster: daily limit reached (%d/%d)",
                                posted_today, _rg_settings.reply_guy_max_daily,
                            )
                        elif not in_window:
                            logger.debug(
                                "Reply guy poster: outside active window (hour %d < %d UTC)",
                                now.hour, _rg_settings.reply_guy_active_start_hour_utc,
                            )
                        elif not gap_ok:
                            logger.debug(
                                "Reply guy poster: pacing — last reply too recent",
                            )
                        else:
                            posted = 0
                            # One per cycle → paced across the day, not a burst.
                            for opp in opps[:1]:
                                try:
                                    target_result = await session.execute(
                                        sa.select(ReplyTarget)
                                        .where(ReplyTarget.id == opp.target_id)
                                    )
                                    target = target_result.scalar_one_or_none()

                                    from src.api.reply_guy_router import _post_reply
                                    url = await _post_reply(opp, target)

                                    if url:
                                        opp.status = "posted"
                                        opp.posted_at = datetime.now(timezone.utc)
                                        opp.posted_url = url
                                        posted += 1
                                        logger.info(
                                            "Reply guy auto-posted: %s -> %s",
                                            opp.platform, url,
                                        )
                                    else:
                                        opp.status = "posting_error"
                                        logger.warning(
                                            "Reply guy post failed: %s %s",
                                            opp.platform, opp.post_uri,
                                        )
                                except Exception:
                                    opp.status = "posting_error"
                                    logger.exception(
                                        "Reply guy post error: %s", opp.post_uri,
                                    )

                            await session.commit()
                            if posted:
                                logger.info(
                                    "Reply guy poster: %d/%d posted",
                                    posted, len(opps),
                                )
        except Exception:
            logger.exception("Reply guy poster failed")
        await asyncio.sleep(interval)


async def _starter_pack_loop(interval: int = STARTER_PACK_INTERVAL) -> None:
    """Job 16: Refresh the Bluesky starter pack every 30 days."""
    import os

    try:
        from scripts.create_bluesky_starter_pack import CURATED_ACCOUNTS
        from scripts.create_bluesky_starter_pack import main as _sp_main
    except ImportError:
        logger.warning(
            "Starter pack script not available (scripts/ not in path), "
            "disabling Job 16",
        )
        return

    logger.info("Bluesky starter pack refresh started (interval=%ds)", interval)
    while True:
        try:
            from src.config import settings as _sp_settings

            if not _sp_settings.starter_pack_refresh_enabled:
                logger.debug("Starter pack refresh disabled, sleeping")
                await asyncio.sleep(interval)
                continue

            # Get Bluesky credentials from marketing config
            from src.marketing.config import marketing_settings

            handle = marketing_settings.bluesky_handle
            password = marketing_settings.bluesky_app_password
            if not handle or not password:
                logger.warning(
                    "Starter pack refresh skipped: BLUESKY_HANDLE or "
                    "BLUESKY_APP_PASSWORD not set in marketing config"
                )
                await asyncio.sleep(interval)
                continue

            # Inject credentials into env for the script's main()
            _prev_handle = os.environ.get("BLUESKY_HANDLE")
            _prev_password = os.environ.get("BLUESKY_PASSWORD")
            os.environ["BLUESKY_HANDLE"] = handle
            os.environ["BLUESKY_PASSWORD"] = password
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, _sp_main)
                logger.info(
                    "Bluesky starter pack refreshed (%d curated accounts)",
                    len(CURATED_ACCOUNTS),
                )
            finally:
                # Restore previous env state
                if _prev_handle is not None:
                    os.environ["BLUESKY_HANDLE"] = _prev_handle
                else:
                    os.environ.pop("BLUESKY_HANDLE", None)
                if _prev_password is not None:
                    os.environ["BLUESKY_PASSWORD"] = _prev_password
                else:
                    os.environ.pop("BLUESKY_PASSWORD", None)
        except Exception:
            logger.exception("Bluesky starter pack refresh failed")
        await asyncio.sleep(interval)


async def _auto_follow_loop(interval: int = AUTO_FOLLOW_INTERVAL) -> None:
    """Job 18: Auto-follow active Bluesky reply targets daily."""
    logger.info("Auto-follow task started (interval=%ds)", interval)
    while True:
        try:
            from src.marketing.auto_follow import run_auto_follow

            stats = await run_auto_follow()
            if stats.get("followed", 0) > 0:
                logger.info("Auto-follow: %s", stats)
            else:
                logger.debug("Auto-follow: %s", stats)
        except Exception:
            logger.exception("Auto-follow failed")
        await asyncio.sleep(interval)


API_HEALTH_CHECK_INTERVAL = 15 * 60  # 15 minutes

SECURITY_SCAN_INTERVAL = 86400  # 24 hours — checks weekly cutoff internally


async def _api_health_loop(interval: int = API_HEALTH_CHECK_INTERVAL) -> None:
    """Job 20: Ping registered API endpoints every 15 minutes."""
    logger.info("API health check task started (interval=%ds)", interval)
    while True:
        try:
            from src.database import async_session
            from src.jobs.api_health_check import run_health_checks

            async with async_session() as db:
                async with db.begin():
                    summary = await run_health_checks(db)
                    if summary.get("checked", 0) > 0:
                        logger.info("API health check: %s", summary)
                    else:
                        logger.debug("API health check: no endpoints registered")
        except Exception:
            logger.exception("API health check failed")
        await asyncio.sleep(interval)


async def _github_budget_loop() -> None:
    """Job 23: Periodic GitHub budget probe (every ~20 min, config-driven).

    Bridges the 24h gap of the daily re-scan probe: a free ``GET /rate_limit``
    call sets/clears the ``github_budget_low`` Redis flag the public scan path
    reads to decide whether to serve stale cache and defer fresh scans. Cheap
    (does not consume the GitHub core budget) and independent of user traffic,
    so the flag stays accurate even when nobody is scanning.
    """
    from src.config import settings as _budget_settings

    interval = _budget_settings.github_budget_probe_interval_seconds
    logger.info("GitHub budget probe started (interval=%ds)", interval)
    while True:
        try:
            from src.jobs.scan_health import check_github_budget

            health = await check_github_budget()
            if health.remaining is not None:
                logger.debug(
                    "GitHub budget probe: %d core requests remaining",
                    health.remaining,
                )
        except Exception:
            logger.exception("GitHub budget probe failed")
        await asyncio.sleep(interval)


async def _security_scan_loop(interval: int = SECURITY_SCAN_INTERVAL) -> None:
    """Job 19: Weekly security re-scan + public scan cache pre-refresh.

    Guarded by a GitHub token-health probe: a silently-expired PAT used to 401
    every repo and fail *quietly* (the old ``except`` just logged). Now a dead
    token or a raised re-scan both fire a throttled admin alert (once/6h), and a
    dead token short-circuits the run since nothing would scan. Caps come from
    config (``security_rescan_limit`` / ``public_cache_refresh_limit``).
    """
    logger.info("Security scan task started (interval=%ds)", interval)
    while True:
        try:
            from src.config import settings as _scan_settings
            from src.database import async_session
            from src.jobs.scan_health import check_and_alert_token
            from src.scanner.service import (
                refresh_public_scan_cache,
                rescan_all_agents,
            )

            # Token-health gate — probe GET /rate_limit first. On a dead token,
            # check_and_alert_token() has already e-mailed the admin (throttled);
            # skip the run because every repo fetch would 401.
            health = await check_and_alert_token()
            if health.dead:
                logger.error(
                    "Security re-scan skipped: GitHub token unusable (%s)",
                    health.reason,
                )
            else:
                # Part A: Re-scan agents past the staleness cutoff (config caps)
                async with async_session() as db:
                    scanned = await rescan_all_agents(
                        db, limit=_scan_settings.security_rescan_limit,
                    )
                if scanned > 0:
                    logger.info("Security re-scan: %d agents scanned", scanned)
                else:
                    logger.debug("Security re-scan: no agents due for scan")

                # Part B: Pre-refresh public scan cache for popular repos
                refreshed = await refresh_public_scan_cache(
                    limit=_scan_settings.public_cache_refresh_limit,
                )
                if refreshed > 0:
                    logger.info(
                        "Public scan cache: %d repos pre-refreshed", refreshed,
                    )
        except Exception as exc:
            # This is the failure that went unnoticed when the PAT expired —
            # alert the admin (throttled) instead of only logging.
            logger.exception("Security re-scan failed")
            try:
                from src.jobs.scan_health import alert_rescan_exception

                await alert_rescan_exception(exc)
            except Exception:
                logger.debug(
                    "Failed to send re-scan exception alert", exc_info=True,
                )
        await asyncio.sleep(interval)


async def _lock_refresh_loop() -> None:
    """Periodically refresh the Redis scheduler lock so it doesn't expire."""
    try:
        from src.redis_client import get_redis

        while True:
            await asyncio.sleep(SCHEDULER_LOCK_REFRESH)
            try:
                r = get_redis()
                await r.expire(SCHEDULER_LOCK_KEY, SCHEDULER_LOCK_TTL)
                logger.debug("Scheduler lock refreshed (TTL=%ds)", SCHEDULER_LOCK_TTL)
            except Exception:
                logger.warning("Failed to refresh scheduler lock", exc_info=True)
    except asyncio.CancelledError:
        # Release the lock on shutdown so another worker can take over immediately
        try:
            from src.redis_client import get_redis

            r = get_redis()
            await r.delete(SCHEDULER_LOCK_KEY)
            logger.info("Scheduler lock released on shutdown")
        except Exception:
            pass
        raise


# Watch re-scan: daily, re-scan watched tools and alert on grade/definition changes.
WATCH_RESCAN_INTERVAL = 24 * 60 * 60


async def _run_watch_rescan(limit: int = 200) -> None:
    from datetime import datetime, timezone

    from sqlalchemy import select

    from src.api.notification_router import create_notification
    from src.database import async_session
    from src.models import Entity, ToolWatch

    async with async_session() as db:
        watches = (
            await db.execute(select(ToolWatch).where(ToolWatch.active.is_(True)).limit(limit))
        ).scalars().all()

    for w in watches:
        async with async_session() as db:
            try:
                from src.api.watch_router import scan_watch_target
                new_score, new_digest = await scan_watch_target(
                    getattr(w, "surface", "github") or "github", w.owner, w.repo, db,
                )
            except Exception:
                continue
            if new_score is None:
                continue  # scan failed this cycle — retry next time, don't false-alert
            dropped = (
                w.last_score is not None and new_score is not None and new_score < w.last_score - 5
            )
            drift = bool(
                w.last_manifest_digest and new_digest and new_digest != w.last_manifest_digest
            )
            improved = (
                w.last_score is not None and new_score is not None
                and new_score > w.last_score + 5
            )
            if dropped or drift:
                reason = "grade dropped" if dropped else "signed definition changed"
                title = f"{w.owner}/{w.repo} — {reason}"
                body = (
                    f"A tool you're watching changed: {reason}"
                    + (f" ({w.last_score} -> {new_score})" if dropped else "")
                    + ". Review it before your agents keep using it."
                )
                try:
                    await create_notification(
                        db, w.watcher_id, "watch_alert", title, body,
                        reference_id=f"{w.owner}/{w.repo}",
                    )
                except Exception:
                    logger.exception("watch notification failed for %s/%s", w.owner, w.repo)
                try:
                    watcher = await db.get(Entity, w.watcher_id)
                    if watcher is not None and watcher.email:
                        from src.email import render_watch_notification, send_email

                        subj, html = render_watch_notification(
                            "drop" if dropped else "drift",
                            w.owner, w.repo, w.last_score, new_score,
                        )
                        await send_email(watcher.email, subj, html)
                except Exception:
                    pass
                # Webhook alert-delivery — POST to the watcher's configured URL.
                try:
                    from sqlalchemy import select as _select

                    from src.models import AlertWebhook

                    hook = (await db.execute(
                        _select(AlertWebhook).where(
                            AlertWebhook.entity_id == w.watcher_id,
                            AlertWebhook.active.is_(True),
                        )
                    )).scalar_one_or_none()
                    if hook is not None:
                        import httpx

                        async with httpx.AsyncClient(timeout=6) as client:
                            resp = await client.post(hook.url, json={
                                "type": "agentavow.alert.grade_change",
                                "owner": w.owner,
                                "repo": w.repo,
                                "old_score": w.last_score,
                                "new_score": new_score,
                                "reason": reason,
                            })
                        hook.last_status = resp.status_code
                        hook.last_delivery_at = datetime.now(timezone.utc)
                except Exception:
                    logger.debug("webhook alert delivery failed for %s/%s", w.owner, w.repo)
            elif improved:
                # Good news — a watched tool got safer. A lighter, positive nudge
                # (also a reason to bring the watcher back to the site).
                title = f"{w.owner}/{w.repo} — grade improved 🎉"
                body = (
                    f"Good news: a tool you're watching improved "
                    f"({w.last_score} → {new_score}/100). See what changed."
                )
                try:
                    await create_notification(
                        db, w.watcher_id, "watch_good_news", title, body,
                        reference_id=f"{w.owner}/{w.repo}",
                    )
                    watcher = await db.get(Entity, w.watcher_id)
                    if watcher is not None and watcher.email:
                        from src.email import render_watch_notification, send_email
                        subj, html = render_watch_notification(
                            "improve", w.owner, w.repo, w.last_score, new_score,
                        )
                        await send_email(watcher.email, subj, html)
                except Exception:
                    logger.debug("good-news notification failed for %s/%s", w.owner, w.repo)
            fresh = await db.get(ToolWatch, w.id)
            if fresh is not None:
                fresh.last_score = new_score
                fresh.last_manifest_digest = new_digest
                fresh.last_checked_at = datetime.now(timezone.utc)
                await db.commit()


async def _watch_rescan_loop(interval: int = WATCH_RESCAN_INTERVAL) -> None:
    logger.info("Watch re-scan loop started (interval=%ds)", interval)
    while True:
        try:
            await _run_watch_rescan()
        except Exception:
            logger.exception("Watch re-scan loop iteration failed")
        await asyncio.sleep(interval)


# GitHub App private-repo re-scan: daily, re-scan every connected (non-revoked)
# installation's repos and alert the owner on grade drops / definition drift.
APP_RESCAN_INTERVAL = 24 * 60 * 60


async def _run_app_rescan(limit: int = 100) -> None:
    """Re-scan every connected, non-revoked GitHub App installation's private
    repos. Own session per install, fail-open — one bad installation can't sink
    the rest."""
    from sqlalchemy import select

    from src.database import async_session
    from src.jobs.app_scan import scan_installation
    from src.models import GitHubAppInstallation

    async with async_session() as db:
        installs = (
            await db.execute(
                select(GitHubAppInstallation)
                .where(GitHubAppInstallation.revoked_at.is_(None))
                .limit(limit)
            )
        ).scalars().all()

    for inst in installs:
        async with async_session() as db:
            try:
                summary = await scan_installation(db, inst)
                await db.commit()
                if summary.get("scanned"):
                    logger.info("App re-scan: %s", summary)
            except Exception:
                logger.exception(
                    "App re-scan failed for installation %s", inst.installation_id
                )


async def _app_rescan_loop(interval: int = APP_RESCAN_INTERVAL) -> None:
    logger.info("App re-scan loop started (interval=%ds)", interval)
    while True:
        try:
            await _run_app_rescan()
        except Exception:
            logger.exception("App re-scan loop iteration failed")
        await asyncio.sleep(interval)


# Catalog re-scan + growth: keep the browse catalog fresh (re-scan the stalest
# community_scans rows) and grow it (backfill the launch-corpus error backlog into
# community_scans via the now-more-precise live scanners). Without this, only
# watched/claimed/registered tools get routine re-scans and the catalog goes stale.
_CATALOG_RESCAN_DEFAULT_INTERVAL = 6 * 60 * 60
_backfill_offset = 0          # progressive cursor over the backfill target list
_openclaw_backfill_cache: list | None = None
_curated_seed_cache: list | None = None


def _curated_seed_targets() -> list[tuple[str, str, str]]:
    """Curated, recognizable agent-ecosystem tools (data/curated-seed.json) — scanned
    into community_scans each cycle so the browse catalog LEADS with tools people
    actually use, not just the launch scrape. Returns [(surface, owner, repo), ...]."""
    global _curated_seed_cache
    if _curated_seed_cache is not None:
        return _curated_seed_cache
    import json
    from pathlib import Path

    out: list[tuple[str, str, str]] = []
    try:
        # Lives under launch-scans/ because that's the data subdir mounted into the
        # container (the rest of data/ is gitignored + not mounted).
        path = (
            Path(__file__).resolve().parents[2]
            / "data" / "launch-scans" / "curated-seed.json"
        )
        doc = json.loads(path.read_text())
        for name in doc.get("npm", []) or []:
            out.append(("npm", "npm", str(name)))
        for name in doc.get("pypi", []) or []:
            out.append(("pypi", "pypi", str(name)))
        for name in doc.get("crates", []) or []:
            out.append(("crates", "crates", str(name)))
        for name in doc.get("huggingface", []) or []:
            # HF coordinate is org/model — carried whole in `repo`.
            out.append(("huggingface", "huggingface", str(name)))
        for name in doc.get("docker", []) or []:
            # Image coordinate (namespace/name or library/name) carried whole in `repo`.
            out.append(("docker", "docker", str(name)))
        for url in doc.get("mcp", []) or []:
            out.append(("mcp", "mcp", str(url)))
        for pair in doc.get("openclaw", []) or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                out.append(("openclaw", str(pair[0]), str(pair[1])))
    except Exception:
        logger.debug("curated seed load failed", exc_info=True)
    _curated_seed_cache = out
    return out


def _openclaw_backfill_targets() -> list[tuple[str, str, str]]:
    """Coordinates for launch-corpus OpenClaw skills that errored / never graded —
    the biggest re-scan opportunity now that skill scanning is more precise. Cached;
    the file is static in the image. Returns [(surface, owner, repo), ...]."""
    global _openclaw_backfill_cache
    if _openclaw_backfill_cache is not None:
        return _openclaw_backfill_cache
    import json
    from pathlib import Path

    out: list[tuple[str, str, str]] = []
    try:
        path = (
            Path(__file__).resolve().parents[2]
            / "data" / "launch-scans" / "openclaw-results.json"
        )
        doc = json.loads(path.read_text())
        for e in (doc.get("repos") or []):
            if not isinstance(e, dict):
                continue
            # Only re-scan the ones that errored or never got a score.
            if e.get("trust_score") is not None and not e.get("error"):
                continue
            full = str(e.get("repo") or "")
            if "/" in full:
                owner, repo = full.split("/", 1)
                if owner and repo:
                    out.append(("openclaw", owner.strip(), repo.strip()))
    except Exception:
        logger.debug("openclaw backfill target load failed", exc_info=True)
    _openclaw_backfill_cache = out
    return out


async def _rescan_catalog_row(surface: str, owner: str, repo: str, db) -> bool:
    """Re-scan one catalog coordinate by surface and upsert the fresh grade into
    community_scans, then computes + persists adoption (the loop is where adoption is
    populated — kept off the live scan path to keep user scans fast). Fail-open."""
    surface = (surface or "github").lower()
    try:
        if surface == "github":
            from src.api.public_scan_router import public_scan
            # public_scan re-scans and captures into community_scans itself.
            await public_scan(owner=owner, repo=repo, force=True, db=db)
            await _store_catalog_adoption(surface, owner, repo, db)
            return True
        from src.api.public_scan_router import (
            _capture_community_scan,
            _scan_result_to_dict,
        )
        from src.scanner.scan import scan_mcp, scan_package, scan_skill

        if surface in ("npm", "pypi", "crates", "huggingface", "docker"):
            result = await scan_package(surface, repo)
        elif surface == "mcp":
            result = await scan_mcp(repo)
        elif surface == "openclaw":
            result = await scan_skill(owner, repo)
        else:
            return False
        if getattr(result, "error", None):
            return False
        data = _scan_result_to_dict(result)
        await _capture_community_scan(owner, repo, data, db, surface=surface)
        await _store_catalog_adoption(surface, owner, repo, db)
        return True
    except Exception:
        logger.debug("catalog re-scan failed for %s %s/%s", surface, owner, repo, exc_info=True)
        return False


async def _store_catalog_adoption(surface: str, owner: str, repo: str, db) -> None:
    """Compute adoption for a coordinate and persist it on its community_scans row so
    Browse can filter/sort by 'widely relied upon'. Best-effort; never blocks a scan."""
    try:
        from sqlalchemy import update

        from src.api.public_scan_router import surface_adoption_summary
        from src.models import CommunityScan

        score, count, unit = await surface_adoption_summary(surface, owner, repo)
        if score is None and count is None:
            return
        await db.execute(
            update(CommunityScan)
            .where(
                CommunityScan.surface == surface,
                CommunityScan.owner == owner,
                CommunityScan.repo == repo,
            )
            .values(adoption_score=score, adoption_count=count, adoption_unit=unit)
        )
        await db.commit()
    except Exception:
        logger.debug("adoption persist failed for %s %s/%s", surface, owner, repo, exc_info=True)


async def _run_catalog_rescan() -> None:
    global _backfill_offset
    from src.config import settings

    if not getattr(settings, "scheduler_catalog_rescan", True):
        return
    from sqlalchemy import select

    from src.database import async_session
    from src.models import CommunityScan

    spacing = getattr(settings, "catalog_rescan_spacing_seconds", 1.5)

    # GitHub budget gate: skip the GitHub-heavy work (repo/skill scans, backfill) when
    # the token is dead or the budget is low, so this never starves live user scans.
    # Registry surfaces (npm/pypi/mcp) don't touch GitHub, so they run regardless.
    gh_ok = True
    try:
        from src.jobs.scan_health import check_and_alert_token
        health = await check_and_alert_token()
        min_budget = getattr(settings, "security_rescan_min_budget", 300)
        gh_ok = not health.dead and (health.remaining is None or health.remaining >= min_budget)
    except Exception:
        gh_ok = True  # probe failure shouldn't block registry re-scans

    # (a) Freshness — re-scan the stalest community_scans rows (surface-aware) so
    # on-demand catalog grades stay current instead of frozen at first-scan time.
    fresh_n = getattr(settings, "catalog_rescan_fresh_limit", 60)
    async with async_session() as db:
        rows = (await db.execute(
            select(CommunityScan.surface, CommunityScan.owner, CommunityScan.repo)
            .order_by(CommunityScan.last_scanned_at.asc()).limit(fresh_n)
        )).all()
    refreshed = 0
    for surface, owner, repo in rows:
        surf = (surface or "github").lower()
        if surf in ("github", "openclaw") and not gh_ok:
            continue  # GitHub-backed; skip under low budget
        async with async_session() as db:
            if await _rescan_catalog_row(surf, owner, repo, db):
                refreshed += 1
        await asyncio.sleep(spacing)

    # (b) Growth — curated seed FIRST (recognizable flagships; keep them fresh every
    # cycle), then work through the OpenClaw launch-corpus error backlog by cursor.
    seeded = 0
    for surface, owner, repo in _curated_seed_targets():
        if surface in ("github", "openclaw") and not gh_ok:
            continue  # only the openclaw seed needs GitHub; npm/pypi/mcp don't
        async with async_session() as db:
            if await _rescan_catalog_row(surface, owner, repo, db):
                seeded += 1
        await asyncio.sleep(spacing)

    back_n = getattr(settings, "catalog_backfill_limit", 40)
    targets = _openclaw_backfill_targets()
    added = 0
    if targets and back_n > 0 and gh_ok:
        start = _backfill_offset % len(targets)
        batch = targets[start:start + back_n]
        for surface, owner, repo in batch:
            async with async_session() as db:
                if await _rescan_catalog_row(surface, owner, repo, db):
                    added += 1
            await asyncio.sleep(spacing)
        _backfill_offset = (start + back_n) % len(targets)

    if refreshed or seeded or added:
        logger.info(
            "Catalog re-scan: refreshed %d community rows, %d curated seed, "
            "%d launch-corpus backfill", refreshed, seeded, added,
        )


async def _catalog_rescan_loop(interval: int | None = None) -> None:
    from src.config import settings

    interval = interval or getattr(
        settings, "catalog_rescan_interval_sec", _CATALOG_RESCAN_DEFAULT_INTERVAL
    )
    logger.info("Catalog re-scan loop started (interval=%ds)", interval)
    # Delay the first run so it doesn't scan-storm (CPU/memory) during the post-deploy
    # cold-start window when live traffic is also warming up.
    await asyncio.sleep(getattr(settings, "catalog_rescan_startup_delay_sec", 300))
    while True:
        try:
            await _run_catalog_rescan()
        except Exception:
            logger.exception("Catalog re-scan loop iteration failed")
        await asyncio.sleep(interval)


async def start_scheduler(interval: int | None = None) -> asyncio.Task | None:
    """Start the background scheduler task.

    Uses a Redis distributed lock (SET NX) so only one uvicorn worker
    runs the scheduler, even when multiple workers are started.
    Returns the asyncio.Task, or None if another worker holds the lock.
    Safe to call multiple times -- subsequent calls are no-ops.
    """
    global _scheduler_task, _reply_monitor_task, _reply_drafter_task
    global _reply_poster_task
    global _starter_pack_task, _auto_follow_task, _security_scan_task
    global _api_health_task, _github_budget_task, _lock_refresh_task

    if _scheduler_task is not None and not _scheduler_task.done():
        logger.debug("Scheduler already running, skipping start")
        return _scheduler_task

    # Acquire distributed lock via Redis SET NX
    try:
        from src.redis_client import get_redis

        r = get_redis()
        acquired = await r.set(
            SCHEDULER_LOCK_KEY, "1", nx=True, ex=SCHEDULER_LOCK_TTL,
        )
        if not acquired:
            logger.info(
                "Scheduler lock held by another worker, skipping start"
            )
            return None
        logger.info("Scheduler lock acquired (TTL=%ds)", SCHEDULER_LOCK_TTL)
    except Exception:
        logger.warning(
            "Redis unavailable for scheduler lock — starting scheduler "
            "anyway (single-worker fallback)",
            exc_info=True,
        )

    # Start lock refresh task
    if _lock_refresh_task is None or _lock_refresh_task.done():
        _lock_refresh_task = asyncio.create_task(
            _lock_refresh_loop(), name="scheduler-lock-refresh",
        )

    effective_interval = interval or SCHEDULER_INTERVAL
    _scheduler_task = asyncio.create_task(
        _scheduler_loop(effective_interval),
        name="background-scheduler",
    )
    logger.info("Scheduler task created (interval=%ds)", effective_interval)

    # Reply Guy fast-loop tasks (gated by reply_guy_enabled inside each loop)
    from src.config import settings as _sched_settings

    # Job 20: API health check (15-minute loop)
    if _api_health_task is None or _api_health_task.done():
        _api_health_task = asyncio.create_task(
            _api_health_loop(),
            name="api-health-check",
        )
        logger.info(
            "API health check task created (interval=%ds)",
            API_HEALTH_CHECK_INTERVAL,
        )

    # Job 23: GitHub budget probe (short loop — keeps the degradation flag fresh)
    if _github_budget_task is None or _github_budget_task.done():
        _github_budget_task = asyncio.create_task(
            _github_budget_loop(),
            name="github-budget-probe",
        )
        logger.info(
            "GitHub budget probe task created (interval=%ds)",
            _sched_settings.github_budget_probe_interval_seconds,
        )

    # Job 19: Security re-scan (daily loop, checks 7-day cutoff internally)
    if _security_scan_task is None or _security_scan_task.done():
        _security_scan_task = asyncio.create_task(
            _security_scan_loop(),
            name="security-scan",
        )
        logger.info(
            "Security scan task created (interval=%ds)",
            SECURITY_SCAN_INTERVAL,
        )

    # Job 16: Bluesky starter pack refresh (30-day loop)
    if _sched_settings.starter_pack_refresh_enabled:
        if _starter_pack_task is None or _starter_pack_task.done():
            _starter_pack_task = asyncio.create_task(
                _starter_pack_loop(),
                name="bluesky-starter-pack-refresh",
            )
            logger.info(
                "Bluesky starter pack task created (interval=%ds)",
                STARTER_PACK_INTERVAL,
            )

    # Job 18: Auto-follow Bluesky reply targets (daily)
    if _auto_follow_task is None or _auto_follow_task.done():
        _auto_follow_task = asyncio.create_task(
            _auto_follow_loop(),
            name="auto-follow-bluesky",
        )
        logger.info(
            "Auto-follow task created (interval=%ds)",
            AUTO_FOLLOW_INTERVAL,
        )

    if _sched_settings.reply_guy_enabled:
        if _reply_monitor_task is None or _reply_monitor_task.done():
            _reply_monitor_task = asyncio.create_task(
                _reply_monitor_loop(),
                name="reply-guy-monitor",
            )
            logger.info(
                "Reply guy monitor task created (interval=%ds)",
                REPLY_MONITOR_INTERVAL,
            )
        if _reply_drafter_task is None or _reply_drafter_task.done():
            _reply_drafter_task = asyncio.create_task(
                _reply_drafter_loop(),
                name="reply-guy-drafter",
            )
            logger.info(
                "Reply guy drafter task created (interval=%ds)",
                REPLY_DRAFTER_INTERVAL,
            )
        if _reply_poster_task is None or _reply_poster_task.done():
            _reply_poster_task = asyncio.create_task(
                _reply_poster_loop(),
                name="reply-guy-poster",
            )
            logger.info(
                "Reply guy auto-poster task created (interval=%ds)",
                REPLY_POSTER_INTERVAL,
            )

    # Job 22: Weekly marketing sync (Fridays)
    asyncio.create_task(
        _marketing_sync_loop(),
        name="marketing-sync",
    )

    asyncio.create_task(
        _watch_rescan_loop(),
        name="watch-rescan",
    )

    # GitHub App private-repo re-scan (daily loop over connected installations)
    asyncio.create_task(
        _app_rescan_loop(),
        name="app-rescan",
    )

    # Catalog re-scan + growth (keep community_scans fresh + backfill the launch-corpus)
    if getattr(_sched_settings, "scheduler_catalog_rescan", True):
        asyncio.create_task(
            _catalog_rescan_loop(),
            name="catalog-rescan",
        )

    return _scheduler_task


def stop_scheduler() -> None:
    """Cancel the running scheduler task (if any)."""
    global _scheduler_task, _reply_monitor_task, _reply_drafter_task
    global _reply_poster_task
    global _starter_pack_task, _auto_follow_task, _security_scan_task
    global _api_health_task, _github_budget_task, _lock_refresh_task

    # Cancel the lock refresh first — its CancelledError handler releases the Redis key
    if _lock_refresh_task is not None and not _lock_refresh_task.done():
        _lock_refresh_task.cancel()
        logger.info("Scheduler lock refresh task cancelled")
    _lock_refresh_task = None

    if _scheduler_task is not None and not _scheduler_task.done():
        _scheduler_task.cancel()
        logger.info("Scheduler task cancelled")
    _scheduler_task = None

    if _reply_monitor_task is not None and not _reply_monitor_task.done():
        _reply_monitor_task.cancel()
        logger.info("Reply guy monitor task cancelled")
    _reply_monitor_task = None

    if _reply_drafter_task is not None and not _reply_drafter_task.done():
        _reply_drafter_task.cancel()
        logger.info("Reply guy drafter task cancelled")
    _reply_drafter_task = None

    if _reply_poster_task is not None and not _reply_poster_task.done():
        _reply_poster_task.cancel()
        logger.info("Reply guy poster task cancelled")
    _reply_poster_task = None

    if _starter_pack_task is not None and not _starter_pack_task.done():
        _starter_pack_task.cancel()
        logger.info("Bluesky starter pack task cancelled")
    _starter_pack_task = None

    if _auto_follow_task is not None and not _auto_follow_task.done():
        _auto_follow_task.cancel()
        logger.info("Auto-follow task cancelled")
    _auto_follow_task = None

    if _security_scan_task is not None and not _security_scan_task.done():
        _security_scan_task.cancel()
        logger.info("Security scan task cancelled")
    _security_scan_task = None

    if _api_health_task is not None and not _api_health_task.done():
        _api_health_task.cancel()
        logger.info("API health check task cancelled")
    _api_health_task = None

    if _github_budget_task is not None and not _github_budget_task.done():
        _github_budget_task.cancel()
        logger.info("GitHub budget probe task cancelled")
    _github_budget_task = None
