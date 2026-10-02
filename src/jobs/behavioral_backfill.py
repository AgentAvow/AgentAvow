"""Behavioral backfill — sandbox the catalog's long tail at LOW priority.

Viewers and the on-change trigger (``src/scanner/behavioral/trigger.py``) only ever
run the sandbox for coordinates somebody looked at or that just changed. The rest of
the browse catalog never gets a runtime observation. This job walks ``community_scans``
most-adopted first and enqueues a run for each sandbox-eligible row that has no cached
block, using ``priority="low"`` so it only ever takes a slot when one would still be
free for a real scan — the first ``deferred`` ends the batch.

It never runs a static scan: a row needs cached scan data (the public scan cache the
endpoints and the catalog re-scan loop write) to shape a sandbox target, and a row
without it is skipped and retried after ``behavioral_backfill_retry_days``.

State (Redis):
  ``ag:backfill:behavioral:done``      set of ``surface:owner/repo`` ever handled
  ``ag:backfill:behavioral:done:at``   hash member -> ``<iso ts>|<outcome>``
  ``ag:backfill:behavioral:progress``  hash {total_eligible, done, last_run_at, ...}
  ``ag:metrics:behavioral:backfill:{attempted,started,deferred,skipped}:<day>``
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

DONE_SET = "ag:backfill:behavioral:done"
DONE_AT = "ag:backfill:behavioral:done:at"
PROGRESS = "ag:backfill:behavioral:progress"
LOCK_KEY = "ag:lock:behavioral-backfill"
LOCK_TTL = 5 * 60

# Outcomes that mean "this row has (or will shortly have) a sandbox block".
_DONE_OUTCOMES = ("started", "cached", "locked")
# ``primary_language`` values the sandbox can install from git (see
# public_scan_router._repo_git_ecosystem) — the SQL pre-filter for github rows.
_GIT_LANGS = ("javascript", "typescript", "javascript/typescript", "python")
_PAGE = 200


def member_key(surface: str, owner: str, repo: str) -> str:
    return f"{surface}:{owner}/{repo}"


def _eligible_filter():
    from sqlalchemy import func, or_

    from src.models import CommunityScan
    return or_(
        CommunityScan.surface.in_(("npm", "pypi", "docker", "openclaw")),
        (CommunityScan.surface == "github")
        & func.lower(CommunityScan.primary_language).in_(_GIT_LANGS),
    )


def eligible_rows_query(limit: int, offset: int = 0):
    """Sandbox-eligible catalog rows, most-adopted first (NULL adoption last), newest
    scan first within a tie, then id so paging is stable."""
    from sqlalchemy import select

    from src.models import CommunityScan
    return (
        select(CommunityScan.surface, CommunityScan.owner, CommunityScan.repo)
        .where(_eligible_filter())
        .order_by(
            CommunityScan.adoption_count.desc().nulls_last(),
            CommunityScan.last_scanned_at.desc(),
            CommunityScan.id,
        )
        .offset(offset)
        .limit(limit)
    )


def eligible_count_query():
    from sqlalchemy import func, select

    from src.models import CommunityScan
    return select(func.count()).select_from(CommunityScan).where(_eligible_filter())


def parse_done_entry(raw: object) -> tuple[datetime | None, str]:
    """``"<iso ts>|<outcome>"`` -> (ts, outcome); tolerates a bare timestamp."""
    try:
        s = raw.decode() if isinstance(raw, bytes) else str(raw or "")
        ts_s, _, outcome = s.partition("|")
        ts = datetime.fromisoformat(ts_s) if ts_s else None
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts, outcome or "attempted"
    except Exception:
        return None, "attempted"


def attempted_recently(raw: object, now: datetime, retry_days: int) -> bool:
    ts, _ = parse_done_entry(raw)
    return ts is not None and (now - ts) < timedelta(days=retry_days)


async def _mark(r, member: str, outcome: str, now: datetime) -> None:
    await r.sadd(DONE_SET, member)
    await r.hset(DONE_AT, member, f"{now.isoformat()}|{outcome}")


async def _count(r, name: str, by: int, day: str) -> None:
    if not by:
        return
    k = f"ag:metrics:behavioral:backfill:{name}:{day}"
    await r.incrby(k, by)
    await r.expire(k, 90 * 24 * 3600)


async def run_behavioral_backfill(
    *, batch: int | None = None, max_examined: int | None = None,
) -> dict:
    """One backfill pass. Returns the pass's stats (also written to Redis)."""
    from src.config import settings
    from src.database import async_session
    from src.redis_client import get_redis
    from src.scanner.behavioral.trigger import (
        behavioral_scan_data,
        cached_scan_data,
        enqueue_behavioral,
    )

    stats = {"attempted": 0, "started": 0, "deferred": 0, "skipped": 0,
             "cached": 0, "locked": 0, "ineligible": 0, "examined": 0}
    if not getattr(settings, "behavioral_backfill_enabled", True) or not getattr(
            settings, "scanner_behavioral_enabled", False):
        stats["disabled"] = True
        return stats
    batch = batch or int(getattr(settings, "behavioral_backfill_batch", 6) or 6)
    max_examined = max_examined or int(
        getattr(settings, "behavioral_backfill_max_examined", 400) or 400)
    retry_days = int(getattr(settings, "behavioral_backfill_retry_days", 7) or 7)
    now = datetime.now(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    r = get_redis()

    done_at: dict[str, object] = {}
    try:
        raw = await r.hgetall(DONE_AT) or {}
        done_at = {(k.decode() if isinstance(k, bytes) else str(k)): v for k, v in raw.items()}
    except Exception:
        done_at = {}

    from src.api import public_scan_router as psr

    async with async_session() as db:
        total_eligible = int(await db.scalar(eligible_count_query()) or 0)
        offset = 0
        stop = False
        while not stop:
            rows = (await db.execute(eligible_rows_query(_PAGE, offset))).all()
            if not rows:
                break
            offset += len(rows)
            for surface, owner, repo in rows:
                if stats["attempted"] >= batch or stats["examined"] >= max_examined:
                    stop = True
                    break
                member = member_key(surface, owner, repo)
                if member in done_at and attempted_recently(done_at[member], now, retry_days):
                    continue  # handled within the retry window — not even examined
                stats["examined"] += 1
                data = await cached_scan_data(surface, owner, repo)
                if data is None:
                    stats["skipped"] += 1
                    await _mark(r, member, "no_scan_data", now)
                    continue
                shaped = behavioral_scan_data(surface, owner, repo, data)
                target = psr._behavioral_target(shaped)
                if not target:
                    stats["skipped"] += 1
                    await _mark(r, member, "ineligible", now)
                    continue
                s, n = target
                if await psr._get_cached_behavioral(
                        s, str(n), psr._declared_egress(shaped), psr._behavioral_plan(shaped, s)):
                    stats["skipped"] += 1
                    await _mark(r, member, "cached", now)
                    continue
                stats["attempted"] += 1
                outcome = await enqueue_behavioral(shaped, reason="backfill", priority="low")
                if outcome == "deferred":
                    stats["deferred"] += 1
                    stop = True  # the sandbox is busy with real scans — try next pass
                    break
                stats[outcome] = stats.get(outcome, 0) + 1
                await _mark(r, member, outcome, now)
                if outcome == "started":
                    await asyncio.sleep(0)  # let the run task get scheduled

    try:
        for name in ("attempted", "started", "deferred", "skipped"):
            await _count(r, name, stats[name], day)
        raw = await r.hgetall(DONE_AT) or {}
        done = sum(1 for v in raw.values() if parse_done_entry(v)[1] in _DONE_OUTCOMES)
        await r.hset(PROGRESS, mapping={
            "total_eligible": total_eligible, "done": done,
            "last_run_at": now.isoformat(), "last_examined": stats["examined"],
            "last_attempted": stats["attempted"], "last_started": stats["started"],
            "last_deferred": stats["deferred"],
        })
    except Exception:
        logger.debug("behavioral backfill progress write failed", exc_info=True)
    if stats["attempted"] or stats["examined"]:
        logger.info("Behavioral backfill: examined %d, attempted %d, started %d, "
                    "deferred %d, skipped %d (eligible %d)", stats["examined"],
                    stats["attempted"], stats["started"], stats["deferred"],
                    stats["skipped"], total_eligible)
    return stats


async def read_backfill_progress() -> dict:
    """The progress hash for the admin dashboard. Missing → zeros."""
    out: dict = {"total_eligible": 0, "done": 0, "last_run_at": None}
    try:
        from src.redis_client import get_redis
        raw = await get_redis().hgetall(PROGRESS) or {}
        for k, v in raw.items():
            ks = k.decode() if isinstance(k, bytes) else str(k)
            vs = v.decode() if isinstance(v, bytes) else v
            if ks == "last_run_at":
                out[ks] = vs or None
            else:
                try:
                    out[ks] = int(float(vs))
                except (TypeError, ValueError):
                    out[ks] = 0
    except Exception:
        pass
    return out


async def behavioral_backfill_loop(interval: int | None = None) -> None:
    """Scheduler loop: one pass every ``behavioral_backfill_interval_minutes`` while
    both the backfill and the sandbox tier are enabled. A short NX lock per pass
    keeps two passes from dispatching at once."""
    from src.config import settings
    from src.worker_lock import try_acquire

    interval = interval or int(
        getattr(settings, "behavioral_backfill_interval_minutes", 10) or 10) * 60
    logger.info("Behavioral backfill loop started (interval=%ds)", interval)
    await asyncio.sleep(getattr(settings, "catalog_rescan_startup_delay_sec", 300))
    while True:
        try:
            if getattr(settings, "behavioral_backfill_enabled", True) and getattr(
                    settings, "scanner_behavioral_enabled", False):
                if await try_acquire(LOCK_KEY, LOCK_TTL):
                    try:
                        await run_behavioral_backfill()
                    finally:
                        try:
                            from src.redis_client import get_redis
                            await get_redis().delete(LOCK_KEY)
                        except Exception:
                            pass
        except Exception:
            logger.exception("Behavioral backfill loop iteration failed")
        await asyncio.sleep(interval)
