"""Run a piece of background work in one uvicorn worker, not in every one.

The app runs several worker processes, and anything started from the lifespan
hook starts in each of them unless it takes a lock. The scheduler already guards
itself with a Redis ``SET NX`` key; this module makes that pattern reusable for
the other startup tasks (the Bluesky Jetstream subscriber, the startup trust
recompute) so a four-worker deploy does not run four copies of each.

If Redis is unreachable the lock is treated as acquired: one copy per worker is
the pre-existing behaviour and beats running none. The scheduler makes the same
call.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)


async def try_acquire(key: str, ttl: int) -> bool:
    """``SET key NX EX ttl``. True when this worker now holds the lock."""
    try:
        from src.redis_client import get_redis

        return bool(await get_redis().set(key, "1", nx=True, ex=ttl))
    except Exception:
        logger.warning("Redis unavailable for lock %s — proceeding without it", key,
                       exc_info=True)
        return True


async def _refresh_loop(key: str, ttl: int) -> None:
    """Keep the lock alive while the work runs; it lapses on its own if we die."""
    from src.redis_client import get_redis

    while True:
        await asyncio.sleep(max(ttl // 3, 1))
        try:
            await get_redis().expire(key, ttl)
        except Exception:
            logger.debug("lock %s refresh failed", key, exc_info=True)


async def run_exclusively(
    key: str, ttl: int, work: Callable[[], Awaitable[None]], *, retry: int = 30,
) -> None:
    """Run ``work()`` in whichever worker holds ``key``.

    Workers that lose the race wait ``retry`` seconds and try again, so if the
    holder dies the work moves to another worker within about ``ttl`` seconds.
    The lock is refreshed every ``ttl // 3`` seconds while ``work()`` runs.
    """
    while True:
        if not await try_acquire(key, ttl):
            await asyncio.sleep(retry)
            continue
        logger.info("Lock %s acquired — running in this worker", key)
        refresher = asyncio.create_task(_refresh_loop(key, ttl), name=f"lock-refresh:{key}")
        try:
            await work()
            return
        finally:
            refresher.cancel()
