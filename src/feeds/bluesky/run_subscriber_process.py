"""Run the Bluesky Jetstream subscriber as its own process.

    python -m src.feeds.bluesky.run_subscriber_process

Prod runs this in the ``bluesky-subscriber`` container and sets
``BLUESKY_SUBSCRIBER_IN_WEB=false`` on the web backend. Keyword-matching the whole
firehose inside a uvicorn worker kept that worker's event loop busy, so every request
it served waited (py-spy, 2026-10-08).

The subscriber only needs Redis (feed sorted set, cursor, lock); no DB session. It
still takes the same ``ag:lock:bluesky-jetstream`` lock, so if a web worker somewhere
is also configured to run it, only one consumes the firehose. ``run_subscriber``
reconnects on every error, so transient failures never end the process; SIGTERM /
SIGINT cancel it, release the lock if we held it, and exit 0.
"""
from __future__ import annotations

import asyncio
import logging
import signal

from src.config import settings
from src.feeds.bluesky.subscriber import BLUESKY_JETSTREAM_LOCK, run_subscriber
from src.logging_config import setup_logging
from src.worker_lock import run_exclusively

logger = logging.getLogger(__name__)

LOCK_TTL = 60
LOCK_RETRY = 30


def _init_sentry() -> None:
    """Same Sentry setup as the web app (minus the FastAPI integration)."""
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk

        from src.sentry_filters import before_send as _sentry_before_send

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            traces_sample_rate=0.0,
            environment="production" if not settings.debug else "development",
            before_send=_sentry_before_send,
        )
    except ImportError:
        logger.warning("sentry-sdk not installed, error tracking disabled")


async def _release_lock() -> None:
    try:
        from src.redis_client import get_redis

        await get_redis().delete(BLUESKY_JETSTREAM_LOCK)
    except Exception:
        logger.debug("lock release failed (it lapses on its own)", exc_info=True)


async def main() -> None:
    """Run the subscriber under the single-instance lock until cancelled."""
    if not settings.bluesky_feed_enabled:
        # Idle instead of exiting so the container's restart policy doesn't loop.
        logger.info("BLUESKY_FEED_ENABLED is false — subscriber idle")
        await asyncio.Event().wait()
        return

    held = {"lock": False}

    async def _work() -> None:
        held["lock"] = True
        await run_subscriber()

    logger.info("Bluesky Jetstream subscriber process starting (lock %s)",
                BLUESKY_JETSTREAM_LOCK)
    try:
        await run_exclusively(BLUESKY_JETSTREAM_LOCK, LOCK_TTL, _work, retry=LOCK_RETRY)
    finally:
        # Hand the lock back on shutdown so the replacement container (deploy) or a
        # web worker can take over at once instead of waiting out the TTL.
        if held["lock"]:
            await _release_lock()


async def _run() -> None:
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    assert task is not None

    def _stop(signame: str) -> None:
        logger.info("Received %s — stopping Bluesky subscriber", signame)
        task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _stop, sig.name)
        except (NotImplementedError, RuntimeError):  # pragma: no cover - non-POSIX
            pass

    try:
        await main()
    except asyncio.CancelledError:
        pass
    finally:
        from src.redis_client import close_redis

        await close_redis()
        logger.info("Bluesky subscriber stopped")


def cli() -> None:
    setup_logging()
    _init_sentry()
    asyncio.run(_run())


if __name__ == "__main__":
    cli()
