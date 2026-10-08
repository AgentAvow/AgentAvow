"""Jetstream subscriber — filters AI agent posts from the Bluesky firehose.

Uses Bluesky's Jetstream (JSON WebSocket) rather than the full CBOR firehose
for simplicity and reduced bandwidth.  Matched posts are stored in a Redis
sorted set keyed by timestamp for fast retrieval by the feed skeleton endpoint.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import websockets  # type: ignore[import-untyped]

# Explicit: newer websockets resolves submodules lazily, so `websockets.exceptions`
# is only an attribute once something imports it. In the web app uvicorn did; in the
# standalone subscriber process the first `except ...ConnectionClosed` raised
# AttributeError and killed the process.
import websockets.exceptions  # type: ignore[import-untyped]  # noqa: F401

from src.feeds.bluesky.keywords import matches_keywords

logger = logging.getLogger(__name__)

# Jetstream endpoint — filter to only post creates
JETSTREAM_URL = (
    "wss://jetstream2.us-east.bsky.network/subscribe"
    "?wantedCollections=app.bsky.feed.post"
)

# Single-instance lock: whichever process holds it (a web worker or the dedicated
# subscriber container) consumes the firehose; everyone else waits.
BLUESKY_JETSTREAM_LOCK = "ag:lock:bluesky-jetstream"

# Redis key for the feed sorted set (score = timestamp_us)
FEED_KEY = "bluesky:feed:ai-agent-news"

# Max posts to keep in the feed
MAX_FEED_SIZE = 2000

# How often to log stats (seconds)
STATS_INTERVAL = 300

# Nth consecutive connect failure at which recovered-blip warnings escalate to
# ERROR (= Sentry). Transient Jetstream blips self-heal in one or two attempts;
# only a sustained outage should page (same policy as the Anthropic client fix).
SUSTAINED_ERROR_THRESHOLD = 6


def _reconnect_plan(consecutive_failures: int) -> tuple[str, float]:
    """(log_level, delay_seconds) for the nth consecutive failure (1-based).

    Backoff 5s → 10 → 20 → 40 → 60 (capped). ERROR fires once at the sustained
    threshold and every 10th attempt after — everything else stays WARNING so
    recovered blips never page.
    """
    delay = float(min(5 * (2 ** min(consecutive_failures - 1, 4)), 60))
    if consecutive_failures >= SUSTAINED_ERROR_THRESHOLD and (
        consecutive_failures == SUSTAINED_ERROR_THRESHOLD
        or consecutive_failures % 10 == 0
    ):
        return "error", delay
    return "warning", delay


async def run_subscriber() -> None:
    """Connect to Jetstream and filter posts into Redis.  Reconnects on failure."""
    streak = {"failures": 0}

    def _mark_connected() -> None:
        streak["failures"] = 0

    while True:
        try:
            await _subscribe(on_connect=_mark_connected)
            streak["failures"] = 0
        except asyncio.CancelledError:
            logger.info("Jetstream subscriber cancelled")
            return
        except websockets.exceptions.ConnectionClosed:
            # We had a working session — a close is normal churn, not a failure streak.
            streak["failures"] = 0
            logger.warning("Jetstream connection closed — reconnecting in 5s")
            await asyncio.sleep(5)
        except Exception as exc:
            streak["failures"] += 1
            level, delay = _reconnect_plan(streak["failures"])
            if level == "error":
                logger.exception(
                    "Jetstream subscriber DOWN — %d consecutive failed attempts, "
                    "reconnecting in %.0fs", streak["failures"], delay,
                )
            else:
                logger.warning(
                    "Jetstream subscriber error (%r) — attempt %d, reconnecting in %.0fs",
                    exc, streak["failures"], delay,
                )
            await asyncio.sleep(delay)


async def _subscribe(on_connect=None) -> None:
    """Single subscription session."""
    from src.redis_client import get_redis

    r = get_redis()

    # Resume from last cursor if available
    cursor = await r.get("bluesky:feed:jetstream_cursor")
    url = JETSTREAM_URL
    if cursor:
        cursor_str = cursor if isinstance(cursor, str) else cursor.decode()
        url += f"&cursor={cursor_str}"
        logger.info("Resuming Jetstream from cursor %s", cursor_str)

    processed = 0
    matched = 0
    last_stats = time.monotonic()

    async with websockets.connect(url, ping_interval=30, ping_timeout=10) as ws:
        logger.info("Connected to Jetstream")
        if on_connect is not None:
            on_connect()
        async for raw in ws:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Only process post creates
            if event.get("kind") != "commit":
                continue
            commit = event.get("commit", {})
            if commit.get("operation") != "create":
                continue
            if commit.get("collection") != "app.bsky.feed.post":
                continue

            record = commit.get("record", {})
            text = record.get("text", "")
            if not text:
                continue

            processed += 1

            # Check keyword match
            kw_matches = matches_keywords(text)
            if not kw_matches:
                continue

            # Build AT-URI
            did = event.get("did", "")
            rkey = commit.get("rkey", "")
            if not did or not rkey:
                continue
            at_uri = f"at://{did}/app.bsky.feed.post/{rkey}"
            timestamp_us = event.get("time_us", int(time.time() * 1_000_000))

            # Store in Redis sorted set
            await r.zadd(FEED_KEY, {at_uri: timestamp_us})
            matched += 1

            # Trim to max size (remove oldest)
            count = await r.zcard(FEED_KEY)
            if count > MAX_FEED_SIZE:
                await r.zremrangebyrank(FEED_KEY, 0, count - MAX_FEED_SIZE - 1)

            # Save cursor periodically (every 1000 events)
            if processed % 1000 == 0:
                cursor_val = str(timestamp_us)
                await r.set("bluesky:feed:jetstream_cursor", cursor_val)

            # Log stats periodically
            now = time.monotonic()
            if now - last_stats > STATS_INTERVAL:
                logger.info(
                    "Jetstream stats: processed=%d matched=%d feed_size=%d",
                    processed, matched, await r.zcard(FEED_KEY),
                )
                last_stats = now
