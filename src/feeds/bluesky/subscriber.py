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

# Jetstream endpoints — filter to only post creates. Bluesky runs four public
# instances; the subscriber starts on the first and moves to the next after a failed
# connect, so one instance's outage cannot take the feed down (2026-10-14).
JETSTREAM_HOSTS = (
    "jetstream2.us-east.bsky.network",
    "jetstream1.us-east.bsky.network",
    "jetstream1.us-west.bsky.network",
    "jetstream2.us-west.bsky.network",
)
JETSTREAM_QUERY = "?wantedCollections=app.bsky.feed.post"
JETSTREAM_URL = f"wss://{JETSTREAM_HOSTS[0]}/subscribe{JETSTREAM_QUERY}"

CURSOR_KEY = "bluesky:feed:jetstream_cursor"

# Save the resume position every N received events or every N seconds, whichever
# comes first. It is the time of the last event RECEIVED, not the last one that
# matched: matches are ~1 in 2,600 posts, and saving only on a match left the
# cursor hours stale, so every reconnect replayed the same backlog (2026-10-14).
CURSOR_SAVE_EVERY = 1000
CURSOR_SAVE_SECONDS = 5.0

# During a replay the socket buffer is never empty, so `async for` never yields and
# the keepalive cannot answer pings: the server closed us at ping_interval +
# ping_timeout (40 s), before the cursor moved, forever. Yield every N messages.
YIELD_EVERY = 200

# A saved cursor older than this is dropped and the subscriber starts live. The feed
# is recent news; a bounded catch-up beats an unbounded replay.
MAX_REPLAY_SECONDS = 2 * 3600

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
    host = {"i": 0}

    def _mark_connected() -> None:
        streak["failures"] = 0

    while True:
        try:
            await _subscribe(
                on_connect=_mark_connected,
                url_base=_url_for(JETSTREAM_HOSTS[host["i"] % len(JETSTREAM_HOSTS)]),
            )
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
            host["i"] += 1  # a failed connect moves to the next Jetstream instance
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


def _url_for(host: str) -> str:
    return f"wss://{host}/subscribe{JETSTREAM_QUERY}"


def _resume_cursor(saved, now_us: int) -> str | None:
    """The cursor to resume from, or None to start live. A missing, unparseable or
    too-old cursor (older than MAX_REPLAY_SECONDS) starts live."""
    if not saved:
        return None
    text = saved if isinstance(saved, str) else saved.decode()
    try:
        value = int(text)
    except ValueError:
        return None
    if now_us - value > MAX_REPLAY_SECONDS * 1_000_000:
        return None
    return str(value)


async def _handle_event(event: dict, r) -> tuple[int, int]:
    """Filter one Jetstream event into the feed. Returns (processed, matched)."""
    # Only process post creates
    if event.get("kind") != "commit":
        return 0, 0
    commit = event.get("commit", {})
    if commit.get("operation") != "create":
        return 0, 0
    if commit.get("collection") != "app.bsky.feed.post":
        return 0, 0

    record = commit.get("record", {})
    text = record.get("text", "")
    if not text:
        return 0, 0

    # Check keyword match
    if not matches_keywords(text):
        return 1, 0

    # Build AT-URI
    did = event.get("did", "")
    rkey = commit.get("rkey", "")
    if not did or not rkey:
        return 1, 0
    at_uri = f"at://{did}/app.bsky.feed.post/{rkey}"
    timestamp_us = event.get("time_us", int(time.time() * 1_000_000))

    # Store in Redis sorted set
    await r.zadd(FEED_KEY, {at_uri: timestamp_us})

    # Trim to max size (remove oldest)
    count = await r.zcard(FEED_KEY)
    if count > MAX_FEED_SIZE:
        await r.zremrangebyrank(FEED_KEY, 0, count - MAX_FEED_SIZE - 1)
    return 1, 1


async def _subscribe(on_connect=None, url_base: str | None = None) -> None:
    """Single subscription session."""
    from src.redis_client import get_redis

    r = get_redis()

    # Resume from the last cursor if there is one and it is recent enough
    saved = await r.get(CURSOR_KEY)
    cursor_str = _resume_cursor(saved, int(time.time() * 1_000_000))
    url = url_base or JETSTREAM_URL
    if cursor_str:
        url += f"&cursor={cursor_str}"
        logger.info("Resuming Jetstream from cursor %s", cursor_str)
    elif saved:
        logger.warning("Saved Jetstream cursor is too old to replay; starting live")

    processed = 0
    matched = 0
    received = 0
    last_stats = time.monotonic()
    last_time_us: int | None = None
    last_saved_at = time.monotonic()

    async def _save_cursor() -> None:
        nonlocal last_saved_at
        if last_time_us is not None:
            await r.set(CURSOR_KEY, str(last_time_us))
        last_saved_at = time.monotonic()

    async with websockets.connect(url, ping_interval=30, ping_timeout=10) as ws:
        logger.info("Connected to Jetstream")
        if on_connect is not None:
            on_connect()
        try:
            async for raw in ws:
                received += 1
                if received % YIELD_EVERY == 0:
                    await asyncio.sleep(0)  # let the keepalive answer pings mid-replay
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                t_us = event.get("time_us")
                if isinstance(t_us, int) and not isinstance(t_us, bool):
                    last_time_us = t_us
                if (received % CURSOR_SAVE_EVERY == 0
                        or time.monotonic() - last_saved_at >= CURSOR_SAVE_SECONDS):
                    await _save_cursor()

                p, m = await _handle_event(event, r)
                processed += p
                matched += m

                # Log stats periodically
                now = time.monotonic()
                if now - last_stats > STATS_INTERVAL:
                    logger.info(
                        "Jetstream stats: processed=%d matched=%d feed_size=%d",
                        processed, matched, await r.zcard(FEED_KEY),
                    )
                    last_stats = now
        finally:
            try:
                await _save_cursor()
            except Exception:  # never mask the close or error that ended the session
                logger.debug("cursor save on exit failed", exc_info=True)
