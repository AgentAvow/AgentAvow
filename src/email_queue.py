"""Email rate limiter, retry logic, and overflow queue.

Uses Redis to track send rate per minute window.  When the rate limit is
hit, emails are queued in-memory and drained on the next send attempt or
via ``flush_email_queue()``.  Falls back gracefully when Redis is
unavailable (in-memory counter only).
"""
from __future__ import annotations

import asyncio
import collections
import logging
import time
from typing import NamedTuple

from src.config import settings
from src.redis_client import get_redis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory overflow queue (lightweight, no Celery/RQ needed)
# ---------------------------------------------------------------------------


class _QueuedEmail(NamedTuple):
    to: str
    subject: str
    html_body: str
    attempts: int
    private: bool = False


def recipient_for_log(to: str, private: bool) -> str:
    """What a log line says about the recipient. A private send (an address we promised
    not to keep, such as "Email me the setup") never writes the address to the logs."""
    return "<private recipient>" if private else to


_queue: collections.deque[_QueuedEmail] = collections.deque(maxlen=500)

# In-memory fallback counter (used when Redis is unavailable)
_mem_window_start: float = 0.0
_mem_window_count: int = 0

# ---------------------------------------------------------------------------
# Rate-limit helpers
# ---------------------------------------------------------------------------


async def _check_rate_limit_redis() -> bool:
    """Return True if we are under the rate limit (OK to send).

    Uses a Redis key ``ag:email:rate:{minute}`` with a 120s TTL.
    """
    try:
        r = get_redis()
        now_minute = int(time.time() // 60)
        key = f"ag:email:rate:{now_minute}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 120)
        if count > settings.email_rate_limit_per_minute:
            # Undo the increment so future checks are accurate
            await r.decr(key)
            return False
        return True
    except Exception:
        logger.debug("Redis unavailable for email rate limit, using in-memory")
        return _check_rate_limit_memory()


def _check_rate_limit_memory() -> bool:
    """Fallback in-memory rate limiter (single-process only)."""
    global _mem_window_start, _mem_window_count

    now = time.time()
    window = int(now // 60)
    if window != int(_mem_window_start // 60):
        _mem_window_start = now
        _mem_window_count = 0

    if _mem_window_count >= settings.email_rate_limit_per_minute:
        return False
    _mem_window_count += 1
    return True


# ---------------------------------------------------------------------------
# Core send-with-retry
# ---------------------------------------------------------------------------


async def _raw_send(to: str, subject: str, html_body: str, *, private: bool = False) -> bool:
    """Import and call the actual send function (avoids circular import)."""
    from src.email import _send_via_resend, _send_via_smtp

    if settings.resend_api_key:
        return await _send_via_resend(to, subject, html_body, private=private)

    if settings.smtp_host:
        return await _send_via_smtp(to, subject, html_body, private=private)

    logger.info(
        "Email (dev mode, no provider):\n  To: %s\n  Subject: %s",
        recipient_for_log(to, private),
        subject,
    )
    return True


async def _send_with_retry(
    to: str,
    subject: str,
    html_body: str,
    max_attempts: int | None = None,
    *,
    private: bool = False,
) -> bool:
    """Try sending up to *max_attempts* times with exponential backoff."""
    attempts = max_attempts or settings.email_retry_max_attempts
    delay = settings.email_retry_base_delay

    for attempt in range(1, attempts + 1):
        ok = await _raw_send(to, subject, html_body, private=private)
        if ok:
            return True
        if attempt < attempts:
            logger.warning(
                "Email send failed (attempt %d/%d), retrying in %.1fs — to=%s subject=%s",
                attempt,
                attempts,
                delay,
                recipient_for_log(to, private),
                subject,
            )
            await asyncio.sleep(delay)
            delay *= 2  # exponential backoff
        else:
            logger.error(
                "Email send failed after %d attempts — to=%s subject=%s",
                attempts,
                recipient_for_log(to, private),
                subject,
            )
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def send_email_rated(
    to: str, subject: str, html_body: str, *, private: bool = False,
) -> bool:
    """Send an email with rate limiting and retry.

    * If under the per-minute rate limit → send immediately (with retry).
    * If over the limit → queue and return True (email will be sent later).
    * If Redis is down → fall back to in-memory counter.
    """
    allowed = await _check_rate_limit_redis()
    if not allowed:
        logger.warning(
            "Email rate limit reached (%d/min), queuing email to=%s subject=%s",
            settings.email_rate_limit_per_minute,
            recipient_for_log(to, private),
            subject,
        )
        _queue.append(_QueuedEmail(to, subject, html_body, 0, private))
        return True  # queued, will be sent later

    return await _send_with_retry(to, subject, html_body, private=private)


async def flush_email_queue() -> int:
    """Drain the overflow queue, respecting rate limits.

    Returns the number of emails successfully sent.  Items that still fail
    after retries are discarded (already logged by ``_send_with_retry``).
    """
    sent = 0
    while _queue:
        allowed = await _check_rate_limit_redis()
        if not allowed:
            logger.info(
                "flush_email_queue: rate limit hit, %d emails still queued",
                len(_queue),
            )
            break
        item = _queue.popleft()
        ok = await _send_with_retry(
            item.to, item.subject, item.html_body, private=item.private,
        )
        if ok:
            sent += 1
    return sent


def queue_depth() -> int:
    """Return current number of queued emails (for monitoring)."""
    return len(_queue)


def _reset_for_testing() -> None:
    """Clear internal state — only for use in test fixtures."""
    global _mem_window_start, _mem_window_count
    _queue.clear()
    _mem_window_start = 0.0
    _mem_window_count = 0
