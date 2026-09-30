"""Webhook event delivery worker.

Subscribes to the Redis event bus (``agentgraph:events``) and delivers
matching events to webhook subscribers via HTTP POST.  Implements
exponential back-off with jitter for failed deliveries, logs every
attempt to ``webhook_delivery_logs``, and auto-deactivates subscriptions
after repeated consecutive failures.

Usage (standalone process)::

    python -m src.jobs.webhook_worker

The worker can also be started programmatically via :func:`start_worker`.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session
from src.models import WebhookDeliveryLog, WebhookSubscription

logger = logging.getLogger(__name__)

# --- Configuration ---------------------------------------------------------

#: Maximum number of delivery retries per event/subscription pair.
MAX_RETRIES: int = 5

#: Base delay in seconds for exponential back-off (doubles each attempt).
RETRY_BASE_DELAY: float = 2.0

#: Maximum delay cap in seconds to avoid absurdly long waits.
RETRY_MAX_DELAY: float = 60.0

#: Per-request timeout (connect + read) in seconds.
REQUEST_TIMEOUT: float = 10.0

#: Consecutive failures before a subscription is auto-deactivated.
AUTO_DEACTIVATE_THRESHOLD: int = 10

#: Redis pub/sub channel name (matches src/events.py).
EVENTS_CHANNEL: str = "agentgraph:events"


# --- Delivery helpers ------------------------------------------------------

def _compute_signature(body: str, signing_key: str) -> str:
    """Compute HMAC-SHA256 signature for the webhook body."""
    return hmac.new(
        signing_key.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()


def _resolve_signing_key(sub: WebhookSubscription) -> str:
    """Return the plaintext signing key for *sub*.

    If the subscription has a Fernet-encrypted ``signing_key`` it will be
    decrypted; otherwise, the ``secret_hash`` is used as the signing key
    (legacy/fallback behaviour matching ``src/events.py``).
    """
    if sub.signing_key:
        from src.encryption import decrypt_secret
        return decrypt_secret(sub.signing_key)
    return sub.secret_hash


def _build_payload_body(
    event_type: str,
    payload: dict[str, Any],
) -> str:
    """Serialise the canonical JSON body that gets POSTed to the subscriber."""
    return json.dumps(
        {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        },
        default=str,
    )


async def _deliver_single(
    client: httpx.AsyncClient,
    sub: WebhookSubscription,
    event_type: str,
    payload: dict[str, Any],
    attempt: int,
    db: AsyncSession,
) -> bool:
    """Attempt a single HTTP delivery and log the result.

    Returns ``True`` when the remote server responded with 2xx.
    """
    body = _build_payload_body(event_type, payload)
    signing_key = _resolve_signing_key(sub)
    signature = _compute_signature(body, signing_key)

    status_code: int | None = None
    error_message: str | None = None
    success = False
    start = time.monotonic()

    try:
        response = await client.post(
            sub.callback_url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-AgentGraph-Signature": f"sha256={signature}",
                "X-AgentGraph-Event": event_type,
            },
        )
        status_code = response.status_code
        success = 200 <= status_code < 300
        if not success:
            error_message = f"HTTP {status_code}"
    except httpx.TimeoutException as exc:
        error_message = f"Timeout: {exc}"
    except httpx.ConnectError as exc:
        error_message = f"Connection error: {exc}"
    except Exception as exc:  # noqa: BLE001
        error_message = f"Unexpected error: {exc}"

    duration_ms = int((time.monotonic() - start) * 1000)

    # Persist delivery log
    log_entry = WebhookDeliveryLog(
        id=uuid.uuid4(),
        subscription_id=sub.id,
        event_type=event_type,
        payload=payload,
        status_code=status_code,
        success=success,
        error_message=error_message,
        attempt_number=attempt,
        duration_ms=duration_ms,
    )
    db.add(log_entry)

    if success:
        logger.info(
            "Webhook delivered: sub=%s event=%s attempt=%d status=%s",
            sub.id, event_type, attempt, status_code,
        )
    else:
        logger.warning(
            "Webhook delivery failed: sub=%s event=%s attempt=%d error=%s",
            sub.id, event_type, attempt, error_message,
        )

    return success


async def _backoff_delay(attempt: int) -> None:
    """Sleep with exponential back-off plus jitter."""
    delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
    jitter = random.uniform(0, delay * 0.25)  # noqa: S311
    await asyncio.sleep(delay + jitter)


async def deliver_with_retries(
    client: httpx.AsyncClient,
    sub: WebhookSubscription,
    event_type: str,
    payload: dict[str, Any],
    db: AsyncSession,
    max_retries: int = MAX_RETRIES,
) -> bool:
    """Deliver a webhook with exponential-backoff retries.

    Updates subscription health (``consecutive_failures``, ``is_active``)
    on the session but does **not** commit — the caller is responsible for
    flushing / committing.

    Returns ``True`` if delivery eventually succeeded.
    """
    for attempt in range(1, max_retries + 1):
        success = await _deliver_single(
            client, sub, event_type, payload, attempt, db,
        )
        if success:
            # Reset failure counter on success
            if sub.consecutive_failures > 0:
                sub.consecutive_failures = 0
            return True

        # Back off before retrying (skip delay after last attempt)
        if attempt < max_retries:
            await _backoff_delay(attempt)

    # All retries exhausted — record consecutive failure
    sub.consecutive_failures = (sub.consecutive_failures or 0) + 1
    if sub.consecutive_failures >= AUTO_DEACTIVATE_THRESHOLD:
        sub.is_active = False
        logger.warning(
            "Auto-deactivated webhook sub=%s after %d consecutive failures",
            sub.id, sub.consecutive_failures,
        )

    return False


# --- Event processing ------------------------------------------------------

async def _find_matching_subscriptions(
    db: AsyncSession,
    event_type: str,
) -> list[WebhookSubscription]:
    """Return active webhook subscriptions interested in *event_type*."""
    result = await db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.is_active.is_(True),
        )
    )
    all_active = result.scalars().all()
    return [s for s in all_active if event_type in (s.event_types or [])]


async def process_event(
    event_type: str,
    payload: dict[str, Any],
    max_retries: int = MAX_RETRIES,
) -> dict[str, int]:
    """Process a single event: find matching subscriptions and deliver.

    Opens its own DB session and commits results.  Returns a summary dict::

        {"matched": N, "delivered": M, "failed": F}
    """
    async with async_session() as db:
        subs = await _find_matching_subscriptions(db, event_type)
        if not subs:
            return {"matched": 0, "delivered": 0, "failed": 0}

        delivered = 0
        failed = 0
        from src.ssrf import ssrf_safe_async_client

        async with ssrf_safe_async_client(
            timeout=REQUEST_TIMEOUT, follow_redirects=False,
        ) as client:
            for sub in subs:
                ok = await deliver_with_retries(
                    client, sub, event_type, payload, db,
                    max_retries=max_retries,
                )
                if ok:
                    delivered += 1
                else:
                    failed += 1

        await db.commit()

    summary = {
        "matched": len(subs),
        "delivered": delivered,
        "failed": failed,
    }
    logger.info(
        "Event %s processed: %d matched, %d delivered, %d failed",
        event_type, summary["matched"], summary["delivered"], summary["failed"],
    )
    return summary


# --- Redis subscriber loop -------------------------------------------------

async def _subscribe_loop() -> None:
    """Subscribe to the Redis event channel and process messages forever."""
    from src.redis_client import get_redis

    r = get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(EVENTS_CHANNEL)
    logger.info("Webhook worker subscribed to %s", EVENTS_CHANNEL)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
                event_type = data.get("event_type")
                payload = data.get("payload", {})
                if event_type:
                    await process_event(event_type, payload)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON on event channel: %s", message["data"])
            except Exception:  # noqa: BLE001
                logger.exception("Error processing event message")
    finally:
        await pubsub.unsubscribe(EVENTS_CHANNEL)
        await pubsub.close()


async def start_worker() -> None:
    """Entry point for the webhook delivery worker.

    Runs the Redis subscriber loop with automatic reconnection.
    """
    logger.info("Starting webhook delivery worker")
    while True:
        try:
            await _subscribe_loop()
        except Exception:  # noqa: BLE001
            logger.exception(
                "Webhook worker lost Redis connection; reconnecting in 5s"
            )
            await asyncio.sleep(5)


# --- CLI entry point -------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(start_worker())
