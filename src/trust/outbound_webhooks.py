"""Outbound scan-change webhooks — notify external providers when scan scores change.

When a security scan result changes for a watched repo, we POST to registered
callback URLs (e.g. MoltBridge). Fire-and-forget with 10s timeout.

Signature scheme: every outbound event carries a JWS in the body (verifiable via
our JWKS at /.well-known/jwks.json). Subscriptions may also register a shared
HMAC signing secret; if present, the outbound request additionally carries:

    X-Partner-Signature: sha256=<hex>  (HMAC-SHA256 over the raw JSON body)
    X-Partner-Timestamp: <ISO-8601>    (±5 minute window, receiver enforced)

This symmetric scheme matches the MoltBridge/VeroQ Shield partner contract and
lets partners verify without fetching our JWKS on every call.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import httpx

from src.signing import canonicalize, create_jws

logger = logging.getLogger(__name__)

# Redis key prefix for webhook subscriptions
_WEBHOOK_PREFIX = "outbound_webhook:"


async def _get_subscriptions(repo: str) -> list[dict]:
    """Look up registered webhook URLs for a repo from Redis.

    Each subscription is stored as a JSON dict:
        {repo, callback_url, provider, registered_at}
    under key ``outbound_webhook:<repo>`` as a Redis list.
    """
    try:
        from src import cache

        data = await cache.get(f"{_WEBHOOK_PREFIX}{repo}")
        if data and isinstance(data, list):
            return data
    except Exception:
        logger.debug("Failed to read webhook subscriptions for %s", repo)
    return []


async def register_subscription(
    repo: str,
    callback_url: str,
    provider: str,
    signing_secret: str | None = None,
) -> dict:
    """Register an outbound webhook subscription for a repo.

    Stores in Redis as a list of dicts under ``outbound_webhook:<repo>``.
    Returns the subscription record (without the signing_secret).

    If ``signing_secret`` is provided, the outbound POST will additionally
    carry ``X-Partner-Signature`` / ``X-Partner-Timestamp`` headers computed
    with HMAC-SHA256 over the raw body.
    """
    from src import cache

    record = {
        "repo": repo,
        "callback_url": callback_url,
        "provider": provider,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    if signing_secret:
        record["signing_secret"] = signing_secret

    existing = await _get_subscriptions(repo)

    # Deduplicate by callback_url + provider
    existing = [
        s for s in existing
        if not (s.get("callback_url") == callback_url and s.get("provider") == provider)
    ]
    existing.append(record)

    # Store with no expiry (0 = persist)
    await cache.set(f"{_WEBHOOK_PREFIX}{repo}", existing, ttl=0)
    logger.info(
        "Registered outbound webhook: repo=%s provider=%s url=%s hmac=%s",
        repo, provider, callback_url, bool(signing_secret),
    )
    # Return a sanitized copy without the secret
    return {k: v for k, v in record.items() if k != "signing_secret"}


async def notify_scan_change(
    repo: str,
    new_score: int,
    old_score: int | None,
) -> None:
    """Notify registered webhooks that a scan score changed for a repo.

    Sends a signed POST to each registered callback URL. Fire-and-forget:
    failures are logged but do not block the caller.

    Args:
        repo: owner/repo identifier
        new_score: new security scan score (0-100)
        old_score: previous score, or None if first scan
    """
    subscriptions = await _get_subscriptions(repo)
    if not subscriptions:
        return

    now = datetime.now(timezone.utc).isoformat()

    # Canonical event type for partner routing is "scan-change" (per A2A partner
    # spec). Keep legacy "ScanScoreChanged" as an alias for older consumers.
    payload_dict = {
        "type": "scan-change",
        "legacy_type": "ScanScoreChanged",
        "repo": repo,
        "new_score": new_score,
        "old_score": old_score,
        "changed_at": now,
    }
    payload_bytes = canonicalize(payload_dict)
    jws = create_jws(payload_bytes)

    body = {
        "type": "scan-change",
        "repo": repo,
        "new_score": new_score,
        "old_score": old_score,
        "changed_at": now,
        "jws": jws,
    }
    # Serialize once — HMAC must be computed over the exact bytes sent on the wire
    # so the receiver can verify byte-for-byte.
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")

    for sub in subscriptions:
        callback_url = sub.get("callback_url")
        provider = sub.get("provider", "unknown")
        signing_secret = sub.get("signing_secret")
        if not callback_url:
            continue

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AgentGraph-Webhook/1.0",
            "X-AgentGraph-Event": "scan-change",
        }
        if signing_secret:
            mac = hmac.new(
                signing_secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Partner-Signature"] = f"sha256={mac}"
            headers["X-Partner-Timestamp"] = now

        try:
            from src.ssrf import ssrf_safe_async_client, validate_url_https

            validate_url_https(callback_url, field_name="callback_url")
            async with ssrf_safe_async_client(timeout=10.0, follow_redirects=False) as client:
                resp = await client.post(
                    callback_url,
                    content=body_bytes,
                    headers=headers,
                )
            logger.info(
                "Outbound webhook delivered: repo=%s provider=%s status=%d hmac=%s",
                repo, provider, resp.status_code, bool(signing_secret),
            )
        except httpx.TimeoutException:
            logger.warning(
                "Outbound webhook timeout: repo=%s provider=%s url=%s",
                repo, provider, callback_url,
            )
        except Exception:
            logger.exception(
                "Outbound webhook failed: repo=%s provider=%s url=%s",
                repo, provider, callback_url,
            )
