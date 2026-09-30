"""API health check job — periodic uptime monitoring for registered endpoints."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from src.ssrf import ssrf_safe_async_client, validate_url

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds
_BATCH_SIZE = 10


async def run_health_checks(db) -> dict:
    """Fetch all active ApiHealthCheck records and ping each endpoint.

    Updates rolling stats (uptime percentage, response time, status code).
    Returns summary dict.
    """
    from sqlalchemy import select

    from src.models import ApiHealthCheck

    result = await db.execute(
        select(ApiHealthCheck).where(ApiHealthCheck.is_active.is_(True))
    )
    checks = list(result.scalars().all())

    if not checks:
        return {"checked": 0, "healthy": 0, "unhealthy": 0}

    healthy = 0
    unhealthy = 0

    # Process in batches
    for i in range(0, len(checks), _BATCH_SIZE):
        batch = checks[i : i + _BATCH_SIZE]
        results = await asyncio.gather(
            *[_ping(check) for check in batch],
            return_exceptions=True,
        )
        for check, ping_result in zip(batch, results):
            if isinstance(ping_result, Exception):
                logger.debug("Health check failed for %s: %s", check.endpoint_url, ping_result)
                _update_check(check, success=False, status=None, response_ms=None)
                unhealthy += 1
            else:
                success, status, response_ms = ping_result
                _update_check(check, success=success, status=status, response_ms=response_ms)
                if success:
                    healthy += 1
                else:
                    unhealthy += 1

    await db.flush()

    return {"checked": len(checks), "healthy": healthy, "unhealthy": unhealthy}


async def _ping(check) -> tuple[bool, int | None, int | None]:
    """Send a HEAD request to the endpoint and return (success, status, ms)."""
    try:
        validate_url(check.endpoint_url, field_name="endpoint_url")
    except ValueError:
        return False, None, None

    try:
        async with ssrf_safe_async_client(timeout=_TIMEOUT, follow_redirects=False) as client:
            start = asyncio.get_event_loop().time()
            resp = await client.head(check.endpoint_url)
            elapsed_ms = int((asyncio.get_event_loop().time() - start) * 1000)
            success = 200 <= resp.status_code < 500
            return success, resp.status_code, elapsed_ms
    except (httpx.HTTPError, ValueError):
        return False, None, None


def _update_check(
    check,
    *,
    success: bool,
    status: int | None,
    response_ms: int | None,
) -> None:
    """Update rolling stats on the health check record."""
    check.total_checks = (check.total_checks or 0) + 1
    if success:
        check.successful_checks = (check.successful_checks or 0) + 1
    check.last_status = status
    check.last_response_ms = response_ms
    check.last_checked_at = datetime.now(timezone.utc)

    total = check.total_checks
    successful = check.successful_checks or 0
    check.uptime_pct_30d = round(successful / total * 100, 2) if total > 0 else 0.0
