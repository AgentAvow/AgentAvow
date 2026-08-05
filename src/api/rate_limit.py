"""Rate limiting using Redis sliding window counters.

Supports per-IP and per-entity limits for reads, writes, and auth.
Falls back to in-memory tracking if Redis is unavailable.

Tiered rate limiting (rate_limit_reads_tiered / rate_limit_writes_tiered)
applies different limits based on entity type and trust score:
  - anonymous: lowest limits (no auth)
  - human: default limits (authenticated human)
  - agent: higher limits (entity.type == "agent")
  - trusted_agent: highest limits (agent with trust_score > threshold)
"""
from __future__ import annotations

import enum
import logging
import time

from fastapi import Depends, HTTPException, Request, status

from src.config import settings

logger = logging.getLogger(__name__)


class RateLimitTier(str, enum.Enum):
    """Rate limit tier based on entity type and trust score."""
    ANONYMOUS = "anonymous"
    PROVISIONAL = "provisional"
    HUMAN = "human"
    AGENT = "agent"
    TRUSTED_AGENT = "trusted_agent"


class RedisRateLimiter:
    """Rate limiter backed by Redis sorted sets (sliding window).

    Each key is a Redis sorted set where members are unique request IDs
    and scores are timestamps. This provides accurate sliding window
    counting that works across multiple Gunicorn workers.

    Falls back to in-memory when Redis is unreachable.
    """

    def __init__(self) -> None:
        self._fallback: dict[str, list[float]] = {}

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        try:
            from src.redis_client import get_redis

            r = get_redis()
            now = time.time()
            redis_key = f"rl:{key}"

            pipe = r.pipeline()
            pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipe.zcard(redis_key)
            pipe.zadd(redis_key, {f"{now}:{id(pipe)}": now})
            pipe.expire(redis_key, window_seconds + 1)
            results = await pipe.execute()

            count = results[1]
            if count >= limit:
                # Remove the entry we just added
                await r.zrem(redis_key, f"{now}:{id(pipe)}")
                return False
            return True
        except Exception:
            return self._check_fallback(key, limit, window_seconds)

    async def get_remaining(self, key: str, limit: int, window_seconds: int = 60) -> int:
        """Return how many requests remain in the current window."""
        try:
            from src.redis_client import get_redis

            r = get_redis()
            now = time.time()
            redis_key = f"rl:{key}"
            await r.zremrangebyscore(redis_key, 0, now - window_seconds)
            count = await r.zcard(redis_key)
            return max(0, limit - count)
        except Exception:
            return self._remaining_fallback(key, limit, window_seconds)

    async def get_reset_time(self, key: str, window_seconds: int = 60) -> int:
        """Return seconds until the oldest request in the window expires."""
        try:
            from src.redis_client import get_redis

            r = get_redis()
            redis_key = f"rl:{key}"
            oldest = await r.zrange(redis_key, 0, 0, withscores=True)
            if not oldest:
                return 0
            return max(0, int(window_seconds - (time.time() - oldest[0][1])))
        except Exception:
            return self._reset_fallback(key, window_seconds)

    # --- In-memory fallbacks ---

    def _clean_window(self, key: str, window_seconds: int) -> None:
        now = time.time()
        if key in self._fallback:
            self._fallback[key] = [
                t for t in self._fallback[key] if now - t < window_seconds
            ]

    def _check_fallback(self, key: str, limit: int, window_seconds: int) -> bool:
        self._clean_window(key, window_seconds)
        if key not in self._fallback:
            self._fallback[key] = []
        if len(self._fallback[key]) >= limit:
            return False
        self._fallback[key].append(time.time())
        return True

    def _remaining_fallback(self, key: str, limit: int, window_seconds: int) -> int:
        self._clean_window(key, window_seconds)
        used = len(self._fallback.get(key, []))
        return max(0, limit - used)

    def _reset_fallback(self, key: str, window_seconds: int) -> int:
        if key not in self._fallback or not self._fallback[key]:
            return 0
        oldest = min(self._fallback[key])
        return max(0, int(window_seconds - (time.time() - oldest)))

    def clear(self) -> None:
        """Clear in-memory fallback. For testing."""
        self._fallback.clear()

    async def clear_all(self) -> None:
        """Clear in-memory fallback AND Redis rate limit keys. For testing."""
        self._fallback.clear()
        try:
            from src.redis_client import get_redis

            r = get_redis()
            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor, match="rl:*", count=200)
                if keys:
                    await r.delete(*keys)
                if cursor == 0:
                    break
        except Exception:
            pass


# Global instance
_limiter = RedisRateLimiter()


def _get_client_ip(request: Request) -> str:
    from src.config import settings

    direct_ip = request.client.host if request.client else "unknown"
    # Only trust X-Forwarded-For when the direct client is a known proxy
    if direct_ip in settings.trusted_proxies:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Walk the chain right-to-left, skip any IPs that are also
            # trusted proxies, and return the first non-proxy IP.  This is
            # the standard secure approach: the rightmost non-trusted IP is
            # the real client, because a trusted proxy appended it.
            ips = [ip.strip() for ip in forwarded.split(",")]
            for ip in reversed(ips):
                if ip and ip not in settings.trusted_proxies:
                    return ip
            # All IPs are trusted proxies — fall through to direct_ip
    return direct_ip


def _get_entity_id(request: Request) -> str | None:
    """Extract entity ID from request state if authenticated."""
    return getattr(request.state, "entity_id", None)


def _rate_limit_response(
    remaining: int, limit: int, window: int = 60,
) -> dict[str, str]:
    """Generate rate limit headers."""
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Window": str(window),
    }


async def _set_rate_limit_headers(
    request: Request, key: str, limit: int, window: int = 60,
) -> None:
    """Store rate limit info on request state for middleware to add to response."""
    remaining = await _limiter.get_remaining(key, limit, window)
    reset = await _limiter.get_reset_time(key, window)
    request.state.rate_limit_limit = limit
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_reset = reset


async def rate_limit_reads(request: Request) -> None:
    ip = _get_client_ip(request)
    limit = settings.rate_limit_reads_per_minute
    key = f"read:{ip}"
    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers=_rate_limit_response(0, limit),
        )
    entity_id = _get_entity_id(request)
    effective_limit = limit * 3 if entity_id else limit
    await _set_rate_limit_headers(request, key, effective_limit)
    if entity_id:
        if not await _limiter.check(f"read:entity:{entity_id}", effective_limit):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers=_rate_limit_response(0, effective_limit),
            )


async def rate_limit_history_reads(request: Request) -> None:
    """Tighter limit for /history endpoint.

    Each call does live-fetch + JCS canonicalize + JWS sign + DB lookup.
    Capped at settings.rate_limit_history_reads_per_minute (default 10/min/IP)
    to keep launch-week press traffic from saturating the JWS signing path.
    """
    ip = _get_client_ip(request)
    limit = settings.rate_limit_history_reads_per_minute
    key = f"history_read:{ip}"
    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers=_rate_limit_response(0, limit),
        )
    await _set_rate_limit_headers(request, key, limit)


async def rate_limit_writes(request: Request) -> None:
    ip = _get_client_ip(request)
    limit = settings.rate_limit_writes_per_minute
    key = f"write:{ip}"
    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers=_rate_limit_response(0, limit),
        )
    entity_id = _get_entity_id(request)
    effective_limit = limit * 3 if entity_id else limit
    await _set_rate_limit_headers(request, key, effective_limit)
    if entity_id:
        if not await _limiter.check(f"write:entity:{entity_id}", effective_limit):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers=_rate_limit_response(0, effective_limit),
            )


async def rate_limit_scans(request: Request) -> None:
    """Tighter per-IP limit for on-demand /public/scan/{owner}/{repo}.

    A cache miss clones + scans a repo, so this is the abuse-prone path. Capped at
    settings.rate_limit_scans_per_minute per IP (default 20/min); authenticated
    callers get 3x. Cache hits count too, but the cap is generous for real users.
    """
    ip = _get_client_ip(request)
    limit = settings.rate_limit_scans_per_minute
    key = f"scan:{ip}"
    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Scan rate limit exceeded — sign in for a higher limit, or retry shortly.",
            headers=_rate_limit_response(0, limit),
        )
    entity_id = _get_entity_id(request)
    effective_limit = limit * 3 if entity_id else limit
    await _set_rate_limit_headers(request, key, effective_limit)
    if entity_id:
        if not await _limiter.check(f"scan:entity:{entity_id}", effective_limit):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Scan rate limit exceeded — try again in a minute.",
                headers=_rate_limit_response(0, effective_limit),
            )


async def rate_limit_export(request: Request) -> None:
    """Very strict limit for heavy export endpoints (5/hour)."""
    ip = _get_client_ip(request)
    key = f"export:{ip}"
    limit = 5
    window = 3600
    if not await _limiter.check(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Export rate limit exceeded. Try again later.",
            headers=_rate_limit_response(0, limit, window),
        )
    entity_id = _get_entity_id(request)
    if entity_id:
        ekey = f"export:entity:{entity_id}"
        if not await _limiter.check(ekey, limit, window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Export rate limit exceeded. Try again later.",
                headers=_rate_limit_response(0, limit, window),
            )
    await _set_rate_limit_headers(request, key, limit, window)


async def rate_limit_auth(request: Request) -> None:
    """Stricter limit for auth endpoints."""
    ip = _get_client_ip(request)
    limit = settings.rate_limit_auth_per_minute
    key = f"auth:{ip}"
    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers=_rate_limit_response(0, limit),
        )
    await _set_rate_limit_headers(request, key, limit)


# ---------------------------------------------------------------------------
# Tiered rate limiting — entity-type-aware limits
# ---------------------------------------------------------------------------


async def _get_optional_entity_safe(
    request: Request,
) -> object | None:
    """Resolve the authenticated entity without raising on anonymous requests.

    This is a lightweight wrapper that extracts credentials from the request
    headers and resolves the entity via the existing auth service helpers.
    Returns ``None`` for unauthenticated requests or on any error.

    Note: This is intentionally NOT a FastAPI ``Depends()`` on
    ``get_optional_entity`` to avoid adding ``get_db`` as a sub-dependency
    (which would open a second DB session in the rate-limiter dependency
    chain). Instead it manually opens a short-lived session only when
    credentials are present.
    """
    try:
        auth_header = request.headers.get("authorization", "")
        api_key_header = request.headers.get("x-api-key")

        if not auth_header.startswith("Bearer ") and api_key_header is None:
            return None

        from src.api.auth_service import decode_token, get_entity_by_id
        from src.database import async_session

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = decode_token(token)
            if payload is None or payload.get("kind") != "access":
                return None
            import uuid as _uuid

            try:
                entity_id = _uuid.UUID(payload["sub"])
            except (ValueError, KeyError):
                return None
            async with async_session() as session:
                return await get_entity_by_id(session, entity_id)

        if api_key_header is not None:
            from src.api.agent_service import authenticate_by_api_key

            async with async_session() as session:
                return await authenticate_by_api_key(session, api_key_header)
    except Exception:
        logger.debug("Tiered rate limiter: failed to resolve entity", exc_info=True)
    return None


async def _get_entity_trust_score(entity_id: str) -> float | None:
    """Fetch cached trust score for an entity. Returns None if unavailable."""
    try:
        from src import cache

        cached = await cache.get(f"trust:{entity_id}")
        if cached is not None:
            # cached value is a dict with a "score" key from the trust router
            if isinstance(cached, dict):
                return cached.get("score")
            # In case it's stored as a bare float
            return float(cached)
    except Exception:
        pass
    return None


def _resolve_tier(entity: object | None) -> RateLimitTier:
    """Determine the rate limit tier for an entity.

    Args:
        entity: The Entity model instance, or None for anonymous requests.
                Uses duck-typing to avoid importing the Entity model here.

    Returns:
        The appropriate RateLimitTier.
    """
    if entity is None:
        return RateLimitTier.ANONYMOUS

    entity_type = getattr(entity, "type", None)
    if entity_type is None:
        return RateLimitTier.HUMAN

    # EntityType is a str enum — getattr(entity_type, "value", entity_type)
    # handles both raw strings and enum instances.
    type_value = getattr(entity_type, "value", entity_type)
    if str(type_value).lower() == "agent":
        # Check if provisional (most restricted agent tier)
        if getattr(entity, "is_provisional", False):
            return RateLimitTier.PROVISIONAL
        return RateLimitTier.AGENT  # May be upgraded to TRUSTED_AGENT later

    return RateLimitTier.HUMAN


async def _maybe_upgrade_to_trusted(
    tier: RateLimitTier, entity: object | None,
) -> RateLimitTier:
    """Upgrade an AGENT tier to TRUSTED_AGENT if their trust score exceeds
    the configured threshold. Only queries cache — no DB hit.
    """
    if tier != RateLimitTier.AGENT or entity is None:
        return tier

    entity_id = getattr(entity, "id", None)
    if entity_id is None:
        return tier

    score = await _get_entity_trust_score(str(entity_id))
    if score is not None and score > settings.rate_limit_trusted_agent_threshold:
        return RateLimitTier.TRUSTED_AGENT

    return tier


def _tier_read_limit(tier: RateLimitTier) -> int:
    """Return the per-minute read limit for a given tier."""
    if tier == RateLimitTier.ANONYMOUS:
        return settings.rate_limit_anon_reads_per_minute
    if tier == RateLimitTier.PROVISIONAL:
        return settings.rate_limit_provisional_reads_per_minute
    if tier == RateLimitTier.AGENT:
        return settings.rate_limit_agent_reads_per_minute
    if tier == RateLimitTier.TRUSTED_AGENT:
        return settings.rate_limit_trusted_agent_reads_per_minute
    # HUMAN (default)
    return settings.rate_limit_reads_per_minute


def _tier_write_limit(tier: RateLimitTier) -> int:
    """Return the per-minute write limit for a given tier."""
    if tier == RateLimitTier.ANONYMOUS:
        return settings.rate_limit_anon_writes_per_minute
    if tier == RateLimitTier.PROVISIONAL:
        return settings.rate_limit_provisional_writes_per_minute
    if tier == RateLimitTier.AGENT:
        return settings.rate_limit_agent_writes_per_minute
    if tier == RateLimitTier.TRUSTED_AGENT:
        return settings.rate_limit_trusted_agent_writes_per_minute
    # HUMAN (default)
    return settings.rate_limit_writes_per_minute


def _trust_scaled_limit(base_limit: int, trust_score: float | None) -> int:
    """Scale a rate limit based on continuous trust score.

    Entities with higher trust scores get proportionally higher limits:
      - score 0.0: base_limit (1.0x)
      - score 0.5: base_limit * 1.5x
      - score 0.7: base_limit * 2.0x
      - score 0.9: base_limit * 3.0x
      - score 1.0: base_limit * 3.5x

    The scaling is piecewise-linear for predictability.
    """
    if trust_score is None or trust_score <= 0:
        return base_limit
    score = min(trust_score, 1.0)
    # Piecewise: [0, 0.5] -> [1.0, 1.5], [0.5, 0.7] -> [1.5, 2.0],
    #            [0.7, 0.9] -> [2.0, 3.0], [0.9, 1.0] -> [3.0, 3.5]
    if score <= 0.5:
        multiplier = 1.0 + score
    elif score <= 0.7:
        multiplier = 1.5 + (score - 0.5) * 2.5
    elif score <= 0.9:
        multiplier = 2.0 + (score - 0.7) * 5.0
    else:
        multiplier = 3.0 + (score - 0.9) * 5.0
    return int(base_limit * multiplier)


async def _check_tiered(
    request: Request,
    kind: str,
    limit: int,
    entity: object | None,
    tier: RateLimitTier,
) -> None:
    """Core tiered rate-limit check for both reads and writes.

    Applies per-IP limit first, then per-entity limit if authenticated.
    """
    ip = _get_client_ip(request)
    key = f"{kind}:{ip}"

    if not await _limiter.check(key, limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers=_rate_limit_response(0, limit),
        )

    await _set_rate_limit_headers(request, key, limit)

    # Per-entity check (only for authenticated callers)
    entity_id = getattr(entity, "id", None) if entity else None
    if entity_id is not None:
        entity_key = f"{kind}:entity:{entity_id}"
        if not await _limiter.check(entity_key, limit):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers=_rate_limit_response(0, limit),
            )

    # Store tier info on request state for info endpoints
    request.state.rate_limit_tier = tier.value
    request.state.rate_limit_effective = limit


async def _resolve_trust_scaled_limit(
    entity: object | None, tier: RateLimitTier, base_limit: int,
) -> int:
    """Apply continuous trust-score scaling on top of tier limits."""
    if entity is None:
        return base_limit
    entity_id = getattr(entity, "id", None)
    if entity_id is None:
        return base_limit
    score = await _get_entity_trust_score(str(entity_id))
    if score is not None:
        return _trust_scaled_limit(base_limit, score)
    return base_limit


async def rate_limit_reads_tiered(
    request: Request,
    entity: object | None = Depends(_get_optional_entity_safe),
) -> None:
    """Rate-limit reads using entity-aware tiers with trust scaling.

    Automatically resolves the caller's tier (anonymous / human / agent /
    trusted_agent) and applies the corresponding per-minute read limit,
    further scaled by their continuous trust score.
    """
    tier = _resolve_tier(entity)
    tier = await _maybe_upgrade_to_trusted(tier, entity)
    base_limit = _tier_read_limit(tier)
    limit = await _resolve_trust_scaled_limit(entity, tier, base_limit)
    await _check_tiered(request, "read", limit, entity, tier)


async def rate_limit_writes_tiered(
    request: Request,
    entity: object | None = Depends(_get_optional_entity_safe),
) -> None:
    """Rate-limit writes using entity-aware tiers with trust scaling.

    Automatically resolves the caller's tier and applies the corresponding
    per-minute write limit, further scaled by their continuous trust score.
    """
    tier = _resolve_tier(entity)
    tier = await _maybe_upgrade_to_trusted(tier, entity)
    base_limit = _tier_write_limit(tier)
    limit = await _resolve_trust_scaled_limit(entity, tier, base_limit)
    await _check_tiered(request, "write", limit, entity, tier)


def get_tier_info() -> dict:
    """Return a summary of all rate limit tiers and their limits."""
    return {
        "tiers": [
            {
                "tier": RateLimitTier.ANONYMOUS.value,
                "description": "Unauthenticated requests",
                "reads_per_minute": settings.rate_limit_anon_reads_per_minute,
                "writes_per_minute": settings.rate_limit_anon_writes_per_minute,
                "trust_scaling": False,
            },
            {
                "tier": RateLimitTier.PROVISIONAL.value,
                "description": "Unclaimed/provisional agents",
                "reads_per_minute": settings.rate_limit_provisional_reads_per_minute,
                "writes_per_minute": settings.rate_limit_provisional_writes_per_minute,
                "trust_scaling": False,
            },
            {
                "tier": RateLimitTier.HUMAN.value,
                "description": "Authenticated human users",
                "reads_per_minute": settings.rate_limit_reads_per_minute,
                "writes_per_minute": settings.rate_limit_writes_per_minute,
                "trust_scaling": True,
            },
            {
                "tier": RateLimitTier.AGENT.value,
                "description": "Authenticated agent entities",
                "reads_per_minute": settings.rate_limit_agent_reads_per_minute,
                "writes_per_minute": settings.rate_limit_agent_writes_per_minute,
                "trust_scaling": True,
            },
            {
                "tier": RateLimitTier.TRUSTED_AGENT.value,
                "description": (
                    f"Agents with trust score > "
                    f"{settings.rate_limit_trusted_agent_threshold}"
                ),
                "reads_per_minute": (
                    settings.rate_limit_trusted_agent_reads_per_minute
                ),
                "writes_per_minute": (
                    settings.rate_limit_trusted_agent_writes_per_minute
                ),
                "trust_scaling": True,
            },
        ],
        "trust_scaling_info": {
            "description": (
                "Authenticated entities get additional rate limit "
                "increases based on their trust score"
            ),
            "multipliers": {
                "0.0": "1.0x (base)",
                "0.5": "1.5x",
                "0.7": "2.0x",
                "0.9": "3.0x",
                "1.0": "3.5x",
            },
        },
    }
