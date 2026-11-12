from __future__ import annotations

import uuid

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.auth_service import decode_token, get_entity_by_id
from src.database import get_db
from src.models import Entity

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_entity(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Entity:
    """Authenticate via Bearer JWT or X-API-Key header."""
    # Try API key first
    if x_api_key is not None:
        from src.api.agent_service import authenticate_by_api_key

        entity = await authenticate_by_api_key(db, x_api_key)
        if entity is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        return entity

    # Fall back to Bearer JWT
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    if payload is None or payload.get("kind") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check token blacklist (for logout)
    jti = payload.get("jti")
    if jti:
        from src.api.auth_service import is_token_blacklisted

        if await is_token_blacklisted(db, jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Parse entity ID from token (once)
    try:
        entity_id = uuid.UUID(payload["sub"])
    except (ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Check password-change invalidation (Redis-based, per-entity)
    from src import cache

    inv_ts = await cache.get(f"token:inv:{entity_id}")
    if inv_ts is not None and payload.get("iat", 0) <= inv_ts:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalidated by password change",
            headers={"WWW-Authenticate": "Bearer"},
        )

    entity = await get_entity_by_id(db, entity_id)
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Auto-reactivate if suspension has expired
    if not entity.is_active and entity.suspended_until is not None:
        from datetime import datetime, timezone

        if datetime.now(timezone.utc) >= entity.suspended_until:
            entity.is_active = True
            entity.suspended_until = None
            await db.flush()

    if not entity.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return entity


def require_scope(scope: str):
    """Dependency that checks API key scopes.

    If the request was authenticated via API key, verifies the key
    has the required scope. JWT-authenticated requests pass through.
    """

    async def _check_scope(
        x_api_key: str | None = Header(None),
        db: AsyncSession = Depends(get_db),
    ) -> None:
        if x_api_key is None:
            return  # JWT auth — scopes not applicable
        import hashlib

        from sqlalchemy import select as sa_select

        from src.models import APIKey

        key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
        api_key = await db.scalar(
            sa_select(APIKey).where(
                APIKey.key_hash == key_hash, APIKey.is_active.is_(True),
            )
        )
        if api_key is None:
            return  # Will be rejected by get_current_entity
        if api_key.scopes and scope not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {scope}",
            )

    return Depends(_check_scope)


def require_admin(entity: Entity) -> None:
    """Raise 403 if entity is not an admin."""
    if not entity.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )


def require_admin_or_viewer(entity: Entity) -> bool:
    """Allow a full admin or a read-only admin viewer; raise 403 for anyone else.

    Returns ``True`` when the caller is a viewer only (not a full admin): the endpoint
    must then pass its response through ``src.api.redaction.redact_for_viewer`` so
    emails, IPs and names tied to them never reach a viewer.

    Use this ONLY on read-only GET endpoints that serve metrics. Anything that changes
    state, posts, replies, toggles or manages users keeps ``require_admin``
    (tests/test_admin_viewer.py fails the build if a non-GET route uses this, or a GET
    route that is not on its reviewed list).
    """
    if entity.is_admin:
        return False
    if getattr(entity, "is_admin_viewer", False):
        return True
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin access required",
    )


async def require_not_quarantined(
    current_entity: Entity = Depends(get_current_entity),
) -> Entity:
    """Reject request if entity is quarantined."""
    if getattr(current_entity, "is_quarantined", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is quarantined. Contact support for details.",
        )
    return current_entity


async def require_not_frozen():
    """Reject write operations if propagation freeze is active."""
    from src.safety.propagation import is_propagation_frozen

    if await is_propagation_frozen():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform safety pause in effect. Please try again later.",
        )


async def get_optional_entity(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Entity | None:
    if credentials is None and x_api_key is None:
        return None
    try:
        return await get_current_entity(credentials, x_api_key, db)
    except HTTPException:
        return None


# Alias with consistent naming (matches get_current_entity)
get_optional_current_entity = get_optional_entity
