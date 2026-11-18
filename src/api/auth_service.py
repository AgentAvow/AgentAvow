from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models import (
    EmailVerification,
    Entity,
    EntityType,
    PasswordResetToken,
    TokenBlacklist,
)

# bcrypt cost for every stored password. tests/conftest.py swaps in a cheaper
# hasher for the suite; nothing in the app lowers it.
PASSWORD_HASH_ROUNDS = 12
_pwd_hasher = PasswordHash((BcryptHasher(rounds=PASSWORD_HASH_ROUNDS),))


def hash_password(password: str) -> str:
    return _pwd_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_hasher.verify(plain, hashed)


def create_access_token(entity_id: uuid.UUID, entity_type: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_access_token_expire_minutes
    )
    payload = {
        "sub": str(entity_id),
        "type": entity_type,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "kind": "access",
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(entity_id: uuid.UUID) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": str(entity_id),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "kind": "refresh",
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None


def generate_did_web(entity_id: uuid.UUID) -> str:
    return f"did:web:agentgraph.co:users:{entity_id}"


async def register_human(
    db: AsyncSession,
    email: str,
    password: str,
    display_name: str,
    registration_ip: str | None = None,
) -> Entity:
    entity_id = uuid.uuid4()
    email = email.lower()
    entity = Entity(
        id=entity_id,
        type=EntityType.HUMAN,
        email=email,
        password_hash=hash_password(password),
        display_name=display_name,
        did_web=generate_did_web(entity_id),
        registration_ip=registration_ip,
    )
    db.add(entity)
    await db.flush()
    return entity


async def get_entity_by_email(db: AsyncSession, email: str) -> Entity | None:
    result = await db.execute(
        select(Entity).where(func.lower(Entity.email) == email.lower())
    )
    return result.scalar_one_or_none()


async def get_entity_by_id(db: AsyncSession, entity_id: uuid.UUID) -> Entity | None:
    return await db.get(Entity, entity_id)


async def create_verification_token(db: AsyncSession, entity_id: uuid.UUID) -> str:
    """Create an email verification token (valid for 24 hours).

    Invalidates any previous unused tokens for the same entity.
    """
    # Invalidate old unused tokens for this entity
    await db.execute(
        update(EmailVerification)
        .where(
            EmailVerification.entity_id == entity_id,
            EmailVerification.is_used.is_(False),
        )
        .values(is_used=True)
    )

    token = secrets.token_urlsafe(48)
    verification = EmailVerification(
        id=uuid.uuid4(),
        entity_id=entity_id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(verification)
    await db.flush()
    return token


async def verify_email_token(db: AsyncSession, token: str) -> Entity | None:
    """Verify an email token and mark the entity as verified."""
    result = await db.execute(
        select(EmailVerification).where(
            EmailVerification.token == token,
            EmailVerification.is_used.is_(False),
        )
    )
    verification = result.scalar_one_or_none()
    if verification is None:
        return None

    if verification.expires_at < datetime.now(timezone.utc):
        return None

    entity = await db.get(Entity, verification.entity_id)
    if entity is None:
        return None

    verification.is_used = True
    entity.email_verified = True
    await db.flush()
    return entity


async def authenticate_human(
    db: AsyncSession, email: str, password: str
) -> Entity | None:
    email = email.lower()
    entity = await get_entity_by_email(db, email)
    if entity is None:
        # Prevent timing attacks — hash a dummy to consume same time as real verify
        _pwd_hasher.hash("timing-attack-dummy")
        return None
    if not entity.password_hash:
        # OAuth-only user — no password set, can't authenticate via password
        return None
    if not verify_password(password, entity.password_hash):
        return None
    if not entity.is_active:
        return None
    return entity


# --- Password Reset ---


async def create_password_reset_token(
    db: AsyncSession, entity_id: uuid.UUID,
) -> str:
    """Create a password reset token (valid for 1 hour).

    Invalidates any previous unused tokens for the same entity.
    """
    # Invalidate old unused tokens for this entity
    await db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.entity_id == entity_id,
            PasswordResetToken.is_used.is_(False),
        )
        .values(is_used=True)
    )

    token = secrets.token_urlsafe(48)
    reset = PasswordResetToken(
        id=uuid.uuid4(),
        entity_id=entity_id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(reset)
    await db.flush()
    return token


async def verify_password_reset_token(
    db: AsyncSession, token: str,
) -> Entity | None:
    """Verify a password reset token and return the associated entity."""
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token == token,
            PasswordResetToken.is_used.is_(False),
        )
    )
    reset = result.scalar_one_or_none()
    if reset is None:
        return None
    if reset.expires_at < datetime.now(timezone.utc):
        return None

    entity = await db.get(Entity, reset.entity_id)
    if entity is None:
        return None

    reset.is_used = True
    await db.flush()
    return entity


# --- Token Blacklist ---


async def blacklist_token(
    db: AsyncSession, jti: str, entity_id: uuid.UUID, expires_at: datetime,
) -> None:
    """Add a JWT token ID to the blacklist.

    Handles duplicate key gracefully (concurrent refresh race condition).
    """
    from sqlalchemy.exc import IntegrityError as SAIntegrityError

    entry = TokenBlacklist(
        id=uuid.uuid4(),
        jti=jti,
        entity_id=entity_id,
        expires_at=expires_at,
    )
    db.add(entry)
    try:
        await db.flush()
    except SAIntegrityError:
        await db.rollback()
        # Token already blacklisted by a concurrent request — safe to ignore


async def cleanup_expired_blacklist(db: AsyncSession) -> int:
    """Delete expired entries from the token blacklist. Returns count removed."""
    from sqlalchemy import delete

    result = await db.execute(
        delete(TokenBlacklist).where(
            TokenBlacklist.expires_at < datetime.now(timezone.utc)
        )
    )
    await db.flush()
    return result.rowcount


async def is_token_blacklisted(db: AsyncSession, jti: str) -> bool:
    """Check if a token has been blacklisted."""
    result = await db.scalar(
        select(TokenBlacklist).where(TokenBlacklist.jti == jti)
    )
    return result is not None
