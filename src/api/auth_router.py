from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.auth_service import (
    authenticate_human,
    blacklist_token,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    create_verification_token,
    decode_token,
    get_entity_by_email,
    get_entity_by_id,
    hash_password,
    register_human,
    verify_email_token,
    verify_password_reset_token,
)
from src.api.deps import get_current_entity
from src.api.github_oauth import (
    exchange_github_code,
    fetch_github_email,
    get_github_auth_url,
)
from src.api.google_auth import exchange_google_code, get_google_auth_url
from src.api.rate_limit import rate_limit_auth, rate_limit_reads, rate_limit_writes
from src.api.schemas import (
    ChangeEmailRequest,
    EntityResponse,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from src.audit import log_action
from src.config import settings
from src.database import get_db
from src.models import AnalyticsEvent, Entity

logger = logging.getLogger(__name__)

# Allowed platforms for OAuth redirect — prevents open redirect via state param
_ALLOWED_OAUTH_PLATFORMS = {"", "ios"}

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_auth)],
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    session_id: str | None = Query(None, max_length=64),
):
    # Content filter on display_name
    from src.content_filter import check_content, sanitize_text

    filter_result = check_content(body.display_name)
    if not filter_result.is_clean:
        raise HTTPException(
            status_code=400,
            detail=f"Display name rejected: {', '.join(filter_result.flags)}",
        )
    body.display_name = sanitize_text(body.display_name)

    body.email = body.email.lower()
    existing = await get_entity_by_email(db, body.email)
    if existing is not None:
        # Don't reveal whether email exists — return same shape as success
        return MessageResponse(
            message="Registration successful. Please check your email for verification.",
        )

    reg_ip = request.client.host if request.client else None
    entity = await register_human(
        db, body.email, body.password, body.display_name,
        registration_ip=reg_ip,
    )
    verification_token = await create_verification_token(db, entity.id)

    await log_action(
        db,
        action="auth.register",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    # Record conversion analytics event linking session to new entity
    if session_id:
        db.add(AnalyticsEvent(
            event_type="register_complete",
            session_id=session_id,
            page="/register",
            entity_id=entity.id,
            ip_address=request.client.host if request.client else None,
        ))
        await db.flush()

    # Send verification email (best-effort — don't fail registration if email fails)
    from src.email import send_verification_email

    await send_verification_email(body.email, verification_token)

    # Commit before emitting so event handlers can see the new entity
    await db.commit()

    # Bootstrap trust score so new users can immediately use DMs etc.
    try:
        from src.trust.score import compute_trust_score

        await compute_trust_score(db, entity.id)
        await db.commit()
    except Exception:
        logger.warning("Failed to bootstrap trust score for %s", entity.id, exc_info=True)

    # Emit registration event for bot reactions (WelcomeBot)
    from src.events import emit

    await emit("entity.registered", {
        "entity_id": str(entity.id),
        "display_name": entity.display_name,
        "entity_type": "human",
    })

    return MessageResponse(
        message="Registration successful. Please check your email for verification.",
    )


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limit_auth)])
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Progressive delay after failed login attempts (per-IP + per-email)
    body.email = body.email.lower()

    from src import cache

    ip = request.client.host if request.client else "unknown"
    fail_key_ip = f"login:fail:{ip}"
    fail_key_email = f"login:fail:email:{body.email.lower()}"
    fail_count_ip = int(await cache.get(fail_key_ip) or 0)
    fail_count_email = int(await cache.get(fail_key_email) or 0)

    # Block if either IP or email has too many failures
    if fail_count_ip >= 10 or fail_count_email >= 20:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again in 15 minutes.",
        )
    fail_count = max(fail_count_ip, fail_count_email)
    if fail_count >= 5:
        delay = min(2 ** (fail_count - 5), 16)  # 1s, 2s, 4s, 8s, 16s
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={"detail": "Too many login attempts. Please try again later."},
            headers={"Retry-After": str(int(delay))},
        )

    entity = await authenticate_human(db, body.email, body.password)
    if entity is None:
        await cache.set(fail_key_ip, fail_count_ip + 1, ttl=900)  # 15 min window
        await cache.set(fail_key_email, fail_count_email + 1, ttl=900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Reset on success
    if fail_count_ip > 0:
        await cache.invalidate(fail_key_ip)
    if fail_count_email > 0:
        await cache.invalidate(fail_key_email)

    await log_action(
        db,
        action="auth.login",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    access_token = create_access_token(entity.id, entity.type.value)
    refresh_token = create_refresh_token(entity.id)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh", response_model=TokenResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if payload is None or payload.get("kind") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Reject blacklisted refresh tokens (rotation / logout)
    old_jti = payload.get("jti")
    if old_jti:
        from src.api.auth_service import is_token_blacklisted

        if await is_token_blacklisted(db, old_jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
            )

    entity = await get_entity_by_id(db, payload["sub"])
    if entity is None or not entity.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Snapshot the scalars we need while the entity is freshly loaded in this
    # async context. Reading ORM attributes AFTER the later awaits (cache,
    # blacklist) can raise MissingGreenlet if the greenlet/session context shifts
    # under Starlette's BaseHTTPMiddleware TaskGroup — the /auth/refresh Sentry issue.
    entity_id = entity.id
    entity_type_value = entity.type.value

    # Check password-change invalidation
    from src import cache

    inv_ts = await cache.get(f"token:inv:{entity_id}")
    if inv_ts is not None and payload.get("iat", 0) <= inv_ts:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalidated by password change",
        )

    # Blacklist the old refresh token to prevent reuse (token rotation)
    if old_jti:
        from datetime import datetime, timezone

        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        await blacklist_token(db, old_jti, entity_id, exp)

    access_token = create_access_token(entity_id, entity_type_value)
    refresh_token = create_refresh_token(entity_id)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.get(
    "/me", response_model=EntityResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_me(current_entity: Entity = Depends(get_current_entity)):
    return current_entity


@router.post(
    "/verify-email", response_model=MessageResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    """Verify email address using the token from registration."""
    entity = await verify_email_token(db, token)
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    # Send welcome email (best-effort)
    from src.email import send_welcome_email

    await send_welcome_email(entity.email, entity.display_name)

    return MessageResponse(message="Email verified successfully")


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def resend_verification(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Resend email verification token."""
    if current_entity.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    token = await create_verification_token(db, current_entity.id)

    from src.email import send_verification_email

    await send_verification_email(current_entity.email, token)

    return MessageResponse(
        message="Verification email sent. Please check your inbox.",
    )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Request a password reset token.

    Always returns success to prevent email enumeration.
    In production, the token would be emailed rather than returned.
    """
    body.email = body.email.lower()

    entity = await get_entity_by_email(db, body.email)
    if entity is None or not entity.is_active:
        # Don't reveal whether account exists
        return MessageResponse(
            message="If an account with that email exists, a reset token has been generated.",
        )

    # Per-email rate limiting: max 3 reset requests per hour
    from src import cache

    reset_key = f"password_reset:{body.email}"
    reset_count = int(await cache.get(reset_key) or 0)
    if reset_count >= 3:
        # Don't reveal whether account exists — return same message
        return MessageResponse(
            message="If an account with that email exists, a reset link has been sent.",
        )
    await cache.set(reset_key, reset_count + 1, ttl=3600)  # 1 hour window

    token = await create_password_reset_token(db, entity.id)

    # Send reset email (best-effort)
    from src.email import send_password_reset_email

    await send_password_reset_email(entity.email, token)

    await log_action(
        db,
        action="auth.password_reset_requested",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    return MessageResponse(
        message="If an account with that email exists, a reset link has been sent.",
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Reset password using a valid reset token."""
    entity = await verify_password_reset_token(db, body.token)
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    entity.password_hash = hash_password(body.new_password)
    await db.flush()

    # Invalidate all existing sessions — tokens with iat <= this value
    # are rejected in deps.py and refresh. Same pattern as change_password.
    import time

    from src import cache

    await cache.set(
        f"token:inv:{entity.id}",
        int(time.time()),
        ttl=settings.jwt_refresh_token_expire_days * 86400,
    )

    await log_action(
        db,
        action="auth.password_reset",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    return MessageResponse(
        message="Password reset successful. All sessions invalidated. Please log in.",
    )


@router.post(
    "/change-email",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit_auth)],
)
async def change_email(
    body: ChangeEmailRequest,
    request: Request,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Change email address. Requires current password. Sends verification."""
    body.new_email = body.new_email.lower()

    # Verify current password
    authed = await authenticate_human(
        db, current_entity.email, body.current_password,
    )
    if authed is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid current password",
        )

    # Check new email not taken — return same message to prevent enumeration
    existing = await get_entity_by_email(db, body.new_email)
    if existing is not None:
        return MessageResponse(
            message="Email changed. Please check your new email for verification.",
        )

    # Update email and reset verification
    current_entity.email = body.new_email
    current_entity.email_verified = False
    await db.flush()

    # Create verification token for new email
    verification_token = await create_verification_token(db, current_entity.id)

    from src.email import send_verification_email

    await send_verification_email(body.new_email, verification_token)

    await log_action(
        db,
        action="auth.email_changed",
        entity_id=current_entity.id,
        details={"new_email": body.new_email},
        ip_address=request.client.host if request.client else None,
    )

    return MessageResponse(
        message="Email changed. Please check your new email for verification.",
    )


@router.post(
    "/logout", response_model=MessageResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def logout(
    request: Request,
    body: LogoutRequest | None = None,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Logout and revoke the current access token and refresh token."""
    from datetime import datetime, timezone

    from src.api.auth_service import decode_token as _decode

    # Blacklist the access token
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    payload = _decode(token)

    if payload and payload.get("jti"):
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        await blacklist_token(db, payload["jti"], current_entity.id, exp)

    # Blacklist the refresh token if provided (verify ownership first)
    if body and body.refresh_token:
        refresh_payload = _decode(body.refresh_token)
        if refresh_payload and refresh_payload.get("jti"):
            # Only blacklist if the token belongs to the requesting user
            token_sub = refresh_payload.get("sub")
            if token_sub and str(token_sub) == str(current_entity.id):
                exp = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)
                await blacklist_token(
                    db, refresh_payload["jti"], current_entity.id, exp,
                )

    await log_action(
        db,
        action="auth.logout",
        entity_id=current_entity.id,
        ip_address=request.client.host if request.client else None,
    )

    return MessageResponse(message="Logged out successfully")


@router.get("/google", dependencies=[Depends(rate_limit_auth)])
async def google_login(request: Request, platform: str | None = None):
    """Redirect to Google OAuth2 consent screen."""
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")
    redirect_uri = f"{settings.base_url}/api/v1/auth/google/callback"

    # CSRF protection: sign the state with HMAC so the callback can verify it
    import hashlib
    import hmac
    import time

    ts = str(int(time.time()))
    plat = platform or ""
    state_data = f"{ts}:{plat}"
    sig = hmac.new(
        settings.jwt_secret.encode(), state_data.encode(), hashlib.sha256,
    ).hexdigest()[:32]
    state = f"{state_data}:{sig}"

    url = get_google_auth_url(redirect_uri, state=state)
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=url)


@router.get("/google/callback", dependencies=[Depends(rate_limit_auth)])
async def google_callback(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    state: str | None = None,
):
    """Handle Google OAuth2 callback -- create or link account, return tokens."""
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    # CSRF protection: verify the HMAC-signed state parameter
    import hashlib
    import hmac
    import time

    if not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state parameter")

    parts = state.rsplit(":", 2)
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    ts_str, platform, sig = parts
    state_data = f"{ts_str}:{platform}"
    expected_sig = hmac.new(
        settings.jwt_secret.encode(), state_data.encode(), hashlib.sha256,
    ).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=400, detail="Invalid OAuth state signature")

    # Whitelist the platform value to prevent open redirect
    if platform not in _ALLOWED_OAUTH_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid OAuth platform")

    # Reject state tokens older than 10 minutes
    try:
        ts = int(ts_str)
        if abs(time.time() - ts) > 600:
            raise HTTPException(
                status_code=400, detail="OAuth state expired",
            )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    redirect_uri = f"{settings.base_url}/api/v1/auth/google/callback"
    userinfo = await exchange_google_code(code, redirect_uri)
    if userinfo is None:
        raise HTTPException(status_code=400, detail="Google authentication failed")

    google_email = userinfo.get("email")
    if not google_email:
        raise HTTPException(status_code=400, detail="Google account has no email")

    # Check if account exists
    entity = await get_entity_by_email(db, google_email)

    if entity is None:
        # Auto-register with Google info
        import uuid as _uuid

        from src.models import EntityType

        entity_id = _uuid.uuid4()
        google_name = userinfo.get("name", google_email.split("@")[0])
        entity = Entity(
            id=entity_id,
            type=EntityType.HUMAN,
            email=google_email,
            password_hash=None,  # No password for OAuth users
            display_name=google_name,
            avatar_url=(userinfo.get("picture") or "")[:2000] or None,
            email_verified=True,  # Google already verified
            did_web=f"did:web:agentgraph.co:users:{entity_id}",
            sso_provider_id=f"google:{userinfo.get('id', '')}",
            registration_ip=request.client.host if request.client else None,
        )
        db.add(entity)
        await db.flush()

        await log_action(
            db,
            action="auth.register.google",
            entity_id=entity.id,
            ip_address=request.client.host if request.client else None,
        )

    else:
        # Existing account — backfill avatar and SSO link from Google if missing
        if not entity.avatar_url and userinfo.get("picture"):
            entity.avatar_url = userinfo["picture"][:2000]
        if not entity.sso_provider_id:
            entity.sso_provider_id = f"google:{userinfo.get('id', '')}"
        await db.flush()

    if not entity.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    await log_action(
        db,
        action="auth.login.google",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    access_token = create_access_token(entity.id, entity.type.value)
    refresh_token = create_refresh_token(entity.id)

    # Redirect with tokens as query params (NOT fragments — fragments leak via
    # Referer headers and persist in browser history).  The frontend reads the
    # tokens once and immediately replaces the URL to clear them.
    from urllib.parse import urlencode as _urlencode

    from fastapi.responses import RedirectResponse

    token_params = _urlencode({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": str(settings.jwt_access_token_expire_minutes * 60),
    })
    if platform == "ios":
        return RedirectResponse(url=f"com.agentgraph.ios://auth/callback?{token_params}")
    return RedirectResponse(url=f"{settings.base_url}/auth/callback?{token_params}")


# ──────────────────────────── GitHub OAuth Login ────────────────────────────


@router.get("/github", dependencies=[Depends(rate_limit_auth)])
async def github_login(request: Request, platform: str | None = None):
    """Redirect to GitHub OAuth2 consent screen for login/register."""
    if not settings.github_client_id:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")
    redirect_uri = f"{settings.base_url}/api/v1/auth/github/callback"

    import hashlib
    import hmac
    import time

    ts = str(int(time.time()))
    plat = platform or ""
    state_data = f"login:{ts}:{plat}"
    sig = hmac.new(
        settings.jwt_secret.encode(), state_data.encode(), hashlib.sha256,
    ).hexdigest()[:32]
    state = f"{state_data}:{sig}"

    url = get_github_auth_url(
        redirect_uri, state=state, scope="read:user user:email",
    )
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=url)


@router.get("/github/callback", dependencies=[Depends(rate_limit_auth)])
async def github_callback(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    state: str | None = None,
):
    """Handle GitHub OAuth2 callback — login/register OR account linking.

    Routing: if state starts with "login:", it's a login flow.
    Otherwise it's an account-linking flow (from linked_accounts_router).
    """
    if not settings.github_client_id:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")

    if not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")

    # Route to linked-accounts handler if this is a linking flow
    if not state.startswith("login:"):
        from src.api.linked_accounts_router import github_callback as link_cb

        return await link_cb(request, code=code, state=state, db=db)

    import hashlib
    import hmac
    import time

    parts = state.rsplit(":", 3)
    if len(parts) != 4 or parts[0] != "login":
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    _, ts_str, platform, sig = parts
    state_data = f"login:{ts_str}:{platform}"
    expected_sig = hmac.new(
        settings.jwt_secret.encode(), state_data.encode(), hashlib.sha256,
    ).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=400, detail="Invalid OAuth state signature")

    # Whitelist the platform value to prevent open redirect
    if platform not in _ALLOWED_OAUTH_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid OAuth platform")

    try:
        ts = int(ts_str)
        if abs(time.time() - ts) > 600:
            raise HTTPException(status_code=400, detail="OAuth state expired")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    redirect_uri = f"{settings.base_url}/api/v1/auth/github/callback"
    userinfo = await exchange_github_code(code, redirect_uri)
    if userinfo is None:
        raise HTTPException(status_code=400, detail="GitHub authentication failed")

    access_token_gh = userinfo.pop("_access_token", None)
    github_id = str(userinfo.get("id", ""))
    github_login = userinfo.get("login", "")
    github_name = userinfo.get("name") or github_login
    github_avatar = userinfo.get("avatar_url")

    # Get email — from profile or via email API
    github_email = userinfo.get("email")
    if not github_email and access_token_gh:
        github_email = await fetch_github_email(access_token_gh)

    if not github_email:
        raise HTTPException(
            status_code=400,
            detail="No verified email found on your GitHub account",
        )

    # Look up by SSO provider ID first, then by email
    from sqlalchemy import select

    entity = await db.scalar(
        select(Entity).where(
            Entity.sso_provider_id == f"github:{github_id}",
        )
    )
    if entity is None:
        entity = await get_entity_by_email(db, github_email)

    if entity is None:
        # Auto-register
        import uuid as _uuid

        from src.models import EntityType

        entity_id = _uuid.uuid4()
        entity = Entity(
            id=entity_id,
            type=EntityType.HUMAN,
            email=github_email,
            password_hash=None,
            display_name=github_name,
            avatar_url=(github_avatar or "")[:2000] or None,
            email_verified=True,
            did_web=f"did:web:agentgraph.co:users:{entity_id}",
            sso_provider_id=f"github:{github_id}",
            registration_ip=(
                request.client.host if request.client else None
            ),
        )
        db.add(entity)
        await db.flush()

        await log_action(
            db,
            action="auth.register.github",
            entity_id=entity.id,
            ip_address=request.client.host if request.client else None,
        )
    else:
        # Existing account — backfill avatar and SSO link if missing
        if not entity.avatar_url and github_avatar:
            entity.avatar_url = github_avatar[:2000]
        if not entity.sso_provider_id:
            entity.sso_provider_id = f"github:{github_id}"
        await db.flush()

    if not entity.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    await log_action(
        db,
        action="auth.login.github",
        entity_id=entity.id,
        ip_address=request.client.host if request.client else None,
    )

    access_token = create_access_token(entity.id, entity.type.value)
    refresh_token = create_refresh_token(entity.id)

    from urllib.parse import urlencode as _urlencode

    from fastapi.responses import RedirectResponse

    token_params = _urlencode({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": str(settings.jwt_access_token_expire_minutes * 60),
    })
    if platform == "ios":
        return RedirectResponse(
            url=f"com.agentgraph.ios://auth/callback?{token_params}",
        )
    return RedirectResponse(url=f"{settings.base_url}/auth/callback?{token_params}")
