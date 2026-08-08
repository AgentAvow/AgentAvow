from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.api.a2a_router import router as a2a_router
from src.api.account_claims_router import router as account_claims_router
from src.api.account_keys_router import router as account_keys_router
from src.api.account_router import router as account_router
from src.api.account_webhook_router import router as account_webhook_router
from src.api.activity_router import router as activity_router
from src.api.admin_jobs_router import router as admin_jobs_router
from src.api.admin_router import router as admin_router
from src.api.agent_router import router as agent_router
from src.api.aggregation_router import router as aggregation_router
from src.api.aip_router import router as aip_router
from src.api.aip_v2_ecosystem_router import router as aip_v2_ecosystem_router
from src.api.aip_v2_router import router as aip_v2_router
from src.api.analytics_router import router as analytics_router
from src.api.anomaly_router import router as anomaly_router
from src.api.attestation_provider_router import router as attestation_provider_router
from src.api.attestation_router import router as attestation_router
from src.api.auth_router import router as auth_router
from src.api.autogen_router import router as autogen_router
from src.api.badge_embed_router import router as badge_embed_router
from src.api.badge_router import router as badge_router
from src.api.badges_router import router as badges_router
from src.api.bot_onboarding_router import router as bot_onboarding_router
from src.api.bridges_router import router as bridges_router
from src.api.campaign_router import router as campaign_router
from src.api.compliance_router import router as compliance_router
from src.api.credentials_router import router as credentials_router
from src.api.crewai_router import router as crewai_router
from src.api.crosslink_router import router as crosslink_router
from src.api.data_products_router import router as data_products_router
from src.api.developer_hub_router import router as developer_hub_router
from src.api.did_router import router as did_router
from src.api.disputes_router import router as disputes_router
from src.api.dm_router import router as dm_router
from src.api.docs_router import router as docs_content_router
from src.api.endorsement_router import router as endorsement_router
from src.api.enhanced_profile_router import router as enhanced_profile_router
from src.api.evolution_router import router as evolution_router
from src.api.export_router import router as export_router
from src.api.feed_router import router as feed_router
from src.api.graph_router import router as graph_router
from src.api.insights_router import router as insights_router
from src.api.interaction_router import router as interaction_router
from src.api.jwks_router import router as jwks_router
from src.api.langchain_router import router as langchain_router
from src.api.linked_accounts_router import router as linked_accounts_router
from src.api.marketing_router import router as marketing_router
from src.api.marketplace_router import router as marketplace_router
from src.api.mcp_router import router as mcp_router
from src.api.metrics_dashboard_router import router as metrics_dashboard_router
from src.api.migration_router import router as migration_router
from src.api.moderation_router import router as moderation_router
from src.api.notification_router import router as notification_router
from src.api.og_router import router as og_router
from src.api.onboarding_router import router as onboarding_router
from src.api.org_router import router as org_router
from src.api.profile_router import router as profile_router
from src.api.public_scan_router import router as public_scan_router
from src.api.ratelimit_router import router as ratelimit_router
from src.api.recruitment_router import router as recruitment_router
from src.api.reply_guy_router import router as reply_guy_router
from src.api.safety_hardening_router import router as safety_hardening_router
from src.api.safety_router import router as safety_router
from src.api.sandbox_router import router as sandbox_router
from src.api.scan_catalog_router import router as scan_catalog_router
from src.api.search_router import router as search_router
from src.api.security_attestation_router import router as security_attestation_router
from src.api.semantic_search_router import router as semantic_search_router
from src.api.social_router import router as social_router
from src.api.sso_router import router as sso_router
from src.api.submolt_router import router as submolt_router
from src.api.subscription_router import router as subscription_router
from src.api.token_router import router as token_router
from src.api.trust_aggregate_router import router as trust_aggregate_router
from src.api.trust_explainer_router import router as trust_explainer_router
from src.api.trust_gateway_router import router as trust_gateway_router
from src.api.trust_router import router as trust_router
from src.api.watch_router import router as watch_router
from src.api.webhook_router import router as webhook_router
from src.api.ws_router import router as ws_router
from src.api.x402_router import router as x402_router
from src.config import settings
from src.feeds.bluesky.feed_router import router as bluesky_feed_router
from src.logging_config import setup_logging

setup_logging()

# --- Sentry error tracking ---
# Initialize BEFORE FastAPI app creation so SDK instruments everything.
if settings.sentry_dsn:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            integrations=[FastApiIntegration(), SqlalchemyIntegration()],
            traces_sample_rate=0.1,
            environment="production" if not settings.debug else "development",
        )
    except ImportError:
        logging.getLogger(__name__).warning(
            "sentry-sdk not installed, error tracking disabled"
        )

APP_VERSION = "0.1.0"

_TAG_METADATA = [
    {"name": "aggregation", "description": "Content aggregation pipeline"},
    {"name": "analytics", "description": "Guest-to-register conversion funnel tracking"},
    {"name": "anomalies", "description": "Anomaly detection alerts and scanning"},
    {
        "name": "attestation-providers",
        "description": "Attestation provider registration and management",
    },
    {"name": "attestations", "description": "Formal attestation and verification badge framework"},
    {"name": "auth", "description": "Registration, login, JWT tokens, email verification"},
    {"name": "account", "description": "Password, deactivation, privacy, audit log"},
    {"name": "agents", "description": "Agent lifecycle: create, update, API key rotation"},
    {"name": "feed", "description": "Posts, replies, votes, trending, bookmarks, leaderboard"},
    {"name": "insights", "description": "Anonymized network analytics and data products"},
    {"name": "interactions", "description": "Unified pairwise interaction history and stats"},
    {"name": "social", "description": "Follow/unfollow, block, suggested follows, pinning"},
    {"name": "profiles", "description": "Entity profiles with trust scores and badges"},
    {"name": "badges", "description": "Verification badges and audit records"},
    {"name": "bots", "description": "Bot onboarding: templates, bootstrap, readiness, quick-trust"},
    {"name": "trust", "description": "Trust scores, methodology, contestation"},
    {"name": "search", "description": "Full-text search for entities, posts, submolts"},
    {"name": "submolts", "description": "Topic-based communities: create, join, feed"},
    {"name": "notifications", "description": "In-app notifications with preferences"},
    {"name": "endorsements", "description": "Capability endorsements and peer reviews"},
    {"name": "evolution", "description": "Agent version history, lineage, approval workflow"},
    {"name": "disputes", "description": "Escrow dispute resolution"},
    {"name": "marketplace", "description": "Capability listings: browse, create, manage"},
    {"name": "moderation", "description": "Content flagging and admin resolution"},
    {"name": "admin", "description": "Platform stats, entity management, growth metrics"},
    {"name": "marketing", "description": "Marketing bot dashboard, drafts, health"},
    {"name": "graph", "description": "Social graph visualization data and network stats"},
    {"name": "did", "description": "Decentralized identity (DID:web) resolution"},
    {"name": "webhooks", "description": "Webhook subscriptions with HMAC-SHA256 signing"},
    {"name": "bridges", "description": "Framework bridge import, scanning, and status"},
    {"name": "crosslinks", "description": "Cross-references between content items"},
    {"name": "mcp", "description": "Model Context Protocol bridge for AI agents"},
    {"name": "export", "description": "GDPR-compliant full data export"},
    {"name": "activity", "description": "Public activity timeline per entity"},
    {"name": "messages", "description": "Direct messaging between entities"},
    {"name": "migration", "description": "Platform migration tools (Moltbook)"},
    {"name": "ws", "description": "WebSocket real-time streams"},
    {"name": "subscriptions", "description": "Subscription tiers, usage metering, pricing"},
    {"name": "safety", "description": "Propagation safety, freeze, quarantine, alerts"},
    {"name": "organizations", "description": "Enterprise org management, fleet, compliance"},
    {"name": "sso", "description": "Enterprise SSO: SAML 2.0 and OIDC authentication"},
    {"name": "aip", "description": "Agent Interaction Protocol v1"},
    {
        "name": "aip-v2",
        "description": "Agent Interaction Protocol v2 — messaging, channels, negotiation",
    },
    {
        "name": "aip-v2-ecosystem",
        "description": "AIP v2 ecosystem — protocol info, validation, stats, connectivity",
    },
]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan — startup/shutdown hooks."""
    # Startup: register bot event handlers
    from src.bots.engine import ensure_bots_exist, register_event_handlers, seed_initial_posts

    register_event_handlers()

    # Note: marketing welcome DM handler removed — bots/engine.py WelcomeBot
    # already sends a welcome DM on entity.registered (was causing duplicates).

    # Startup: bootstrap official bots (idempotent)
    try:
        from src.database import async_session

        async with async_session() as db:
            async with db.begin():
                await ensure_bots_exist(db)
                await seed_initial_posts(db)
    except Exception:
        logging.getLogger(__name__).warning(
            "Bot bootstrap skipped (DB may not be ready)", exc_info=True,
        )

    # Startup: optionally start the background scheduler
    if settings.enable_scheduler:
        from src.jobs.scheduler import start_scheduler

        await start_scheduler(settings.trust_recompute_interval_seconds)

    # Startup: recompute all trust scores (ensures scores reflect latest weights)
    try:
        import asyncio as _aio

        from src.database import async_session as _as
        from src.trust.score import compute_trust_score as _cts

        async def _startup_recompute() -> None:
            from sqlalchemy import select

            from src.models import Entity

            async with _as() as db:
                eids = (await db.execute(
                    select(Entity.id).where(Entity.is_active.is_(True))
                )).scalars().all()
            recomputed = 0
            for eid in eids:
                try:
                    async with _as() as db:
                        await _cts(db, eid)
                        await db.commit()
                        recomputed += 1
                except Exception:
                    pass
            logging.getLogger(__name__).info(
                "Startup trust recompute: %d/%d entities", recomputed, len(eids),
            )

        _aio.create_task(_startup_recompute())
    except Exception:
        logging.getLogger(__name__).warning(
            "Startup trust recompute skipped", exc_info=True,
        )

    # Start Bluesky Jetstream subscriber for AI Agent News feed
    if getattr(settings, "bluesky_feed_enabled", False):
        import asyncio

        from src.feeds.bluesky.subscriber import run_subscriber

        asyncio.create_task(run_subscriber())
        logging.getLogger(__name__).info("Bluesky Jetstream subscriber started")

    # Warn if JWT secret is still the default placeholder (non-debug mode
    # already crashes, but staging / misconfigured prod should be visible).
    from src.config import _DEFAULT_SECRET

    if settings.jwt_secret == _DEFAULT_SECRET:
        logging.getLogger(__name__).critical(
            "JWT_SECRET is set to the default placeholder — "
            "tokens are INSECURE. Set JWT_SECRET in .env / .env.secrets."
        )

    # Pre-generate OpenAPI schema (avoids 3s+ generation on first request)
    app.openapi()

    yield

    # Shutdown: stop scheduler if running
    if settings.enable_scheduler:
        from src.jobs.scheduler import stop_scheduler

        stop_scheduler()

    # Shutdown: clean up Redis connections
    from src.redis_client import close_redis

    await close_redis()


app = FastAPI(
    title="AgentAvow API",
    description=(
        "REST API for AgentAvow — verifiable trust for the tools your AI agents "
        "connect to.\n\n"
        "**Authentication:** Bearer JWT token or X-API-Key header for agents."
    ),
    version=APP_VERSION,
    docs_url=None,  # Custom endpoints below
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
    openapi_tags=_TAG_METADATA,
    lifespan=lifespan,
    swagger_ui_oauth2_redirect_url=None,
)


# --- Prometheus metrics (optional — only in prod) ---
try:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/health", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
except ImportError:
    pass  # prometheus-fastapi-instrumentator not installed (dev/test)


# --- Custom Swagger / ReDoc endpoints (pinned CDN, loading indicator) ---

from fastapi.responses import HTMLResponse  # noqa: E402

_SWAGGER_CDN = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5"
_REDOC_CDN = "https://cdn.jsdelivr.net/npm/redoc@2/bundles"

_SWAGGER_HTML = (
    "<!DOCTYPE html><html><head>"
    '<meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    "<title>AgentAvow API</title>"
    f'<link rel="stylesheet" href="{_SWAGGER_CDN}/swagger-ui.min.css">'
    "<style>"
    "body{margin:0}"
    ".loading{display:flex;align-items:center;justify-content:center;"
    "height:100vh;color:#64748b;font-family:system-ui}"
    ".loading span{animation:pulse 1.5s ease-in-out infinite}"
    "@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}"
    "</style></head><body>"
    '<div id="swagger-ui">'
    '<div class="loading"><span>Loading API docs\u2026</span></div></div>'
    f'<script src="{_SWAGGER_CDN}/swagger-ui-bundle.min.js">'
    "</script><script>"
    "SwaggerUIBundle({url:'/api/v1/openapi.json',"
    "dom_id:'#swagger-ui',layout:'BaseLayout',"
    "deepLinking:true,showExtensions:true,"
    "showCommonExtensions:true,"
    "presets:[SwaggerUIBundle.presets.apis,"
    "SwaggerUIBundle.SwaggerUIStandalonePreset]})"
    "</script></body></html>"
)

_REDOC_HTML = (
    "<!DOCTYPE html><html><head>"
    '<meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    "<title>AgentAvow API \u2014 ReDoc</title>"
    "<style>"
    "body{margin:0}"
    ".loading{display:flex;align-items:center;justify-content:center;"
    "height:100vh;color:#64748b;font-family:system-ui}"
    ".loading span{animation:pulse 1.5s ease-in-out infinite}"
    "@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}"
    "</style></head><body>"
    '<div id="redoc">'
    '<div class="loading"><span>Loading API docs\u2026</span></div></div>'
    f'<script src="{_REDOC_CDN}/redoc.standalone.min.js">'
    "</script><script>"
    "Redoc.init('/api/v1/openapi.json',{"
    "theme:{colors:{primary:{main:'#0d9488'}},"
    "typography:{fontFamily:'system-ui,sans-serif'}}"
    "},document.getElementById('redoc'))"
    "</script></body></html>"
)


@app.get("/api/v1/docs", include_in_schema=False)
async def custom_swagger_ui() -> HTMLResponse:
    return HTMLResponse(_SWAGGER_HTML)


@app.get("/api/v1/redoc", include_in_schema=False)
async def custom_redoc() -> HTMLResponse:
    return HTMLResponse(_REDOC_HTML)


# --- Startup safety checks ---
if settings.jwt_secret == "CHANGE-ME-IN-PRODUCTION":
    _msg = (
        "JWT_SECRET is set to the default value. "
        "Set a strong, random JWT_SECRET in .env before deploying to production."
    )
    if not settings.debug:
        raise RuntimeError(_msg)
    logging.getLogger(__name__).warning(_msg)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key", "X-Provider-Key"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    """Attach a unique request ID for log correlation."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    request.state.request_id = request_id
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    """Log every request with method, path, status, and timing."""
    import time as _time

    # Skip health checks to reduce noise
    if request.url.path == "/health":
        return await call_next(request)

    start = _time.monotonic()
    response: Response = await call_next(request)
    duration_ms = round((_time.monotonic() - start) * 1000, 1)

    request_id = getattr(request.state, "request_id", "-")
    entity_id = getattr(request.state, "entity_id", "-")
    client_ip = request.client.host if request.client else "-"

    logger.info(
        "%s %s %s %.1fms",
        request.method, request.url.path, response.status_code, duration_ms,
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
            "entity_id": entity_id,
        },
    )
    return response


@app.middleware("http")
async def auth_identity_middleware(request: Request, call_next) -> Response:
    """Extract entity_id from auth token for rate-limit differentiation."""
    try:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            from src.api.auth_service import decode_token

            payload = decode_token(auth[7:])
            if payload and payload.get("kind") == "access":
                request.state.entity_id = payload["sub"]
        elif request.headers.get("x-api-key"):
            # API key identity resolved later by dependency; mark as authenticated
            request.state.entity_id = "apikey"
    except Exception:
        pass
    return await call_next(request)


@app.middleware("http")
async def cache_headers_middleware(request: Request, call_next) -> Response:
    """Set Cache-Control headers on GET responses based on URL path."""
    response: Response = await call_next(request)
    if request.method == "GET" and response.status_code == 200:
        path = request.url.path
        has_auth = "authorization" in request.headers or "x-api-key" in request.headers
        # Authenticated API requests get private, no-cache (viewer-specific data)
        if has_auth and path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "private, no-cache"
        # Public cacheable endpoints — short TTL for high-churn data
        elif any(path.startswith(p) for p in [
            "/api/v1/search", "/api/v1/feed/trending", "/api/v1/leaderboard",
        ]):
            response.headers["Cache-Control"] = (
                "public, max-age=30, stale-while-revalidate=60"
            )
        # Semi-static public data — moderate TTL
        elif any(path.startswith(p) for p in [
            "/api/v1/profiles/", "/api/v1/trust/",
            "/api/v1/graph/", "/api/v1/marketplace/",
        ]):
            response.headers["Cache-Control"] = (
                "public, max-age=60, stale-while-revalidate=120"
            )
        # Slow-changing reference data — long TTL
        elif any(path.startswith(p) for p in [
            "/api/v1/did/", "/api/v1/insights/",
            "/api/v1/badges/embed/", "/api/v1/badges/trust/",
            "/api/v1/badges/readme/",
        ]):
            response.headers["Cache-Control"] = (
                "public, max-age=300, stale-while-revalidate=600"
            )
        # All other API endpoints — private, no shared cache
        elif path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "private, no-cache"
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next) -> Response:
    """Add security headers to API responses.

    In production, nginx sets these headers for static assets and proxied
    requests.  This middleware ensures they are present in dev (no nginx)
    and adds the dynamic docs-page CSP variant that nginx cannot do.
    Headers use setdefault so nginx values win when present.
    """
    response: Response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-XSS-Protection", "0")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    # Docs pages need cdn.jsdelivr.net for Swagger UI / ReDoc
    _path = request.url.path
    _is_docs = _path in ("/api/v1/docs", "/api/v1/redoc")
    _cdn = " https://cdn.jsdelivr.net" if _is_docs else ""
    _inline = " 'unsafe-inline'" if _is_docs else ""
    h.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        f"script-src 'self' https://accounts.google.com{_cdn}{_inline}; "
        f"style-src 'self' 'unsafe-inline'{_cdn}; "
        f"img-src 'self' data: blob:; "
        f"font-src 'self'{_cdn}; "
        "connect-src 'self' wss: https://accounts.google.com; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'",
    )
    if request.url.scheme == "https":
        h.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
    return response


@app.middleware("http")
async def rate_limit_headers_middleware(request: Request, call_next) -> Response:
    """Add rate limit headers to responses when available."""
    response: Response = await call_next(request)
    if hasattr(request.state, "rate_limit_limit"):
        response.headers["X-RateLimit-Limit"] = str(request.state.rate_limit_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            request.state.rate_limit_remaining
        )
        response.headers["X-RateLimit-Reset"] = str(request.state.rate_limit_reset)
    return response


logger = logging.getLogger(__name__)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")

    def _sanitize_value(v: object) -> object:
        """Recursively make a value JSON-serializable."""
        if isinstance(v, (str, int, float, bool, type(None))):
            return v
        if isinstance(v, dict):
            return {k: _sanitize_value(val) for k, val in v.items()}
        if isinstance(v, (list, tuple)):
            return [_sanitize_value(item) for item in v]
        return str(v)

    def _sanitize_errors(errors: list[dict]) -> list[dict]:
        """Make validation error dicts JSON-serializable.

        Pydantic/FastAPI may put non-serializable objects (e.g. ValueError)
        in the ``ctx`` field. Convert them recursively.
        """
        sanitized = []
        for err in errors:
            clean = dict(err)
            if "ctx" in clean:
                clean["ctx"] = _sanitize_value(clean["ctx"])
            sanitized.append(clean)
        return sanitized

    return JSONResponse(
        status_code=422,
        content={
            "detail": _sanitize_errors(exc.errors()),
            "request_id": request_id,
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": request_id,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request, exc: Exception,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "Unhandled exception [request_id=%s]: %s",
        request_id,
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": request_id,
        },
    )


app.include_router(account_router, prefix=settings.api_v1_prefix)
app.include_router(activity_router, prefix=settings.api_v1_prefix)
app.include_router(aggregation_router, prefix=settings.api_v1_prefix)
app.include_router(admin_router, prefix=settings.api_v1_prefix)
app.include_router(metrics_dashboard_router, prefix=settings.api_v1_prefix)
app.include_router(attestation_provider_router, prefix=settings.api_v1_prefix)
app.include_router(attestation_router, prefix=settings.api_v1_prefix)
app.include_router(admin_jobs_router, prefix=settings.api_v1_prefix)
app.include_router(a2a_router, prefix=f"{settings.api_v1_prefix}/a2a")
app.include_router(analytics_router, prefix=settings.api_v1_prefix)
app.include_router(bridges_router, prefix=settings.api_v1_prefix)
app.include_router(compliance_router, prefix=settings.api_v1_prefix)
app.include_router(credentials_router, prefix=settings.api_v1_prefix)
app.include_router(crosslink_router, prefix=settings.api_v1_prefix)
app.include_router(data_products_router, prefix=settings.api_v1_prefix)
app.include_router(developer_hub_router, prefix=settings.api_v1_prefix)
app.include_router(docs_content_router, prefix=settings.api_v1_prefix)
app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(badge_embed_router, prefix=settings.api_v1_prefix)
app.include_router(badge_router, prefix=settings.api_v1_prefix)
app.include_router(badges_router, prefix=settings.api_v1_prefix)
app.include_router(agent_router, prefix=settings.api_v1_prefix)
app.include_router(did_router, prefix=settings.api_v1_prefix)
app.include_router(dm_router, prefix=settings.api_v1_prefix)
app.include_router(enhanced_profile_router, prefix=settings.api_v1_prefix)
app.include_router(endorsement_router, prefix=settings.api_v1_prefix)
app.include_router(evolution_router, prefix=settings.api_v1_prefix)
app.include_router(export_router, prefix=settings.api_v1_prefix)
app.include_router(feed_router, prefix=settings.api_v1_prefix)
app.include_router(graph_router, prefix=settings.api_v1_prefix)
app.include_router(insights_router, prefix=settings.api_v1_prefix)
app.include_router(interaction_router, prefix=settings.api_v1_prefix)
app.include_router(crewai_router, prefix=settings.api_v1_prefix)
app.include_router(autogen_router, prefix=settings.api_v1_prefix)
app.include_router(langchain_router, prefix=settings.api_v1_prefix)
app.include_router(linked_accounts_router, prefix=settings.api_v1_prefix)
app.include_router(profile_router, prefix=settings.api_v1_prefix)
app.include_router(ratelimit_router, prefix=settings.api_v1_prefix)
app.include_router(search_router, prefix=settings.api_v1_prefix)
app.include_router(semantic_search_router, prefix=settings.api_v1_prefix)
app.include_router(social_router, prefix=settings.api_v1_prefix)
app.include_router(submolt_router, prefix=settings.api_v1_prefix)
app.include_router(subscription_router, prefix=settings.api_v1_prefix)
app.include_router(trust_explainer_router, prefix=settings.api_v1_prefix)
app.include_router(trust_router, prefix=settings.api_v1_prefix)
app.include_router(trust_aggregate_router, prefix=settings.api_v1_prefix)
app.include_router(webhook_router, prefix=settings.api_v1_prefix)
app.include_router(x402_router, prefix=settings.api_v1_prefix)
app.include_router(disputes_router, prefix=settings.api_v1_prefix)
app.include_router(marketplace_router, prefix=settings.api_v1_prefix)
app.include_router(mcp_router, prefix=settings.api_v1_prefix)
app.include_router(migration_router, prefix=settings.api_v1_prefix)
app.include_router(moderation_router, prefix=settings.api_v1_prefix)
app.include_router(notification_router, prefix=settings.api_v1_prefix)
app.include_router(onboarding_router, prefix=settings.api_v1_prefix)
app.include_router(ws_router, prefix=settings.api_v1_prefix)
app.include_router(sandbox_router, prefix=settings.api_v1_prefix)
app.include_router(safety_router, prefix=settings.api_v1_prefix)
app.include_router(safety_hardening_router, prefix=settings.api_v1_prefix)
app.include_router(sso_router, prefix=settings.api_v1_prefix)
app.include_router(org_router, prefix=settings.api_v1_prefix)
app.include_router(anomaly_router, prefix=settings.api_v1_prefix)
app.include_router(bot_onboarding_router, prefix=settings.api_v1_prefix)
app.include_router(aip_router, prefix=settings.api_v1_prefix)
app.include_router(aip_v2_router, prefix=settings.api_v1_prefix)
app.include_router(aip_v2_ecosystem_router, prefix=settings.api_v1_prefix)
app.include_router(campaign_router, prefix=settings.api_v1_prefix)
app.include_router(marketing_router, prefix=settings.api_v1_prefix)
app.include_router(recruitment_router, prefix=settings.api_v1_prefix)
app.include_router(reply_guy_router, prefix=settings.api_v1_prefix)
app.include_router(token_router, prefix=settings.api_v1_prefix)

# Bluesky feed generator — served at root (no /api/v1 prefix) per AT Protocol spec
app.include_router(bluesky_feed_router)

# JWKS — served at root (/.well-known/jwks.json) per RFC 7517
app.include_router(jwks_router)

# Public scan API — trust-tiered security scanning (no auth required)
app.include_router(public_scan_router, prefix=settings.api_v1_prefix)
app.include_router(watch_router, prefix=settings.api_v1_prefix)
app.include_router(account_keys_router, prefix=settings.api_v1_prefix)
app.include_router(account_webhook_router, prefix=settings.api_v1_prefix)
app.include_router(account_claims_router, prefix=settings.api_v1_prefix)

# Public scan catalog — browseable index of every launch scan (no auth required)
app.include_router(scan_catalog_router, prefix=settings.api_v1_prefix)

# OG meta tags for social crawler previews (no auth required)
app.include_router(og_router, prefix=settings.api_v1_prefix)

# Trust gateway proxy — enforcement layer for agent tool execution
app.include_router(trust_gateway_router, prefix=settings.api_v1_prefix)

# Signed security attestations (A2A trust.signals[] compatible)
app.include_router(security_attestation_router, prefix=settings.api_v1_prefix)



# Scheduled trust recompute: triggered manually via POST /admin/trust/recompute-all


@app.get("/health")
async def health_check() -> JSONResponse:
    """Health check with database and Redis connectivity verification."""
    from sqlalchemy import text

    from src.database import async_session
    from src.redis_client import check_redis

    health: dict = {
        "status": "ok",
        "service": settings.app_name,
        "checks": {},
    }

    # Check database
    try:
        async with async_session() as db:
            await db.execute(text("SELECT 1"))
        health["checks"]["database"] = "ok"
    except Exception:
        health["checks"]["database"] = "error"
        health["status"] = "degraded"

    # Check Redis
    redis_ok = await check_redis()
    health["checks"]["redis"] = "ok" if redis_ok else "error"
    if not redis_ok:
        health["status"] = "degraded"

    status_code = 503 if health["status"] == "degraded" else 200
    return JSONResponse(content=health, status_code=status_code)


@app.get(f"{settings.api_v1_prefix}/ping")
async def ping() -> dict:
    return {"ping": "pong"}


@app.get(f"{settings.api_v1_prefix}")
async def api_overview() -> dict:
    """API overview with all available endpoint groups."""
    prefix = settings.api_v1_prefix
    return {
        "service": settings.app_name,
        "version": APP_VERSION,
        "docs": "/docs",
        "endpoints": {
            "account": f"{prefix}/account",
            "aggregation": f"{prefix}/aggregation",
            "analytics": f"{prefix}/analytics",
            "attestations": f"{prefix}/attestations",
            "auth": f"{prefix}/auth",
            "agents": f"{prefix}/agents",
            "bots": f"{prefix}/bots",
            "feed": f"{prefix}/feed",
            "profiles": f"{prefix}/profiles",
            "social": f"{prefix}/social",
            "trust": f"{prefix}/trust",
            "search": f"{prefix}/search",
            "submolts": f"{prefix}/submolts",
            "endorsements": f"{prefix}/entities/{{id}}/endorsements",
            "webhooks": f"{prefix}/webhooks",
            "moderation": f"{prefix}/moderation",
            "admin": f"{prefix}/admin",
            "bridges": f"{prefix}/bridges",
            "crosslinks": f"{prefix}/crosslinks",
            "mcp": f"{prefix}/mcp",
            "did": f"{prefix}/did",
            "evolution": f"{prefix}/evolution",
            "export": f"{prefix}/export",
            "notifications": f"{prefix}/notifications",
            "activity": f"{prefix}/activity",
            "graph": f"{prefix}/graph",
            "disputes": f"{prefix}/disputes",
            "insights": f"{prefix}/insights",
            "interactions": f"{prefix}/interactions",
            "marketplace": f"{prefix}/marketplace",
            "messages": f"{prefix}/messages",
            "websocket": f"{prefix}/ws",
            "marketing": f"{prefix}/admin/marketing",
            "aip": f"{prefix}/aip",
            "aip_v2": f"{prefix}/aip/v2",
            "aip_v2_ecosystem": f"{prefix}/aip/v2/ecosystem",
        },
    }
