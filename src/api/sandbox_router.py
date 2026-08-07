"""Sandbox API — temporary tokens and proxied read-only endpoints for
zero-friction developer onboarding.

Sandbox tokens are short-lived JWTs (15 min) that map to ephemeral
in-memory identities.  They allow unauthenticated visitors to call a
curated subset of the API without signing up.

Rate limiting is strict: 10 requests/minute per IP.
"""
from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.rate_limit import RedisRateLimiter, _get_client_ip
from src.config import settings
from src.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

# ── Sandbox rate limiter (10 req/min per IP) ──

_sandbox_limiter = RedisRateLimiter()
_SANDBOX_LIMIT = 10
_SANDBOX_WINDOW = 60  # seconds


async def _sandbox_rate_limit(request: Request) -> None:
    ip = _get_client_ip(request)
    key = f"sandbox:{ip}"
    if not await _sandbox_limiter.check(key, _SANDBOX_LIMIT, _SANDBOX_WINDOW):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Sandbox rate limit exceeded (10 requests/minute). Try again shortly.",
        )


# ── Sandbox token store (in-memory, ephemeral) ──

_sandbox_tokens: dict[str, dict] = {}
_SANDBOX_TOKEN_TTL = 900  # 15 minutes


def _cleanup_expired() -> None:
    """Remove expired sandbox tokens."""
    now = time.time()
    expired = [k for k, v in _sandbox_tokens.items() if v["exp"] < now]
    for k in expired:
        del _sandbox_tokens[k]


def _create_sandbox_token(ip: str) -> dict:
    """Create an ephemeral sandbox token with a fake entity identity."""
    _cleanup_expired()
    token_id = uuid.uuid4().hex
    entity_id = str(uuid.uuid4())
    now = time.time()
    _sandbox_tokens[token_id] = {
        "token": token_id,
        "entity_id": entity_id,
        "display_name": f"sandbox-agent-{token_id[:8]}",
        "ip": ip,
        "created_at": now,
        "exp": now + _SANDBOX_TOKEN_TTL,
    }
    return _sandbox_tokens[token_id]


def _validate_sandbox_token(token: str) -> dict | None:
    """Validate a sandbox token. Returns the token data or None."""
    _cleanup_expired()
    data = _sandbox_tokens.get(token)
    if data is None:
        return None
    if data["exp"] < time.time():
        del _sandbox_tokens[token]
        return None
    return data


# ── Schemas ──


class SandboxTokenResponse(BaseModel):
    token: str
    entity_id: str
    display_name: str
    expires_in: int
    message: str


class SandboxCallRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    body: dict | None = None


# ── Allowed sandbox endpoints (read-only subset) ──
#
# Scan-oriented: the sandbox demos the public tool-safety scan API (no auth
# required for these paths), not the social surfaces. All three are read-only
# and cache-first on the common path.

_ALLOWED_ENDPOINTS: dict[str, dict] = {
    "check_tool": {
        "method": "GET",
        "path": "/public/scan/agenttrust/mcp-server",
        "description": "Check a tool's signed safety grade",
        "params": {},
        "curl": 'curl "{base}/api/v1/public/scan/agenttrust/mcp-server"',
    },
    "list_catalog": {
        "method": "GET",
        "path": "/public/scan-catalog",
        "description": "Browse recently scanned tools",
        "params": {"limit": "5"},
        "curl": 'curl "{base}/api/v1/public/scan-catalog?limit=5"',
    },
    "platform_stats": {
        "method": "GET",
        "path": "/public/scan-catalog",
        "description": "Platform-wide scan statistics",
        "params": {},
        "curl": 'curl "{base}/api/v1/public/scan-catalog?limit=1"',
    },
}


# ── Routes ──


@router.post(
    "/token",
    response_model=SandboxTokenResponse,
    dependencies=[Depends(_sandbox_rate_limit)],
)
async def create_sandbox_token(request: Request) -> SandboxTokenResponse:
    """Generate a temporary sandbox bearer token (15 min TTL).

    No signup required. The token maps to an ephemeral in-memory identity
    suitable for exploring read-only API endpoints.
    """
    ip = _get_client_ip(request)

    # Limit concurrent sandbox tokens per IP (max 3)
    _cleanup_expired()
    ip_tokens = [v for v in _sandbox_tokens.values() if v["ip"] == ip]
    if len(ip_tokens) >= 3:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many active sandbox sessions. Wait for an existing token to expire.",
        )

    token_data = _create_sandbox_token(ip)
    return SandboxTokenResponse(
        token=token_data["token"],
        entity_id=token_data["entity_id"],
        display_name=token_data["display_name"],
        expires_in=_SANDBOX_TOKEN_TTL,
        message="Sandbox token created. Use this as a Bearer token to try API calls.",
    )


@router.get(
    "/endpoints",
    dependencies=[Depends(_sandbox_rate_limit)],
)
async def list_sandbox_endpoints() -> dict:
    """List all available sandbox API endpoints with example curl commands."""
    base = settings.base_url or "https://agentgraph.co"
    endpoints = {}
    for key, info in _ALLOWED_ENDPOINTS.items():
        endpoints[key] = {
            "method": info["method"],
            "path": info["path"],
            "description": info["description"],
            "params": info["params"],
            "curl": info["curl"].format(token="<your-sandbox-token>", base=base),
        }
    return {"endpoints": endpoints, "rate_limit": "10 requests/minute per IP"}


@router.post(
    "/execute",
    dependencies=[Depends(_sandbox_rate_limit)],
)
async def execute_sandbox_call(
    body: SandboxCallRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Execute a sandboxed API call.

    Proxies the request to the real endpoint but only allows a curated
    read-only subset. The sandbox token is validated from the Authorization
    header.
    """
    # Validate sandbox token from header
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing sandbox token. Call POST /sandbox/token first.",
        )
    token = auth_header[7:]
    token_data = _validate_sandbox_token(token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired sandbox token.",
        )

    # Resolve the endpoint
    endpoint_info = _ALLOWED_ENDPOINTS.get(body.endpoint)
    if endpoint_info is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown endpoint '{body.endpoint}'. Use GET /sandbox/endpoints for the list.",
        )

    if body.method.upper() != endpoint_info["method"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Endpoint '{body.endpoint}' only supports {endpoint_info['method']}.",
        )

    # Execute the actual query based on endpoint
    try:
        result = await _run_sandbox_query(body.endpoint, endpoint_info, db)
        return JSONResponse(content={
            "sandbox": True,
            "endpoint": body.endpoint,
            "data": result,
        })
    except Exception as exc:
        logger.warning("Sandbox execution error for %s: %s", body.endpoint, exc)
        return JSONResponse(
            status_code=500,
            content={"sandbox": True, "endpoint": body.endpoint, "error": str(exc)},
        )


async def _run_sandbox_query(
    endpoint_key: str,
    endpoint_info: dict,
    db: AsyncSession,
) -> dict | list:
    """Run a sandboxed query against the real public scan API (read-only).

    Reuses the public scan + catalog endpoint handlers directly so the sandbox
    returns exactly what an anonymous public caller receives. Every path is
    cache-first and read-only on the common path (the demo repo is cached after
    its first scan, so repeated sandbox calls never re-scan).
    """
    if endpoint_key == "check_tool":
        # Demo a real, known repo — the same signed grade a public caller gets
        # from GET /public/scan/{owner}/{repo}. Cache-first (force=False).
        from src.api.public_scan_router import _grade_from_score, public_scan

        owner, repo = "agenttrust", "mcp-server"
        resp = await public_scan(owner=owner, repo=repo, force=False, db=db)
        return {
            "repo": resp.repo,
            "security_score": resp.security_score,
            "grade": _grade_from_score(resp.security_score),
            "trust_tier": resp.trust_tier,
            "scan_result": resp.scan_result,
            "findings": {
                "critical": resp.findings.critical,
                "high": resp.findings.high,
                "medium": resp.findings.medium,
                "total": resp.findings.total,
            },
            "positive_signals": resp.positive_signals[:5],
            "scanned_at": resp.scanned_at,
            "cached": resp.cached,
            # Signed EdDSA attestation — verifiable offline against the JWKS below.
            "jws": resp.jws,
            "key_id": resp.key_id,
            "jwks_url": resp.jwks_url,
        }

    if endpoint_key == "list_catalog":
        # Recently scanned tools from the browsable catalog (launch corpus +
        # community/on-demand scans). GET /public/scan-catalog?limit=5.
        from src.api.scan_catalog_router import scan_catalog

        catalog = await scan_catalog(
            surface=None,
            q=None,
            severity=None,
            sort="default",
            limit=5,
            offset=0,
            db=db,
        )
        return {
            "total": catalog.total,
            "tools": [
                {
                    "surface": row.surface,
                    "name": row.full_name or row.name,
                    "trust_score": row.trust_score,
                    "critical": row.critical,
                    "high": row.high,
                    "primary_language": row.primary_language,
                }
                for row in catalog.rows
            ],
        }

    if endpoint_key == "platform_stats":
        # Platform-wide scan statistics — the catalog summary block that the
        # landing page's proof-of-scale strip reads. GET /public/scan-catalog.
        from src.api.scan_catalog_router import scan_catalog

        catalog = await scan_catalog(
            surface=None,
            q=None,
            severity=None,
            sort="default",
            limit=1,
            offset=0,
            db=db,
        )
        return catalog.summary.model_dump()

    return {"message": "Endpoint not implemented in sandbox"}
