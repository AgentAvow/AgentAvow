"""Best-effort auth-posture probe for a live MCP endpoint.

The store gates want OAuth 2.0 with a real challenge. We don't send credentials;
we just look for the signals a reviewer would: a ``.well-known`` OAuth discovery
document, or a 401 + ``WWW-Authenticate`` challenge on an unauthenticated request.
Fully fail-open — any error returns ``None`` and the gate degrades to "unknown".
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

_WELL_KNOWN = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
)


async def probe_mcp_auth(endpoint_url: str) -> dict | None:
    """Return ``{oauth_discovered, challenge, open}`` or ``None`` on any failure.

    ``oauth_discovered`` — a well-known OAuth document is served.
    ``challenge``        — an unauthenticated request draws 401 + WWW-Authenticate.
    ``open``             — the endpoint answered with neither (served without auth).
    """
    try:
        from src.ssrf import ssrf_safe_async_client, validate_url_https

        url = validate_url_https(endpoint_url, field_name="endpoint")
        parts = urlsplit(url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

        oauth_discovered = False
        challenge = False
        async with ssrf_safe_async_client(timeout=5, follow_redirects=True) as client:
            for path in _WELL_KNOWN:
                try:
                    r = await client.get(origin + path)
                    if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                        oauth_discovered = True
                        break
                except Exception:
                    continue

            if not oauth_discovered:
                try:
                    r = await client.get(url)
                    if r.status_code == 401 and r.headers.get("www-authenticate"):
                        challenge = True
                except Exception:
                    pass

        return {
            "oauth_discovered": oauth_discovered,
            "challenge": challenge,
            "open": not (oauth_discovered or challenge),
        }
    except Exception:
        logger.debug("auth probe failed for %s", endpoint_url, exc_info=True)
        return None
