"""Best-effort auth probe for a live MCP endpoint, following Claude's discovery steps.

Claude's connector authentication doc (claude.com/docs/connectors/building/authentication)
says how Claude finds a server's sign-in:

1. An unauthenticated request draws ``401`` with ``WWW-Authenticate: Bearer
   resource_metadata="…"``. A ``WWW-Authenticate`` on a ``200`` is ignored.
2. Without that pointer Claude probes ``/.well-known/oauth-protected-resource/<path>``
   and then ``/.well-known/oauth-protected-resource`` on the server's origin.
3. The protected resource metadata's ``resource`` must equal the server URL exactly,
   and Claude uses only the first ``authorization_servers`` entry.
4. That authorization server serves RFC 8414 or OpenID Connect discovery metadata,
   supports S256 PKCE, and offers DCR (``registration_endpoint``) or CIMD
   (``client_id_metadata_document_supported`` plus ``"none"`` among the token
   endpoint auth methods). Without either, Anthropic has to hold a client you enter in
   the portal.

We send no credentials. Every URL we fetch is validated and redirects are followed by
hand through the SSRF guard (URLs in the metadata are server-controlled). Fully
fail-open: an error returns ``None`` and the auth gates read "unknown".
"""
from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

# (method, url, json_body) -> (status, lower-cased headers, parsed JSON or None)
Fetch = Callable[[str, str, "dict | None"], Awaitable[tuple[int, dict, "dict | None"]]]

_RESOURCE_METADATA = re.compile(r'resource_metadata\s*=\s*"([^"]+)"', re.I)
_INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "AgentAvow-Preflight", "version": "1.0"}},
}


async def _default_fetch(method: str, url: str, body: dict | None):
    from src.ssrf import ssrf_safe_async_client, ssrf_safe_follow, validate_url_https

    validate_url_https(url, field_name="url")
    headers = {"Accept": "application/json, text/event-stream",
               "User-Agent": "AgentAvow-Preflight"}
    async with ssrf_safe_async_client(timeout=5, follow_redirects=False) as client:
        kw: dict = {"headers": headers}
        if body is not None:
            kw["json"] = body
        resp, _final = await ssrf_safe_follow(client, method, url, **kw)
        parsed = None
        if "json" in resp.headers.get("content-type", ""):
            try:
                js = resp.json()
                parsed = js if isinstance(js, dict) else None
            except ValueError:
                parsed = None
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, parsed


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _prm_candidates(url: str) -> list[str]:
    p = urlsplit(url)
    path = p.path.rstrip("/")
    base = _origin(url) + "/.well-known/oauth-protected-resource"
    return ([base + path] if path else []) + [base]


def _as_candidates(issuer: str) -> list[str]:
    p = urlsplit(issuer)
    path = p.path.rstrip("/")
    origin = _origin(issuer)
    out = [origin + "/.well-known/oauth-authorization-server" + path]
    if path:
        out.append(origin + path + "/.well-known/openid-configuration")
        out.append(origin + "/.well-known/openid-configuration" + path)
    else:
        out.append(origin + "/.well-known/openid-configuration")
    return out


async def _first_json(fetch: Fetch, urls: list[str]) -> tuple[str | None, dict | None]:
    for u in urls:
        try:
            status, _h, js = await fetch("GET", u, None)
        except Exception:  # noqa: BLE001 — one bad candidate must not end the probe
            continue
        if status == 200 and js is not None:
            return u, js
    return None, None


async def probe_mcp_auth(endpoint_url: str, *, fetch: Fetch | None = None) -> dict | None:
    """Return the probe facts, or ``None`` when the endpoint could not be probed.

    Keys: ``challenge`` (401 + WWW-Authenticate), ``challenge_points_to_metadata``
    (the header carries ``resource_metadata``), ``status`` (unauthenticated
    initialize), ``prm_found``, ``prm_url``, ``resource_matches``,
    ``authorization_server``, ``as_metadata_found``, ``pkce_s256``, ``dcr``, ``cimd``,
    ``oauth_discovered`` (a protected resource document was found) and ``open``
    (neither a challenge nor discovery metadata).
    """
    fetch = fetch or _default_fetch
    try:
        from src.ssrf import validate_url_https

        url = validate_url_https(endpoint_url, field_name="endpoint")
        status, headers, _ = await fetch("POST", url, _INIT)
        www = headers.get("www-authenticate") or ""
        challenge = status == 401 and bool(www)
        pointer = _RESOURCE_METADATA.search(www) if challenge else None

        out: dict = {
            "status": status,
            "challenge": challenge,
            "challenge_points_to_metadata": bool(pointer),
            "prm_found": False, "prm_url": None, "resource_matches": None,
            "authorization_server": None, "as_metadata_found": None,
            "pkce_s256": None, "dcr": None, "cimd": None,
        }

        prm_urls = ([pointer.group(1)] if pointer else []) + _prm_candidates(url)
        prm_url, prm = await _first_json(fetch, prm_urls)
        if prm is not None:
            out["prm_found"], out["prm_url"] = True, prm_url
            res = prm.get("resource")
            out["resource_matches"] = isinstance(res, str) and res == url
            servers = prm.get("authorization_servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], str):
                issuer = servers[0]
                out["authorization_server"] = issuer
                _u, meta = await _first_json(fetch, _as_candidates(issuer))
                out["as_metadata_found"] = meta is not None
                if meta is not None:
                    methods = meta.get("code_challenge_methods_supported") or []
                    out["pkce_s256"] = isinstance(methods, list) and "S256" in methods
                    out["dcr"] = bool(meta.get("registration_endpoint"))
                    auth_methods = meta.get("token_endpoint_auth_methods_supported") or []
                    out["cimd"] = (meta.get("client_id_metadata_document_supported") is True
                                   and isinstance(auth_methods, list)
                                   and "none" in auth_methods)

        out["oauth_discovered"] = out["prm_found"]
        out["open"] = not (challenge or out["prm_found"])
        return out
    except Exception:  # noqa: BLE001 — the probe is best-effort
        logger.debug("auth probe failed for %s", endpoint_url, exc_info=True)
        return None
