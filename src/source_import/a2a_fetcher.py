"""A2A (Agent2Agent) Agent Card fetching and parsing.

A2A 1.0 serves the card at ``/.well-known/agent-card.json``; cards before 0.3 used
``/.well-known/agent.json``. Both are tried, new path first. ``parse_agent_card``
reads either shape into one normalized dict:

- 1.0: ``supportedInterfaces[]``, ``capabilities`` as an object (``streaming``,
  ``pushNotifications``, ``extensions[]``, ``extendedAgentCard``), ``skills[]``,
  ``securitySchemes`` as oneof wrappers (``apiKeySecurityScheme`` …),
  ``securityRequirements[]`` as ``{"schemes": {name: {"list": [...]}}}``,
  ``signatures[]``.
- 0.3: top-level ``url`` + ``preferredTransport`` + ``additionalInterfaces[]``,
  ``securitySchemes`` with a ``type`` field, ``security[]`` as ``{name: [scopes]}``,
  ``supportsAuthenticatedExtendedCard``.
- older: ``capabilities`` as a list of names.

Every fetch goes through the SSRF-pinned client, each redirect hop is re-validated,
and the body is capped.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.types import SourceImportResult
from src.ssrf import validate_url

logger = logging.getLogger(__name__)

WELL_KNOWN_CARD = "/.well-known/agent-card.json"
LEGACY_WELL_KNOWN_CARD = "/.well-known/agent.json"
MAX_CARD_BYTES = 1024 * 1024
_MAX_REDIRECTS = 3
_TIMEOUT = 10.0


def card_url_candidates(url: str) -> list[str]:
    """The URLs to try for ``url``, in order.

    A URL that names a JSON file (or either well-known path) is used as is. Anything
    else is treated as the agent's base: the 1.0 well-known path first, then the
    legacy one.
    """
    path = urlsplit(url).path or ""
    if path.endswith(".json") or WELL_KNOWN_CARD in path or LEGACY_WELL_KNOWN_CARD in path:
        return [url]
    base = url.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    return [base + WELL_KNOWN_CARD, base + LEGACY_WELL_KNOWN_CARD]


@dataclass
class FetchedCard:
    card: dict
    url: str            # the URL the card was finally served from (after redirects)
    requested_url: str  # the candidate URL we asked for
    legacy_path: bool   # served from /.well-known/agent.json
    body: bytes


async def _get_capped(client, url: str, validate) -> tuple[int, bytes, str]:
    """GET ``url`` following up to three redirects by hand, validating every hop.
    Returns (status, body, final_url). The body is cut off at ``MAX_CARD_BYTES``."""
    for _ in range(_MAX_REDIRECTS + 1):
        validate(url)
        async with client.stream("GET", url, headers={"Accept": "application/json"}) as resp:
            location = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                url = urljoin(url, location)
                continue
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_CARD_BYTES:
                    raise SourceParseError(
                        f"A2A agent card is larger than {MAX_CARD_BYTES // 1024} KiB")
            return resp.status_code, bytes(buf), url
    raise SourceFetchError("A2A agent card URL redirected too many times")


async def fetch_agent_card(url: str, *, https_only: bool = True) -> FetchedCard:
    """Fetch and JSON-decode an Agent Card from ``url`` (a card URL or an agent base).

    ``https_only`` (the public check) refuses http:// for the card and every redirect
    hop; the legacy importer allows http. Raises SourceFetchError / SourceParseError.
    """
    from src.ssrf import ssrf_safe_async_client, validate_url_https

    def validate(u: str) -> None:
        try:
            (validate_url_https if https_only else validate_url)(u, field_name="card_url")
        except ValueError as exc:
            raise SourceFetchError(str(exc)) from exc

    last_error = "not found"
    candidates = card_url_candidates(url)
    try:
        async with ssrf_safe_async_client(timeout=_TIMEOUT, follow_redirects=False) as client:
            for cand in candidates:
                try:
                    status, body, final = await _get_capped(client, cand, validate)
                except (httpx.HTTPError, ValueError) as exc:
                    if isinstance(exc, (SourceFetchError, SourceParseError)):
                        raise
                    last_error = f"{exc.__class__.__name__}: {exc}"
                    continue
                if status != 200:
                    last_error = f"HTTP {status}"
                    continue
                try:
                    data = json.loads(body.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    last_error = "the response was not JSON"
                    # A base URL whose new path serves an HTML page: try the legacy path.
                    continue
                if not isinstance(data, dict):
                    raise SourceParseError("A2A agent card must be a JSON object")
                return FetchedCard(
                    card=data, url=final, requested_url=cand,
                    legacy_path=urlsplit(cand).path.endswith(LEGACY_WELL_KNOWN_CARD),
                    body=body,
                )
    except (SourceFetchError, SourceParseError):
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise SourceFetchError(f"Failed to fetch A2A agent card: {exc}") from exc
    raise SourceFetchError(f"Failed to fetch A2A agent card: {last_error}")


# ── parsing ──────────────────────────────────────────────────────────────────────

def _s(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _str_list(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _dicts(v: Any) -> list[dict]:
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


_WRAPPED_SCHEMES = {
    "apiKeySecurityScheme": "apiKey",
    "httpAuthSecurityScheme": "http",
    "oauth2SecurityScheme": "oauth2",
    "openIdConnectSecurityScheme": "openIdConnect",
    "mtlsSecurityScheme": "mutualTLS",
}
_TYPE_ALIASES = {
    "apikey": "apiKey", "http": "http", "oauth2": "oauth2",
    "openidconnect": "openIdConnect", "mutualtls": "mutualTLS", "mtls": "mutualTLS",
}


def parse_security_scheme(raw: Any) -> dict:
    """``{"kind", "description", ...}`` for one scheme in either the 1.0 oneof shape
    or the 0.3 ``type`` shape. Unknown shapes read ``kind: "unknown"``."""
    if not isinstance(raw, dict):
        return {"kind": "unknown", "description": ""}
    body: dict = {}
    kind = "unknown"
    for key, k in _WRAPPED_SCHEMES.items():
        if isinstance(raw.get(key), dict):
            body, kind = raw[key], k
            break
    else:
        t = _s(raw.get("type")).replace("_", "").replace("-", "").lower()
        if t in _TYPE_ALIASES:
            body, kind = raw, _TYPE_ALIASES[t]
    out: dict = {"kind": kind, "description": _s(body.get("description"))}
    if kind == "apiKey":
        out["location"] = _s(body.get("location") or body.get("in")).lower()
        out["name"] = _s(body.get("name"))
    elif kind == "http":
        out["scheme"] = _s(body.get("scheme")).lower()
    elif kind == "oauth2":
        flows = body.get("flows") if isinstance(body.get("flows"), dict) else {}
        out["flows"] = {}
        for fname, flow in flows.items():
            if not isinstance(flow, dict):
                continue
            out["flows"][str(fname)] = {
                k: _s(flow.get(k)) for k in (
                    "authorizationUrl", "tokenUrl", "refreshUrl", "deviceAuthorizationUrl")
                if _s(flow.get(k))
            }
        meta = _s(body.get("oauth2MetadataUrl"))
        if meta:
            out["metadataUrl"] = meta
    elif kind == "openIdConnect":
        out["openIdConnectUrl"] = _s(body.get("openIdConnectUrl"))
    return out


def parse_security_requirements(raw: Any) -> list[dict[str, list[str]]]:
    """Requirements as ``[{scheme_name: [scopes]}]`` from either shape."""
    out: list[dict[str, list[str]]] = []
    for req in _dicts(raw):
        schemes = req.get("schemes") if isinstance(req.get("schemes"), dict) else None
        if schemes is not None:  # 1.0: {"schemes": {name: {"list": [...]}}}
            out.append({
                str(k): _str_list(v.get("list") if isinstance(v, dict) else v)
                for k, v in schemes.items()
            })
        else:                    # 0.3: {name: [scopes]}
            out.append({str(k): _str_list(v) for k, v in req.items()})
    return out


def parse_agent_card(data: dict) -> dict:
    """Normalize an Agent Card (1.0, 0.3 or older) into one shape. Pure; never raises
    on odd input. The raw card is kept by the caller for digests and signatures."""
    data = data if isinstance(data, dict) else {}
    interfaces: list[dict] = []
    for i in _dicts(data.get("supportedInterfaces")):
        interfaces.append({
            "url": _s(i.get("url")), "binding": _s(i.get("protocolBinding")),
            "protocol_version": _s(i.get("protocolVersion")), "field": "supportedInterfaces",
        })
    legacy_url = _s(data.get("url"))
    if legacy_url:
        interfaces.append({
            "url": legacy_url, "binding": _s(data.get("preferredTransport")),
            "protocol_version": _s(data.get("protocolVersion")), "field": "url",
        })
    for i in _dicts(data.get("additionalInterfaces")):
        interfaces.append({
            "url": _s(i.get("url")), "binding": _s(i.get("transport")),
            "protocol_version": "", "field": "additionalInterfaces",
        })

    raw_caps = data.get("capabilities")
    caps = raw_caps if isinstance(raw_caps, dict) else {}
    legacy_capability_names: list[str] = []
    if isinstance(raw_caps, list):
        for cap in raw_caps:
            if isinstance(cap, str):
                legacy_capability_names.append(cap)
            elif isinstance(cap, dict) and cap.get("name"):
                legacy_capability_names.append(str(cap["name"]))
    extensions = [{
        "uri": _s(e.get("uri")), "description": _s(e.get("description")),
        "required": e.get("required") is True,
    } for e in _dicts(caps.get("extensions"))]
    extended = caps.get("extendedAgentCard") is True or (
        data.get("supportsAuthenticatedExtendedCard") is True
        or data.get("supportsExtendedAgentCard") is True)

    skills: list[dict] = []
    for sk in _dicts(data.get("skills")):
        reqs = sk.get("securityRequirements", sk.get("security"))
        skills.append({
            "id": _s(sk.get("id")) or _s(sk.get("name")),
            "name": _s(sk.get("name")),
            "description": _s(sk.get("description")),
            "tags": _str_list(sk.get("tags")),
            "examples": _str_list(sk.get("examples")),
            "security_requirements": parse_security_requirements(reqs),
            "declares_security": isinstance(reqs, list) and bool(reqs),
        })

    raw_schemes = data.get("securitySchemes")
    schemes = {str(k): parse_security_scheme(v) for k, v in raw_schemes.items()} \
        if isinstance(raw_schemes, dict) else {}
    reqs = data.get("securityRequirements", data.get("security"))
    provider = data.get("provider") if isinstance(data.get("provider"), dict) else {}

    return {
        "name": _s(data.get("name")),
        "description": _s(data.get("description")),
        "version": _s(data.get("version")),
        "protocol_version": _s(data.get("protocolVersion")) or next(
            (i["protocol_version"] for i in interfaces if i["protocol_version"]), ""),
        "provider": {"organization": _s(provider.get("organization")),
                     "url": _s(provider.get("url"))},
        "documentation_url": _s(data.get("documentationUrl")),
        "icon_url": _s(data.get("iconUrl")),
        "interfaces": interfaces,
        "capabilities": {
            "streaming": caps.get("streaming") is True,
            "push_notifications": caps.get("pushNotifications") is True,
            "extended_agent_card": extended,
            "extensions": extensions,
        },
        "legacy_capability_names": legacy_capability_names[:20],
        "skills": skills,
        "skill_count": len(_dicts(data.get("skills"))),
        "security_schemes": schemes,
        "security_requirements": parse_security_requirements(reqs),
        "signatures": _dicts(data.get("signatures")),
        "shape": ("1.0" if "supportedInterfaces" in data
                  else "0.3" if legacy_url or "securitySchemes" in data
                  or isinstance(raw_caps, dict) else "legacy"),
    }


async def fetch_a2a(card_url: str) -> SourceImportResult:
    """Fetch an A2A Agent Card for the source importer (legacy social app).

    Accepts a card URL or an agent base URL; tries ``/.well-known/agent-card.json``
    then the legacy ``/.well-known/agent.json``. http is allowed here (it always was);
    the public check uses https only.

    Raises:
        SourceFetchError: If the card cannot be fetched.
        SourceParseError: If the response is not a valid A2A agent card.
    """
    # SSRF protection — reject private/internal IPs before any request.
    for cand in card_url_candidates(card_url):
        try:
            validate_url(cand, field_name="card_url")
        except ValueError as exc:
            raise SourceFetchError(str(exc)) from exc

    fetched = await fetch_agent_card(card_url, https_only=False)
    data = fetched.card

    name = data.get("name")
    if not name:
        raise SourceParseError("A2A agent card must contain a 'name' field")
    card = parse_agent_card(data)

    # Capabilities for the importer: skill names first (1.0 and 0.3 cards), then the
    # capability flags; a pre-0.3 card's capability names are kept as they were.
    capabilities: list[str] = [s["name"] or s["id"] for s in card["skills"]
                               if s["name"] or s["id"]]
    capabilities += [k for k in ("streaming", "push_notifications", "extended_agent_card")
                     if card["capabilities"][k]]
    capabilities += card["legacy_capability_names"]
    capabilities = list(dict.fromkeys(capabilities))[:20]

    return SourceImportResult(
        source_type="a2a_card",
        source_url=card_url,
        display_name=str(name),
        bio=card["description"],
        capabilities=capabilities,
        detected_framework="a2a",
        community_signals={"provider": data.get("provider", {})},
        raw_metadata=data,
        avatar_url=data.get("avatar_url") or data.get("iconUrl"),
        version=data.get("version"),
    )
