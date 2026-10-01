"""Bluesky feed generator HTTP endpoints.

Serves the three required endpoints for a Bluesky feed generator:
1. /.well-known/did.json  — DID document (host-aware: agentgraph.co or agentavow.com)
2. /xrpc/app.bsky.feed.describeFeedGenerator — feed declaration
3. /xrpc/app.bsky.feed.getFeedSkeleton — the actual feed content
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bluesky-feed"])

# Feed configuration — set via env vars
FEED_GENERATOR_DID = f"did:web:{settings.domain}"  # e.g. did:web:agentgraph.co
FEED_PUBLISHER_DID = getattr(settings, "bluesky_did", "")  # The account DID
FEED_RKEY = "ai-agent-news"
FEED_URI = f"at://{FEED_PUBLISHER_DID}/app.bsky.feed.generator/{FEED_RKEY}"

# Redis key (matches subscriber.py)
FEED_KEY = "bluesky:feed:ai-agent-news"


# Hosts that resolve to the rebrand DID. The Ed25519 key is the same one that
# anchors did:web:agentgraph.co; only the DID (and the services) differ.
AGENTAVOW_DOMAIN = "agentavow.com"
AGENTAVOW_HOSTS = frozenset({AGENTAVOW_DOMAIN, f"www.{AGENTAVOW_DOMAIN}"})
AGENTAVOW_DID = f"did:web:{AGENTAVOW_DOMAIN}"
MCP_ENDPOINT = f"https://{AGENTAVOW_DOMAIN}/mcp"

_DID_CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
]


def request_host(request: Request) -> str:
    """The host the client asked for: ``X-Forwarded-Host`` (first value) if nginx
    set it, else ``Host``; lowercased, port stripped. Empty if neither is present."""
    raw = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = raw.split(",")[0].strip().lower()
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    return host.split(":")[0]


def _verification_methods(did: str) -> tuple[list[dict], list[str], list[str]]:
    """(verificationMethod, assertionMethod, authentication) for *did*.

    The Ed25519 platform key signs attestations and may authenticate; the
    optional ES256 catalog key is assertion-only (it signs ai-catalog.json).
    """
    # Lazy import to avoid a circular dependency with src.signing at module load.
    from src.signing import get_catalog_es256_jwk, get_jwk

    ed_jwk = get_jwk()  # {kty, crv, x, kid, use, alg}
    ed_id = f"{did}#{ed_jwk['kid']}"
    methods = [{
        "id": ed_id,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": ed_jwk,
    }]
    assertion = [ed_id]
    es_jwk = get_catalog_es256_jwk()
    if es_jwk is not None:
        es_id = f"{did}#{es_jwk['kid']}"
        methods.append({
            "id": es_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": es_jwk,
        })
        assertion.append(es_id)
    return methods, assertion, [ed_id]


def build_did_document(host: str | None = None) -> dict:
    """The DID document to serve for *host*.

    ``agentavow.com`` / ``www.agentavow.com`` get ``did:web:agentavow.com``;
    every other host (including no host at all) gets the ``settings.domain``
    document, ``did:web:agentgraph.co`` in production. Both publish the same
    Ed25519 key and cross-reference each other through ``alsoKnownAs``.
    """
    if host in AGENTAVOW_HOSTS:
        did = AGENTAVOW_DID
        methods, assertion, authentication = _verification_methods(did)
        return {
            "@context": _DID_CONTEXT,
            "id": did,
            "alsoKnownAs": [FEED_GENERATOR_DID],
            "verificationMethod": methods,
            "assertionMethod": assertion,
            "authentication": authentication,
            "service": [
                {
                    "id": f"{did}#jwks",
                    "type": "JsonWebKeySet",
                    "serviceEndpoint": (
                        f"https://{settings.domain}/.well-known/jwks.json"
                    ),
                },
                {
                    "id": f"{did}#mcp",
                    "type": "MCPServer",
                    "serviceEndpoint": MCP_ENDPOINT,
                },
                {
                    "id": f"{did}#site",
                    "type": "LinkedDomains",
                    "serviceEndpoint": f"https://{AGENTAVOW_DOMAIN}",
                },
            ],
        }

    did = FEED_GENERATOR_DID  # did:web:<settings.domain>
    methods, assertion, authentication = _verification_methods(did)
    return {
        "@context": _DID_CONTEXT,
        "id": did,
        "alsoKnownAs": [AGENTAVOW_DID],
        "verificationMethod": methods,
        "assertionMethod": assertion,
        "authentication": authentication,
        "service": [
            {
                "id": f"{did}#bsky_fg",
                "type": "BskyFeedGenerator",
                "serviceEndpoint": f"https://{settings.domain}",
            },
            {
                "id": f"{did}#gateway-reverify",
                "type": "TrustGatewayReverify",
                "serviceEndpoint": (
                    f"https://{settings.domain}/api/v1/gateway/re-verify"
                ),
            },
            {
                "id": f"{did}#jwks",
                "type": "JsonWebKeySet",
                "serviceEndpoint": (
                    f"https://{settings.domain}/.well-known/jwks.json"
                ),
            },
        ],
    }


@router.get("/.well-known/did.json")
async def did_document(request: Request) -> JSONResponse:
    """Serve the DID document for the requested host.

    Host-aware: ``agentavow.com`` serves ``did:web:agentavow.com``; any other
    host serves ``did:web:<settings.domain>`` (``did:web:agentgraph.co``), which
    also carries the Bluesky feed-generator service entry, the Ed25519
    verification key used to sign AgentGraph attestations (JWS, CTEF outer
    envelope), and the ``#gateway-reverify`` service endpoint referenced as
    ``aud`` in CTEF envelopes.

    Both documents publish the SAME Ed25519 key, served byte-identical at
    ``/.well-known/jwks.json``, so ``did:web:<either>#agentgraph-security-v1``
    resolves for verifiers. When ``CATALOG_SIGNING_KEY_P256`` is configured,
    both also publish the ES256 catalog key as ``#catalog-es256-v1`` under
    ``assertionMethod`` only.
    """
    return JSONResponse(
        content=build_did_document(request_host(request)),
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get("/xrpc/app.bsky.feed.describeFeedGenerator")
async def describe_feed_generator() -> JSONResponse:
    """Declare which feeds this service hosts."""
    return JSONResponse(
        content={
            "did": FEED_GENERATOR_DID,
            "feeds": [{"uri": FEED_URI}],
        },
    )


@router.get("/xrpc/app.bsky.feed.getFeedSkeleton")
async def get_feed_skeleton(
    feed: str = Query(..., description="AT-URI of the requested feed"),
    cursor: str | None = Query(None, description="Pagination cursor"),
    limit: int = Query(30, ge=1, le=100, description="Number of posts"),
) -> JSONResponse:
    """Return the feed skeleton — a list of post AT-URIs sorted by recency.

    Bluesky's AppView hydrates these URIs into full posts.
    """
    # Validate feed URI
    if feed != FEED_URI:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown feed: {feed}",
        )

    from src.redis_client import get_redis

    r = get_redis()

    # Parse cursor (format: timestamp_us as string)
    max_score = "+inf"
    if cursor and cursor != "eof":
        try:
            max_score = f"({cursor}"  # exclusive — don't re-include the cursor item
        except (ValueError, TypeError):
            raise HTTPException(400, "Invalid cursor")

    # Fetch posts from Redis sorted set (newest first)
    results = await r.zrevrangebyscore(
        FEED_KEY,
        max_score,
        "-inf",
        start=0,
        num=limit + 1,  # fetch one extra to know if there's more
        withscores=True,
    )

    feed_items = []
    next_cursor = None

    for i, (uri_bytes, score) in enumerate(results):
        if i >= limit:
            # There are more results — set cursor
            next_cursor = str(int(score))
            break
        uri = uri_bytes.decode() if isinstance(uri_bytes, bytes) else uri_bytes
        feed_items.append({"post": uri})

    response: dict = {"feed": feed_items}
    if next_cursor:
        response["cursor"] = next_cursor

    return JSONResponse(
        content=response,
        headers={"Cache-Control": "public, max-age=30"},
    )
