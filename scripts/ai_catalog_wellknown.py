"""Build, sign, and verify AgentAvow's ``/.well-known/ai-catalog.json``.

Target: the Agent-Card/ai-catalog specification on ``main`` at ``9aac2c1b``
(PR #117 merged 2026-10-28: ADR-0028 independent Trust Manifests with
whole-object JCS signatures, ADR-0029 the Policy URLs extension).

Entries
-------
1. **Our own MCP server** (``urn:air:agentavow.com:mcp:agentavow-trust``),
   carried inline as an SEP-2127 MCP Server Card in ``entry.data`` with the
   live ``tools/list`` under ``_meta["agentavow.com/tools"]``. Its
   ``trustManifests`` holds one manifest contributed by ``did:web:agentavow.com``:
   trust schema, provenance, the signed self-scan attestation, and the per-tool
   definition digests (``agentavow.mcp-tool-definition.v1``). Signed under the
   ``did:web`` Signer Profile, it also satisfies the ``did:web`` Publisher
   Profile because the signer matches the ``urn:air`` publisher segment. The
   policy links live in the entry's ``policy-urls`` extension (ADR-0029), which
   the manifest signature does not cover; the catalog signature does.
2. **Optional: an assessed third-party MCP server.** AgentAvow, as the catalog
   operator, projects a server another party publishes (default: GitHub's MCP
   server, whose Server Card is served at
   ``https://api.githubcopilot.com/mcp/server-card``). Because AgentAvow is
   neither the publisher nor its delegate, the entry uses an identifier under
   AgentAvow's control (``https://agentavow.com/ids/mcp/{card name}``), never a
   ``urn:air``, and carries no ``publisher`` object. ``entry.digest`` is the
   SHA-256 of the exact card bytes retrieved. Its single manifest is an
   independent assessor contribution from ``did:web:agentavow.com`` that points
   to AgentAvow's signed scan verdict for the source repository the card names.

The catalog root is signed too (``typ`` ``ai-catalog+jws``), covering every
entry, every nested manifest and its signature, and the build extension.

Subcommands
-----------
``build``   fetch ``tools/list`` (or read ``--tools-json``), optionally embed a
            self-scan verdict (``--self-scan`` / ``--scan-json``) and an assessed
            third-party entry (``--assess-card-url`` + ``--assess-repo``), and
            write an UNSIGNED catalog (no ``signature`` members anywhere).
``sign``    sign every Trust Manifest whose ``contributor`` is the host DID,
            then the catalog root: detached compact JWS (RFC 7515 Appendix F)
            over the RFC 8785 JCS payload, ``alg`` ES256, ``kid``
            ``did:web:agentavow.com#catalog-es256-v1``, profile ``did-web-v1``.
            ``--prod`` loads the P-256 key from ``CATALOG_SIGNING_KEY_P256``
            through ``src.signing.get_catalog_es256_key`` (host only);
            ``--test-key`` generates a throwaway P-256 key and writes a matching
            DID document next to the output. Test-key output is marked
            ``signed-test-key`` and is not publishable.
``verify``  apply the spec's verification rules offline against a DID document
            file, or ``--resolve`` the ``did:web`` document (and fetch URL
            artifacts) over HTTPS.

Examples
--------
    .venv312/bin/python3 scripts/ai_catalog_wellknown.py build --self-scan \\
        --assess-card-url https://api.githubcopilot.com/mcp/server-card \\
        --assess-repo github/github-mcp-server
    .venv312/bin/python3 scripts/ai_catalog_wellknown.py sign --test-key
    .venv312/bin/python3 scripts/ai_catalog_wellknown.py verify \\
        --did-document web/public/.well-known/ai-catalog.test-did.json --fetch-artifacts
    .venv312/bin/python3 scripts/ai_catalog_wellknown.py sign --prod     # on the host
    .venv312/bin/python3 scripts/ai_catalog_wellknown.py verify --resolve
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import rfc8785  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from src.scanner.mcp_scan import (  # noqa: E402
    MCP_TOOL_DIGEST_PROFILE,
    compute_tool_digests,
)
from src.signing import (  # noqa: E402
    CATALOG_ES256_KID,
    p256_jwk_for,
    p256_public_key_from_jwk,
    sign_es256,
    verify_es256,
)

# ── constants ────────────────────────────────────────────────────────────────

SPEC_VERSION = "1.0"
SPEC_TARGET = "Agent-Card/ai-catalog main @ 9aac2c1b (ADR-0028 + ADR-0029, merged 2026-10-28)"
MCP_SERVER_CARD_TYPE = "application/mcp-server-card+json"
SERVER_CARD_SCHEMA = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"

PROFILE_DID_WEB = "did-web-v1"
TYP_MANIFEST = "ai-catalog-trust-manifest+jws"
TYP_CATALOG = "ai-catalog+jws"
POLICY_URLS_EXT = "https://ai-catalog.org/extensions/policy-urls"

DEFAULT_PUBLISHER_DOMAIN = "agentavow.com"
DEFAULT_MCP_ENDPOINT = "https://agentavow.com/mcp"
DEFAULT_KID_FRAGMENT = CATALOG_ES256_KID  # catalog-es256-v1
JWKS_URL = "https://agentgraph.co/.well-known/jwks.json"
DEFAULT_OUT = REPO_ROOT / "web" / "public" / ".well-known" / "ai-catalog.json"
SCAN_API = "https://agentavow.com/api/v1/public/scan/mcp?endpoint="
MCP_PROTOCOL_VERSION = "2025-03-26"

# The assessed third-party server the host refresh publishes by default.
DEFAULT_ASSESS_CARD_URL = "https://api.githubcopilot.com/mcp/server-card"
DEFAULT_ASSESS_REPO = "github/github-mcp-server"

BUILD_EXT_KEY = "com.agentavow.catalogBuild"
TOOL_MANIFEST_EXT_KEY = "com.agentavow.toolManifest"
SOURCE_COORDS_EXT_KEY = "com.agentavow.sourceCoordinates"
ASSESSMENT_EXT_KEY = "com.agentavow.assessment"
SCAN_ATTESTATION_TYPE = "com.agentavow.scan-attestation"
SCAN_VERDICT_TYPE = "com.agentavow.scan-verdict"

# Endorsement lifetimes. A publisher endorsement of our own release is renewed
# daily by the host cron; an assessment is about someone else's moving target,
# so it lapses sooner if the refresh stops.
PUBLISHER_TTL = timedelta(days=30)
ASSESSOR_TTL = timedelta(days=7)
CATALOG_TTL = timedelta(days=30)
CLOCK_SKEW = timedelta(minutes=5)
MAX_ARTIFACT_BYTES = 1_000_000

_URN_AIR = re.compile(r"^urn:air:(?P<publisher>[^:]+):(?P<rest>.+:.+)$")
# Root did:web (Signer Profile): lowercase ASCII labels, no port, path, IP, or root dot.
_DID_WEB_ROOT = re.compile(r"^did:web:(?P<domain>(?!-)[a-z0-9-]+(?:\.(?!-)[a-z0-9-]+)+)$")
_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_ABS_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:\S+$")
_CARD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$")
_DIGEST = re.compile(r"^(?P<alg>sha256|sha384|sha512):(?P<hex>[0-9a-f]+)$")
_DIGEST_LEN = {"sha256": 64, "sha384": 96, "sha512": 128}


# ── small helpers ────────────────────────────────────────────────────────────


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical bytes (raises on non-I-JSON input)."""
    return rfc8785.dumps(value)


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_with(alg: str, data: bytes) -> str:
    return f"{alg}:{hashlib.new(alg, data).hexdigest()}"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(text: Any) -> datetime:
    if not isinstance(text, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", text
    ):
        raise ValueError(f"not an RFC 3339 timestamp: {text!r}")
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def fold_manifest_digest(tool_digests: dict) -> str | None:
    """Identical fold to ``src.scanner.scan._compute_manifest_digest``.

    Kept inline so this script does not import the full scanner; the test
    suite asserts the two stay byte-equal.
    """
    if not tool_digests:
        return None
    joined = "\n".join(f"{p}={tool_digests[p]}" for p in sorted(tool_digests))
    return sha256_digest(joined.encode("utf-8"))


def publisher_domain(identifier: str) -> str:
    m = _URN_AIR.match(identifier)
    if not m:
        raise ValueError(f"not a urn:air identifier: {identifier!r}")
    return m.group("publisher")


def is_root_did_web(value: Any) -> bool:
    m = _DID_WEB_ROOT.match(value) if isinstance(value, str) else None
    return bool(m) and not _IPV4.match(m.group("domain"))


def loads_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate member names (spec: parsers MUST reject)."""

    def no_duplicates(pairs: list) -> dict:
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            dupes = sorted({k for k in keys if keys.count(k) > 1})
            raise ValueError(f"duplicate JSON member names: {dupes}")
        return dict(pairs)

    return json.loads(text, object_pairs_hook=no_duplicates)


def _http_bytes(url: str, *, body: dict | None = None, accept: str = "application/json",
                timeout: float = 60.0, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
    """HTTPS-only fetch with a size ceiling (urllib; no third-party client)."""
    if not url.startswith("https://"):
        raise ValueError("only https:// URLs are fetched")
    data = None
    headers = {"Accept": accept, "User-Agent": "agentavow-ai-catalog-builder"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"response from {url} exceeds {max_bytes} bytes")
    return raw


def _http_json(url: str, body: dict | None = None, timeout: float = 60.0) -> Any:
    text = _http_bytes(url, body=body, accept="application/json, text/event-stream",
                       timeout=timeout).decode("utf-8").strip()
    if text.startswith("{"):
        return json.loads(text)
    # Streamable-HTTP servers may answer with SSE frames.
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:") and line[5:].strip().startswith("{"):
            return json.loads(line[5:].strip())
    raise ValueError(f"no JSON object in response from {url}")


# ── build ────────────────────────────────────────────────────────────────────


def fetch_tools_list(endpoint: str) -> tuple[list, dict]:
    """``initialize`` + ``tools/list`` against a Streamable-HTTP MCP endpoint."""
    init = _http_json(endpoint, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": "agentavow-ai-catalog-builder", "version": "0"}},
    })
    server_info = (init.get("result") or {}).get("serverInfo") or {}
    listed = _http_json(endpoint, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = (listed.get("result") or {}).get("tools") or []
    return tools, server_info


SAFETY_MODEL_SPEC_URL = (
    "https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/"
    "agentavow-safety-model-v1.md"
)

_ANSWER_PHRASES = {
    "safe": "Safe to connect",
    "review": "Review before you connect",
    "do_not_connect": "Do not connect",
}


def _answer_phrase(scan: dict) -> str:
    """The three-answer phrase for a scan verdict, with a trailing ", "."""
    phrase = _ANSWER_PHRASES.get(str(scan.get("decision") or ""))
    return f"{phrase}, " if phrase else ""


def _trust_schema(publisher: str) -> dict:
    return {
        # The published spec (there is no /docs/safety-model page on the site).
        "identifier": SAFETY_MODEL_SPEC_URL,
        "version": "1",
        "governanceUri": f"https://{publisher}/docs/verify-attestations",
        "verificationMethods": ["did:web"],
    }


def build_server_card(tools: list, server_info: dict, endpoint: str, publisher: str) -> dict:
    """An SEP-2127 Server Card. Tools are not a card field; they ride in ``_meta``."""
    name = server_info.get("name") or "agentavow-trust"
    return {
        "$schema": SERVER_CARD_SCHEMA,
        "name": f"{publisher}/{name}",
        "version": server_info.get("version") or "0.0.0",
        "title": "AgentAvow Trust",
        "description": (
            "Is this tool safe for your agent to connect? Safe to connect, Review "
            "before you connect, or Do not connect, with a signed, offline-verifiable "
            "trust score and an adoption score for repos, packages, and MCP servers. "
            "Read-only."
        ),
        "websiteUrl": f"https://{publisher}",
        "repository": {"source": "github", "url": "https://github.com/agentgraph-co/agentgraph"},
        "remotes": [{
            "type": "streamable-http",
            "url": endpoint,
            "supportedProtocolVersions": [MCP_PROTOCOL_VERSION],
        }],
        "_meta": {
            f"{publisher}/tools": [
                {k: t[k] for k in ("name", "title", "description", "inputSchema",
                                   "outputSchema", "annotations") if t.get(k) is not None}
                for t in tools if isinstance(t, dict)
            ],
            f"{publisher}/tool-count": len(tools),
        },
    }


def _jws_payload(jws: str) -> dict:
    try:
        payload = json.loads(b64url_decode(jws.split(".")[1]))
    except (ValueError, UnicodeDecodeError, IndexError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _scan_attestation(scan: dict, subject_label: str, live_check: str) -> dict | None:
    """Attestation pinning a signed scan verdict (compact JWS) inline.

    Inline ``data:`` is what the spec says consumers SHOULD prefer; the digest
    and size make the pinned bytes checkable without a fetch.
    """
    jws = scan.get("jws")
    if not isinstance(jws, str) or jws.count(".") != 2:
        return None
    raw = jws.encode("ascii")
    payload = _jws_payload(jws)
    score = scan.get("security_score", scan.get("score"))
    tier = scan.get("trust_tier")
    tier_text = f", tier {tier}" if tier else ""
    return {
        "type": SCAN_ATTESTATION_TYPE,
        "uri": "data:application/jose," + jws,
        "digest": sha256_digest(raw),
        "size": len(raw),
        "description": (
            f"AgentAvow scan verdict for {subject_label}: {_answer_phrase(scan)}"
            f"trust score {score}/100{tier_text}. "
            f"Compact JWS ({scan.get('algorithm', 'EdDSA')}, kid "
            f"{scan.get('key_id') or 'agentgraph-security-v1'}); verify against "
            f"{scan.get('jwks_url') or JWKS_URL}. Issued {payload.get('issuedAt', '?')}, "
            f"expires {payload.get('expiresAt', '?')}. Live re-check: {live_check}"
        ),
    }


def build_publisher_entry(
    tools: list,
    server_info: dict,
    *,
    endpoint: str,
    publisher: str,
    scan: dict | None,
    observed: datetime,
) -> dict:
    """Our own MCP server, with our publisher-contributed Trust Manifest (unsigned)."""
    did = f"did:web:{publisher}"
    identifier = f"urn:air:{publisher}:mcp:agentavow-trust"
    card = build_server_card(tools, server_info, endpoint, publisher)
    digest = sha256_digest(jcs(card))
    tool_digests = compute_tool_digests(tools)

    manifest: dict = {
        "contributor": did,
        "subject": {"identifier": identifier, "type": MCP_SERVER_CARD_TYPE, "digest": digest},
        "trustSchema": _trust_schema(publisher),
        "provenance": [{
            "relation": "publishedFrom",
            "sourceId": "https://github.com/agentgraph-co/agentgraph",
        }],
        "extensions": {
            TOOL_MANIFEST_EXT_KEY: {
                "profile": MCP_TOOL_DIGEST_PROFILE,
                "endpoint": endpoint,
                "observedAt": rfc3339(observed),
                "toolDigests": tool_digests,
                "toolManifestDigest": fold_manifest_digest(tool_digests),
                "vectors": "https://github.com/agentgraph-co/agentgraph/tree/main/docs/standards/tool-manifest-digest-vectors-v1",
            },
        },
    }
    att = _scan_attestation(scan, f"mcp:{endpoint}", SCAN_API + endpoint) if scan else None
    if att:
        manifest["attestations"] = [att]

    return {
        "identifier": identifier,
        "type": MCP_SERVER_CARD_TYPE,
        "data": card,
        "digest": digest,
        "tags": ["security", "trust", "attestation", "mcp", "scanner"],
        "updatedAt": rfc3339(observed),
        "publisher": {"identifier": did, "displayName": "AgentAvow", "identityType": "did"},
        "extensions": {
            # ADR-0029: governing policies of the artifact, on the entry. Not
            # covered by the manifest signature; covered by the catalog signature.
            POLICY_URLS_EXT: {
                "privacyPolicyUrl": f"https://{publisher}/legal/privacy",
                "termsOfServiceUrl": f"https://{publisher}/legal/terms",
            },
        },
        "trustManifests": [manifest],
    }


def assessed_identifier(publisher: str, card_name: str) -> str:
    """Operator-assigned identifier for a projected third-party server.

    Catalog Projection: an operator that is neither the artifact publisher nor
    its delegate MUST use a non-``urn:air`` identifier under its own control.
    It is derived from the card's own reverse-DNS ``name`` so it stays stable
    across versions and retrieval-URL changes and is never reassigned.
    """
    if not _CARD_NAME.match(card_name or ""):
        raise ValueError(f"server card name {card_name!r} is not reverse-DNS 'namespace/name'")
    return f"https://{publisher}/ids/mcp/{card_name}"


def build_assessed_entry(
    card_bytes: bytes,
    *,
    card_url: str,
    repo: str,
    verdict: dict,
    publisher: str,
    observed: datetime,
    etag: str | None = None,
) -> dict:
    """A third-party MCP server projected by AgentAvow as catalog operator, with
    AgentAvow's independent assessor Trust Manifest (unsigned).

    ``entry.digest`` and ``subject.digest`` are the SHA-256 of the exact card
    bytes retrieved from ``card_url`` (spec: for ``url``, hash the exact
    retrieved artifact bytes). The card is parsed only to read its ``name`` and
    ``repository``; the bytes themselves are what the digest binds.
    """
    if not card_url.startswith("https://"):
        raise ValueError("card_url must be https://")
    if not _REPO.match(repo or ""):
        raise ValueError(f"repo {repo!r} is not owner/name")
    if not isinstance(verdict.get("jws"), str) or verdict["jws"].count(".") != 2:
        raise ValueError(f"no signed verdict for {repo} (scan it first)")
    card = loads_strict(card_bytes.decode("utf-8"))
    if not isinstance(card, dict):
        raise ValueError("server card is not a JSON object")
    did = f"did:web:{publisher}"
    identifier = assessed_identifier(publisher, card.get("name", ""))
    digest = sha256_digest(card_bytes)
    card_repo = ((card.get("repository") or {}).get("url") or "").rstrip("/")
    repo_url = f"https://github.com/{repo}"
    if card_repo and card_repo.lower() != repo_url.lower():
        raise ValueError(f"card repository {card_repo!r} is not {repo_url!r}")

    verdict_url = f"https://{publisher}/api/v1/public/scan/{repo}/verdict.json"
    report_url = f"https://{publisher}/check/{repo}"
    scanned = _jws_payload(verdict["jws"])
    coverage = ((scanned.get("scan") or {}).get("coverage") or {})
    scope = (
        f"The scan covers the source repository the card names ({repo_url}"
        + (f", tree {coverage['tree_sha']}" if coverage.get("tree_sha") else "")
        + "), not the remote deployment the card describes."
    )
    attestations = [{
        "type": SCAN_VERDICT_TYPE,
        "uri": verdict_url,
        "description": (
            f"AgentAvow's current signed scan verdict for {repo} (JSON with an EdDSA "
            f"compact JWS; verify against {JWKS_URL}). Full report: {report_url}. {scope}"
        ),
    }]
    pinned = _scan_attestation(verdict, repo, verdict_url)
    if pinned:
        attestations.append(pinned)

    manifest = {
        "contributor": did,
        "subject": {"identifier": identifier, "type": MCP_SERVER_CARD_TYPE, "digest": digest},
        "trustSchema": _trust_schema(publisher),
        "attestations": attestations,
        "extensions": {
            ASSESSMENT_EXT_KEY: {
                "role": "independent-assessor",
                "assessedAt": rfc3339(observed),
                "artifactUrl": card_url,
                "repository": repo_url,
                "scanDepth": coverage.get("scan_depth"),
                "treeSha": coverage.get("tree_sha"),
                "liveObserved": coverage.get("live_observed"),
                "decision": verdict.get("decision"),
                "score": verdict.get("score"),
                "scope": scope,
            },
        },
    }
    manifest["extensions"][ASSESSMENT_EXT_KEY] = {
        k: v for k, v in manifest["extensions"][ASSESSMENT_EXT_KEY].items() if v is not None
    }
    source = {"serverCardName": card["name"], "serverCardUrl": card_url, "repository": repo_url}
    if etag:
        source["etag"] = etag
    return {
        "identifier": identifier,
        "type": MCP_SERVER_CARD_TYPE,
        "url": card_url,
        "digest": digest,
        "tags": ["mcp", "assessed", "third-party"],
        "updatedAt": rfc3339(observed),
        # Projection: the replaced source identifier is retained in a namespaced
        # entry extension; it establishes no publisher identity or trust.
        "extensions": {SOURCE_COORDS_EXT_KEY: source},
        "trustManifests": [manifest],
    }


def build_catalog(
    tools: list,
    server_info: dict,
    *,
    endpoint: str = DEFAULT_MCP_ENDPOINT,
    publisher: str = DEFAULT_PUBLISHER_DOMAIN,
    scan: dict | None = None,
    issued_at: datetime | None = None,
    assessed: dict | None = None,
) -> dict:
    """Assemble the unsigned catalog. ``assessed`` is a prebuilt third-party entry."""
    observed = issued_at or now_utc()
    did = f"did:web:{publisher}"
    entries = [build_publisher_entry(tools, server_info, endpoint=endpoint,
                                     publisher=publisher, scan=scan, observed=observed)]
    if assessed:
        entries.append(assessed)
    return {
        "specVersion": SPEC_VERSION,
        "host": {
            "displayName": "AgentAvow",
            "identifier": did,
            "documentationUrl": f"https://{publisher}/docs",
            "logoUrl": f"https://{publisher}/apple-touch-icon.png",
        },
        "entries": entries,
        "extensions": {
            BUILD_EXT_KEY: {
                "status": "draft-unsigned",
                "generator": "scripts/ai_catalog_wellknown.py",
                "specTarget": SPEC_TARGET,
                "signatureProfile": PROFILE_DID_WEB,
                "signatureAlg": "ES256 (P-256)",
                "signerDid": did,
                "signerKid": f"{did}#{CATALOG_ES256_KID}",
                "didDocument": f"https://{publisher}/.well-known/did.json",
                "jwks": JWKS_URL,
            },
        },
    }


# ── sign ─────────────────────────────────────────────────────────────────────


def signed_payload(obj: dict) -> bytes:
    """Signed Payload and JWS Construction: the containing object minus only its
    immediate ``signature.jws`` and immediate ``additionalSignatures``; JCS.
    Not recursive: nested ``jws`` / ``additionalSignatures`` stay in."""
    payload = {k: v for k, v in obj.items() if k != "additionalSignatures"}
    sig = payload.get("signature")
    if isinstance(sig, dict):
        payload["signature"] = {k: v for k, v in sig.items() if k != "jws"}
    return jcs(payload)


def detached_jws(payload: bytes, key: ec.EllipticCurvePrivateKey, kid: str, typ: str) -> str:
    """Detached compact JWS (RFC 7515 Appendix F): ``header..signature``.

    ES256 only (the ``did:web`` Signer Profile); 64-byte ``r || s``, not DER.
    """
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("the did:web Signer Profile requires an ES256 (P-256) key")
    header = b64url(jcs({"alg": "ES256", "kid": kid, "typ": typ}))
    signing_input = f"{header}.{b64url(payload)}".encode("ascii")
    return f"{header}..{b64url(sign_es256(signing_input, key))}"


def sign_object(obj: dict, key: ec.EllipticCurvePrivateKey, *, signer: str, kid_fragment: str,
                typ: str, issued: datetime, ttl: timedelta | None) -> dict:
    """Attach a complete Signature object to ``obj`` in place and return it."""
    sig = {"signer": signer, "profile": PROFILE_DID_WEB, "issuedAt": rfc3339(issued)}
    if ttl is not None:
        sig["expiresAt"] = rfc3339(issued + ttl)
    obj.pop("signature", None)
    obj["signature"] = sig
    sig["jws"] = detached_jws(signed_payload(obj), key, f"{signer}#{kid_fragment}", typ)
    return obj


def _manifest_ttl(entry: dict, signer: str) -> timedelta:
    ident = entry.get("identifier", "")
    if _URN_AIR.match(ident) and f"did:web:{publisher_domain(ident)}" == signer:
        return PUBLISHER_TTL
    return ASSESSOR_TTL


def sign_catalog(catalog: dict, key: ec.EllipticCurvePrivateKey, kid_fragment: str, status: str,
                 *, now: datetime | None = None) -> dict:
    """Sign our own manifests, then the whole catalog root. Returns the catalog.

    Only manifests whose ``contributor`` is the host DID are signed: a manifest
    signature must be by its contributor (``signer`` == ``contributor``), and we
    never sign someone else's contribution.
    """
    issued = now or now_utc()
    signer = (catalog.get("host") or {}).get("identifier", "")
    if not is_root_did_web(signer):
        raise ValueError(f"host.identifier {signer!r} is not a root did:web DID")
    for entry in catalog.get("entries", []):
        for tm in entry.get("trustManifests") or []:
            if tm.get("contributor") != signer:
                continue
            tm.pop("signature", None)
            sign_object(tm, key, signer=signer, kid_fragment=kid_fragment, typ=TYP_MANIFEST,
                        issued=issued, ttl=_manifest_ttl(entry, signer))
    build = catalog.setdefault("extensions", {}).setdefault(BUILD_EXT_KEY, {})
    build["status"] = status
    build["signedAt"] = rfc3339(issued)
    build["signerKid"] = f"{signer}#{kid_fragment}"
    # Last: the snapshot covers every nested manifest and its signature.
    catalog.pop("signature", None)
    sign_object(catalog, key, signer=signer, kid_fragment=kid_fragment, typ=TYP_CATALOG,
                issued=issued, ttl=CATALOG_TTL)
    return catalog


def test_did_document(identity: str, kid_fragment: str, pub: ec.EllipticCurvePublicKey) -> dict:
    """A DID document shaped like the one ``src/feeds/bluesky/feed_router.py``
    serves: the ES256 key listed under ``assertionMethod`` only."""
    vm_id = f"{identity}#{kid_fragment}"
    return {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/jws-2020/v1"],
        "id": identity,
        "verificationMethod": [{"id": vm_id, "type": "JsonWebKey2020", "controller": identity,
                                "publicKeyJwk": p256_jwk_for(pub, kid_fragment)}],
        "assertionMethod": [vm_id],
        "authentication": [],
    }


# ── verify ───────────────────────────────────────────────────────────────────


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []
        self.notes: list[str] = []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((name, bool(ok), detail))
        return bool(ok)

    def extend(self, prefix: str, other: Report) -> None:
        self.checks.extend((f"{prefix}{n}", ok, d) for n, ok, d in other.checks)
        self.notes.extend(f"{prefix}{n}" for n in other.notes)

    @property
    def ok(self) -> bool:
        return all(c[1] for c in self.checks)

    def failures(self) -> list[str]:
        return [c[0] for c in self.checks if not c[1]]

    def render(self) -> str:
        lines = [f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {d}" if d else "")
                 for name, ok, d in self.checks]
        lines += [f"  [NOTE] {n}" for n in self.notes]
        return ("VERIFIED" if self.ok else "REJECTED") + "\n" + "\n".join(lines)


def _resolve_did_web(did: str) -> dict:
    if not is_root_did_web(did):
        raise ValueError(f"not a root did:web DID: {did!r}")
    domain = did[len("did:web:"):]
    return loads_strict(_http_bytes(f"https://{domain}/.well-known/did.json",
                                    timeout=20).decode("utf-8"))


def _select_assertion_key(did_doc: dict, signer: str, kid: str, r: Report) -> dict | None:
    """DID Document Resolution and Key Selection (did:web Signer Profile)."""
    if not r.add("did-document-id-equals-signer", did_doc.get("id") == signer,
                 f"id={did_doc.get('id')!r} signer={signer!r}"):
        return None

    def absolute(ref: str) -> str:
        return signer + ref if ref.startswith("#") else ref

    methods = {absolute(vm["id"]): vm for vm in did_doc.get("verificationMethod") or []
               if isinstance(vm, dict) and isinstance(vm.get("id"), str)}
    authorized = []
    for item in did_doc.get("assertionMethod") or []:
        if isinstance(item, str) and absolute(item) in methods:
            authorized.append(methods[absolute(item)])
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            authorized.append(item)
    selected = [vm for vm in authorized if absolute(vm["id"]) == kid]
    if not r.add("kid-selects-exactly-one-assertionMethod-key", len(selected) == 1,
                 f"kid={kid!r} matches={len(selected)}"):
        return None
    vm = selected[0]
    if not r.add("verification-method-controller-equals-signer", vm.get("controller") == signer,
                 f"controller={vm.get('controller')!r}"):
        return None
    jwk = vm.get("publicKeyJwk")
    if not r.add("publicKeyJwk-is-p256", isinstance(jwk, dict) and jwk.get("kty") == "EC"
                 and jwk.get("crv") == "P-256"):
        return None
    ok = r.add("jwk-no-private-material", "d" not in jwk)
    ok &= r.add("jwk-alg-use-key_ops", jwk.get("alg", "ES256") == "ES256"
                and jwk.get("use", "sig") == "sig"
                and ("key_ops" not in jwk or "verify" in (jwk.get("key_ops") or [])))
    return jwk if ok else None


def verify_signature_object(obj: dict, *, typ: str, did_docs: dict[str, dict] | None,
                            resolve: bool, now: datetime) -> Report:
    """Signature Object, Profile Selection, JWS construction, Signature
    Acceptance and Time, and the did:web Signer Profile for one signed object."""
    r = Report()
    sig = obj.get("signature")
    if not r.add("signature-is-object", isinstance(sig, dict)):
        return r
    members_ok = all(isinstance(sig.get(m), str) and sig[m] for m in
                     ("signer", "profile", "issuedAt", "jws"))
    if not r.add("signature-has-signer-profile-issuedAt-jws", members_ok):
        return r
    # Profile Selection: exact, case-sensitive; no inference and no fallback.
    if not r.add("profile-is-did-web-v1", sig["profile"] == PROFILE_DID_WEB, repr(sig["profile"])):
        return r
    signer = sig["signer"]
    if not r.add("signer-is-root-did-web", is_root_did_web(signer), repr(signer)):
        return r
    try:
        issued = parse_rfc3339(sig["issuedAt"])
        expires = parse_rfc3339(sig["expiresAt"]) if "expiresAt" in sig else None
    except ValueError as exc:
        r.add("timestamps-rfc3339", False, str(exc))
        return r
    r.add("timestamps-rfc3339", True)
    if expires is not None and not r.add("expiresAt-after-issuedAt", expires > issued):
        return r
    r.add("not-before-issuedAt", now + CLOCK_SKEW >= issued, sig["issuedAt"])
    if expires is not None:
        r.add("before-expiresAt", now < expires, sig["expiresAt"])

    parts = sig["jws"].split(".")
    if not r.add("jws-detached-compact", len(parts) == 3 and parts[1] == "",
                 f"{len(parts)} segments"):
        return r
    try:
        header = loads_strict(b64url_decode(parts[0]).decode("utf-8"))
        raw_sig = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError) as exc:
        r.add("jws-segments-decode", False, str(exc))
        return r
    if not r.add("jws-header-is-object", isinstance(header, dict)):
        return r
    r.add("jws-typ", header.get("typ") == typ, f"typ={header.get('typ')!r} expected={typ!r}")
    if not r.add("jws-alg-es256", header.get("alg") == "ES256", repr(header.get("alg"))):
        return r
    r.add("jws-no-b64", "b64" not in header)
    r.add("jws-no-key-source-headers", not any(k in header for k in ("jku", "jwk", "x5u", "x5c")))
    r.add("jws-no-unsupported-crit", "crit" not in header)
    kid = header.get("kid")
    frag = kid[len(signer):] if isinstance(kid, str) else ""
    if not r.add("kid-is-signer-plus-fragment",
                 isinstance(kid, str) and kid.startswith(signer + "#") and len(frag) > 1
                 and "/" not in frag and "?" not in frag, repr(kid)):
        return r

    did_doc = (did_docs or {}).get(signer)
    if did_doc is None and resolve:
        try:
            did_doc = _resolve_did_web(signer)
        except Exception as exc:  # noqa: BLE001
            r.add("did-resolution", False, str(exc))
            return r
    if not r.add("did-document-available", did_doc is not None,
                 "" if did_doc is not None else "pass --did-document or --resolve"):
        return r
    jwk = _select_assertion_key(did_doc, signer, kid, r)
    if jwk is None:
        return r
    try:
        pub = p256_public_key_from_jwk(jwk)
    except (ValueError, KeyError, TypeError) as exc:
        r.add("jwk-p256-point-valid", False, str(exc))
        return r
    signing_input = f"{parts[0]}.{b64url(signed_payload(obj))}".encode("ascii")
    try:
        verify_es256(signing_input, raw_sig, pub)
        r.add("signature-verifies", True, "ES256 over JCS payload")
    except InvalidSignature:
        r.add("signature-verifies", False, "ES256 verification failed")
    return r


def _artifact_bytes(entry: dict, artifacts: dict[str, bytes] | None, fetch: bool) -> bytes | None:
    if "data" in entry:
        return jcs(entry["data"])
    url = entry.get("url")
    if artifacts and url in artifacts:
        return artifacts[url]
    if fetch and isinstance(url, str):
        return _http_bytes(url, accept=f"{entry.get('type')}, application/json")
    return None


def verify_entry_coverage(entry: dict, manifest: dict, *, artifacts: dict[str, bytes] | None,
                          fetch: bool) -> Report:
    """Entry Release Coverage + Verifying Artifact Integrity."""
    r = Report()
    subject = manifest.get("subject")
    if not r.add("subject-present", isinstance(subject, dict)):
        return r
    r.add("contributor-equals-signer",
          manifest.get("contributor") == (manifest.get("signature") or {}).get("signer"))
    r.add("subject-identifier-equals-entry", subject.get("identifier") == entry.get("identifier"))
    r.add("subject-type-equals-entry", subject.get("type") == entry.get("type"))
    r.add("subject-version-presence-and-value",
          ("version" in subject) == ("version" in entry) and subject.get("version") == entry.get("version"),
          f"entry={entry.get('version')!r} subject={subject.get('version')!r}")
    if not r.add("entry-digest-present", isinstance(entry.get("digest"), str)):
        return r
    if not r.add("subject-digest-equals-entry", subject.get("digest") == entry["digest"]):
        return r
    m = _DIGEST.match(entry["digest"])
    if not r.add("digest-format-sha256-or-stronger",
                 bool(m) and len(m.group("hex")) == _DIGEST_LEN[m.group("alg")], entry["digest"][:20]):
        return r
    try:
        data = _artifact_bytes(entry, artifacts, fetch)
    except Exception as exc:  # noqa: BLE001
        r.add("artifact-retrieved", False, str(exc))
        return r
    if not r.add("artifact-retrieved", data is not None,
                 "" if data is not None else f"{entry.get('url')} not fetched (use --fetch-artifacts)"):
        return r
    computed = digest_with(m.group("alg"), data)
    r.add("artifact-digest-matches", computed == entry["digest"],
          f"computed={computed[:23]}… declared={entry['digest'][:23]}…")
    return r


def _manifest_valid(tm: Any) -> Report:
    """Manifest Validity + Contributor Identity (structural)."""
    r = Report()
    if not r.add("manifest-is-object", isinstance(tm, dict)):
        return r
    contributor = tm.get("contributor")
    r.add("contributor-absolute-uri", isinstance(contributor, str) and bool(_ABS_URI.match(contributor)),
          repr(contributor))
    substantive = ("signature" in tm or "trustSchema" in tm or bool(tm.get("attestations"))
                   or bool(tm.get("provenance")) or bool(tm.get("extensions")))
    r.add("manifest-substantive", substantive)
    if "signature" in tm:
        r.add("signed-manifest-has-subject", isinstance(tm.get("subject"), dict))
    return r


def verify_entry(
    entry: dict,
    *,
    did_docs: dict[str, dict] | None = None,
    resolve: bool = False,
    now: datetime | None = None,
    unsigned_ok: bool = False,
    artifacts: dict[str, bytes] | None = None,
    fetch: bool = False,
) -> Report:
    """Entry shape, then every manifest. Our catalog policy: each entry needs at
    least one accepted signed manifest; a ``urn:air`` entry additionally needs
    one that passes the did:web Publisher Profile."""
    r = Report()
    now = now or now_utc()
    r.add("entry-identifier-type", isinstance(entry.get("identifier"), str)
          and isinstance(entry.get("type"), str))
    r.add("entry-url-xor-data", ("url" in entry) != ("data" in entry))
    if "publisher" in entry:
        pub = entry["publisher"]
        r.add("publisher-object", isinstance(pub, dict) and bool(pub.get("identifier"))
              and bool(pub.get("displayName")))
    ext = (entry.get("extensions") or {}).get(POLICY_URLS_EXT)
    if ext is not None:
        r.add("policy-urls-extension-shape", isinstance(ext, dict) and all(
            isinstance(ext.get(k), str) for k in ("privacyPolicyUrl", "termsOfServiceUrl") if k in ext))
    manifests = entry.get("trustManifests")
    if not r.add("trustManifests-is-array", isinstance(manifests, list)):
        return r
    accepted_publisher = accepted_any = False
    ident = entry.get("identifier", "")
    for i, tm in enumerate(manifests):
        sub = _manifest_valid(tm)
        if isinstance(tm, dict) and "signature" in tm:
            sub.extend("", verify_signature_object(tm, typ=TYP_MANIFEST, did_docs=did_docs,
                                                   resolve=resolve, now=now))
            if sub.ok:
                sub.extend("", verify_entry_coverage(entry, tm, artifacts=artifacts, fetch=fetch))
            if sub.ok:
                accepted_any = True
                signer = tm["signature"]["signer"]
                if _URN_AIR.match(ident) and f"did:web:{publisher_domain(ident)}" == signer:
                    accepted_publisher = True
                    sub.notes.append(f"accepted: publisher endorsement by {signer} (did:web Publisher Profile)")
                else:
                    sub.notes.append(f"accepted: independent contribution by {signer}"
                                     " (not publisher authority)")
        r.extend(f"trustManifests[{i}].", sub)
    if unsigned_ok and not any(isinstance(tm, dict) and "signature" in tm for tm in manifests):
        return r
    r.add("at-least-one-accepted-signed-manifest", accepted_any)
    if _URN_AIR.match(ident):
        r.add("urn-air-entry-has-publisher-endorsement", accepted_publisher,
              f"expected signer did:web:{publisher_domain(ident)}")
    return r


def verify_catalog(catalog: dict, *, did_doc: dict | None = None, did_docs: dict | None = None,
                   resolve: bool = False, now: datetime | None = None, unsigned_ok: bool = False,
                   artifacts: dict[str, bytes] | None = None, fetch: bool = False) -> Report:
    r = Report()
    now = now or now_utc()
    docs = dict(did_docs or {})
    if did_doc is not None and isinstance(did_doc.get("id"), str):
        docs.setdefault(did_doc["id"], did_doc)
    r.add("specVersion", catalog.get("specVersion") == SPEC_VERSION, repr(catalog.get("specVersion")))
    entries = catalog.get("entries")
    if not r.add("entries-is-array", isinstance(entries, list)):
        return r
    host = catalog.get("host")
    r.add("host-displayName (Level 2)", isinstance(host, dict) and bool(host.get("displayName")))
    keys = [(e.get("identifier"), e.get("version")) for e in entries if isinstance(e, dict)]
    r.add("identifier-version-unique", len(keys) == len(set(keys)))
    for i, entry in enumerate(entries):
        r.extend(f"entries[{i}].", verify_entry(entry, did_docs=docs, resolve=resolve, now=now,
                                                unsigned_ok=unsigned_ok, artifacts=artifacts,
                                                fetch=fetch))
    if "signature" in catalog:
        root = verify_signature_object(catalog, typ=TYP_CATALOG, did_docs=docs, resolve=resolve,
                                       now=now)
        # Catalog Authorization is local policy: we accept the snapshot only
        # from the operator named in host.identifier.
        root.add("catalog-signer-is-host-operator (local policy)",
                 (catalog.get("signature") or {}).get("signer") == (host or {}).get("identifier"))
        r.extend("catalog.", root)
    elif not unsigned_ok:
        r.add("catalog.signature-present", False, "unsigned catalog")
    return r


# ── CLI ──────────────────────────────────────────────────────────────────────


def _load(path: Path) -> Any:
    return loads_strict(path.read_text(encoding="utf-8"))


def _dump(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _fetch_card(url: str) -> tuple[bytes, str | None]:
    """Exact Server Card bytes plus the response ETag (if any)."""
    if not url.startswith("https://"):
        raise ValueError("only https:// URLs are fetched")
    req = urllib.request.Request(url, headers={
        "Accept": f"{MCP_SERVER_CARD_TYPE}, application/json",
        "User-Agent": "agentavow-ai-catalog-builder"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        raw = resp.read(MAX_ARTIFACT_BYTES + 1)
        etag = resp.headers.get("ETag")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError("server card too large")
    return raw, etag


def _assessed_from_args(args: argparse.Namespace, observed: datetime) -> dict | None:
    if not (args.assess_card_url or args.assess_card_file):
        return None
    card_url = args.assess_card_url or DEFAULT_ASSESS_CARD_URL
    try:
        if args.assess_card_file:
            card_bytes, etag = Path(args.assess_card_file).read_bytes(), None
        else:
            card_bytes, etag = _fetch_card(card_url)
        if args.assess_verdict_json:
            verdict = _load(Path(args.assess_verdict_json))
        else:
            verdict = _http_json(f"https://{args.publisher_domain}/api/v1/public/scan/"
                                 f"{args.assess_repo}/verdict.json", timeout=30)
        return build_assessed_entry(card_bytes, card_url=card_url, repo=args.assess_repo,
                                    verdict=verdict, publisher=args.publisher_domain,
                                    observed=observed, etag=etag)
    except Exception as exc:  # noqa: BLE001 — the assessed entry is optional
        print(f"warning: assessed entry omitted ({card_url}, {args.assess_repo}): {exc}")
        return None


def cmd_build(args: argparse.Namespace) -> int:
    if args.tools_json:
        raw = _load(Path(args.tools_json))
        tools = raw.get("result", {}).get("tools") if "result" in raw else raw.get("tools", raw)
        server_info = raw.get("serverInfo", {"name": "agentavow-trust", "version": "0.16.0"})
    else:
        tools, server_info = fetch_tools_list(args.endpoint)
    scan = None
    if args.scan_json:
        scan = _load(Path(args.scan_json))
    elif args.self_scan:
        scan = _http_json(SCAN_API + args.endpoint, timeout=150)
    observed = now_utc()
    catalog = build_catalog(tools, server_info, endpoint=args.endpoint,
                            publisher=args.publisher_domain, scan=scan, issued_at=observed,
                            assessed=_assessed_from_args(args, observed))
    _dump(Path(args.out), catalog)
    print(f"wrote {args.out}: {len(catalog['entries'])} entr{'y' if len(catalog['entries']) == 1 else 'ies'}, "
          f"{len(tools)} tools, unsigned")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    out = Path(args.out)
    catalog = _load(out)
    identity = (catalog.get("host") or {}).get("identifier", "")
    if args.prod:
        # P-256 catalog key from CATALOG_SIGNING_KEY_P256; its public half is what
        # the live DID documents publish as #catalog-es256-v1.
        from src.signing import get_catalog_es256_key, has_catalog_es256_key

        if args.kid_fragment != CATALOG_ES256_KID:
            print(f"refusing: --kid-fragment {args.kid_fragment!r} != catalog KID "
                  f"{CATALOG_ES256_KID!r} (the fragment the DID document publishes)")
            return 2
        if not has_catalog_es256_key():
            print("refusing: CATALOG_SIGNING_KEY_P256 is not set on this host "
                  "(generate with scripts/gen_catalog_key.py, add to .env.secrets)")
            return 2
        key = get_catalog_es256_key()  # raises on a malformed secret
        sign_catalog(catalog, key, args.kid_fragment, "signed")
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        sign_catalog(catalog, key, args.kid_fragment, "signed-test-key")
        did_path = out.with_name(out.stem + ".test-did.json")
        _dump(did_path, test_did_document(identity, args.kid_fragment, key.public_key()))
        print(f"TEST KEY ONLY — not publishable. Matching DID document: {did_path}")
    _dump(out, catalog)
    print(f"signed {out} as {identity}#{args.kid_fragment}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    catalog = _load(Path(args.out))
    did_doc = _load(Path(args.did_document)) if args.did_document else None
    report = verify_catalog(catalog, did_doc=did_doc, resolve=args.resolve,
                            unsigned_ok=args.unsigned_ok,
                            fetch=args.fetch_artifacts or args.resolve)
    print(report.render())
    return 0 if report.ok else 1


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="catalog path (default: web/public/.well-known/ai-catalog.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="write an unsigned catalog")
    b.add_argument("--endpoint", default=DEFAULT_MCP_ENDPOINT)
    b.add_argument("--publisher-domain", default=DEFAULT_PUBLISHER_DOMAIN,
                   help="urn:air publisher + did:web domain (default agentavow.com)")
    b.add_argument("--tools-json", help="offline tools/list JSON instead of a live fetch")
    b.add_argument("--self-scan", action="store_true", help="embed a live AgentAvow scan verdict")
    b.add_argument("--scan-json", help="offline scan verdict JSON (public API response)")
    b.add_argument("--assess-card-url", help="add an assessed third-party entry: its Server Card URL "
                   f"(e.g. {DEFAULT_ASSESS_CARD_URL})")
    b.add_argument("--assess-card-file", help="offline Server Card bytes for the assessed entry")
    b.add_argument("--assess-repo", default=DEFAULT_ASSESS_REPO,
                   help=f"source repo scanned for the assessed entry (default {DEFAULT_ASSESS_REPO})")
    b.add_argument("--assess-verdict-json", help="offline verdict.json for the assessed repo")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("sign", help="sign our manifests and the catalog root")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--prod", action="store_true",
                   help="ES256 with the P-256 key from CATALOG_SIGNING_KEY_P256 (src.signing)")
    g.add_argument("--test-key", action="store_true",
                   help="ephemeral P-256 key; output marked signed-test-key")
    s.add_argument("--kid-fragment", default=DEFAULT_KID_FRAGMENT,
                   help=f"DID URL fragment of the signing key (default {DEFAULT_KID_FRAGMENT})")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="apply the spec's verification rules")
    v.add_argument("--did-document", help="DID document JSON file for the signer")
    v.add_argument("--resolve", action="store_true",
                   help="resolve did:web and fetch URL artifacts over HTTPS")
    v.add_argument("--fetch-artifacts", action="store_true",
                   help="fetch url artifacts to check entry.digest")
    v.add_argument("--unsigned-ok", action="store_true", help="accept an unsigned draft")
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
