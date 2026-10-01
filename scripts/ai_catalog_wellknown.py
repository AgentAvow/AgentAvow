"""Build, sign, and verify AgentAvow's ``/.well-known/ai-catalog.json``.

Target: the Agent-Card/ai-catalog specification as merged on ``main`` at
2026-10-01 (PRs #108 release-coordinate binding, #109 no host manifests, #110
``did:web`` publisher profile) — NOT draft PR #117 (identity-keyed manifests +
``signatures[]`` arrays), which is still open.

One Catalog Entry: the AgentAvow MCP server (``https://agentavow.com/mcp``),
carried inline as an SEP-2127 MCP Server Card in ``entry.data`` with the live
``tools/list`` under ``_meta["agentavow.com/tools"]``. The entry's Trust
Manifest binds the publisher identity, a signed scan attestation, the per-tool
definition digests (``agentavow.mcp-tool-definition.v1``), and the subject
digest of the inline card.

Subcommands
-----------
``build``   fetch ``tools/list`` (or read ``--tools-json``), optionally embed a
            self-scan verdict (``--self-scan`` / ``--scan-json``), and write
            an UNSIGNED draft with a placeholder ``signature``.
``sign``    canonicalize the Trust Manifest with RFC 8785 JCS and attach a
            detached compact JWS (RFC 7515 Appendix F). ``--prod`` loads the
            platform Ed25519 key through ``src.signing.get_signing_key``;
            ``--test-key`` generates a throwaway key and writes a matching DID
            document next to the output so the result can be verified offline.
            Test-key output is marked ``signed-test-key`` and is not publishable.
``verify``  run the spec's Level 3 checks offline against a DID document file
            (or ``--resolve`` the ``did:web`` document over HTTPS).

Known deviation from the merged profile
---------------------------------------
The ``did:web`` Publisher Profile mandates ``ES256`` with a P-256 key. AgentAvow
signs with Ed25519 (``EdDSA``), the same key that signs every attestation.
``verify`` reports this as ``alg-profile`` and fails unless ``--allow-eddsa``
is passed. PR #117's signed ``profile`` field is the path to expressing an
EdDSA profile without forking the spec.

Examples
--------
    .venv/bin/python3 scripts/ai_catalog_wellknown.py build --self-scan
    .venv/bin/python3 scripts/ai_catalog_wellknown.py sign --test-key
    .venv/bin/python3 scripts/ai_catalog_wellknown.py verify --allow-eddsa \\
        --did-document web/public/.well-known/ai-catalog.test-did.json
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.scanner.mcp_scan import (  # noqa: E402
    MCP_TOOL_DIGEST_PROFILE,
    compute_tool_digests,
)

# ── constants ────────────────────────────────────────────────────────────────

SPEC_VERSION = "1.0"
MCP_SERVER_CARD_TYPE = "application/mcp-server-card+json"
SERVER_CARD_SCHEMA = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"

DEFAULT_PUBLISHER_DOMAIN = "agentavow.com"
DEFAULT_MCP_ENDPOINT = "https://agentavow.com/mcp"
DEFAULT_KID_FRAGMENT = "agentgraph-security-v1"
DEFAULT_OUT = REPO_ROOT / "web" / "public" / ".well-known" / "ai-catalog.json"
SCAN_API = "https://agentavow.com/api/v1/public/scan/mcp?endpoint="
MCP_PROTOCOL_VERSION = "2025-03-26"

SIGNATURE_PLACEHOLDER = (
    "UNSIGNED-DRAFT: run `scripts/ai_catalog_wellknown.py sign --prod` on the "
    "signing host to replace this with the detached JWS"
)
BUILD_EXT_KEY = "com.agentavow.catalogBuild"
TOOL_MANIFEST_EXT_KEY = "com.agentavow.toolManifest"
SCAN_ATTESTATION_TYPE = "com.agentavow.scan-attestation"

_URN_AIR = re.compile(r"^urn:air:(?P<publisher>[^:]+):(?P<rest>.+:.+)$")
_DID_WEB_ROOT = re.compile(r"^did:web:(?P<domain>[a-z0-9.-]+)$")


# ── small helpers ────────────────────────────────────────────────────────────


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical bytes (raises on non-I-JSON input)."""
    return rfc8785.dumps(value)


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp has no offset: {text!r}")
    return dt


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


def _http_json(url: str, body: dict | None = None, timeout: float = 60.0) -> Any:
    """Minimal HTTPS JSON fetch (urllib; no third-party client needed)."""
    if not url.startswith("https://"):
        raise ValueError("only https:// URLs are fetched")
    data = None
    headers = {"Accept": "application/json, text/event-stream"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        text = resp.read().decode("utf-8")
    text = text.strip()
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


def build_server_card(tools: list, server_info: dict, endpoint: str, publisher: str) -> dict:
    """An SEP-2127 Server Card. Tools are not a card field; they ride in ``_meta``."""
    name = server_info.get("name") or "agentavow-trust"
    card: dict = {
        "$schema": SERVER_CARD_SCHEMA,
        "name": f"{publisher}/{name}",
        "version": server_info.get("version") or "0.0.0",
        "title": "AgentAvow Trust",
        "description": (
            "Signed, offline-verifiable safety grades for repos, packages, "
            "and MCP servers. Read-only."
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
    return card


def _scan_attestation(scan: dict, endpoint: str) -> dict | None:
    """Attestation object pinning the signed scan verdict (compact JWS) inline.

    Inline ``data:`` is what the spec says consumers SHOULD prefer; the digest
    and size make the pinned bytes checkable without a fetch.
    """
    jws = scan.get("jws")
    if not isinstance(jws, str) or jws.count(".") != 2:
        return None
    raw = jws.encode("ascii")
    try:
        payload = json.loads(b64url_decode(jws.split(".")[1]))
    except (ValueError, UnicodeDecodeError):
        payload = {}
    return {
        "type": SCAN_ATTESTATION_TYPE,
        "uri": "data:application/jose," + jws,
        "digest": sha256_digest(raw),
        "size": len(raw),
        "description": (
            f"AgentAvow scan verdict for mcp:{endpoint}: grade {scan.get('grade')}, "
            f"score {scan.get('security_score')}/100, tier {scan.get('trust_tier')}. "
            f"Compact JWS ({scan.get('algorithm', 'EdDSA')}, kid {scan.get('key_id')}); "
            f"verify against {scan.get('jwks_url')}. "
            f"Issued {payload.get('issuedAt', '?')}, expires {payload.get('expiresAt', '?')}. "
            f"Live re-check: {SCAN_API}{endpoint}"
        ),
    }


def build_catalog(
    tools: list,
    server_info: dict,
    *,
    endpoint: str = DEFAULT_MCP_ENDPOINT,
    publisher: str = DEFAULT_PUBLISHER_DOMAIN,
    scan: dict | None = None,
    issued_at: datetime | None = None,
    expires_in: timedelta = timedelta(days=30),
) -> dict:
    """Assemble the unsigned catalog (merged spec; signature is a placeholder)."""
    issued = issued_at or now_utc()
    identity = f"did:web:{publisher}"
    identifier = f"urn:air:{publisher}:mcp:agentavow-trust"
    card = build_server_card(tools, server_info, endpoint, publisher)
    tool_digests = compute_tool_digests(tools)

    attestations = []
    att = _scan_attestation(scan, endpoint) if scan else None
    if att:
        attestations.append(att)

    manifest: dict = {
        "identity": identity,
        "identityType": "did",
        "trustSchema": {
            "identifier": f"https://{publisher}/docs/safety-model",
            "version": "1",
            "governanceUri": f"https://{publisher}/docs/verify-attestations",
            "verificationMethods": ["did:web"],
        },
        "provenance": [{
            "relation": "publishedFrom",
            "sourceId": "https://github.com/agentgraph-co/agentgraph",
        }],
        "privacyPolicyUrl": f"https://{publisher}/legal/privacy",
        "termsOfServiceUrl": f"https://{publisher}/legal/terms",
        "extensions": {
            TOOL_MANIFEST_EXT_KEY: {
                "profile": MCP_TOOL_DIGEST_PROFILE,
                "endpoint": endpoint,
                "observedAt": rfc3339(issued),
                "toolDigests": tool_digests,
                "toolManifestDigest": fold_manifest_digest(tool_digests),
                "vectors": "https://github.com/agentgraph-co/agentgraph/tree/main/docs/standards/tool-manifest-digest-vectors-v1",
            },
        },
        "subject": {
            "identifier": identifier,
            "type": MCP_SERVER_CARD_TYPE,
            "digest": sha256_digest(jcs(card)),
        },
        "issuedAt": rfc3339(issued),
        "expiresAt": rfc3339(issued + expires_in),
        "signature": SIGNATURE_PLACEHOLDER,
    }
    if attestations:
        manifest["attestations"] = attestations

    return {
        "specVersion": SPEC_VERSION,
        "host": {
            "displayName": "AgentAvow",
            "identifier": identity,
            "documentationUrl": f"https://{publisher}/docs",
            "logoUrl": f"https://{publisher}/apple-touch-icon.png",
        },
        "entries": [{
            "identifier": identifier,
            "type": MCP_SERVER_CARD_TYPE,
            "data": card,
            "tags": ["security", "trust", "attestation", "mcp", "scanner"],
            "updatedAt": rfc3339(issued),
            "publisher": {"identifier": identity, "displayName": "AgentAvow", "identityType": "did"},
            "trustManifest": manifest,
        }],
        "extensions": {
            BUILD_EXT_KEY: {
                "status": "draft-unsigned",
                "generator": "scripts/ai_catalog_wellknown.py",
                "specTarget": "Agent-Card/ai-catalog main @ 2026-10-01 (post #108/#109/#110)",
                "signatureAlg": "EdDSA (Ed25519) — deviates from the did:web profile's ES256",
                "signerDid": identity,
                "jwks": "https://agentgraph.co/.well-known/jwks.json",
            },
        },
    }


# ── sign ─────────────────────────────────────────────────────────────────────


def manifest_payload(manifest: dict) -> bytes:
    """JWS payload: JCS of the Trust Manifest with ``signature`` removed."""
    return jcs({k: v for k, v in manifest.items() if k != "signature"})


def detached_jws(payload: bytes, key: Ed25519PrivateKey, kid: str) -> str:
    header = jcs({"alg": "EdDSA", "kid": kid})
    h, p = b64url(header), b64url(payload)
    sig = key.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}..{b64url(sig)}"


def sign_catalog(catalog: dict, key: Ed25519PrivateKey, kid_fragment: str, status: str) -> dict:
    """Sign every entry Trust Manifest in place; returns the catalog."""
    for entry in catalog.get("entries", []):
        tm = entry.get("trustManifest")
        if not tm:
            continue
        kid = f"{tm['identity']}#{kid_fragment}"
        tm["signature"] = detached_jws(manifest_payload(tm), key, kid)
    build = catalog.setdefault("extensions", {}).setdefault(BUILD_EXT_KEY, {})
    build["status"] = status
    build["signedAt"] = rfc3339(now_utc())
    return catalog


def test_did_document(identity: str, kid_fragment: str, pub: Ed25519PublicKey) -> dict:
    """A DID document shaped like ``src/feeds/bluesky/feed_router.py`` serves."""
    vm_id = f"{identity}#{kid_fragment}"
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(pub.public_bytes_raw()),
           "kid": kid_fragment, "use": "sig", "alg": "EdDSA"}
    return {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/jws-2020/v1"],
        "id": identity,
        "verificationMethod": [{"id": vm_id, "type": "JsonWebKey2020",
                                "controller": identity, "publicKeyJwk": jwk}],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    }


# ── verify ───────────────────────────────────────────────────────────────────


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((name, bool(ok), detail))
        return bool(ok)

    @property
    def ok(self) -> bool:
        return all(c[1] for c in self.checks)

    def failures(self) -> list[str]:
        return [c[0] for c in self.checks if not c[1]]

    def render(self) -> str:
        lines = [f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {d}" if d else "")
                 for name, ok, d in self.checks]
        return ("VERIFIED" if self.ok else "REJECTED") + "\n" + "\n".join(lines)


def _resolve_did_web(did: str) -> dict:
    m = _DID_WEB_ROOT.match(did)
    if not m:
        raise ValueError(f"not a root did:web DID: {did!r}")
    return _http_json(f"https://{m.group('domain')}/.well-known/did.json", timeout=20)


def _select_assertion_key(did_doc: dict, identity: str, kid: str, r: Report) -> dict | None:
    r.add("did-document-id", did_doc.get("id") == identity,
          f"id={did_doc.get('id')!r} identity={identity!r}")
    methods = {}
    for vm in did_doc.get("verificationMethod") or []:
        if isinstance(vm, dict) and "id" in vm:
            vid = vm["id"]
            if vid.startswith("#"):
                vid = identity + vid
            methods[vid] = vm
    authorized: dict = {}
    for item in did_doc.get("assertionMethod") or []:
        if isinstance(item, str):
            ref = identity + item if item.startswith("#") else item
            if ref in methods:
                authorized[ref] = methods[ref]
        elif isinstance(item, dict) and "id" in item:
            authorized[item["id"]] = item
    vm = authorized.get(kid)
    r.add("kid-authorized-by-assertionMethod", vm is not None,
          f"kid={kid!r} authorized={sorted(authorized)}")
    if vm is None:
        return None
    r.add("verification-method-controller", vm.get("controller") == identity,
          f"controller={vm.get('controller')!r}")
    jwk = vm.get("publicKeyJwk")
    r.add("verification-method-has-publicKeyJwk", isinstance(jwk, dict))
    return jwk if isinstance(jwk, dict) else None


def verify_entry(
    entry: dict,
    *,
    did_doc: dict | None = None,
    resolve: bool = False,
    allow_eddsa: bool = False,
    now: datetime | None = None,
    unsigned_ok: bool = False,
) -> Report:
    """Level 3 checks for one Catalog Entry per the merged spec."""
    r = Report()
    now = now or now_utc()
    tm = entry.get("trustManifest")
    if not isinstance(tm, dict):
        r.add("trust-manifest-present", False, "entry has no trustManifest")
        return r

    # Entry shape
    has_url, has_data = "url" in entry, "data" in entry
    r.add("entry-url-xor-data", has_url != has_data)
    r.add("entry-identifier-urn-air", bool(_URN_AIR.match(entry.get("identifier", ""))),
          entry.get("identifier", ""))

    # Manifest validity (substantive members)
    substantive = (
        ("signature" in tm and tm["signature"] != SIGNATURE_PLACEHOLDER)
        or bool(tm.get("attestations")) or bool(tm.get("provenance")) or "trustSchema" in tm
    )
    r.add("manifest-substantive", substantive)

    # Identity / publisher namespace authorization
    identity = tm.get("identity", "")
    try:
        pub = publisher_domain(entry["identifier"])
        r.add("identity-equals-did-web-publisher", identity == f"did:web:{pub}",
              f"identity={identity!r} expected={'did:web:' + pub!r}")
    except (KeyError, ValueError) as exc:
        r.add("identity-equals-did-web-publisher", False, str(exc))
    r.add("publisher-domain-lowercase-ascii",
          identity[len("did:web:"):] == identity[len("did:web:"):].lower()
          and ":" not in identity[len("did:web:"):] and "%" not in identity)
    if "identityType" in tm:
        r.add("identityType-is-did", tm["identityType"] == "did")

    # Subject binding
    subject = tm.get("subject")
    r.add("subject-present", isinstance(subject, dict))
    if isinstance(subject, dict):
        r.add("subject-identifier-matches-entry", subject.get("identifier") == entry.get("identifier"))
        r.add("subject-type-matches-entry", subject.get("type") == entry.get("type"))
        ev, sv = entry.get("version"), subject.get("version")
        r.add("subject-version-both-absent-or-equal", (ev is None and sv is None) or (ev is not None and ev == sv),
              f"entry={ev!r} subject={sv!r}")
        if "url" in subject:
            r.add("subject-url-matches-entry", subject["url"] == entry.get("url"))
        digest = subject.get("digest", "")
        algo = digest.split(":", 1)[0]
        r.add("digest-algorithm-sha256-or-stronger", algo in ("sha256", "sha384", "sha512"), digest[:16])
        if has_data:
            computed = "sha256:" + hashlib.sha256(jcs(entry["data"])).hexdigest()
            r.add("subject-digest-matches-jcs(data)", computed == digest,
                  f"computed={computed[:23]}… declared={digest[:23]}…")
        else:
            r.add("subject-digest-url-artifact", True, "url artifact not fetched (offline)")

    # Timestamps
    r.add("issuedAt-present", "issuedAt" in tm)
    try:
        issued = parse_rfc3339(tm["issuedAt"])
        r.add("issuedAt-not-in-future", issued <= now + timedelta(minutes=5), tm["issuedAt"])
    except (KeyError, ValueError) as exc:
        r.add("issuedAt-not-in-future", False, str(exc))
    if "expiresAt" in tm:
        try:
            r.add("expiresAt-in-future", parse_rfc3339(tm["expiresAt"]) > now, tm["expiresAt"])
        except ValueError as exc:
            r.add("expiresAt-in-future", False, str(exc))

    # Signature
    sig = tm.get("signature")
    if sig == SIGNATURE_PLACEHOLDER or not sig:
        r.add("signature-present", unsigned_ok, "placeholder / unsigned draft")
        return r
    parts = sig.split(".")
    r.add("jws-detached-compact-form", len(parts) == 3 and parts[1] == "", f"{len(parts)} segments")
    if len(parts) != 3:
        return r
    try:
        header = json.loads(b64url_decode(parts[0]))
    except (ValueError, UnicodeDecodeError) as exc:
        r.add("jws-header-parses", False, str(exc))
        return r
    r.add("jws-header-parses", isinstance(header, dict))
    alg = header.get("alg")
    r.add("jws-alg-not-none", alg not in (None, "none"))
    r.add("jws-no-b64-param", "b64" not in header)
    r.add("jws-no-key-source-headers", not any(k in header for k in ("jku", "jwk", "x5u", "x5c")))
    if alg == "ES256":
        r.add("alg-profile", True, "ES256 (did:web Publisher Profile)")
    elif alg == "EdDSA":
        r.add("alg-profile", allow_eddsa,
              "EdDSA — the merged did:web profile mandates ES256; accepted only with --allow-eddsa")
    else:
        r.add("alg-profile", False, f"unsupported alg {alg!r}")
    kid = header.get("kid", "")
    r.add("kid-absolute-did-url-under-identity",
          isinstance(kid, str) and kid.startswith(identity + "#") and len(kid) > len(identity) + 1
          and "/" not in kid[len(identity):] and "?" not in kid[len(identity):],
          repr(kid))

    # Key material
    if did_doc is None and resolve:
        try:
            did_doc = _resolve_did_web(identity)
        except Exception as exc:  # noqa: BLE001
            r.add("did-resolution", False, str(exc))
            return r
    if did_doc is None:
        r.add("did-document-available", False, "pass --did-document or --resolve")
        return r
    jwk = _select_assertion_key(did_doc, identity, kid, r)
    if jwk is None:
        return r
    r.add("jwk-no-private-material", "d" not in jwk)
    if alg == "EdDSA":
        r.add("jwk-is-ed25519", jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519")
        if not (jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"):
            return r
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
        signing_input = f"{parts[0]}.{b64url(manifest_payload(tm))}".encode("ascii")
        try:
            pub.verify(b64url_decode(parts[2]), signing_input)
            r.add("signature-verifies", True)
        except InvalidSignature:
            r.add("signature-verifies", False, "Ed25519 verification failed")
    else:
        r.add("jwk-is-p256", jwk.get("kty") == "EC" and jwk.get("crv") == "P-256")
        r.add("signature-verifies", False, "ES256 verification not implemented in this script")
    return r


def verify_catalog(catalog: dict, **kw: Any) -> Report:
    r = Report()
    r.add("specVersion", catalog.get("specVersion") == SPEC_VERSION, repr(catalog.get("specVersion")))
    r.add("entries-is-array", isinstance(catalog.get("entries"), list))
    host = catalog.get("host")
    r.add("host-displayName (Level 2)", isinstance(host, dict) and bool(host.get("displayName")))
    for i, entry in enumerate(catalog.get("entries") or []):
        sub = verify_entry(entry, **kw)
        for name, ok, detail in sub.checks:
            r.add(f"entries[{i}].{name}", ok, detail)
    return r


# ── CLI ──────────────────────────────────────────────────────────────────────


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


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
    catalog = build_catalog(tools, server_info, endpoint=args.endpoint,
                            publisher=args.publisher_domain, scan=scan)
    _dump(Path(args.out), catalog)
    print(f"wrote {args.out}: {len(tools)} tools, "
          f"{len(catalog['entries'][0]['trustManifest'].get('attestations', []))} attestation(s), unsigned")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    out = Path(args.out)
    catalog = _load(out)
    identity = catalog["entries"][0]["trustManifest"]["identity"]
    if args.prod:
        from src.signing import KID, get_signing_key  # platform key; raises if unset
        if args.kid_fragment != KID:
            print(f"refusing: --kid-fragment {args.kid_fragment!r} != platform KID {KID!r}")
            return 2
        key = get_signing_key()
        sign_catalog(catalog, key, args.kid_fragment, "signed")
    else:
        key = Ed25519PrivateKey.generate()
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
                            allow_eddsa=args.allow_eddsa, unsigned_ok=args.unsigned_ok)
    print(report.render())
    return 0 if report.ok else 1


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="catalog path (default: web/public/.well-known/ai-catalog.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="write an unsigned draft catalog")
    b.add_argument("--endpoint", default=DEFAULT_MCP_ENDPOINT)
    b.add_argument("--publisher-domain", default=DEFAULT_PUBLISHER_DOMAIN,
                   help="urn:air publisher + did:web domain (default agentavow.com)")
    b.add_argument("--tools-json", help="offline tools/list JSON instead of a live fetch")
    b.add_argument("--self-scan", action="store_true", help="embed a live AgentAvow scan verdict")
    b.add_argument("--scan-json", help="offline scan verdict JSON (public API response)")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("sign", help="attach the detached JWS")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--prod", action="store_true", help="use the platform key via src.signing")
    g.add_argument("--test-key", action="store_true", help="ephemeral key; output marked signed-test-key")
    s.add_argument("--kid-fragment", default=DEFAULT_KID_FRAGMENT)
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="offline Level 3 checks")
    v.add_argument("--did-document", help="DID document JSON file for the issuer")
    v.add_argument("--resolve", action="store_true", help="resolve did:web over HTTPS instead")
    v.add_argument("--allow-eddsa", action="store_true", help="accept EdDSA (profile deviation)")
    v.add_argument("--unsigned-ok", action="store_true", help="accept the placeholder signature")
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
