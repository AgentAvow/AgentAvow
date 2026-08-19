"""JWKS and well-known endpoints for AgentGraph's cryptographic identity."""
from __future__ import annotations

import hashlib
import hmac
import json

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

from src.signing import (
    canonicalize_jcs_strict,
    get_jwk,
    get_trust_v2_jwks,
    has_dedicated_trust_v2_key,
)

router = APIRouter(tags=["jwks"])

# OATR (Open Agent Trust Registry) identity
_OATR_ISSUER_ID = "agentgraph"
_OATR_PUBLIC_KEY = "jWRrozl7KF08Cxjpu41FpdLMvXMC_L8U2ZYJUMvckgk"

# MCP Registry HTTP domain-verification key (namespace com.agentavow/*).
# The registry fetches /.well-known/mcp-registry-auth, reads this Ed25519
# public key, and challenges the publisher to sign with the matching private
# key (held offline, never committed). Proves we control agentavow.com and
# authorizes publishing under the com.agentavow/* namespace.
_MCP_REGISTRY_AUTH_PUBKEY = "yVsQ2iV04DaVqHjO6P/yfbUAkJ7pa8nPT4H76KuvHN4="

# ── Webhook test vectors ──────────────────────────────────────────────
# Partners implementing the scan-change receiver (MoltBridge, Verascore,
# etc.) can fetch /.well-known/webhook-test-vectors.json, reproduce the
# HMAC locally, and confirm byte-for-byte agreement with our outbound
# signing path before we wire a live shared secret. These are fixed,
# deterministic, and intentionally use an obvious test-only key.
_TEST_VECTOR_SECRET = "TEST-ONLY-DO-NOT-USE-FOR-LIVE-VERIFICATION"
_TEST_VECTOR_TIMESTAMP = "2026-04-22T00:00:00+00:00"
_TEST_VECTOR_BODY_OBJ = {
    "type": "scan-change",
    "repo": "example-org/example-repo",
    "new_score": 82,
    "old_score": 71,
    "changed_at": _TEST_VECTOR_TIMESTAMP,
    "jws": "TEST-PLACEHOLDER-JWS-NOT-A-VALID-SIGNATURE",
}


@router.get("/.well-known/jwks.json")
async def jwks() -> JSONResponse:
    """Return the platform JWKS (RFC 7517) for attestation verification.

    Includes the dedicated Trust Score v2 key when one is configured; otherwise
    v2 envelopes are signed with (and verify against) the platform key already
    published here.
    """
    keys = [get_jwk()]
    if has_dedicated_trust_v2_key():
        keys.extend(get_trust_v2_jwks())
    return JSONResponse(
        content={"keys": keys},
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/mcp-registry-auth")
async def mcp_registry_auth() -> PlainTextResponse:
    """Domain-ownership proof for the official MCP Registry (HTTP method).

    The registry fetches this file to verify we control agentavow.com, then
    challenges us to sign a nonce with the private key matching the published
    Ed25519 public key. On success it grants the ``com.agentavow/*`` namespace.
    Format: ``v=MCPv1; k=ed25519; p=<base64 public key>``.
    """
    body = f"v=MCPv1; k=ed25519; p={_MCP_REGISTRY_AUTH_PUBKEY}\n"
    return PlainTextResponse(
        content=body,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/webhook-test-vectors.json")
async def webhook_test_vectors() -> JSONResponse:
    """Publish deterministic test vectors for the partner scan-change webhook.

    Partners building a receive-side verifier for AgentGraph's outbound
    ``scan-change`` events can reproduce the HMAC locally and confirm
    byte-for-byte agreement with our sender before a live shared secret
    is exchanged. The canonical form is identical to what production
    emits from ``src.trust.outbound_webhooks``.

    Canonical form:
      ``body_bytes = json.dumps(body, separators=(",", ":"),
      sort_keys=True).encode("utf-8")``

    Signature:
      ``X-Partner-Signature: sha256=<hex>`` where
      ``hex = hmac_sha256(shared_secret, body_bytes).hexdigest()``

    Replay window: ``X-Partner-Timestamp`` (ISO-8601) must be within ±5
    minutes of receive time.
    """
    canonical_bytes = json.dumps(
        _TEST_VECTOR_BODY_OBJ, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    mac = hmac.new(
        _TEST_VECTOR_SECRET.encode("utf-8"),
        canonical_bytes,
        hashlib.sha256,
    ).hexdigest()

    return JSONResponse(
        content={
            "version": "1.0",
            "event": "scan-change",
            "contract": {
                "canonicalization": (
                    'json.dumps(body, separators=(",", ":"), sort_keys=True)'
                    ' encoded as UTF-8'
                ),
                "signature_algorithm": "HMAC-SHA256",
                "signature_header": "X-Partner-Signature",
                "signature_format": "sha256=<hex>",
                "timestamp_header": "X-Partner-Timestamp",
                "timestamp_format": "ISO-8601 (±5 minute window)",
                "event_header": "X-AgentGraph-Event",
                "content_type": "application/json",
                "jws_verification": (
                    "Body.jws is optionally verifiable via "
                    "/.well-known/jwks.json (kid agentgraph-security-v1,"
                    " Ed25519/EdDSA). The test vector uses a placeholder "
                    "jws string — real outbound events carry a valid JWS."
                ),
                "partner_docs": (
                    "https://agentgraph.co/api/v1/gateway/webhook/subscribe"
                ),
            },
            "test_vector": {
                "note": (
                    "Test-only shared secret — deterministic; do NOT use for"
                    " live signature verification. Partners should reproduce"
                    " canonical_bytes + signature locally and compare."
                ),
                "shared_secret": _TEST_VECTOR_SECRET,
                "body_object": _TEST_VECTOR_BODY_OBJ,
                "canonical_bytes_utf8": canonical_bytes.decode("utf-8"),
                "expected_headers": {
                    "Content-Type": "application/json",
                    "User-Agent": "AgentGraph-Webhook/1.0",
                    "X-AgentGraph-Event": "scan-change",
                    "X-Partner-Timestamp": _TEST_VECTOR_TIMESTAMP,
                    "X-Partner-Signature": f"sha256={mac}",
                },
                "expected_signature_hex": mac,
            },
        },
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── CTEF (Composable Trust Evidence Format) test vectors ─────────────
# Partners implementing CTEF v0.3 verifiers (APS, AgentID, MoltBridge,
# Verascore, Concordia, ...) can fetch /.well-known/cte-test-vectors.json,
# reproduce the canonical bytes + delegation_chain_root locally, and
# confirm byte-for-byte agreement with the AgentGraph canonicalizer
# before wiring a live bilateral composition. The canonical form is
# RFC 8785 JCS, identical to what src.signing.canonicalize_jcs_strict
# produces and byte-exact with the APS bilateral-delegation fixture at
# aeoess/agent-passport-system/fixtures/bilateral-delegation.
_CTE_ENVELOPE_EXAMPLE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://agentgraph.co/ns/trust-evidence/v1",
    ],
    "type": "TrustAttestation",
    "version": "0.3.1",
    "claim_type": "authority",
    "provider": {
        "id": "did:web:agentgraph.co",
        "name": "AgentGraph Trust Scanner",
        "category": "static_analysis",
        "version": "0.3.1",
    },
    "subject": {
        "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "repo": "example-org/example-repo",
        "ref": "main",
    },
    "attestation": {
        "type": "SecurityAttestation",
        "confidence": 0.82,
        "payload": {
            "trust_score": 66,
            "grade": "B",
            "findings": {"critical": 0, "high": 2, "medium": 5, "total": 7},
        },
    },
    "delegation": {
        "delegation_chain_root": (
            "4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a"
        ),
        "delegation_depth": 2,
        "canonicalization": "RFC-8785",
    },
    "issued_at": "2026-04-23T00:00:00Z",
    "expires_at": "2026-04-23T01:00:00Z",
}

# v0.3.1 negative-path vector: scope violation.
# Envelope declares claim_type="identity" but carries authority-layer
# fields (delegation). A conformant verifier MUST return
# INVALID_CLAIM_SCOPE before any semantic evaluation.
_CTE_SCOPE_VIOLATION_EXAMPLE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://agentgraph.co/ns/trust-evidence/v1",
    ],
    "type": "TrustAttestation",
    "version": "0.3.1",
    "claim_type": "identity",
    "provider": {
        "id": "did:web:agentgraph.co",
        "name": "AgentGraph Trust Scanner",
        "category": "static_analysis",
        "version": "0.3.1",
    },
    "subject": {
        "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    },
    "attestation": {
        "type": "IdentityAttestation",
        "confidence": 0.9,
        "payload": {"key_status": "active"},
    },
    "delegation": {
        "delegation_chain_root": (
            "4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a"
        ),
        "delegation_depth": 2,
        "canonicalization": "RFC-8785",
    },
    "issued_at": "2026-04-23T00:00:00Z",
    "expires_at": "2026-04-23T01:00:00Z",
}

# v0.3.1 negative-path vector: composition failure.
# Two authority-layer delegation chains with disjoint scopes. Monotonic
# narrowing produces an empty intersection, so a conformant verifier MUST
# return INVALID_COMPOSITION before semantic evaluation.
_CTE_COMPOSITION_FAILURE_EXAMPLE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://agentgraph.co/ns/trust-evidence/v1",
    ],
    "type": "TrustAttestation",
    "version": "0.3.1",
    "claim_type": "authority",
    "provider": {
        "id": "did:web:agentgraph.co",
        "name": "AgentGraph Trust Scanner",
        "category": "static_analysis",
        "version": "0.3.1",
    },
    "subject": {
        "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    },
    "attestation": {
        "type": "AuthorityComposition",
        "confidence": 0.7,
        "payload": {"composition_type": "multi_chain"},
    },
    "delegation": {
        "chains": [
            {
                "delegation_chain_root": (
                    "4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a"
                ),
                "scope": "urn:agentgraph:platform:feed:write",
            },
            {
                "delegation_chain_root": (
                    "b11a72b09b8184e3cc4620e0d5fe0926f6fecfb8cd35c2ef364c5761647c43b4"
                ),
                "scope": "urn:agentgraph:platform:marketplace:buy",
            },
        ],
        "canonicalization": "RFC-8785",
    },
    "issued_at": "2026-04-23T00:00:00Z",
    "expires_at": "2026-04-23T01:00:00Z",
}

_CTE_VERDICT_EXAMPLE = {
    "type": "EnforcementVerdict",
    "version": "0.3.1",
    "gateway": {
        "id": "did:web:agentgraph.co#gateway",
        "name": "AgentGraph Trust Gateway",
        "version": "0.3.1",
    },
    "claim": {
        "action": {
            "type": "mutation:platform_access",
            "target": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "scope": "urn:agentgraph:platform:feed:write",
        },
        "evidence_basis": {
            "bundle_hash": (
                "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            ),
            "delegation_chain_root": (
                "4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a"
            ),
        },
        "admissibility_result": "conditional_allow",
        "validity_window": {
            "not_before": "2026-04-23T00:00:00Z",
            "not_after": "2026-04-23T01:00:00Z",
            "binding_mode": "authority_within_window_evidence_after",
        },
        "forwardability": {
            "mode": "local",
            "forwardable_to": [],
            "delegation_path": None,
        },
    },
    "issued_at": "2026-04-23T00:00:00Z",
    "expires_at": "2026-04-23T01:00:00Z",
}


@router.get("/.well-known/cte-test-vectors.json")
async def cte_test_vectors() -> JSONResponse:
    """Publish deterministic test vectors for CTEF v0.3 canonicalization.

    Partners building a CTEF v0.3 verifier (or a provider that composes
    with AgentGraph bilaterally) can reproduce the canonical bytes + the
    delegation-chain-root hash locally and confirm byte-for-byte
    agreement with AgentGraph's canonicalizer. The canonical form is
    identical to ``src.signing.canonicalize_jcs_strict`` and is validated
    against the APS bilateral-delegation fixture (10 JCS vectors, all
    passing) — so an APS-conformant verifier and an AgentGraph-conformant
    verifier MUST produce byte-exact agreement on the same input.

    The two example envelopes here (a ``TrustAttestation`` carrying a
    ``delegation_chain_root``, and an ``EnforcementVerdict`` carrying
    the v0.3 5-dimension claim model) exercise the full surface a
    partner needs to implement.
    """
    envelope_bytes = canonicalize_jcs_strict(_CTE_ENVELOPE_EXAMPLE)
    verdict_bytes = canonicalize_jcs_strict(_CTE_VERDICT_EXAMPLE)
    scope_violation_bytes = canonicalize_jcs_strict(_CTE_SCOPE_VIOLATION_EXAMPLE)
    composition_failure_bytes = canonicalize_jcs_strict(
        _CTE_COMPOSITION_FAILURE_EXAMPLE
    )

    envelope_sha = hashlib.sha256(envelope_bytes).hexdigest()
    verdict_sha = hashlib.sha256(verdict_bytes).hexdigest()
    scope_violation_sha = hashlib.sha256(scope_violation_bytes).hexdigest()
    composition_failure_sha = hashlib.sha256(composition_failure_bytes).hexdigest()

    return JSONResponse(
        content={
            "version": "0.3.1",
            "spec": "CTEF (Composable Trust Evidence Format)",
            "contract": {
                "canonicalization": "RFC 8785 (JSON Canonicalization Scheme)",
                "canonicalization_rules": [
                    "Keys sorted by Unicode code point.",
                    "Non-ASCII above U+001F emitted as literal UTF-8 bytes (not \\uXXXX escapes).",
                    "null values preserved at every depth.",
                    "Integer-valued floats normalized to integers (ECMA-262 §7.1.12.1).",
                ],
                "hash_algorithm": "SHA-256",
                "delegation_chain_root": (
                    "hex(sha256(canonicalize_jcs_strict(delegation_chain)))"
                ),
                "reference_implementation": (
                    "src.signing.canonicalize_jcs_strict "
                    "(agentgraph-co/agentgraph)"
                ),
                "reference_fixtures": [
                    {
                        "source": (
                            "aeoess/agent-passport-system/fixtures/bilateral-delegation/"
                            "canonicalize-fixture-v1.json"
                        ),
                        "vectors": 10,
                        "status": "AgentGraph passes 10/10 byte-exact",
                        "test": "tests/test_jcs_canonicalize_aps_interop.py",
                    },
                    {
                        "source": "https://aeoess.com/fixtures/rotation-attestation/",
                        "vectors": 5,
                        "status": "AgentGraph passes 5/5 byte-exact (live-fetch dual-lock)",
                        "test": "tests/test_aps_rotation_attestation_interop.py",
                    },
                ],
                "rfc": (
                    "See docs/internal/rfc-evidence-format-v1.md in "
                    "agentgraph-co/agentgraph for the full CTEF v0.3.1 spec."
                ),
            },
            "claim_model": {
                "claim_type": {
                    "closed_set": [
                        "identity",
                        "transport",
                        "authority",
                        "continuity",
                    ],
                    "required_on_envelope": True,
                    "note": (
                        "Outer discriminator for the claim-layer semantics. "
                        "Added in v0.3.1. A claim carrying fields outside "
                        "its declared category MUST be rejected with "
                        "INVALID_CLAIM_SCOPE before semantic evaluation."
                    ),
                },
                "composition_rules": {
                    "identity": (
                        "Key binding — same DID across claims, same "
                        "resolution path. Two verifiers given the same "
                        "identity claim must resolve the same key."
                    ),
                    "transport": (
                        "Identity-key binding — the identity signs the "
                        "transport key. Transport-layer claims compose "
                        "onto the identity they reference."
                    ),
                    "authority": (
                        "Monotonic narrowing — effective scope after a "
                        "delegation chain is the greatest lower bound "
                        "(intersection) of every scope in the chain. "
                        "Content-addressed via delegation_chain_root. "
                        "Two claims with disjoint scopes produce "
                        "INVALID_COMPOSITION."
                    ),
                    "continuity": (
                        "Rotation-attestation chain — history-stability "
                        "under rotation, content-addressed over the "
                        "rotation event sequence. An SMSH-style tier "
                        "trajectory is a superset-with-projection: "
                        "reduces to a scalar under an AGT-compatible "
                        "projection but carries richer evidence that "
                        "is not lost under the projection."
                    ),
                },
                "superset_with_projection_principle": (
                    "When one layer's representation can project to a "
                    "simpler shape a partner verifier expects, declare "
                    "the superset form and the projection explicitly. "
                    "Lossy projections between layer representations "
                    "are where silent divergence lives; an explicit "
                    "superset-with-projection avoids it. This is the "
                    "composition principle for every layer, not only "
                    "a one-off example — every future layer addition "
                    "should template safe downgrade this way."
                ),
                "projection_family_examples": [
                    {
                        "layer": "authority",
                        "superset": "delegation_chain_root (content-addressed chain)",
                        "projection": "AGT trust_score (scalar)",
                        "loses": "chain depth, per-hop scope narrowing, intermediate principals",
                    },
                    {
                        "layer": "continuity",
                        "superset": "rotation-attestation chain (ordered event sequence)",
                        "projection": "has_rotated: bool",
                        "loses": "rotation timing, migration_type, attestor identity",
                    },
                    {
                        "layer": "continuity",
                        "superset": "continuity receipts (trajectory over kid history)",
                        "projection": "last_seen_kid (scalar key identifier)",
                        "loses": "prior kids, rotation reasons, issuance timestamps",
                    },
                    {
                        "layer": "identity",
                        "superset": "multi-anchor resolution path (JWKS + DNS + WebPKI)",
                        "projection": "resolved_did (scalar identifier)",
                        "loses": "anchor diversity, federation trust tier, AGT metadata",
                    },
                ],
            },
            "error_codes": {
                "INVALID_CLAIM_SCOPE": {
                    "triggers_on": (
                        "Claim carries fields outside its declared "
                        "claim_type (e.g. identity-categorized "
                        "claim carrying authority-layer delegation)."
                    ),
                    "ordering": (
                        "Structural failure precedes semantic evaluation. "
                        "Fail-closed is mandatory before any layer-specific "
                        "logic runs."
                    ),
                    "test_vector": "scope_violation_vector (below)",
                },
                "INVALID_COMPOSITION": {
                    "triggers_on": (
                        "Well-typed claims at each layer cannot be combined "
                        "under the layer's composition rule (e.g. disjoint "
                        "authority scopes, broken rotation chain, unresolvable "
                        "identity-to-transport binding). Distinct from "
                        "INVALID_CLAIM_SCOPE — no per-claim scope violation "
                        "has occurred; the composition is what fails."
                    ),
                    "ordering": (
                        "Structural failure precedes semantic evaluation. "
                        "Same ordering constraint as INVALID_CLAIM_SCOPE."
                    ),
                    "test_vector": "composition_failure_vector (below)",
                },
            },
            "reserved_values": {
                "claim_type.envelope": {
                    "status": "reserved",
                    "committed_in": "v0.3.2 or v0.3.1 errata",
                    "composition_rule_variants": [
                        {
                            "name": "zero_knowledge_membership",
                            "use_when": (
                                "The envelope identity itself must stay "
                                "private from the verifier (envelope name "
                                "is sensitive, not just the member list)."
                            ),
                            "shape": (
                                "ZK proof of membership in the "
                                "attestation-registry snapshot, "
                                "content-addressed over the snapshot root."
                            ),
                        },
                        {
                            "name": "signed_snapshot_attestation",
                            "use_when": (
                                "The envelope is public; only the member "
                                "list is sensitive. Cheaper, no ZK runtime "
                                "dependency, still unlinkable across members."
                            ),
                            "shape": (
                                "Issuer signature over "
                                "{subject, registry_root, "
                                "asserted_membership: true} where "
                                "registry_root is the content-addressed "
                                "snapshot identifier at attestation time."
                            ),
                        },
                    ],
                    "note": (
                        "Fifth-layer regulatory-envelope attestation "
                        "(Hive Civilization contribution). Implementations "
                        "pick by privacy requirement: ZK for private "
                        "envelope identity, signed-snapshot when only the "
                        "member list needs unlinkability. Both variants "
                        "will be named in the v0.3.2 normative rule table. "
                        "APS (aeoess/agent-passport-system) has committed "
                        "to adopting the same claim_type value in "
                        "adapter mappings when it lands. "
                        "Specification forthcoming."
                    ),
                },
                "evidence_basis.evidence_type.payment_execution": {
                    "status": "reserved",
                    "committed_in": "v0.3.2 or v0.3.1 errata",
                    "note": (
                        "Payment-execution receipt as an independent "
                        "signal type (HiveCompute x402 contribution). "
                        "Answers 'consideration was exchanged' — "
                        "distinct from 'task result matches spec' (SAR). "
                        "Expected fields: eip3009_authorization_hash, "
                        "base_tx_hash, wallet_did, amount_usdc, issued_at. "
                        "Specification forthcoming."
                    ),
                },
            },
            "envelope_vector": {
                "note": (
                    "Example CTEF v0.3.1 TrustAttestation envelope "
                    "(claim_type=authority) with delegation_chain_root "
                    "composition per §4.6. A partner verifier MUST "
                    "reproduce canonical_bytes_utf8 and canonical_sha256 "
                    "exactly; divergence indicates a canonicalizer drift "
                    "that would break bilateral composition."
                ),
                "input_object": _CTE_ENVELOPE_EXAMPLE,
                "canonical_bytes_utf8": envelope_bytes.decode("utf-8"),
                "canonical_sha256": envelope_sha,
                "expected_result": "pass",
            },
            "verdict_vector": {
                "note": (
                    "Example CTEF v0.3.1 EnforcementVerdict with the "
                    "5-dimension claim-model surface per §6.3 (action, "
                    "evidence_basis, admissibility_result, validity_window, "
                    "forwardability). A partner that consumes AgentGraph "
                    "verdicts should verify canonical_sha256 matches what "
                    "they compute locally."
                ),
                "input_object": _CTE_VERDICT_EXAMPLE,
                "canonical_bytes_utf8": verdict_bytes.decode("utf-8"),
                "canonical_sha256": verdict_sha,
                "expected_result": "pass",
            },
            "scope_violation_vector": {
                "note": (
                    "Negative-path vector (v0.3.1). Envelope declares "
                    "claim_type='identity' but carries authority-layer "
                    "delegation fields. A conformant verifier MUST reject "
                    "with INVALID_CLAIM_SCOPE before semantic evaluation "
                    "— structural failure precedes any layer-specific "
                    "logic. Canonical bytes are reproducible; the "
                    "expected_result is fail-closed, not pass."
                ),
                "input_object": _CTE_SCOPE_VIOLATION_EXAMPLE,
                "canonical_bytes_utf8": scope_violation_bytes.decode("utf-8"),
                "canonical_sha256": scope_violation_sha,
                "expected_result": "fail-closed",
                "expected_error_code": "INVALID_CLAIM_SCOPE",
            },
            "composition_failure_vector": {
                "note": (
                    "Negative-path vector (v0.3.1). Two authority-layer "
                    "delegation chains with disjoint scopes "
                    "(feed:write vs marketplace:buy). Monotonic narrowing "
                    "produces an empty intersection, so a conformant "
                    "verifier MUST reject with INVALID_COMPOSITION before "
                    "semantic evaluation. Canonical bytes are reproducible; "
                    "the expected_result is fail-closed, not pass."
                ),
                "input_object": _CTE_COMPOSITION_FAILURE_EXAMPLE,
                "canonical_bytes_utf8": composition_failure_bytes.decode("utf-8"),
                "canonical_sha256": composition_failure_sha,
                "expected_result": "fail-closed",
                "expected_error_code": "INVALID_COMPOSITION",
            },
        },
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/action-ref-near-miss-vectors.json")
async def action_ref_near_miss_vectors() -> JSONResponse:
    """CTEF action_ref near-miss conformance vectors (A2A #1734/#1850).

    The failure modes action_ref correlation MUST catch — ambiguous issuer
    binding, rescoped replay, issuance→verification semantic drift — in canonical
    fixture format (preimage JSON + expected receipt fields + failure-mode label),
    byte-reproducible against any RFC 8785 canonicalizer. Contributed to the
    draft-giskard-aeoess-action-ref I-D and the substrate-attestation suite.
    """
    from src.trust.action_ref_vectors import build_artifact

    return JSONResponse(
        content=build_artifact(),
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/ctef-error-codes.json")
async def ctef_error_codes() -> JSONResponse:
    """CTEF unified error vocabulary (v0.3.3 Artifact 2) — CTEF-side contribution
    to the cross-spec error enum, layer-routed (wire / identity / authority /
    continuity / correlation), every code structural + fail-closed."""
    from src.trust.ctef_error_codes import build_vocabulary

    return JSONResponse(
        content=build_vocabulary(),
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/agent-trust.json")
async def agent_trust() -> JSONResponse:
    """Domain verification for Open Agent Trust Registry (OATR).

    CI at FransDevelopment/open-agent-trust-registry fetches this to verify
    domain ownership during issuer registration.
    """
    return JSONResponse(
        content={
            "issuer_id": _OATR_ISSUER_ID,
            "public_key_fingerprint": _OATR_PUBLIC_KEY,
        },
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/.well-known/interop-harness.json")
async def interop_harness() -> JSONResponse:
    """Consolidated CTEF v0.3.1 byte-match interop harness state.

    Single artifact summarizing every implementation that has byte-match
    validated against the published test vectors. Requested by aeoess for
    A2A WG #1786 sponsorship readiness — partners and maintainers can
    fetch one URL to see the full cross-implementation harness state.

    Updated whenever a new implementation byte-match-validates.
    """
    return JSONResponse(
        content={
            "spec": "CTEF (Composable Trust Evidence Format)",
            "spec_version": "0.3.1",
            "spec_anchor": "https://agentgraph.co/.well-known/cte-test-vectors.json",
            "wg_proposal": "https://github.com/a2aproject/A2A/issues/1786",
            "as_of": "2026-05-05",
            "evidence_taxonomy": {
                "substrate": (
                    "JCS canonicalizer byte-match across independent "
                    "implementations on signed fixtures. Multi-source-proven "
                    "as of 2026-05-01 via 8 independent canonicalizers + 2 "
                    "publicly-runnable verification scripts (Nobulex "
                    "verify-aps-byte-match.mjs + verify-ctef-byte-match.mjs)."
                ),
                "verifier_conformance": (
                    "claim_type discrimination, composition contracts, "
                    "negative-path semantics. Per-implementation work that "
                    "lands per role-taxonomy slot. Citation-graph framing "
                    "from msaleme (A2A #1786, 2026-04-30) — substrate and "
                    "verifier conformance are separable evidence categories."
                ),
                "reproducibility": (
                    "Anyone-can-clone reproducibility added 2026-04-30 via "
                    "Nobulex scripts that pull APS + CTEF fixtures from "
                    "their canonical sources, run through @nobulex/crypto, "
                    "compare SHA-256 against expected hashes, and emit "
                    "verification receipts. Lifts the substrate-evidence "
                    "claim from 'stated and validated' to 'reader-runnable.' "
                    "On 2026-05-01, APS independently re-ran both scripts "
                    "and posted PASS receipts (10/10 + 4/4 incl negative-"
                    "path) mirrored at aeoess/aps-conformance-suite/cross-"
                    "impl-receipts/ — substrate evidence now lives in two "
                    "independent repos with no maintainer re-run dependency."
                ),
            },
            "role_taxonomy": {
                "evidence_provider": (
                    "Issues claim_type-tagged attestations against the CTEF "
                    "envelope; produces JCS-canonicalized signed evidence; "
                    "appears as the upstream signer in a verifier's trust "
                    "chain."
                ),
                "enforcement_gateway": (
                    "Evaluation-only: receives evidence bundles, evaluates "
                    "against policy, returns JWS-signed verdicts (certified "
                    "true/false + attestation). No evidence emission, no "
                    "canonicalization dependency. Verifies existing proofs "
                    "and issues policy decisions only — does not re-sign or "
                    "re-canonicalize. Sits downstream of evidence providers. "
                    "Per arkforge framing, A2A #1734 comment 2026-04-30."
                ),
                "substrate_verifier": (
                    "Independent canonicalizer + fixture-validation runner "
                    "with no implementation overlap with the providers it "
                    "verifies. Reproduces SHA-256s without issuing or "
                    "evaluating evidence. Closes the 'everyone running the "
                    "same canonicalizer library' objection for sponsorship "
                    "review weighting."
                ),
            },
            "implementations": [
                {
                    "name": "AgentGraph",
                    "maintainer": "@kenneives",
                    "language": "Python",
                    "role": "evidence_provider",
                    "bilateral_delegation_byte_match": "10/10",
                    "rotation_attestation_byte_match": "5/5 (live-fetch)",
                    "claim_type_live": True,
                    "claim_type_endpoint": (
                        "https://agentgraph.co/.well-known/cte-test-vectors.json"
                    ),
                    "test_files": [
                        "tests/test_jcs_canonicalize_aps_interop.py",
                        "tests/test_aps_rotation_attestation_interop.py",
                        "tests/test_cte_test_vectors.py",
                    ],
                },
                {
                    "name": "Agent Passport System (APS)",
                    "maintainer": "@aeoess",
                    "language": "Python",
                    "role": "evidence_provider",
                    "bilateral_delegation_byte_match": (
                        "publishes the fixture set"
                    ),
                    "rotation_attestation_byte_match": (
                        "publishes the fixture set"
                    ),
                    "claim_type_live": True,
                    "fixture_repo": (
                        "https://github.com/aeoess/agent-passport-system"
                    ),
                },
                {
                    "name": "AgentID",
                    "maintainer": "@haroldmalikfrimpong-ops",
                    "language": "Python",
                    "role": "evidence_provider",
                    "bilateral_delegation_byte_match": "10/10 (32/32 tests)",
                    "rotation_attestation_byte_match": None,
                    "claim_type_live": True,
                    "claim_type_endpoint": (
                        "https://getagentid.dev/api/v1/agents/verify"
                    ),
                },
                {
                    "name": "@nobulex/crypto",
                    "maintainer": "@arian-gogani",
                    "language": "TypeScript",
                    "role": "evidence_provider",
                    "bilateral_delegation_byte_match": "10/10",
                    "ctef_inline_byte_match": (
                        "4/4 SHA-256-exact including both negative-path "
                        "vectors (INVALID_CLAIM_SCOPE, INVALID_COMPOSITION) "
                        "— A2A #1786 comment 2026-04-30"
                    ),
                    "rotation_attestation_byte_match": "verifier testing in flight",
                    "claim_type_live": False,
                    "package": "@nobulex/crypto (npm)",
                    "merged_into": (
                        "Microsoft Agent Governance Toolkit "
                        "(microsoft/agent-governance-toolkit#1333, "
                        "OpenSSF passing badge, 2026-04 week)"
                    ),
                    "reproducibility_scripts": {
                        "aps_bilateral_delegation": (
                            "https://github.com/arian-gogani/nobulex/blob/main/"
                            "scripts/verify-aps-byte-match.mjs"
                        ),
                        "ctef_v031_inline": (
                            "https://github.com/arian-gogani/nobulex/blob/main/"
                            "scripts/verify-ctef-byte-match.mjs"
                        ),
                        "receipt_artifacts": (
                            "aps-byte-match-receipt.json + "
                            "ctef-byte-match-receipt.json in repo root"
                        ),
                        "instructions": (
                            "Anyone can clone arian-gogani/nobulex and run "
                            "`node scripts/verify-aps-byte-match.mjs` and "
                            "`node scripts/verify-ctef-byte-match.mjs` to "
                            "reproduce 10/10 APS + 4/4 CTEF byte-match "
                            "without any AgentGraph or APS code path"
                        ),
                    },
                    "aaif_filing": (
                        "aaif/project-proposals#20 (Nobulex, filed "
                        "2026-04-30) — Growth-stage proposal positioning "
                        "Nobulex bilateral-receipt primitive as accountability "
                        "infrastructure layered on the CTEF substrate; cites "
                        "AgentGraph as harness maintainer + 8 byte-match "
                        "implementations as cross-organization adoption proof"
                    ),
                },
                {
                    "name": "HiveTrust",
                    "maintainer": "@srotzin",
                    "language": "Python",
                    "role": "evidence_provider",
                    "inline_vector_byte_match": (
                        "4/4 byte-exact + SHA-256-exact (envelope, verdict, "
                        "scope_violation, composition_failure) — A2A #1786 "
                        "comment 2026-04-28"
                    ),
                    "bilateral_delegation_byte_match": (
                        "alignment confirmed; APS bilateral-delegation + "
                        "rotation-attestation runs queued"
                    ),
                    "rotation_attestation_byte_match": "queued",
                    "claim_type_live": True,
                    "verifier_url": (
                        "https://hive-gamification.onrender.com/v1/compliance/verify/{attestation_id}"
                    ),
                    "ed25519_pubkey": (
                        "12de746d51fca019c5c64685f2688a0e4a57ab532f6f6c67d44494de43f4c408"
                    ),
                    "schema_url": "https://hivemorph.onrender.com/openapi.json",
                },
                {
                    "name": "ArkForge Trust Layer",
                    "maintainer": "@desiorac",
                    "language": "Python",
                    "role": "enforcement_gateway",
                    "inline_vector_byte_match": (
                        "4/4 byte-exact (canonical + SHA-256) — qntm#7 PR #14, "
                        "2026-04-30"
                    ),
                    "constraint_evaluation_vectors": (
                        "3 scenarios delivered (within-limit delta=250, "
                        "near-miss delta=5, exceeded delta=-150) — facet/limit/"
                        "actual/delta shape from corpollc/qntm#6"
                    ),
                    "claim_type_live": True,
                    "did": "did:web:trust.arkforge.tech",
                    "verifier_url": "https://trust.arkforge.tech/v1/proxy",
                    "self_verification_script": (
                        "specs/test-vectors/verify_execution_attestation_arkforge.py"
                    ),
                },
                {
                    "name": "msaleme clean-room canonicalizer",
                    "maintainer": "@msaleme",
                    "language": "Python",
                    "role": "substrate_verifier",
                    "canonicalizer": "trailofbits/rfc8785.py v0.1.4",
                    "byte_match_aggregate": (
                        "19/19 byte-exact + SHA-256-exact across three fixture "
                        "sources: AgentGraph CTEF v0.3.1 inline (4/4), APS "
                        "bilateral-delegation (10/10), APS rotation-attestation "
                        "(5/5) — A2A #1786 comment 2026-04-30"
                    ),
                    "implementation_independence": (
                        "Zero implementation overlap with AgentGraph / APS / "
                        "AgentID / Nobulex / HiveTrust — closes the 'everyone "
                        "running the same canonicalizer library' objection"
                    ),
                    "verifier_reference_artifact": (
                        "~150 lines of Python over rfc8785.py; offered as "
                        "standalone WG-citation artifact"
                    ),
                    "claim_type_live": False,
                },
                {
                    "name": "Foxbook",
                    "maintainer": "@cloakmaster",
                    "language": "TypeScript",
                    "role": "evidence_provider",
                    "claim_type_layer": "identity",
                    "canonicalizer": "canonicalize@2.1.0 (erdtman RFC 8785 reference impl)",
                    "inline_vector_byte_match": (
                        "4/4 SHA-256-exact against agentgraph-co/agentgraph@69ad94d "
                        "— A2A #1672 comment 2026-04-30"
                    ),
                    "claim_type_live": True,
                    "did_method": "did:foxbook:{ULID}",
                    "transparency_log": "https://transparency.foxbook.dev",
                    "byte_match_report": (
                        "https://github.com/cloakmaster/foxbook/blob/9e392c5/"
                        "ops/evidence/2026-04-30-ctef-v0.3.1-byte-match.md"
                    ),
                    "wg_proposal": "A2A #1803",
                },
                {
                    "name": "substrate-attestation",
                    "maintainer": "@andysalvo",
                    "language": "Python",
                    "role": "substrate_verifier",
                    "description": (
                        "Neutral verification-layer adapter; validates against the "
                        "referenced CTEF / action_ref near-miss vectors for issuer "
                        "binding, replay rescoping, and semantic drift cases."
                    ),
                    "repo": "https://github.com/andysalvo/substrate-attestation",
                    "license": "Apache-2.0",
                    "near_miss_corpus_pinned": (
                        "agentgraph-co/agentgraph@a07cdf8 "
                        "(action-ref-near-miss-vectors.json)"
                    ),
                    "ctef_anchor_pinned": (
                        "agentgraph.co/.well-known/cte-test-vectors.json"
                    ),
                    "inline_vector_byte_match": (
                        "4/4 SHA-256-exact (envelope, verdict, scope_violation, "
                        "composition_failure) vs rfc8785 Python v0.1.4 — receipt "
                        "CVR-2026-013.json, confirmed 2026-06-01"
                    ),
                    "claim_type_live": False,
                    "added": "2026-06-01 per A2A #1734",
                },
            ],
            "in_flight": [
                {
                    "name": "Vorim AI",
                    "maintainer": "@kwame",
                    "language": "TypeScript",
                    "ietf_draft": "draft-vorim-vaip-00",
                    "status": "byte-match validation in flight as 6th implementation",
                },
                {
                    "name": "Concordia",
                    "maintainer": "@erik-newton",
                    "language": "Python",
                    "status": (
                        "PR #10 to haroldmalikfrimpong-ops/agentid-aps-interop "
                        "approved with 131/131 checks; Concordia v1.0.0 fixtures + "
                        "verify.py repair"
                    ),
                },
                {
                    "name": "lawcontinue distributed-inference reference",
                    "maintainer": "@lawcontinue",
                    "status": (
                        "245-step sequence_bound case in coordination with APS for "
                        "v0.3.2 §6.3.1 worked example"
                    ),
                },
                {
                    "name": "msaleme x402 conformance harness (claim_type module)",
                    "maintainer": "@msaleme",
                    "status": (
                        "substrate-layer byte-match completed and promoted to "
                        "the implementations list (7th impl, substrate_verifier "
                        "role, 19/19 across three fixture sources via "
                        "trailofbits/rfc8785.py). Verifier-conformance work for "
                        "claim_type-tagged compliance scoped against the "
                        "experimental-ext repo once it opens for test-vector "
                        "contributions; delivery window not yet scoped. A2A "
                        "#1786 comment 2026-04-30"
                    ),
                },
                {
                    "name": "AEP (Agentic Exchange Protocol)",
                    "maintainer": "@Pineapples100",
                    "language": "spec draft",
                    "status": (
                        "T0–T3 trust tier model + /.well-known/aep-manifest.json "
                        "for org-level trust boundaries on SMTP/iCal/messaging "
                        "surfaces; tier-transition proofs would compose as "
                        "authority-layer claims in CTEF envelope; "
                        "https://github.com/pmyers-abundance/aep — A2A #1734 "
                        "comment 2026-04-30"
                    ),
                },
                {
                    "name": "Dominion Observatory",
                    "maintainer": "@vdineshk",
                    "role": "evidence_provider",
                    "claim_type_layer": "behavioral",
                    "did": "did:web:dominion-observatory.sgdata.workers.dev",
                    "evidence_uri_pattern": (
                        "https://dominion-observatory.sgdata.workers.dev/"
                        "v1/behavioral-evidence/{server-id}"
                    ),
                    "fallback_uri_pattern": (
                        "https://dominion-observatory.sgdata.workers.dev/"
                        "benchmark/{server-id}"
                    ),
                    "tier_distribution_endpoint": (
                        "https://dominion-observatory.sgdata.workers.dev/"
                        "api/sla-tier"
                    ),
                    "production_scale": (
                        "Behaviorally monitoring 4,586 MCP servers since "
                        "April 2026; live tier distribution per /api/sla-tier: "
                        "8 Platinum / 0 Gold / 3 Silver / 4 Bronze / 27 "
                        "Unrated (rest insufficient_data)"
                    ),
                    "evidence_pattern": "Path C — URI-reference, not fixture-embedding",
                    "rationale": (
                        "Behavioral evidence degrades on hours-to-days under "
                        "the 7-day TTL cap; static fixtures are stale by "
                        "definition. URI-reference preserves substrate-and-"
                        "primitive separation: substrate (CTEF v0.3.2) "
                        "defines envelope; primitive (Observatory) defines "
                        "the live measurement. Symmetric to how identity + "
                        "authority claim_types reference live DID resolvers "
                        "rather than ship cached identity fixtures."
                    ),
                    "ttl_cap": "7 days (CTEF v0.3.2 §1.5 normative MUST)",
                    "tier_mapping": {
                        "Platinum": {"trust_tier": "trusted", "confidence_min": 0.9},
                        "Gold": {"trust_tier": "trusted", "confidence_min": 0.85},
                        "Silver": {"trust_tier": "standard", "confidence_min": 0.7},
                        "Bronze": {"trust_tier": "minimal", "confidence_min": 0.5},
                        "Unrated": {
                            "trust_tier": "restricted",
                            "note": "insufficient_data, NOT failing posture",
                        },
                    },
                    "live_verification_examples": {
                        "platinum": (
                            "/v1/behavioral-evidence/sg-cpf-calculator-mcp"
                        ),
                        "silver_with_degradation": (
                            "identifiable via /api/trust-delta"
                        ),
                        "unrated_insufficient_data": (
                            "served with explicit sample_count + "
                            "observation_window_days"
                        ),
                        "negative_path_malformed": (
                            "/benchmark/{nonexistent-server} returns "
                            "documented 404 envelope"
                        ),
                    },
                    "status": (
                        "Registered 2026-05-04 PM per A2A #1734 sequencing. "
                        "URI-reference pattern locked for CTEF v0.3.2 §4.5; "
                        "spec-text draft + litepaper §3.4 citation pending "
                        "vdineshk review pre-publish."
                    ),
                },
                {
                    "name": "openclaw-skill-quality-analyzer (Miaoqu AI)",
                    "maintainer": "@jingchang0623-crypto / AIwalker",
                    "role_target": "evidence_provider",
                    "claim_type_layer": "behavioral",
                    "claim_subtype_target": "maintenance_health",
                    "repo": (
                        "https://github.com/jingchang0623-crypto/"
                        "openclaw-skill-quality-analyzer"
                    ),
                    "complementary_to": (
                        "AgentGraph security scanner — five-dimension "
                        "scoring (security/docs/tests/maintenance/compatibility)"
                        " complements security-only static analysis"
                    ),
                    "operator_evidence": (
                        "90-day production deployment running 25 OpenClaw "
                        "skills; concrete failure observations cited at "
                        "agentgraph-co/agentgraph#17 (telemetry-leaking RSS "
                        "skill, hardcoded API keys with shell=True SEO skill, "
                        "fork/upstream permission confusion in GitHub "
                        "automation skill)"
                    ),
                    "maintenance_health_metric_proposal": (
                        "commit_recency + commit_frequency + change_magnitude"
                        " + maintainer_continuity — proposed for adoption as "
                        "v0.4 §6.x.y maintenance_health claim_subtype under "
                        "behavioral layer"
                    ),
                    "status": (
                        "Welcomed at agentgraph-co/agentgraph#17 2026-05-04 "
                        "as Chinese-market operator-side voice + complementary "
                        "evidence_provider; byte-match validation against "
                        "CTEF v0.3.1 inline vectors invited"
                    ),
                },
            ],
            "negative_path_vectors": {
                "scope_violation": {
                    "expected_error_code": "INVALID_CLAIM_SCOPE",
                    "purpose": (
                        "structural-before-semantic ordering — claim carrying "
                        "fields outside its declared claim_type MUST be rejected "
                        "before semantic evaluation"
                    ),
                },
                "composition_failure": {
                    "expected_error_code": "INVALID_COMPOSITION",
                    "purpose": (
                        "scope-narrowing-only invariant — child scope MUST NOT "
                        "expand parent scope; composition failure is fail-closed"
                    ),
                },
            },
            "summary": {
                "implementations_byte_match_validated": 9,
                "implementations_inline_vector_byte_match_validated": 6,
                "evidence_providers": 6,
                "enforcement_gateways": 1,
                "substrate_verifiers": 2,
                "languages": 2,
                "independent_canonicalizers": 8,
                "wg_proposal_phase": "Proposal Phase, awaiting maintainer sponsorship",
                "fail_closed_negative_paths": 2,
                "reader_runnable_verifiers": 2,
                "cross_repository_receipt_mirrors": 2,
                "automated_mirror_sync": True,
            },
            "cross_validation_receipts": {
                "receipt_sources": {
                    "primary": {
                        "repo": "https://github.com/arian-gogani/nobulex",
                        "role": "originating verifier",
                        "maintainer": "@arian-gogani",
                        "files": [
                            "aps-byte-match-receipt.json",
                            "ctef-byte-match-receipt.json",
                        ],
                    },
                    "mirror": {
                        "repo": (
                            "https://github.com/aeoess/aps-conformance-suite/"
                            "tree/main/cross-impl-receipts"
                        ),
                        "role": "third-party mirror with byte-exact SHA-256 verification",
                        "maintainer": "@aeoess",
                        "sync": (
                            "Daily-poll GitHub Action at "
                            ".github/workflows/sync-cross-impl-receipts.yml — "
                            "schedule 00:00 UTC, workflow_dispatch wired for "
                            "ad-hoc triggers"
                        ),
                        "files_pinned_2026_05_02": {
                            "aps-byte-match-receipt.json": (
                                "a4d63359574a7408cac8dd3c132586cff611535c4c8f"
                                "074ed3556a61cf165443"
                            ),
                            "ctef-byte-match-receipt.json": (
                                "2e8afc85080ed64fe539c913410f2343d10cba8c5b17"
                                "f61cc8a7d19e4fa11216"
                            ),
                            "ctef-vectors.json": (
                                "b655d1b3e7aeccb8b75517c1efc46d2dbf6759dea075"
                                "81a1b39d4ab59baa7046"
                            ),
                            "source_commit": "arian-gogani/nobulex@d68fcee",
                            "fetched_at": "2026-05-02T00:18:49Z",
                        },
                    },
                },
                "agentgraph_to_aps_via_nobulex": {
                    "verifier_repo": "https://github.com/arian-gogani/nobulex",
                    "verifier_script": "scripts/verify-aps-byte-match.mjs",
                    "fixture_source": (
                        "https://github.com/aeoess/agent-passport-system/blob/"
                        "main/fixtures/bilateral-delegation/"
                        "canonicalize-fixture-v1.json"
                    ),
                    "result": "10/10 PASS",
                    "third_party_rerun": (
                        "APS-side rerun 2026-05-01T16:59:33Z; receipt "
                        "mirrored at aeoess/aps-conformance-suite/cross-"
                        "impl-receipts/aps-byte-match-receipt.json"
                    ),
                    "seed_sha256": (
                        "4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a"
                    ),
                },
                "ctef_v031_via_nobulex": {
                    "verifier_repo": "https://github.com/arian-gogani/nobulex",
                    "verifier_script": "scripts/verify-ctef-byte-match.mjs",
                    "fixture_source": "https://agentgraph.co/.well-known/cte-test-vectors.json",
                    "fixture_version": "0.3.1",
                    "fixture_commit": "agentgraph-co/agentgraph@69ad94d",
                    "result": (
                        "4/4 PASS including both negative-path vectors "
                        "(INVALID_CLAIM_SCOPE, INVALID_COMPOSITION)"
                    ),
                    "independent_reproductions": [
                        {
                            "party": "Nobulex (origin)",
                            "date": "2026-04-30",
                            "result": "4/4 PASS",
                        },
                        {
                            "party": "APS (aeoess)",
                            "date": "2026-05-01T17:03:08Z",
                            "result": "4/4 PASS",
                            "receipt_mirror": (
                                "aeoess/aps-conformance-suite/cross-impl-"
                                "receipts/ctef-byte-match-receipt.json"
                            ),
                        },
                        {
                            "party": "Dominion Observatory (vdineshk)",
                            "date": "2026-05-05",
                            "result": "4/4 PASS",
                            "receipt_committed": (
                                "vdineshk/daee-engine: dominion-observatory/"
                                "conformance-receipts/2026-05-05-ctef-v031-"
                                "byte-match-receipt.json"
                            ),
                        },
                    ],
                },
                "canonical_bytes_diff_v032": {
                    "fixture_source_pr": "https://github.com/corpollc/qntm/pull/15",
                    "fixture_path": (
                        "specs/test-vectors/canonical-bytes-diff-v032.json"
                    ),
                    "verifier_script": (
                        "specs/test-vectors/verify_canonical_bytes_diff.py"
                    ),
                    "result": "5/5 PASS (hash divergence + collision + canonical immunity)",
                    "independent_reproductions": [
                        {
                            "party": "AgentGraph",
                            "date": "2026-05-01",
                            "result": "5/5 PASS",
                        },
                        {
                            "party": "APS (aeoess)",
                            "date": "2026-05-04",
                            "result": "5/5 + 5 cross-language byte-equality PASS (10/10)",
                            "receipt_mirror": (
                                "aeoess/aps-conformance-suite@e48ec05: "
                                "fixtures/canonical-bytes/canonical-bytes-"
                                "diff-v032.json (file-level sha256 "
                                "84df9e0a634eba40f5388872bed4f028a240e0c2f2d"
                                "646755ecbdfb6b8ee0e42 byte-matches qntm "
                                "source) + runners/ts/canonical-bytes-qntm-"
                                "v0.3.2.test.ts cross-language regression "
                                "(TS JCS path produces output byte-identical "
                                "to Python json.dumps(sort_keys=True, "
                                "separators=(\",\", \":\")))"
                            ),
                        },
                    ],
                    "cross_language_proof": (
                        "TS JCS canonicalizer + Python json.dumps with "
                        "sort_keys=True + separators=(\",\", \":\") produce "
                        "byte-identical output for the plain-string field "
                        "shape this fixture uses. Pre-emptive guard against "
                        "the same off-by-one termination class that hit "
                        "ArkForge Merkle-chain in production."
                    ),
                },
                "section_a_cross_validation_triangle": {
                    "structure": (
                        "Three impls / one fixture / four verifier code paths"
                    ),
                    "aps_README_anchor": (
                        "https://github.com/aeoess/aps-conformance-suite/"
                        "blob/e48ec05/README.md"
                    ),
                    "aps_test_state": (
                        "37/37 + 10/10 canonical-bytes (1 skip baseline) on "
                        "main as of 2026-05-04"
                    ),
                    "section_a_cite_strategy": (
                        "APS README §A-aligned section currently quotes "
                        "comment-permalink as reference; flips to 'Mirrors "
                        "CTEF v0.3.2 §A as published <date>, <section name>' "
                        "once v0.3.2 ships mid-May"
                    ),
                },
                "reciprocal_property": (
                    "@nobulex/crypto canonicalizeJson against APS-emitted "
                    "fixture produces byte-identical SHA-256 to APS SDK "
                    "canonicalizeJCS at every vector — substrate-layer "
                    "interop is proven symmetric, not just one-directional."
                ),
                "aeoess_verifier_runs_2026_05_05": {
                    "source": (
                        "aeoess re-ran both Nobulex verifier scripts from "
                        "arian-gogani/nobulex/scripts/ on 2026-05-05; "
                        "freshly-generated receipts posted in A2A #1786 "
                        "thread comment dated 2026-05-05"
                    ),
                    "aps_byte_match": {
                        "verifier": "verify-aps-byte-match.mjs",
                        "spec": "JCS — RFC 8785",
                        "canonicalization": (
                            "APS SDK canonicalizeJCS (src/core/canonical-jcs.ts)"
                        ),
                        "vectors": 10,
                        "result": "10/10 byte-match",
                        "receipt_sha256": (
                            "5e31d6cf37d6a4ee7459a631a289733308c50f01b1f85db4c15370406a3e6dda"
                        ),
                    },
                    "ctef_byte_match": {
                        "verifier": "verify-ctef-byte-match.mjs",
                        "version": "0.3.1",
                        "vectors": 4,
                        "result": "4/4 byte-match",
                        "receipt_sha256": (
                            "a14e6db4477989a1f5c0d60078b0efcc4dc9dd7e3cd1276c4480bdd95b52bcfb"
                        ),
                        "negative_path_codes": [
                            "INVALID_CLAIM_SCOPE",
                            "INVALID_COMPOSITION",
                        ],
                    },
                    "discoverability": (
                        "Both verifier scripts linked from "
                        "aeoess/aps-conformance-suite/fixtures/canonical-"
                        "bytes/README.md per aeoess 2026-05-05 — future "
                        "verifiers locate them at source"
                    ),
                },
                "verifiability_property": (
                    "Reviewers can pull receipt artifacts from EITHER "
                    "arian-gogani/nobulex (originating) OR "
                    "aeoess/aps-conformance-suite (third-party mirror) OR "
                    "vdineshk/daee-engine (third independent reproduction) "
                    "and reproduce the byte-match independently. SHA-256 of "
                    "each mirrored file is documented at the mirror surface "
                    "with the source-commit pin. Closes the maintainer-"
                    "rerun-dependency gap entirely. Three independent "
                    "reproduction surfaces as of 2026-05-05 — the substrate "
                    "evidence claim now stands without ANY single party in "
                    "the trust path. aeoess's 2026-05-05 verifier-run "
                    "receipts (recorded in aeoess_verifier_runs_2026_05_05 "
                    "block above) demonstrate the property is exercisable "
                    "on demand, not historical."
                ),
            },
        },
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )
