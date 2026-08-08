#!/usr/bin/env python3
"""Deterministic generator for the v0.1 host-check vectors.

Rebuilds safety_screen_v0_1.json byte-for-byte from fixed Ed25519 seeds, so a
reviewer can regenerate and diff. It signs with the same detached-JWS discipline
as src/trust/envelope_v2.py, derives action_ref with the same recipe as
src/trust/action_ref_vectors.py, and reuses the v0 reference screen
(../safety_screen.py) to produce each embedded safety verdict.

When the product source tree is importable, this script cross-checks its vendored
primitives against src.* and aborts on any divergence (parity is asserted, not
assumed). When src is absent (a bare clone of the conformance dir), the vendored
primitives stand alone and the check is skipped.

    python3 gen_v0_1.py        # writes safety_screen_v0_1.json
"""
from __future__ import annotations

import base64
import json
import os
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
sys.path.insert(0, PARENT)  # for the v0 reference screen
import safety_screen as ss  # noqa: E402

# Shared verifier primitives — the generator signs, the verifier checks, both
# canonicalize/derive identically because they share this module.
sys.path.insert(0, HERE)
import verify_v0_1 as vv  # noqa: E402

# ── fixed, reproducible key material ──────────────────────────────────────
# Ed25519 is deterministic (RFC 8032); a fixed seed => byte-identical signatures.
PLATFORM_SEED = bytes.fromhex("a1" * 32)
FOREIGN_SEED = bytes.fromhex("b2" * 32)  # attacker key, NOT published in the JWKS

KID = "agentgraph-security-v1"  # src.signing.KID
VERIFICATION_METHOD = f"did:web:agentgraph.co#{KID}"
SUBJECT_DID = "did:web:example.com:agent:x402-payer"
GRADED_URL = "https://api.example.com/x402"
DRIFTED_URL = "https://api.evil.example/x402"
TS_MS = 1_748_736_000_000  # fixed epoch-ms (pinned, no clock)

_platform_key = Ed25519PrivateKey.from_private_bytes(PLATFORM_SEED)
_foreign_key = Ed25519PrivateKey.from_private_bytes(FOREIGN_SEED)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(pub, kid: str) -> dict:
    """OKP/Ed25519 public JWK — field shape matches src.signing._jwk_for."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(pub.public_bytes_raw()),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


PLATFORM_JWKS = {"keys": [_jwk(_platform_key.public_key(), KID)]}


# ── verdict assembly ──────────────────────────────────────────────────────


def _safety_input(findings: dict, grade: str) -> dict:
    """A v0-shaped screen input (matches ../safety_screen_v0.json vectors)."""
    return {
        "resource_url": GRADED_URL,
        "safety_attestation": {
            "type": "TrustAttestation",
            "version": "0.3.3",
            "claim_type": "authority",
            "subject": {"resource_url": GRADED_URL},
            "attestation": {
                "type": "SecurityAttestation",
                "confidence": 0.9,
                "payload": {"grade": grade, "trust_score": 20, "findings": findings},
            },
        },
    }


def _build_verdict(screen_input: dict, *, action_ref: str) -> dict:
    """A pre-execution-verdict-v0 envelope carrying the safety screen verdict.

    Shape per docs/standards/v0.4-pre-execution-verdict-v0.md. The safety
    decision is produced by the v0 reference screen so v0.1 stays tied to the
    verdict v0 already pins.
    """
    verdict = ss.screen(screen_input, {})
    return {
        "envelope": "pre-execution-verdict-v0",
        "verifier_did": "did:web:agentgraph.co",
        "subject_did": SUBJECT_DID,
        "resource_url": screen_input["resource_url"],
        "admission": {
            "verdict": "admit" if verdict["verdict"] == "admit" else "deny",
            "confidence": 0.9,
        },
        "screen": dict(
            name=ss.NAME,
            version=ss.VERSION,
            **verdict,
        ),
        "binding": {
            "action_ref": action_ref,
            "action_ref_method": "draft-giskard-aeoess-action-ref",
        },
        "issued_at": "2026-06-01T00:00:00Z",
        "expires_at": "2026-06-01T00:00:35Z",
        "freshness_ttl_seconds": 35,
    }


def _sign(verdict: dict, key: Ed25519PrivateKey) -> dict:
    """Attach a detached-JWS proof block (mirrors envelope_v2.sign_envelope).

    Signs the SHA-256 digest of the JCS-canonical, proof-stripped verdict;
    compact detached JWS is header..signature (empty payload segment).
    """
    header = {"alg": "EdDSA", "kid": KID, "typ": "JWT"}
    signature = key.sign(vv.verdict_digest(verdict))
    jws = f"{_b64url(rfc8785.dumps(header))}..{_b64url(signature)}"
    signed = dict(verdict)
    signed["proof"] = {
        "type": vv.PROOF_TYPE,
        "verificationMethod": VERIFICATION_METHOD,
        "jws": jws,
    }
    return signed


def _effective_call(scope: str, action_type: str = "x402_payment") -> dict:
    return {
        "agent_id": SUBJECT_DID,
        "action_type": action_type,
        "scope": scope,
        "timestamp_ms": TS_MS,
    }


# ── vectors ───────────────────────────────────────────────────────────────

_DENY_FINDINGS = {"critical": 2, "high": 3, "medium": 4, "total": 9}
_CLEAN_FINDINGS = {"critical": 0, "high": 0, "medium": 1, "total": 1}


def _signature_vectors() -> list[dict]:
    # A signed DENY verdict over the graded endpoint call.
    call = _effective_call(GRADED_URL)
    action_ref = vv.compute_action_ref(**call)
    base = _build_verdict(_safety_input(_DENY_FINDINGS, "F"), action_ref=action_ref)

    good = _sign(base, _platform_key)

    # Tamper 1: mutate a signed field AFTER signing (flip the safety verdict to
    # admit and zero the findings). The proof no longer covers these bytes.
    tampered = json.loads(json.dumps(good))
    tampered["admission"]["verdict"] = "admit"
    tampered["screen"] = {"name": ss.NAME, "version": ss.VERSION, "verdict": "admit"}

    # Tamper 2: re-sign with an attacker key while claiming the platform kid.
    # The kid resolves to the published platform key, which rejects the sig.
    foreign = _sign(base, _foreign_key)

    return [
        {
            "name": "sig_valid",
            "check": "signature",
            "expected": "pass",
            "note": "authentic detached JWS over the JCS proof-stripped verdict; "
                    "kid resolves in the embedded JWKS and the signature verifies.",
            "jwks": PLATFORM_JWKS,
            "signed_verdict": good,
        },
        {
            "name": "sig_tampered_payload",
            "check": "signature",
            "expected": "fail",
            "note": "admission.verdict/screen flipped deny->admit after signing; "
                    "recomputed digest no longer matches the signature.",
            "jwks": PLATFORM_JWKS,
            "signed_verdict": tampered,
        },
        {
            "name": "sig_foreign_key",
            "check": "signature",
            "expected": "fail",
            "note": "signed by a key not in the published JWKS but claiming the "
                    "platform kid; the published key rejects the swapped signature.",
            "jwks": PLATFORM_JWKS,
            "signed_verdict": foreign,
        },
    ]


def _binding_vectors() -> list[dict]:
    # A signed ADMIT verdict bound to the graded endpoint call.
    bound_call = _effective_call(GRADED_URL)
    action_ref = vv.compute_action_ref(**bound_call)
    verdict = _sign(
        _build_verdict(_safety_input(_CLEAN_FINDINGS, "A"), action_ref=action_ref),
        _platform_key,
    )

    drifted_call = _effective_call(DRIFTED_URL)

    return [
        {
            "name": "bind_match",
            "check": "action_ref_binding",
            "expected": "pass",
            "note": "the host's effective call equals the call the verdict bound; "
                    "recomputed action_ref matches binding.action_ref.",
            "signed_verdict": verdict,
            "effective_call": bound_call,
            "recomputed_action_ref": vv.compute_action_ref(**bound_call),
        },
        {
            "name": "bind_mismatch",
            "check": "action_ref_binding",
            "expected": "fail",
            "note": "the effective call drifted to a different endpoint than the "
                    "one graded/admitted; recomputed action_ref diverges, so the "
                    "presented verdict does not bind this call.",
            "signed_verdict": verdict,
            "effective_call": drifted_call,
            "recomputed_action_ref": vv.compute_action_ref(**drifted_call),
        },
    ]


def build_artifact() -> dict:
    return {
        "schema_version": "1.0",
        "artefact_id": "x402-safety-screen-conformance-v0.1",
        "extends": "x402-safety-screen-conformance-v0",
        "scope": (
            "Host-level checks the host performs ahead of the screen and that v0 "
            "asserted only in prose: (1) signature verification against the "
            "published JWKS, (2) action_ref-to-effective-call binding. See "
            "x402-foundation/x402#2533."
        ),
        "signed_object": (
            "pre-execution-verdict-v0 envelope "
            "(docs/standards/v0.4-pre-execution-verdict-v0.md) carrying the v0 "
            "reference safety screen verdict"
        ),
        "signature": {
            "algorithm": "EdDSA / Ed25519 (RFC 8032, deterministic)",
            "form": "detached compact JWS 'header..signature' (RFC 7515)",
            "signed_input": "SHA-256 of RFC 8785 (JCS) canonical, proof-stripped verdict",
            "reference_implementation": "src.trust.envelope_v2.sign_envelope / verify_envelope",
            "kid": KID,
        },
        "action_ref": {
            "definition": 'action_ref = "sha256:" + hex(SHA-256(JCS({agent_id, '
                          "action_type, scope, timestamp_ms})))",
            "reference_implementation": "src.trust.action_ref_vectors.compute_action_ref",
        },
        "canonicalizer": "rfc8785 0.1.4 (RFC 8785 JCS)",
        "derivation": (
            "Vectors are regenerated byte-for-byte by gen_v0_1.py from fixed "
            "Ed25519 seeds. verify_v0_1.py reproduces each host check offline: "
            "signature vectors verify the detached JWS against the embedded JWKS; "
            "binding vectors recompute action_ref over the effective_call and "
            "compare it to the signed binding.action_ref. Good/match MUST pass; "
            "tampered/mismatch MUST fail."
        ),
        "vectors": _signature_vectors() + _binding_vectors(),
    }


def _cross_check_parity() -> str:
    """Assert the vendored primitives match src.* when the product tree is present."""
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(PARENT, "..", "..", "..")))
        from src.signing import canonicalize_jcs_strict
        from src.trust import envelope_v2 as ev
        from src.trust.action_ref_vectors import compute_action_ref as repo_car
    except Exception as e:  # noqa: BLE001 - src is optional for a bare clone
        return f"skipped (src not importable: {type(e).__name__})"

    call = _effective_call(GRADED_URL)
    assert vv.compute_action_ref(**call) == repo_car(**call), "action_ref parity"
    pre = {"agent_id": "a", "action_type": "b", "scope": "c", "timestamp_ms": 1}
    assert vv.canonicalize(pre) == canonicalize_jcs_strict(pre), "JCS parity"

    # Sign with the product primitive, verify with the vendored JWKS path.
    env = _build_verdict(_safety_input(_DENY_FINDINGS, "F"),
                         action_ref=vv.compute_action_ref(**call))
    repo_signed = ev.sign_envelope(dict(env), _platform_key, VERIFICATION_METHOD)
    assert vv.verify_signature(repo_signed, PLATFORM_JWKS), "sign/verify parity"
    return "ok (vendored primitives byte-match src.*)"


def main() -> int:
    parity = _cross_check_parity()
    artifact = build_artifact()
    out = os.path.join(HERE, "safety_screen_v0_1.json")
    with open(out, "w") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(f"wrote {out}")
    print(f"parity check: {parity}")
    print(f"vectors: {len(artifact['vectors'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
