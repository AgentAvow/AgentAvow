#!/usr/bin/env python3
"""Host-level conformance verifier for the x402 endpoint-safety screen (v0.1).

The v0 corpus (../safety_screen_v0.json) proves only what the *screen* does:
it reruns screen() and checks the verdict is byte-for-byte reproducible. The
two checks that actually keep an attacker from swapping the verdict happen in
the **host**, ahead of the screen, and v0 asserted them in prose only:

  1. Signature-against-JWKS  — is this signed safety verdict authentic?
  2. action_ref binding      — does the verdict bind the call about to be made?

v0.1 turns both into runnable vectors. This verifier reproduces each host check
from scratch, using only stdlib + the same cryptography / rfc8785 the product
uses (src/signing.py, src/trust/envelope_v2.py, src/trust/action_ref_vectors.py),
and confirms the good/match vectors PASS and the tampered/mismatch vectors FAIL.

    pip install rfc8785==0.1.4 cryptography
    python3 verify_v0_1.py     # exits non-zero if any vector misbehaves

Offline and self-contained: every vector embeds its own JWKS, so no network and
no import of the product code is required to verify it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ── canonicalization + crypto primitives (mirror the product) ─────────────
#
# canonicalize() is rfc8785.dumps — byte-identical to src.trust.envelope_v2's
# canonicalize() and to src.signing.canonicalize_jcs_strict on this subset.
# The signed detached JWS and the digest-over-JCS discipline mirror
# src.trust.envelope_v2.sign_envelope / verify_envelope exactly.

PROOF_TYPE = "Ed25519Signature2020"  # src.trust.envelope_v2.PROOF_TYPE


def canonicalize(obj: object) -> bytes:
    """RFC 8785 (JCS) canonical bytes."""
    return rfc8785.dumps(obj)


def strip_proof(envelope: dict) -> dict:
    """Proof-stripped view of the verdict — the payload the signature covers."""
    return {k: v for k, v in envelope.items() if k != "proof"}


def verdict_digest(envelope: dict) -> bytes:
    """SHA-256 over the JCS-canonical, proof-stripped verdict (the signed bytes)."""
    return hashlib.sha256(canonicalize(strip_proof(envelope))).digest()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _kid_from_jws(jws: str) -> str | None:
    """Recover the kid from the JWS protected header (first dot-segment)."""
    try:
        header = json.loads(_b64url_decode(jws.split(".")[0]))
        return header.get("kid")
    except (ValueError, IndexError, json.JSONDecodeError):
        return None


def _pubkey_from_jwk(jwk: dict) -> Ed25519PublicKey:
    """Reconstruct an Ed25519 public key from an OKP/Ed25519 JWK (RFC 8037)."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"unsupported JWK: {jwk.get('kty')}/{jwk.get('crv')}")
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))


# ── check 1: signature against published JWKS ─────────────────────────────


def verify_signature(verdict: dict, jwks: dict) -> bool:
    """Verify the verdict's detached JWS against a key published in *jwks*.

    Mirrors the host's preflight step 1 (v0.4-pre-execution-verdict-v0.md §"What
    the gateway does at preflight", step 1): resolve the signing key by kid from
    the *published* JWKS (never a signer-controlled fetch), recompute the digest
    over the JCS-canonical proof-stripped verdict, and verify the Ed25519 sig.
    Returns False on any failure (bad sig, kid not published, malformed proof).
    """
    try:
        proof = verdict.get("proof")
        if not proof or proof.get("type") != PROOF_TYPE:
            return False
        jws = proof.get("jws", "")
        parts = jws.split(".")
        if len(parts) != 3:
            return False
        signature = _b64url_decode(parts[2])

        kid = _kid_from_jws(jws)
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if key is None:
            return False  # signer's kid is not in the published JWKS
        pub = _pubkey_from_jwk(key)

        pub.verify(signature, verdict_digest(verdict))
        return True
    except (InvalidSignature, ValueError, KeyError, IndexError):
        return False


# ── check 2: action_ref-to-effective-call binding ─────────────────────────


def compute_action_ref(
    *, agent_id: str, action_type: str, scope: str, timestamp_ms: int
) -> str:
    """action_ref = "sha256:" + hex(SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))).

    Byte-identical to src.trust.action_ref_vectors.compute_action_ref (the
    product's derivation, draft-giskard-aeoess-action-ref §3): JCS sorts keys,
    so preimage key order is irrelevant.
    """
    preimage = {
        "agent_id": agent_id,
        "action_type": action_type,
        "scope": scope,
        "timestamp_ms": timestamp_ms,
    }
    return "sha256:" + hashlib.sha256(canonicalize(preimage)).hexdigest()


def check_binding(verdict: dict, effective_call: dict) -> bool:
    """Does the verdict's bound action_ref name the call the host is about to make?

    Mirrors preflight step 6 / the RESCOPED_REPLAY discipline: the host recomputes
    action_ref over the *effective call* it is about to execute and requires it to
    equal the action_ref carried (and signed) inside the verdict. A drifted call
    recomputes to a different action_ref and MUST be rejected — the presented
    verdict does not bind this call.
    """
    embedded = (verdict.get("binding") or {}).get("action_ref")
    recomputed = compute_action_ref(
        agent_id=effective_call["agent_id"],
        action_type=effective_call["action_type"],
        scope=effective_call["scope"],
        timestamp_ms=effective_call["timestamp_ms"],
    )
    return bool(embedded) and embedded == recomputed


# ── driver ────────────────────────────────────────────────────────────────

_CHECKS = {"signature": "sig ", "action_ref_binding": "bind"}


def _run_vector(v: dict) -> bool:
    """Return the actual pass/fail outcome of the vector's declared check."""
    if v["check"] == "signature":
        return verify_signature(v["signed_verdict"], v["jwks"])
    if v["check"] == "action_ref_binding":
        return check_binding(v["signed_verdict"], v["effective_call"])
    raise ValueError(f"unknown check: {v['check']}")


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    fixture = json.load(open(os.path.join(here, "safety_screen_v0_1.json")))
    errors = []

    for v in fixture["vectors"]:
        expect_pass = v["expected"] == "pass"
        got_pass = _run_vector(v)

        ok = got_pass == expect_pass
        if not ok:
            errors.append(
                f"{v['name']}: check={v['check']} expected={v['expected']} "
                f"got={'pass' if got_pass else 'fail'}"
            )
        tag = _CHECKS[v["check"]]
        outcome = "pass" if got_pass else "fail"
        mark = "✓" if ok else "✗"
        print(f"  {mark} [{tag}] {v['name']:26} expect {v['expected']:4} -> {outcome}")

    print("-" * 60)
    if errors:
        for e in errors:
            print("FAIL:", e)
        print(f"{len(errors)} vector(s) misbehaved")
        return 1
    n = len(fixture["vectors"])
    print(f"OK - {n}/{n} host-level vectors behave as specified "
          "(good/match pass, tampered/mismatch fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
