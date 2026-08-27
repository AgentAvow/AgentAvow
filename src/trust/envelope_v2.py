"""Trust Score Envelope v2.0 — builder, canonicalizer, signer, verifier.

Pure functions; no DB, no app state. The aggregation engine in
``src/trust/aggregator_v2.py`` (forthcoming) calls into this module to
produce signed envelopes; the API endpoints in ``src/api/trust_aggregate.py``
(forthcoming) call into this module to verify externally-supplied envelopes.

Spec: docs/standards/trust-score-envelope-v2.0.md
Schema: docs/standards/trust-score-envelope-v2.0.json

Same substrate discipline as CTEF: JCS-canonical (RFC 8785) + Ed25519 +
lowercase-hex SHA-256. Byte-for-byte verifiable across the 5 reference
JCS implementations.
"""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Envelope-level constants — match the JSON schema exactly.
SHAPE_VERSION = "trust-score-envelope-v2.0"
SCORE_VERSION = "v2.0"
CANONICALIZATION = "jcs-rfc8785-v1"
HASH_ALGO = "sha256"
PROOF_TYPE = "Ed25519Signature2020"

# Default issuer for AgentGraph-issued envelopes.
DEFAULT_ISSUER_DID = "did:web:agentgraph.co"
DEFAULT_VERIFICATION_METHOD = "did:web:agentgraph.co#trust-v2-2026"

# Per-claim_type caps per spec §4. Bound the aggregation, not the schema.
CLAIM_TYPE_CAPS = {
    "identity": 0.60,
    "authority": 0.25,
    "continuity": 0.15,
    "transport": 0.0,  # transport claims are envelope hygiene, not trust signal
}

VALID_SUBJECT_KINDS = ("agent", "human", "service")
VALID_SOURCES = (
    "ctef_attestation",
    "erc8004_reputation",
    "scan_corpus",
    "third_party_observer",
    "community_signal",
    "self_attested",
)
VALID_CLAIM_TYPES = ("identity", "authority", "continuity", "transport")

NEGATIVE_FEEDBACK_FLOOR = -0.20


class EnvelopeError(ValueError):
    """Raised when envelope construction or verification fails."""


@dataclass(frozen=True)
class Contribution:
    """One input source's contribution to the aggregate score.

    Subset of the JSON schema fields — keep optional ones None and let
    ``to_dict`` strip them, so equivalent inputs produce equivalent
    canonical bytes regardless of source-specific metadata.
    """

    source: str
    raw_signal: float
    weighted_contribution: float
    freshness_ttl_seconds: int
    source_attestation_hash: str | None = None
    claim_type: str | None = None
    evidence_type: str | None = None  # serialized as evidenceType in JSON
    source_provider_did: str | None = None
    contested_signal: bool = False
    metadata: dict | None = None  # serialized as _metadata in JSON

    def to_dict(self) -> dict:
        """JSON-serializable dict matching schema $defs/contribution."""
        if self.source not in VALID_SOURCES:
            raise EnvelopeError(f"invalid source: {self.source}")
        if self.claim_type is not None and self.claim_type not in VALID_CLAIM_TYPES:
            raise EnvelopeError(f"invalid claim_type: {self.claim_type}")

        out: dict = {
            "source": self.source,
            "raw_signal": _normalize_number(self.raw_signal),
            "weighted_contribution": _normalize_number(self.weighted_contribution),
            "freshness_ttl_seconds": int(self.freshness_ttl_seconds),
        }
        if self.source_attestation_hash is not None:
            out["source_attestation_hash"] = self.source_attestation_hash
        if self.claim_type is not None:
            out["claim_type"] = self.claim_type
        if self.evidence_type is not None:
            out["evidenceType"] = self.evidence_type  # schema uses camelCase here
        if self.source_provider_did is not None:
            out["source_provider_did"] = self.source_provider_did
        if self.contested_signal:
            out["contested_signal"] = True
        if self.metadata:
            out["_metadata"] = self.metadata
        return out


def build_envelope(
    *,
    subject_did: str,
    subject_kind: str,
    contributions: Iterable[Contribution],
    computed_at: datetime | None = None,
    freshness_ttl_seconds: int = 3600,
    issuer: str = DEFAULT_ISSUER_DID,
    issued_at: datetime | None = None,
) -> dict:
    """Build the unsigned envelope (no proof block yet).

    Caller signs with ``sign_envelope(unsigned, private_key, verification_method)``.

    `contributions` are aggregated via the §4 algorithm: sum of
    ``weighted_contribution``, then clamp to [0.0, 1.0] with floor at
    -0.20 BEFORE clamp for negative ERC-8004 cases (allows true zero on
    provably-bad subjects vs masking via in-house signals).
    """
    if subject_kind not in VALID_SUBJECT_KINDS:
        raise EnvelopeError(f"invalid subject_kind: {subject_kind}")
    if not subject_did.startswith("did:"):
        raise EnvelopeError(f"subject_did must be a DID URI: {subject_did}")

    contrib_list = [c.to_dict() for c in contributions]
    if not contrib_list:
        raise EnvelopeError("envelope requires at least one contribution")

    # Aggregate per §4: sum, apply -0.20 floor, then clamp to [0, 1].
    raw_sum = sum(c["weighted_contribution"] for c in contrib_list)
    floored = max(raw_sum, NEGATIVE_FEEDBACK_FLOOR)
    trust_score = max(0.0, min(1.0, floored))

    computed_at = computed_at or _now_utc()
    issued_at = issued_at or computed_at

    envelope = {
        "subject_did": subject_did,
        "subject_kind": subject_kind,
        "trust_score": _normalize_number(trust_score),
        "score_version": SCORE_VERSION,
        "computed_at": _format_timestamp(computed_at),
        "freshness_ttl_seconds": int(freshness_ttl_seconds),
        "contributions": contrib_list,
        "shape_version": SHAPE_VERSION,
        "canonicalization": CANONICALIZATION,
        "hash_algo": HASH_ALGO,
        "issuer": issuer,
        "issued_at": _format_timestamp(issued_at),
    }
    return envelope


def canonicalize(envelope: dict) -> bytes:
    """JCS-canonical bytes of the envelope (RFC 8785 strict).

    Used for both signing (input to SHA-256) and verification. Strips the
    ``proof`` block per spec §2 — depth-first proof-stripping, matching the
    CTEF v0.3.2 normative addition. ``rfc8785.dumps`` is the reference
    Python implementation; output byte-identical to the canonicalize JS lib,
    gowebpki/jcs Go, Rundgren's Java reference, and serde_jcs Rust.
    """
    stripped = _strip_proof(envelope)
    return rfc8785.dumps(stripped)


def envelope_hash(envelope: dict) -> str:
    """lowercase-hex SHA-256 of the canonical proof-stripped envelope.

    The detached payload that proof.jws signs.
    """
    return hashlib.sha256(canonicalize(envelope)).hexdigest()


def sign_envelope(
    envelope: dict,
    private_key: Ed25519PrivateKey,
    verification_method: str = DEFAULT_VERIFICATION_METHOD,
) -> dict:
    """Attach proof block to envelope via Ed25519 signature.

    Returns a NEW dict (does not mutate input). The signed envelope is
    ready to serve via /api/v1/aggregate/{did} or include in any response.
    """
    if "proof" in envelope:
        raise EnvelopeError("envelope already has proof; sign before adding")

    digest = bytes.fromhex(envelope_hash(envelope))
    signature = private_key.sign(digest)

    # Compact JWS: header.payload.signature (detached payload form).
    # Header is JSON {"alg":"EdDSA","kid":"<kid>","typ":"JWT"}; we use a
    # stable JCS-canonicalized header so identical inputs produce identical
    # JWS strings (substrate discipline).
    kid = verification_method.split("#", 1)[-1] if "#" in verification_method else "trust-v2"
    header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
    header_b64 = _b64url(rfc8785.dumps(header))
    # detached payload = empty between the dots
    signature_b64 = _b64url(signature)
    jws = f"{header_b64}..{signature_b64}"

    signed = dict(envelope)
    signed["proof"] = {
        "type": PROOF_TYPE,
        "verificationMethod": verification_method,
        "jws": jws,
    }
    return signed


def verify_envelope(envelope: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify a signed envelope against the given Ed25519 public key.

    Returns True on success, False on any failure. Does NOT check freshness
    (TTL) — that's a consumer-policy decision; this function only verifies
    cryptographic authenticity per spec §6 steps 3-5.
    """
    try:
        proof = envelope.get("proof")
        if not proof or proof.get("type") != PROOF_TYPE:
            return False
        jws = proof.get("jws", "")
        parts = jws.split(".")
        if len(parts) != 3:
            return False
        signature = _b64url_decode(parts[2])

        # Recompute the digest the same way sign_envelope did.
        digest = bytes.fromhex(envelope_hash(envelope))
        public_key.verify(signature, digest)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def is_fresh(envelope: dict, *, now: datetime | None = None) -> bool:
    """Check whether envelope is within its freshness_ttl_seconds window.

    Spec §6 step 2. Pure check — does not verify signature.
    """
    now = now or _now_utc()
    computed_at = _parse_timestamp(envelope["computed_at"])
    ttl = int(envelope.get("freshness_ttl_seconds", 0))
    age_seconds = (now - computed_at).total_seconds()
    return age_seconds <= ttl


# ---- internal helpers ----


def _strip_proof(envelope: dict) -> dict:
    """Remove proof block for canonicalization (depth-first proof-stripping).

    Only top-level proof is stripped here. Nested proofs (e.g. inside
    contributions._metadata) are NOT stripped — they're not part of OUR
    signature surface.
    """
    return {k: v for k, v in envelope.items() if k != "proof"}


def _format_timestamp(dt: datetime) -> str:
    """RFC 3339 UTC, exactly 3 ms digits, Z suffix.

    Matches CTEF v0.3.2 timestamp discipline and the schema pattern
    ``^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$``.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # strftime gives microseconds via %f; we want milliseconds.
    ms = dt.microsecond // 1000
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def _parse_timestamp(s: str) -> datetime:
    """Parse the RFC 3339 form produced by _format_timestamp."""
    # Python's fromisoformat accepts the +HH:MM offset form but not Z directly
    # in 3.9; swap Z for +00:00 for compat.
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _normalize_number(x: Any) -> Any:
    """Convert integer-valued floats to int for JCS byte-stability.

    rfc8785.dumps handles canonical number formatting, but Python's
    representation of 0.74 vs 74/100 etc. is consistent enough that we
    only need to bump exact ints to int type.
    """
    if isinstance(x, float) and x == int(x):
        return int(x)
    return x


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode, restoring padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "Contribution",
    "EnvelopeError",
    "build_envelope",
    "canonicalize",
    "envelope_hash",
    "sign_envelope",
    "verify_envelope",
    "is_fresh",
    "SHAPE_VERSION",
    "SCORE_VERSION",
    "CANONICALIZATION",
    "HASH_ALGO",
    "PROOF_TYPE",
    "CLAIM_TYPE_CAPS",
    "DEFAULT_ISSUER_DID",
    "DEFAULT_VERIFICATION_METHOD",
    "NEGATIVE_FEEDBACK_FLOOR",
]
