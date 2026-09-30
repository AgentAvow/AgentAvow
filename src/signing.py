"""Ed25519 signing key management for attestation payloads.

AgentGraph signs security attestations as a platform-level issuer.
The private key is loaded from ATTESTATION_SIGNING_KEY_ED25519 (base64
encoded 32-byte seed).  In debug mode a transient key is generated if
the env var is absent.

Payload canonicalization follows JCS (RFC 8785): sorted keys, no
whitespace, integer-valued floats without decimal (1.0 → 1), null
values stripped.  This ensures byte-identical serialization across
Python and TypeScript runtimes.
"""
from __future__ import annotations

import base64
import json
import logging
import math

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.config import settings

logger = logging.getLogger(__name__)

KID = "agentgraph-security-v1"
# Dedicated kid for Trust Score v2 envelopes (spec §9.1). Only published/used
# when a distinct trust_v2_signing_key_ed25519 is configured; otherwise v2
# signing transparently falls back to the platform key + KID above.
TRUST_V2_KID = "trust-v2-2026"

_private_key: Ed25519PrivateKey | None = None
_trust_v2_key: Ed25519PrivateKey | None = None


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def get_signing_key() -> Ed25519PrivateKey:
    """Return the platform Ed25519 private key (singleton)."""
    global _private_key
    if _private_key is not None:
        return _private_key

    raw = getattr(settings, "attestation_signing_key_ed25519", None)
    if raw:
        seed = base64.b64decode(raw)
        _private_key = Ed25519PrivateKey.from_private_bytes(seed)
        logger.info("Loaded attestation signing key from env")
    elif settings.debug:
        _private_key = Ed25519PrivateKey.generate()
        logger.warning("Generated transient attestation signing key (debug mode)")
    else:
        raise RuntimeError(
            "ATTESTATION_SIGNING_KEY_ED25519 must be set in production"
        )
    return _private_key


def get_public_key() -> Ed25519PublicKey:
    """Return the platform Ed25519 public key."""
    return get_signing_key().public_key()


def _jwk_for(pub: Ed25519PublicKey, kid: str) -> dict:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(pub.public_bytes_raw()),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


def get_jwk() -> dict:
    """Return the platform public key as a JWK dict (RFC 7517 / RFC 8037)."""
    return _jwk_for(get_public_key(), KID)


def has_dedicated_trust_v2_key() -> bool:
    """True iff a distinct Trust Score v2 signing key is configured."""
    return bool(getattr(settings, "trust_v2_signing_key_ed25519", None))


def get_trust_v2_signing_key() -> Ed25519PrivateKey:
    """Return the Trust Score v2 signing key, or the platform key as fallback.

    Lets v2 envelopes be signed today (with the platform key + KID) and
    transparently upgrade to a dedicated key + TRUST_V2_KID once the secret is
    provisioned — no code change, just an env var.
    """
    global _trust_v2_key
    raw = getattr(settings, "trust_v2_signing_key_ed25519", None)
    if not raw:
        return get_signing_key()
    if _trust_v2_key is None:
        _trust_v2_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
        logger.info("Loaded dedicated Trust Score v2 signing key")
    return _trust_v2_key


def get_trust_v2_kid() -> str:
    """kid for v2 envelopes: TRUST_V2_KID if dedicated key set, else platform KID."""
    return TRUST_V2_KID if has_dedicated_trust_v2_key() else KID


def get_trust_v2_jwks() -> list[dict]:
    """JWK list for v2 verification: the dedicated key if set, else the platform key."""
    if has_dedicated_trust_v2_key():
        return [_jwk_for(get_trust_v2_signing_key().public_key(), TRUST_V2_KID)]
    return [get_jwk()]


def sign_payload(payload_bytes: bytes) -> bytes:
    """Sign *payload_bytes* with Ed25519, return 64-byte raw signature."""
    return get_signing_key().sign(payload_bytes)


def canonicalize(payload: dict) -> bytes:
    """Serialize *payload* to canonical JSON bytes (JCS-compatible).

    Sorted keys, no whitespace, integer-valued floats without decimal,
    null values stripped.  Matches APS interop fixtures for cross-language
    verification (Python json.dumps(1.0)='1.0' vs JS JSON.stringify(1.0)='1').
    """
    cleaned = _normalize_for_jcs(payload)
    return json.dumps(
        cleaned, sort_keys=True, separators=(",", ":"),
    ).encode()


def _normalize_for_jcs(obj: object) -> object:
    """Recursively normalize a Python object for JCS serialization.

    - Strip keys with None values
    - Convert integer-valued floats to int (1.0 → 1)
    - Reject Inf/NaN
    """
    if isinstance(obj, dict):
        return {
            k: _normalize_for_jcs(v) for k, v in obj.items() if v is not None
        }
    if isinstance(obj, list):
        return [_normalize_for_jcs(item) for item in obj]
    if isinstance(obj, float):
        if math.isinf(obj) or math.isnan(obj):
            raise ValueError(f"Cannot canonicalize {obj}")
        if obj == int(obj):
            return int(obj)
    return obj


def canonicalize_jcs_strict(payload: object) -> bytes:
    """Serialize *payload* to RFC 8785 (JCS) canonical JSON bytes.

    Unlike ``canonicalize()`` (legacy AgentGraph path that strips nulls
    and uses ASCII-only escapes), this is RFC 8785 as written, delegated
    to the ``rfc8785`` library (the same canonicalizer the v2 envelope
    path signs with):

    - Keys sorted by UTF-16 code unit (§3.2.3), so non-BMP keys order the
      way an ECMAScript verifier orders them.
    - Numbers serialized per ECMA-262 (§3.2.2.3): ``1.0`` → ``1``,
      ``1e30`` → ``1e+30``, ``1e-7`` → ``1e-7``.
    - ``None`` values **preserved** (not stripped) at every depth.
    - Non-ASCII characters emitted as literal UTF-8 bytes.

    Raises ``ValueError`` (``rfc8785.CanonicalizationError``) for input JCS
    cannot represent: Inf/NaN, integers beyond ±(2**53 - 1), non-string
    object keys. Refusing is deliberate — a value that an IEEE 754 verifier
    would read back differently must not be signed.

    Used by CTEF (Composable Trust Evidence Format, A2A#1734) envelopes
    where ``delegation_chain_root`` composition requires byte-for-byte
    agreement with APS. **Do not** use for legacy signed attestations —
    the original ``canonicalize()`` is preserved verbatim so previously
    signed payloads keep verifying.
    """
    return rfc8785.dumps(payload)


def create_jws(payload_bytes: bytes) -> str:
    """Return a compact JWS (RFC 7515) string: header.payload.signature.

    The signing input is ``header_b64 + "." + payload_b64`` (ASCII bytes).
    This avoids canonical-JSON ambiguity across languages — the payload
    bytes are preserved exactly as provided.
    """
    header = b'{"alg":"EdDSA","kid":"' + KID.encode() + b'"}'
    h_b64 = _b64url(header)
    p_b64 = _b64url(payload_bytes)
    signing_input = (h_b64 + "." + p_b64).encode()
    sig = get_signing_key().sign(signing_input)
    return h_b64 + "." + p_b64 + "." + _b64url(sig)
