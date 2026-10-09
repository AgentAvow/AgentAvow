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
import hashlib
import json
import logging
import math

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from src.config import settings

logger = logging.getLogger(__name__)

KID = "agentgraph-security-v1"
# Dedicated kid for Trust Score v2 envelopes (spec §9.1). Only published/used
# when a distinct trust_v2_signing_key_ed25519 is configured; otherwise v2
# signing transparently falls back to the platform key + KID above.
TRUST_V2_KID = "trust-v2-2026"
# ES256 (P-256) assertion key for /.well-known/ai-catalog.json. The Agent-Card
# did:web Publisher Profile is ES256-only, so this is a separate key from the
# Ed25519 platform key. Published in the DID documents (assertionMethod only)
# and in the JWKS iff CATALOG_SIGNING_KEY_P256 is configured.
CATALOG_ES256_KID = "catalog-es256-v1"

_private_key: Ed25519PrivateKey | None = None
_trust_v2_key: Ed25519PrivateKey | None = None
_catalog_key: ec.EllipticCurvePrivateKey | None = None


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


# ── ES256 catalog key ────────────────────────────────────────────────────


def load_p256_private_key(raw: str) -> ec.EllipticCurvePrivateKey:
    """Parse a P-256 private key from PEM text or base64-encoded PKCS8 DER.

    Accepts the two forms ``scripts/gen_catalog_key.py`` can emit. Raises
    ``RuntimeError`` with a precise message on anything else (wrong curve,
    unparseable bytes) so a misconfigured secret fails loudly at first use
    rather than publishing the wrong key.
    """
    text = raw.strip()
    try:
        if "-----BEGIN" in text:
            key = serialization.load_pem_private_key(text.encode(), password=None)
        else:
            key = serialization.load_der_private_key(base64.b64decode(text), password=None)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "CATALOG_SIGNING_KEY_P256 is not a PEM or base64 PKCS8 private key"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise RuntimeError("CATALOG_SIGNING_KEY_P256 must be an EC P-256 (secp256r1) key")
    return key


def has_catalog_es256_key() -> bool:
    """True iff CATALOG_SIGNING_KEY_P256 is configured (not validated)."""
    return bool(getattr(settings, "catalog_signing_key_p256", None))


def get_catalog_es256_key() -> ec.EllipticCurvePrivateKey:
    """Return the P-256 catalog signing key (singleton).

    Unlike the platform key there is no debug-mode fallback: the key is
    optional, and ``has_catalog_es256_key()`` is the gate callers check first.
    """
    global _catalog_key
    if _catalog_key is not None:
        return _catalog_key
    raw = getattr(settings, "catalog_signing_key_p256", None)
    if not raw:
        raise RuntimeError(
            "CATALOG_SIGNING_KEY_P256 is not set (generate one with "
            "scripts/gen_catalog_key.py)"
        )
    _catalog_key = load_p256_private_key(raw)
    logger.info("Loaded catalog ES256 signing key from env")
    return _catalog_key


def p256_jwk_for(pub: ec.EllipticCurvePublicKey, kid: str) -> dict:
    """Public P-256 key as a JWK (RFC 7518 §6.2.1), ``alg`` ES256."""
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    }


def get_catalog_es256_jwk() -> dict | None:
    """Public catalog JWK, or ``None`` when the key is not configured.

    A configured-but-malformed secret is logged and treated as absent so the
    DID document and JWKS (which anchor every attestation) keep serving; the
    signing script surfaces the same error loudly when it tries to sign.
    """
    if not has_catalog_es256_key():
        return None
    try:
        return p256_jwk_for(get_catalog_es256_key().public_key(), CATALOG_ES256_KID)
    except RuntimeError as exc:
        logger.error("Catalog ES256 key not published: %s", exc)
        return None


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) over the required members."""
    if jwk.get("kty") == "EC":
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "OKP":
        members = {k: jwk[k] for k in ("crv", "kty", "x")}
    else:
        raise ValueError(f"unsupported kty {jwk.get('kty')!r}")
    digest = hashlib.sha256(rfc8785.dumps(members)).digest()
    return _b64url(digest)


def sign_es256(signing_input: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    """ECDSA P-256/SHA-256 over *signing_input*, as the 64-byte ``r || s`` JWS form."""
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_es256(signing_input: bytes, sig: bytes, pub: ec.EllipticCurvePublicKey) -> None:
    """Verify a 64-byte ``r || s`` ES256 signature; raises ``InvalidSignature``."""
    if len(sig) != 64:
        from cryptography.exceptions import InvalidSignature

        raise InvalidSignature("ES256 signature must be 64 bytes (r || s)")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))


def p256_public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Rebuild a P-256 public key from an EC JWK (``x``/``y`` base64url)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("JWK is not an EC P-256 key")
    pad = lambda t: t + "=" * (-len(t) % 4)  # noqa: E731
    x = int.from_bytes(base64.urlsafe_b64decode(pad(jwk["x"])), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(pad(jwk["y"])), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


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


def rfc3339_ms(dt) -> str:
    """A UTC instant as RFC 3339 at millisecond precision with ``Z``, e.g.
    ``2026-10-09T01:02:03.456Z``. Signed timestamps use this form so that a consumer whose
    clock type holds milliseconds (JavaScript ``Date``, ``jose``) reads the same instant the
    issuer wrote; microseconds were truncated by such consumers and misjudged freshness at the
    window boundary."""
    from datetime import timezone as _tz
    return dt.astimezone(_tz.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
