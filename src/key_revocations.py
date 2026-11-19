"""The signed key revocation list served at ``/.well-known/key-revocations.json``.

A verifier that pins one of our keys (by its RFC 7638 thumbprint, as
web/src/rebrand/docs/verify-attestations.md invites) never re-reads the JWKS, so
removing a compromised key from the JWKS does not reach it. This list does: it is
signed, dated, says which keys it covers, and names each revoked key with the
time the revocation takes effect.

An empty ``revocations`` list with a key in ``keysCovered`` means "not revoked as
of ``issuedAt``". A key missing from ``keysCovered`` means the list says nothing
about it. That is the difference between an empty list and an absent one.

``REVOCATIONS`` below is the record. It lives in the repository so the public
GitHub history is a second origin for it, as it is for the thumbprint table.
Adding an entry is a reviewed PR plus a deploy; see the key policy in
verify-attestations.md.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.signing import (
    KID,
    canonicalize_jcs_strict,
    create_jws,
    jwk_thumbprint,
    rfc3339_ms,
)

LIST_TYPE = "agentavow-key-revocations-v1"
ISSUER = "did:web:agentgraph.co"
# A verifier should treat a list older than nextUpdate as stale.
VALIDITY = timedelta(hours=24)
REASONS = frozenset({"key_compromise", "superseded", "cessation_of_operation"})

# Each entry: {"kid", "thumbprint", "effectiveFrom" (RFC 3339 UTC), "reason" (one of
# REASONS), "notice" (https URL of the public notice)}. Empty: no key has been revoked.
REVOCATIONS: tuple[dict, ...] = ()


def validate_entry(entry: dict) -> None:
    """Raise ``ValueError`` if a revocation entry is malformed."""
    required = {"kid", "thumbprint", "effectiveFrom", "reason", "notice"}
    if set(entry) != required:
        raise ValueError(f"revocation entry needs exactly {sorted(required)}, got {sorted(entry)}")
    if not all(isinstance(entry[k], str) and entry[k] for k in required):
        raise ValueError("revocation entry fields must be non-empty strings")
    if entry["reason"] not in REASONS:
        raise ValueError(f"unknown revocation reason {entry['reason']!r}")
    if not entry["notice"].startswith("https://"):
        raise ValueError("revocation notice must be an https URL")
    when = datetime.fromisoformat(entry["effectiveFrom"].replace("Z", "+00:00"))
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise ValueError("effectiveFrom must be a UTC time")


def build_payload(
    covered_jwks: list[dict],
    now: datetime | None = None,
    revocations: tuple[dict, ...] = REVOCATIONS,
) -> dict:
    """The unsigned list. ``covered_jwks`` are the JWKS entries the list speaks for."""
    for entry in revocations:
        validate_entry(entry)
    now = now or datetime.now(timezone.utc)
    covered: dict[str, dict] = {}
    for jwk in covered_jwks:
        thumbprint = jwk_thumbprint(jwk)
        covered.setdefault(thumbprint, {"kid": jwk["kid"], "thumbprint": thumbprint})
    return {
        "type": LIST_TYPE,
        "issuer": ISSUER,
        "issuedAt": rfc3339_ms(now),
        "nextUpdate": rfc3339_ms(now + VALIDITY),
        "keysCovered": sorted(covered.values(), key=lambda k: k["kid"]),
        "revocations": [dict(e) for e in revocations],
    }


def signed_list(covered_jwks: list[dict], now: datetime | None = None) -> dict:
    """The served document: the payload and a compact JWS over its RFC 8785 bytes."""
    payload = build_payload(covered_jwks, now)
    return {
        "payload": payload,
        "jws": create_jws(canonicalize_jcs_strict(payload)),
        "kid": KID,
    }
