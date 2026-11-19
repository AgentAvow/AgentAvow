"""The signed key revocation list served at ``/.well-known/key-revocations.json``.

A verifier that pins one of our keys (by its RFC 7638 thumbprint, as
web/src/rebrand/docs/verify-attestations.md invites) never re-reads the JWKS, so
removing a compromised key from the JWKS does not reach it. This list does: it is
signed, dated, says which keys it covers, and names each revoked key with the
time the revocation takes effect.

``keysCovered`` holds every key in the JWKS and every revoked key. A covered key
with no entry in ``revocations`` means "not revoked in the record that was live when
the list was served" (``issuedAt`` is the serve time). A key
missing from ``keysCovered`` is one the list says nothing about. That is the
difference between an empty list and an absent one.

``REVOCATIONS`` below is the record. It lives in the repository so the public
GitHub history is a second origin for it, as it is for the thumbprint table.
Entries are only ever added, never removed. Adding one is a reviewed PR plus a
deploy; see the key policy in verify-attestations.md. The list is signed at request
time by whatever key ``create_jws`` loads, under the constant ``KID``, so a
revocation of the scan key itself must be deployed and left live before that key
is replaced (verify-attestations.md, "The revocation list"). A JWS ``typ`` header
is a possible later addition; it would change the signed bytes, so it is not here.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from src.signing import (
    canonicalize_jcs_strict,
    create_jws,
    jwk_thumbprint,
    rfc3339_ms,
)

LIST_TYPE = "agentavow-key-revocations-v1"
ISSUER = "did:web:agentgraph.co"
# A verifier should treat a list whose nextUpdate has passed as stale.
VALIDITY = timedelta(hours=24)
REASONS = frozenset({"key_compromise", "superseded", "cessation_of_operation"})
_FIELDS = frozenset({"kid", "thumbprint", "effectiveFrom", "reason", "notice"})
# RFC 3339 in UTC with a Z, whole seconds or milliseconds: what rfc3339_ms emits.
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z")
# An RFC 7638 SHA-256 thumbprint: 32 bytes as unpadded base64url.
_THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")

# Each entry: {"kid", "thumbprint", "effectiveFrom" (e.g. "2026-11-01T00:00:00Z"),
# "reason" (one of REASONS), "notice" (https URL of the public notice)}.
# Empty: no key has been revoked.
REVOCATIONS: tuple[dict, ...] = ()


def validate_entry(entry: dict) -> None:
    """Raise ``ValueError`` if a revocation entry is malformed."""
    if set(entry) != _FIELDS:
        raise ValueError(f"revocation entry needs exactly {sorted(_FIELDS)}, got {sorted(entry)}")
    if not all(isinstance(entry[k], str) and entry[k] for k in _FIELDS):
        raise ValueError("revocation entry fields must be non-empty strings")
    if not _THUMBPRINT.fullmatch(entry["thumbprint"]):
        raise ValueError("thumbprint must be an RFC 7638 SHA-256 thumbprint (43 base64url chars)")
    if not _UTC_TIME.fullmatch(entry["effectiveFrom"]):
        raise ValueError("effectiveFrom must be RFC 3339 UTC like 2026-11-01T00:00:00Z")
    datetime.fromisoformat(entry["effectiveFrom"].replace("Z", "+00:00"))  # a real date
    if entry["reason"] not in REASONS:
        raise ValueError(f"unknown revocation reason {entry['reason']!r}")
    if not entry["notice"].startswith("https://"):
        raise ValueError("revocation notice must be an https URL")


def validate_record(revocations: tuple[dict, ...]) -> None:
    """Validate every entry and refuse two entries for the same key."""
    seen: set[str] = set()
    for entry in revocations:
        validate_entry(entry)
        if entry["thumbprint"] in seen:
            raise ValueError(f"duplicate revocation for {entry['thumbprint']}")
        seen.add(entry["thumbprint"])


def build_payload(
    covered_jwks: list[dict],
    now: datetime | None = None,
    revocations: tuple[dict, ...] = REVOCATIONS,
) -> dict:
    """The unsigned list. ``covered_jwks`` are the live JWKS entries."""
    validate_record(revocations)
    now = now or datetime.now(timezone.utc)
    covered: dict[str, dict] = {}
    for jwk in covered_jwks:
        thumbprint = jwk_thumbprint(jwk)
        covered.setdefault(thumbprint, {"kid": jwk["kid"], "thumbprint": thumbprint})
    # A revoked key leaves the JWKS but stays covered, so its entry is never "unmentioned".
    for entry in revocations:
        thumbprint = entry["thumbprint"]
        covered.setdefault(thumbprint, {"kid": entry["kid"], "thumbprint": thumbprint})
    return {
        "type": LIST_TYPE,
        "issuer": ISSUER,
        "issuedAt": rfc3339_ms(now),
        "nextUpdate": rfc3339_ms(now + VALIDITY),
        "keysCovered": sorted(covered.values(), key=lambda k: (k["kid"], k["thumbprint"])),
        "revocations": [dict(e) for e in revocations],
    }


def signed_list(covered_jwks: list[dict], now: datetime | None = None) -> dict:
    """The served document: the payload and a compact JWS over its RFC 8785 bytes.

    Only ``jws`` is signed. ``payload`` is a convenience copy; verifiers read the
    payload decoded from the JWS.
    """
    payload = build_payload(covered_jwks, now)
    return {"payload": payload, "jws": create_jws(canonicalize_jcs_strict(payload))}
