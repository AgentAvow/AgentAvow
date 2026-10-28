"""The signed observation of one live ``tools/list`` read (``scan.observation``).

An MCP scan's ``toolDigests`` say WHAT was served. This block says how the scanner
got it, so a verifier can check the claim against its own policy (TRACE #443's
"authenticated-catalog observation", first slice):

* the endpoint the scanner asked for (scheme, host, port, path) and that it followed
  no redirect;
* for every ``tools/list`` page, the TLS facts of the connection that returned it:
  the reference identity the client verified (the SNI host the certificate was
  checked against), whether certificate-path and identity validation ran, and the
  SHA-256 of the leaf certificate and of its SubjectPublicKeyInfo;
* every page in order, with its JSON-RPC request id, a hash of the cursor that asked
  for it and of the ``nextCursor`` it returned, its item count and the SHA-256 of the
  raw response body, so one observation covers the whole paged list;
* an observation id and the capture interval.

Limits (also stated in the block): it is one observer's capture claim, signed by the
scanning service, not the server's own signature over ``tools/list``; a TLS-terminating
proxy is the authenticated peer, and its certificate says nothing about the code or
runtime behind it; a historical re-validation needs the trust policy, time and
certificate status material of the capture, not today's trust store.
"""
from __future__ import annotations

import hashlib
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

PROFILE = "agentavow.mcp-catalog-observation.v0"
LIMITS = (
    "One observer's capture claim, signed by the scanning service; not a server "
    "signature over tools/list. A TLS-terminating proxy is the authenticated peer and "
    "identifies no backend code or runtime. Re-validating later needs the capture's "
    "trust policy, time and certificate status material."
)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def spki_sha256(der_cert: bytes) -> str | None:
    """SHA-256 of the DER SubjectPublicKeyInfo of a DER certificate (None if it can't
    be parsed). The pin HPKP and RFC 7469 use, over the key rather than the cert."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        cert = x509.load_der_x509_certificate(der_cert)
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return sha256_hex(spki)
    except Exception:  # noqa: BLE001 — an unparseable cert is reported as unavailable
        return None


def tls_facts(network_stream) -> dict | None:
    """The TLS facts of the connection an httpcore response arrived on (its
    ``network_stream`` extension), or None for a plain-HTTP / fake stream.

    ``certificatePathValidated`` and ``identityMatched`` are read off the live SSL
    context: with ``CERT_REQUIRED`` and ``check_hostname`` a completed handshake means
    the chain validated against the trust store and the certificate matched
    ``referenceIdentity`` (the SNI host the pinned transport sets; RFC 9525 §6)."""
    if network_stream is None:
        return None
    try:
        ssl_obj = network_stream.get_extra_info("ssl_object")
    except Exception:  # noqa: BLE001
        return None
    if ssl_obj is None:
        return None
    try:
        der = ssl_obj.getpeercert(binary_form=True)
    except Exception:  # noqa: BLE001
        der = None
    ctx = getattr(ssl_obj, "context", None)
    required = bool(ctx is not None and ctx.verify_mode == ssl.CERT_REQUIRED)
    cipher = None
    try:
        c = ssl_obj.cipher()
        cipher = c[0] if c else None
    except Exception:  # noqa: BLE001
        pass
    return {
        "tlsVersion": ssl_obj.version(),
        "cipher": cipher,
        "referenceIdentity": getattr(ssl_obj, "server_hostname", None),
        "certificatePathValidated": required and der is not None,
        "identityMatched": bool(required and ctx is not None and ctx.check_hostname
                                and der is not None),
        "leafCertificateSha256": sha256_hex(der) if der else None,
        "spkiSha256": spki_sha256(der) if der else None,
    }


def now_ms() -> str:
    from src.signing import rfc3339_ms
    return rfc3339_ms(datetime.now(timezone.utc))


def build_observation(url: str, pages: list[dict], *, started: str, finished: str,
                      complete: bool) -> dict:
    """The ``scan.observation`` block for one scanner read of ``tools/list``.

    ``pages`` come from ``McpSession.list`` (each with ``tls`` facts or None).
    ``transport`` summarises the connection when every page agrees on it; a page whose
    TLS facts differ or are missing makes ``sameConnectionFacts`` false, and the
    per-page facts stay on each page."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    tls_set = [p.get("tls") for p in pages]
    keys = ("referenceIdentity", "leafCertificateSha256", "spkiSha256",
            "certificatePathValidated", "identityMatched")
    first = tls_set[0] if tls_set else None
    same = bool(first) and all(
        t is not None and all(t.get(k) == first.get(k) for k in keys) for t in tls_set)
    transport = dict(first) if same else None
    out_pages = []
    for p in pages:
        t = p.get("tls") or {}
        out_pages.append({
            "requestId": p["requestId"],
            "cursorSha256": p.get("cursorSha256"),
            "nextCursorSha256": p.get("nextCursorSha256"),
            "itemCount": p["itemCount"],
            "responseSha256": p["responseSha256"],
            "leafCertificateSha256": t.get("leafCertificateSha256"),
            "spkiSha256": t.get("spkiSha256"),
        })
    return {
        "profile": PROFILE,
        "observationId": uuid.uuid4().hex,
        "capturedFrom": started,
        "capturedUntil": finished,
        "request": {
            "scheme": parts.scheme, "host": (parts.hostname or "").lower(),
            "port": port, "path": parts.path or "/",
        },
        "redirectsFollowed": False,
        "transport": transport,
        "sameConnectionFacts": same,
        "toolsList": {"pages": out_pages, "complete": complete},
        "limits": LIMITS,
    }
