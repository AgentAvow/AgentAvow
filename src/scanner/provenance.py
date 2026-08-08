"""Phase 3 — provenance / signing verification (read-only, no code execution).

Verifies whether a published package carries **cryptographic build provenance**
binding the artifact to a source repo+commit built by a trusted CI builder — the
strongest, hardest-to-game trust axis (roadmap §2.C) and the signal that gates
AgentAvow's top "certified" tier. This module is **pure verification**: it fetches
attestation bundles and checks signatures/identity. It NEVER executes the artifact.

Surfaces:
  * **npm** — Sigstore-based SLSA build provenance published through the registry
    attestations endpoint (``/-/npm/v1/attestations/{pkg}@{ver}``).
  * **PyPI (PEP 740)** — Sigstore attestations hosted per-file at
    ``/integrity/{project}/{version}/{filename}/provenance``.

What "verified" honestly means here (the guarantee we actually provide offline):
  The ``sigstore`` Python library is NOT a dependency, and we do not ship the
  Fulcio TUF trust root or query Rekor, so we do **not** anchor to Sigstore's
  trust root nor prove transparency-log inclusion. What we DO, fully offline with
  ``cryptography``:
    1. Parse the DSSE / in-toto statement and extract the binding.
    2. Reconstruct the DSSE PAE and **cryptographically verify the signature**
       against the leaf certificate's public key (proves the statement was signed
       by the holder of that Fulcio-issued cert and was not tampered).
    3. Extract the leaf cert's **SAN identity + OIDC issuer** and enforce the two
       §2.C override gates: (a) issuer must be a trusted CI OIDC issuer and the
       SAN must bind to the claimed source; (b) the statement subject digest must
       match the exact bytes we graded (when a digest is available).
  ``verification_level`` names precisely what was achieved. ``verified=True`` is
  set ONLY at the ``signature`` level with identity binding — never for something
  merely *present*. The un-anchored trust-root / missing-Rekor limits are recorded
  in ``notes`` and ``method`` so the signal is never oversold.

Design rules (identical discipline to ``supply_chain.py``):
  * **Feature-flagged** (``settings.scanner_verify_provenance``, default False).
  * **Fail-open, always.** Any network/parse/verify error → ``present=False``
    ("not present"), never an exception that breaks a scan.
  * **Additive.** Absent provenance is **N/A, never a penalty** (Kenne decision
    #4). Present+verified is a small bonus; a package that *claims* provenance but
    fails verification is a real red flag (small penalty).
  * **Recomputable.** Every fetched bundle + Rekor log index + fetch timestamp is
    pinned into ``snapshot`` so a verifier can replay the check from pinned bytes.
  * **Pure reducers** (``dsse_pae``, ``extract_intoto_binding``,
    ``parse_npm_attestations``, ``parse_pypi_provenance``, ``verify_dsse_signature``,
    ``provenance_score_delta``, ``coverage_binding_value``) are network-free and
    unit-tested directly with canned fixtures.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
NPM_ATTESTATIONS_URL = (
    "https://registry.npmjs.org/-/npm/v1/attestations/{pkg}@{version}"
)
PYPI_PROVENANCE_URL = (
    "https://pypi.org/integrity/{project}/{version}/{filename}/provenance"
)

_HTTP_TIMEOUT = 12.0

# DSSE payload type for in-toto statements (fixed by the in-toto/PEP 740 specs).
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# SLSA provenance predicate types we recognize.
SLSA_PREDICATE_TYPES = {
    "https://slsa.dev/provenance/v1",
    "https://slsa.dev/provenance/v0.2",
}

# Trusted CI OIDC issuers — a *hosted* keyless builder identity. A self-hosted or
# unknown issuer must NOT be accepted as "signed" (§2.C gate 1: identity binding).
TRUSTED_CI_ISSUERS = {
    "https://token.actions.githubusercontent.com",  # GitHub Actions
    "https://oauth2.sigstore.dev/auth",             # legacy Fulcio email flow (weak)
    "https://gitlab.com",                            # GitLab CI
}
# Issuers that indicate a *hosted*, non-falsifiable-ish builder (SLSA L2+ material).
HOSTED_CI_ISSUERS = {
    "https://token.actions.githubusercontent.com",
    "https://gitlab.com",
}

# Fulcio X.509 custom OIDs (github.com/sigstore/fulcio docs).
_OID_OIDC_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"   # raw UTF-8 string
_OID_OIDC_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"   # DER-wrapped UTF8String
_OID_SAN_OTHERNAME = "1.3.6.1.4.1.57264.1.7"    # otherName SAN (some flows)

# What the offline check actually is — recorded verbatim into the result so the
# guarantee is never overstated.
VERIFY_METHOD = (
    "dsse-pae + leaf-cert-signature (cryptography, offline); "
    "fulcio SAN/issuer identity gate; subject-digest gate. "
    "NOT anchored to Fulcio TUF trust-root; Rekor inclusion NOT proven offline."
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass
class ProvenanceResult:
    """Structured provenance-verification outcome for one package coordinate."""

    surface: str = ""                      # npm | pypi
    coordinate: str = ""                   # name@version[/filename]
    present: bool = False                  # an attestation/provenance was found
    signature_valid: bool = False          # DSSE signature verified against leaf cert
    verified: bool = False                 # signature + identity + source binding OK
    verification_level: str = "none"       # none | structural | signature
    binding: dict = field(default_factory=dict)   # {repo, commit, builder}
    claimed_repo: str | None = None
    source_matches_claim: bool | None = None      # provenance repo == declared repo
    subject_name: str | None = None
    subject_digest: str | None = None             # digest the attestation is about
    subject_matches: bool | None = None           # matches the bytes we graded
    identity: dict = field(default_factory=dict)  # {san, issuer}
    predicate_type: str | None = None
    builder_hosted: bool | None = None            # hosted CI builder (SLSA L2+ material)
    certified_eligible: bool = False              # meets the top-tier gate (see below)
    method: str = ""
    snapshot: dict = field(default_factory=dict)  # recompute anchors
    notes: list[str] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> dict:
        """A JSON-ready dict for the scan's ``provenance`` block (no None churn)."""
        out: dict = {
            "surface": self.surface,
            "coordinate": self.coordinate,
            "present": self.present,
            "signature_valid": self.signature_valid,
            "verified": self.verified,
            "verification_level": self.verification_level,
            "binding": dict(self.binding),
            "identity": dict(self.identity),
            "method": self.method,
            "notes": list(self.notes),
            "certified_eligible": self.certified_eligible,
        }
        if self.claimed_repo is not None:
            out["claimed_repo"] = self.claimed_repo
        if self.source_matches_claim is not None:
            out["source_matches_claim"] = self.source_matches_claim
        if self.subject_digest is not None:
            out["subject_digest"] = self.subject_digest
        if self.subject_matches is not None:
            out["subject_matches"] = self.subject_matches
        if self.predicate_type is not None:
            out["predicate_type"] = self.predicate_type
        if self.builder_hosted is not None:
            out["builder_hosted"] = self.builder_hosted
        if self.snapshot:
            out["snapshot"] = dict(self.snapshot)
        if self.error is not None:
            out["error"] = self.error
        return out


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------
def _b64d(data: str | bytes) -> bytes:
    """Decode standard or URL-safe base64, tolerant of missing padding."""
    if isinstance(data, bytes):
        return data
    s = data.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except (binascii.Error, ValueError):
        return base64.urlsafe_b64decode(s)


def normalize_repo(url: str | None) -> str | None:
    """Canonicalize a repo reference to lowercase ``host/owner/repo`` (no scheme).

    Handles ``git+https://github.com/o/r.git``, ``github.com/o/r``, ``o/r``,
    and provenance URIs like ``git+https://github.com/o/r@refs/tags/v1``.
    Returns None for empty input.
    """
    if not url:
        return None
    u = str(url).strip().lower()
    for prefix in ("git+", "ssh://", "git://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
    for prefix in ("https://", "http://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
    # scp-style "git@github.com:owner/repo" → "github.com/owner/repo"
    if u.startswith("git@"):
        u = u[len("git@"):].replace(":", "/", 1)
    # strip a trailing ref (…@refs/…) and query/fragment
    for sep in ("@refs/", "@", "#", "?"):
        idx = u.find(sep)
        if idx > 0:
            u = u[:idx]
            break
    if u.endswith(".git"):
        u = u[:-4]
    u = u.rstrip("/")
    # collapse to host/owner/repo if a known forge host is present
    for host in ("github.com/", "gitlab.com/", "bitbucket.org/"):
        pos = u.find(host)
        if pos >= 0:
            u = u[pos:]
            parts = u.split("/")
            if len(parts) >= 3:
                return "/".join(parts[:3])
            return u
    # bare owner/repo
    parts = [p for p in u.split("/") if p]
    if len(parts) == 2:
        return f"github.com/{parts[0]}/{parts[1]}"
    return u or None


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (what a DSSE signature actually covers).

    ``PAE = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`` with LEN as ASCII
    decimal byte-length. This is the exact preimage both npm Sigstore bundles and
    PEP 740 attestations sign, so reconstructing it lets us verify offline.
    """
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def extract_intoto_binding(statement: dict) -> dict:
    """Pull {repo, commit, builder} + subject out of an in-toto statement.

    Supports SLSA provenance v1 (``buildDefinition``/``runDetails``) and v0.2
    (``predicate.invocation``/``predicate.builder``). Missing fields are simply
    absent from the returned dict — this is a best-effort extractor.
    """
    out: dict = {}
    if not isinstance(statement, dict):
        return out

    # subject (first entry) — the bytes the attestation is about.
    subjects = statement.get("subject") or []
    if subjects and isinstance(subjects[0], dict):
        out["subject_name"] = subjects[0].get("name")
        digest = subjects[0].get("digest")
        if isinstance(digest, dict) and digest:
            algo, val = next(iter(digest.items()))
            out["subject_digest"] = f"{algo}:{val}"

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return out

    # SLSA v1
    build_def = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if isinstance(build_def, dict):
        ext = build_def.get("externalParameters") or {}
        wf = ext.get("workflow") if isinstance(ext, dict) else None
        if isinstance(wf, dict) and wf.get("repository"):
            out["repo"] = normalize_repo(wf.get("repository"))
        # commit from resolvedDependencies (source git checkout)
        for dep in build_def.get("resolvedDependencies") or []:
            if not isinstance(dep, dict):
                continue
            dg = dep.get("digest") or {}
            if isinstance(dg, dict) and dg.get("gitCommit"):
                out["commit"] = dg.get("gitCommit")
                if "repo" not in out and dep.get("uri"):
                    out["repo"] = normalize_repo(dep.get("uri"))
                break
    if isinstance(run_details, dict):
        builder = run_details.get("builder")
        if isinstance(builder, dict) and builder.get("id"):
            out["builder"] = builder.get("id")

    # SLSA v0.2 (fallback)
    if "repo" not in out:
        inv = predicate.get("invocation")
        if isinstance(inv, dict):
            cs = inv.get("configSource") or {}
            if isinstance(cs, dict):
                if cs.get("uri"):
                    out["repo"] = normalize_repo(cs.get("uri"))
                cd = cs.get("digest") or {}
                if isinstance(cd, dict) and cd.get("sha1"):
                    out.setdefault("commit", cd.get("sha1"))
    if "builder" not in out:
        b = predicate.get("builder")
        if isinstance(b, dict) and b.get("id"):
            out["builder"] = b.get("id")
    return out


def _digests_match(subject_digest: str | None, artifact_digest: str | None) -> bool | None:
    """Compare an attestation subject digest to the bytes we graded.

    Returns True/False only when both sides expose a comparable algorithm; returns
    None ("unknown") otherwise, so we never raise a false red-flag on a format we
    can't line up. Handles ``algo:hex`` and npm ``sha512-<base64>`` integrity.
    """
    if not subject_digest or not artifact_digest:
        return None

    def _parts(d: str) -> tuple[str, str] | None:
        d = d.strip()
        if "-" in d and ":" not in d:  # npm integrity: sha512-<base64>
            algo, _, b64 = d.partition("-")
            try:
                return algo.lower(), _b64d(b64).hex()
            except Exception:  # noqa: BLE001
                return None
        if ":" in d:
            algo, _, val = d.partition(":")
            return algo.lower(), val.strip().lower()
        return None

    a = _parts(subject_digest)
    b = _parts(artifact_digest)
    if not a or not b or a[0] != b[0]:
        return None
    return a[1] == b[1]


# ---------------------------------------------------------------------------
# Certificate parsing + signature verification (cryptography, offline)
# ---------------------------------------------------------------------------
def extract_cert_identity(cert_der: bytes) -> dict:
    """Extract {san, issuer} identity from a Fulcio leaf certificate (DER).

    ``san`` is the signer identity (a workflow URI for GitHub Actions); ``issuer``
    is the OIDC issuer from the Fulcio custom OID. Never raises — returns {} on any
    parse failure so the caller can fall back to a structural-only result.
    """
    try:
        from cryptography import x509
    except Exception:  # noqa: BLE001 — cryptography missing ⇒ structural only
        return {}
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:  # noqa: BLE001
        return {}

    ident: dict = {}
    # SAN — prefer a URI GeneralName (the GitHub Actions workflow identity).
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            ident["san"] = uris[0]
        else:
            # otherName SAN (some Fulcio flows) — read raw general names.
            for gn in san.value:
                val = getattr(gn, "value", None)
                if isinstance(val, bytes):
                    txt = _decode_der_string(val)
                    if txt:
                        ident["san"] = txt
                        break
    except Exception:  # noqa: BLE001
        pass

    # OIDC issuer — try V2 (DER-wrapped) then V1 (raw string).
    for oid_str in (_OID_OIDC_ISSUER_V2, _OID_OIDC_ISSUER_V1):
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid_str))
            raw = getattr(ext.value, "value", None)
            if isinstance(raw, bytes):
                issuer = _decode_der_string(raw)
                if issuer:
                    ident["issuer"] = issuer
                    break
        except Exception:  # noqa: BLE001
            continue
    return ident


def _decode_der_string(raw: bytes) -> str | None:
    """Decode a Fulcio OID value that is either a raw UTF-8 string or a DER
    UTF8String (tag 0x0C). Best-effort, never raises."""
    if not raw:
        return None
    # DER UTF8String: 0x0C <len> <bytes…>
    if len(raw) >= 2 and raw[0] == 0x0C:
        length = raw[1]
        body = raw[2:2 + length]
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def verify_dsse_signature(
    cert_der: bytes, payload_type: str, payload: bytes, signature: bytes,
) -> bool:
    """Verify a DSSE signature over the PAE against a leaf certificate's key.

    Supports the algorithms Fulcio issues (ECDSA P-256/384, RSA, Ed25519). Returns
    True only on a cryptographically valid signature; False on any mismatch or
    error. This is the load-bearing offline check — it proves the in-toto statement
    was signed by the holder of ``cert_der`` and was not modified in transit.
    """
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding
    except Exception:  # noqa: BLE001
        return False
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        pubkey = cert.public_key()
        pae = dsse_pae(payload_type, payload)
    except Exception:  # noqa: BLE001
        return False

    try:
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            # Fulcio ECDSA sigs are DER-encoded (r,s); hash matches the curve.
            key_size = pubkey.curve.key_size
            algo = hashes.SHA384() if key_size >= 384 else hashes.SHA256()
            pubkey.verify(signature, pae, ec.ECDSA(algo))
            return True
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(signature, pae)
            return True
        # RSA
        pubkey.verify(signature, pae, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 — unknown key type / malformed sig ⇒ unverified
        return False


# ---------------------------------------------------------------------------
# Surface parsers (pure) — extract signed material from registry responses
# ---------------------------------------------------------------------------
def _leaf_cert_from_sigstore_bundle(bundle: dict) -> bytes | None:
    """Pull the leaf certificate DER out of a Sigstore bundle's verificationMaterial."""
    vm = bundle.get("verificationMaterial") or {}
    if not isinstance(vm, dict):
        return None
    cert = vm.get("certificate")
    if isinstance(cert, dict) and cert.get("rawBytes"):
        try:
            return _b64d(cert["rawBytes"])
        except Exception:  # noqa: BLE001
            return None
    chain = vm.get("x509CertificateChain")
    if isinstance(chain, dict):
        certs = chain.get("certificates") or []
        if certs and isinstance(certs[0], dict) and certs[0].get("rawBytes"):
            try:
                return _b64d(certs[0]["rawBytes"])  # leaf is first
            except Exception:  # noqa: BLE001
                return None
    return None


def _rekor_index_from_bundle(bundle: dict) -> str | None:
    vm = bundle.get("verificationMaterial") or {}
    tlogs = vm.get("tlogEntries") if isinstance(vm, dict) else None
    if isinstance(tlogs, list) and tlogs and isinstance(tlogs[0], dict):
        idx = tlogs[0].get("logIndex")
        if idx is not None:
            return str(idx)
    return None


def parse_npm_attestations(doc: dict) -> list[dict]:
    """Parse the npm attestations response into a list of signed-material dicts.

    Each item: ``{predicate_type, payload_type, payload(bytes), statement(dict),
    signature(bytes), cert_der(bytes|None), rekor_index}``. Only in-toto/DSSE
    Sigstore bundles are returned. Never raises.
    """
    out: list[dict] = []
    atts = doc.get("attestations") if isinstance(doc, dict) else None
    if not isinstance(atts, list):
        return out
    for att in atts:
        if not isinstance(att, dict):
            continue
        bundle = att.get("bundle")
        if not isinstance(bundle, dict):
            continue
        env = bundle.get("dsseEnvelope")
        if not isinstance(env, dict):
            continue
        try:
            payload = _b64d(env.get("payload", ""))
            sigs = env.get("signatures") or []
            sig = _b64d(sigs[0]["sig"]) if sigs and sigs[0].get("sig") else b""
            statement = json.loads(payload.decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        out.append({
            "predicate_type": att.get("predicateType")
            or statement.get("predicateType"),
            "payload_type": env.get("payloadType") or INTOTO_PAYLOAD_TYPE,
            "payload": payload,
            "statement": statement,
            "signature": sig,
            "cert_der": _leaf_cert_from_sigstore_bundle(bundle),
            "rekor_index": _rekor_index_from_bundle(bundle),
        })
    return out


def parse_pypi_provenance(doc: dict) -> list[dict]:
    """Parse a PEP 740 provenance object into a list of signed-material dicts.

    Each item mirrors :func:`parse_npm_attestations`, plus ``publisher`` (the
    declared Trusted Publisher: repo/workflow/environment). Never raises.
    """
    out: list[dict] = []
    bundles = doc.get("attestation_bundles") if isinstance(doc, dict) else None
    if not isinstance(bundles, list):
        return out
    for b in bundles:
        if not isinstance(b, dict):
            continue
        publisher = b.get("publisher") if isinstance(b.get("publisher"), dict) else {}
        for att in b.get("attestations") or []:
            if not isinstance(att, dict):
                continue
            env = att.get("envelope") or {}
            vm = att.get("verification_material") or {}
            if not isinstance(env, dict):
                continue
            try:
                payload = _b64d(env.get("statement", ""))
                sig = _b64d(env.get("signature", "")) if env.get("signature") else b""
                statement = json.loads(payload.decode("utf-8"))
            except Exception:  # noqa: BLE001
                continue
            cert_der = None
            if isinstance(vm, dict) and vm.get("certificate"):
                try:
                    cert_der = _b64d(vm["certificate"])
                except Exception:  # noqa: BLE001
                    cert_der = None
            rekor_index = None
            tents = vm.get("transparency_entries") if isinstance(vm, dict) else None
            if isinstance(tents, list) and tents and isinstance(tents[0], dict):
                if tents[0].get("logIndex") is not None:
                    rekor_index = str(tents[0]["logIndex"])
            out.append({
                "predicate_type": statement.get("predicateType"),
                "payload_type": INTOTO_PAYLOAD_TYPE,
                "payload": payload,
                "statement": statement,
                "signature": sig,
                "cert_der": cert_der,
                "rekor_index": rekor_index,
                "publisher": publisher,
            })
    return out


# ---------------------------------------------------------------------------
# Core verification reducer (pure) — material -> ProvenanceResult
# ---------------------------------------------------------------------------
def verify_material(
    material: list[dict],
    *,
    surface: str,
    coordinate: str,
    claimed_repo: str | None = None,
    artifact_digest: str | None = None,
    scan_depth: str = "repo-only",
) -> ProvenanceResult:
    """Reduce parsed signed material into a verified :class:`ProvenanceResult`.

    Pure and deterministic — the unit tests drive this with canned fixtures so no
    network is involved and a verifier can replay it from pinned bytes. Prefers a
    SLSA-provenance predicate; verifies the DSSE signature against the leaf cert,
    enforces the identity gate (trusted CI issuer + SAN binds to claimed source),
    and the subject-digest gate (when a digest is available).
    """
    result = ProvenanceResult(
        surface=surface, coordinate=coordinate,
        claimed_repo=normalize_repo(claimed_repo),
        method=VERIFY_METHOD,
    )
    if not material:
        return result  # present=False, level=none

    result.present = True
    result.notes.append(
        "trust-root NOT anchored to Fulcio TUF; Rekor inclusion NOT proven offline",
    )

    # Prefer a SLSA provenance predicate; else take the first item.
    chosen = next(
        (m for m in material if m.get("predicate_type") in SLSA_PREDICATE_TYPES),
        material[0],
    )
    result.predicate_type = chosen.get("predicate_type")
    binding = extract_intoto_binding(chosen.get("statement") or {})
    result.binding = {k: v for k, v in binding.items()
                      if k in ("repo", "commit", "builder") and v}
    result.subject_name = binding.get("subject_name")
    result.subject_digest = binding.get("subject_digest")
    if chosen.get("rekor_index"):
        result.snapshot["rekor_log_index"] = chosen["rekor_index"]

    # Source-match: provenance repo vs the declared/graded repo.
    prov_repo = binding.get("repo")
    if prov_repo and result.claimed_repo:
        result.source_matches_claim = (prov_repo == result.claimed_repo)
    elif prov_repo:
        result.source_matches_claim = None  # nothing to compare against

    # Subject-digest gate (§2.C gate 2).
    result.subject_matches = _digests_match(result.subject_digest, artifact_digest)

    # Structural level reached (parsed + bound), signature not yet checked.
    result.verification_level = "structural"

    cert_der = chosen.get("cert_der")
    if not cert_der:
        result.notes.append("no leaf certificate in bundle — signature not checked")
        return result  # structural only, verified=False

    # Cryptographic signature check over the DSSE PAE.
    sig_ok = verify_dsse_signature(
        cert_der,
        chosen.get("payload_type") or INTOTO_PAYLOAD_TYPE,
        chosen.get("payload") or b"",
        chosen.get("signature") or b"",
    )
    identity = extract_cert_identity(cert_der)
    result.identity = identity
    issuer = identity.get("issuer")
    san = identity.get("san")
    result.builder_hosted = issuer in HOSTED_CI_ISSUERS if issuer else None

    result.signature_valid = sig_ok
    if not sig_ok:
        result.notes.append("DSSE signature did NOT verify against leaf cert")
        # structural, signature_valid=False → red flag "unverified" (see scoring).
        return result

    # Signature verified. Now enforce the identity gate (§2.C gate 1).
    result.verification_level = "signature"
    issuer_trusted = issuer in TRUSTED_CI_ISSUERS
    # SAN identity must bind to the claimed source when we have one.
    san_binds = True
    if result.claimed_repo and san:
        # SAN is a workflow URI like https://github.com/o/r/.github/workflows/…
        norm_san = normalize_repo(san)
        san_binds = bool(norm_san) and result.claimed_repo in norm_san
        if not san_binds:
            # be precise: does the SAN at least CONTAIN the owner/repo path?
            owner_repo = "/".join(result.claimed_repo.split("/")[-2:])
            san_binds = owner_repo in (san or "")

    if not issuer_trusted:
        result.notes.append(
            f"OIDC issuer not in trusted-CI set ({issuer!r}) — signer not a trusted CI",
        )
        # Valid signature but from an untrusted/self-hosted issuer → not certifiable.
        # A verified signature we can't attribute to a trusted CI is suspicious, so
        # scoring treats it as a mismatch (source cannot be trusted-bound).
        result.source_matches_claim = False
        return result
    if not san_binds:
        result.notes.append(
            "cert SAN does not bind to the claimed source — treated as mismatch",
        )
        result.source_matches_claim = False
        return result

    # Passed signature + trusted-issuer + SAN-binding gates.
    result.verified = True

    # Top-tier ("certified") eligibility — the stricter A+ gate (§4.4 rule 1):
    #   verified + source matches + subject-digest matches + artifact-depth scan.
    result.certified_eligible = bool(
        result.verified
        and (result.source_matches_claim in (True, None))
        and (result.subject_matches in (True, None))
        and scan_depth in ("artifact", "artifact+live")
        and result.builder_hosted
    )
    return result


# ---------------------------------------------------------------------------
# Scoring + coverage policy (pure) — Kenne decision #4
# ---------------------------------------------------------------------------
# A separate, additive signal. Absent provenance is N/A (never a penalty). Present
# + verified is a small bonus. A package that CLAIMS provenance but fails to verify
# is a real red flag (small penalty). Kept modest so it never rewrites the grade of
# packages without provenance.
PROV_BONUS_VERIFIED = 4          # verified + source matches
PROV_PENALTY_UNVERIFIED = 5      # claims provenance, signature/identity failed
PROV_PENALTY_MISMATCH = 8        # verified signer but source ≠ claimed (suspicious)


def provenance_score_delta(result: ProvenanceResult) -> tuple[int, str]:
    """Return ``(score_delta, reason)`` for a provenance result.

    Positive = bonus, negative = penalty, 0 = N/A. **Absent = 0, always** — the
    long tail without provenance is never penalized (decision #4).
    """
    if not result.present:
        return 0, "no provenance (N/A — not penalized)"

    if result.verified:
        if result.subject_matches is False:
            # verified signature but about different bytes than we graded.
            return -PROV_PENALTY_MISMATCH, "verified provenance for a different artifact digest"
        return PROV_BONUS_VERIFIED, "verified build provenance (bonus)"

    # Valid signature but the signer identity / source does not bind to the claimed
    # source (SAN mismatch, untrusted issuer, or predicate repo ≠ claim). A real,
    # cryptographically-valid attestation pointing at a DIFFERENT source is the
    # strongest suspicious signal — penalize more than a plain unverifiable claim.
    if result.signature_valid or result.source_matches_claim is False:
        return -PROV_PENALTY_MISMATCH, "verified signer but source/identity mismatch"

    # Present but the signature could not be verified at all — a package that
    # advertises provenance and fails the cryptographic check is a genuine red flag.
    return -PROV_PENALTY_UNVERIFIED, "claimed provenance failed verification"


def coverage_binding_value(result: ProvenanceResult) -> str:
    """Map a result to ``coverage.provenance_binding`` (§4.4 vocabulary).

    ``verified:<repo>@<commit>`` | ``mismatch`` | ``unverified`` | ``absent`` |
    ``n/a``. ``absent`` means we looked and found none (scored N/A, not a penalty);
    ``n/a`` means provenance was not attempted (flag off / no coordinate).
    """
    if not result.surface:
        return "n/a"
    if not result.present:
        return "absent"
    if result.verified:
        if result.subject_matches is False:
            return "mismatch"
        repo = result.binding.get("repo") or result.claimed_repo or "unknown"
        commit = result.binding.get("commit")
        return f"verified:{repo}@{commit}" if commit else f"verified:{repo}"
    # Present, not fully verified: a valid signature from the wrong source (or an
    # explicit predicate/source mismatch) is a mismatch; anything else is unverified.
    if result.signature_valid or result.source_matches_claim is False:
        return "mismatch"
    return "unverified"


# ---------------------------------------------------------------------------
# Async I/O layer — fetch bundles (fail-open)
# ---------------------------------------------------------------------------
async def fetch_npm_provenance(
    name: str, version: str, client: httpx.AsyncClient,
) -> dict | None:
    """GET the npm attestations bundle. 404/any-error ⇒ None (not present)."""
    url = NPM_ATTESTATIONS_URL.format(pkg=name, version=version)
    try:
        resp = await client.get(url, timeout=_HTTP_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def fetch_pypi_provenance(
    project: str, version: str, filename: str, client: httpx.AsyncClient,
) -> dict | None:
    """GET the PEP 740 provenance object for a specific file. Any-error ⇒ None."""
    url = PYPI_PROVENANCE_URL.format(
        project=project, version=version, filename=filename,
    )
    try:
        resp = await client.get(url, timeout=_HTTP_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def analyze_provenance(
    surface: str,
    name: str,
    version: str,
    *,
    filename: str | None = None,
    claimed_repo: str | None = None,
    artifact_digest: str | None = None,
    scan_depth: str = "repo-only",
    client: httpx.AsyncClient | None = None,
) -> ProvenanceResult:
    """Fetch + verify provenance for one package coordinate. **Fail-open.**

    ``surface`` is ``npm`` or ``pypi``. On any network/parse/verify error the
    result is a benign "not present" (``present=False``) — provenance verification
    must never break a scan. Every fetched bundle's Rekor index + fetch timestamp
    is pinned into ``snapshot`` for offline recompute.
    """
    coordinate = f"{name}@{version}" + (f"/{filename}" if filename else "")
    fallback = ProvenanceResult(
        surface=surface, coordinate=coordinate,
        claimed_repo=normalize_repo(claimed_repo), method=VERIFY_METHOD,
    )

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(headers={"User-Agent": "AgentAvow-Scanner"})
    try:
        if surface == "npm":
            doc = await fetch_npm_provenance(name, version, client)
            material = parse_npm_attestations(doc) if doc else []
        elif surface == "pypi":
            if not filename:
                return fallback  # PEP 740 provenance is per-file
            doc = await fetch_pypi_provenance(name, version, filename, client)
            material = parse_pypi_provenance(doc) if doc else []
        else:
            return fallback

        result = verify_material(
            material,
            surface=surface,
            coordinate=coordinate,
            claimed_repo=claimed_repo,
            artifact_digest=artifact_digest,
            scan_depth=scan_depth,
        )
        result.snapshot["fetched_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ",
        )
        return result
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        fallback.error = str(exc)
        logger.warning(
            "Provenance verification failed for %s %s (fail-open to N/A): %s",
            surface, coordinate, exc,
        )
        return fallback
    finally:
        if owns_client and client is not None:
            await client.aclose()
