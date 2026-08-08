"""Phase 3 provenance / signing verification — fully offline.

The pure parsers/reducers are driven with canned JSON, and the async fetch+verify
orchestrator runs against an httpx.MockTransport, so no network is hit. The
"verified" path is exercised with a REAL Sigstore-style leaf certificate + a REAL
DSSE signature (generated locally with ``cryptography``), so the cryptographic
check is genuinely tested rather than stubbed.
"""
from __future__ import annotations

import base64
import datetime
import json

import httpx
import pytest

from src.scanner.provenance import (
    INTOTO_PAYLOAD_TYPE,
    ProvenanceResult,
    analyze_provenance,
    coverage_binding_value,
    dsse_pae,
    extract_cert_identity,
    extract_intoto_binding,
    normalize_repo,
    parse_npm_attestations,
    parse_pypi_provenance,
    provenance_score_delta,
    verify_dsse_signature,
    verify_material,
)

OWNER_REPO = "github.com/owner/repo"
CLAIMED = "https://github.com/owner/repo"
SAN_URI = "https://github.com/owner/repo/.github/workflows/publish.yml@refs/tags/v1.0.0"
GH_ISSUER = "https://token.actions.githubusercontent.com"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


# ── fixture builders (real crypto) ───────────────────────────────────────────
def _make_leaf_cert(private_key, *, san_uri=SAN_URI, issuer=GH_ISSUER):
    """Build a Fulcio-style self-signed leaf cert with SAN URI + OIDC-issuer OID."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore")])
    # OIDC issuer V2 extension: DER UTF8String (tag 0x0C).
    issuer_bytes = issuer.encode()
    der_utf8 = b"\x0c" + bytes([len(issuer_bytes)]) + issuer_bytes
    oidc_ext = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), der_utf8,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]),
            critical=True,
        )
        .add_extension(oidc_ext, critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def _slsa_statement(subject_sha512_hex="ab" * 32):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": "pkg:npm/foo@1.0.0",
            "digest": {"sha512": subject_sha512_hex},
        }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa.dev/github-actions",
                "externalParameters": {
                    "workflow": {
                        "repository": "https://github.com/owner/repo",
                        "ref": "refs/tags/v1.0.0",
                        "path": ".github/workflows/publish.yml",
                    },
                },
                "resolvedDependencies": [{
                    "uri": "git+https://github.com/owner/repo@refs/tags/v1.0.0",
                    "digest": {"gitCommit": COMMIT},
                }],
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
        },
    }


def _sign_dsse(private_key, payload: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    return private_key.sign(
        dsse_pae(INTOTO_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()),
    )


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@pytest.fixture()
def signed_bundle():
    """Return (npm_doc, pypi_doc, statement, key) with a real signature."""
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    cert_der = _make_leaf_cert(key)
    statement = _slsa_statement()
    payload = json.dumps(statement).encode()
    sig = _sign_dsse(key, payload)

    npm_doc = {
        "attestations": [{
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                "verificationMaterial": {
                    "certificate": {"rawBytes": _b64(cert_der)},
                    "tlogEntries": [{"logIndex": "12345678"}],
                },
                "dsseEnvelope": {
                    "payloadType": INTOTO_PAYLOAD_TYPE,
                    "payload": _b64(payload),
                    "signatures": [{"sig": _b64(sig)}],
                },
            },
        }],
    }
    pypi_doc = {
        "version": 1,
        "attestation_bundles": [{
            "publisher": {"kind": "GitHub", "repository": "owner/repo",
                          "workflow": "publish.yml"},
            "attestations": [{
                "version": 1,
                "verification_material": {
                    "certificate": _b64(cert_der),
                    "transparency_entries": [{"logIndex": "999"}],
                },
                "envelope": {"statement": _b64(payload), "signature": _b64(sig)},
            }],
        }],
    }
    return npm_doc, pypi_doc, statement, key


# ── pure helpers ─────────────────────────────────────────────────────────────
def test_normalize_repo_variants():
    assert normalize_repo("git+https://github.com/Owner/Repo.git") == OWNER_REPO
    assert normalize_repo(SAN_URI) == OWNER_REPO
    assert normalize_repo("git@github.com:owner/repo.git") == OWNER_REPO
    assert normalize_repo("owner/repo") == OWNER_REPO
    assert normalize_repo(None) is None


def test_dsse_pae_encoding():
    assert dsse_pae("t", b"body") == b"DSSEv1 1 t 4 body"


def test_extract_binding_slsa_v1():
    b = extract_intoto_binding(_slsa_statement())
    assert b["repo"] == OWNER_REPO
    assert b["commit"] == COMMIT
    assert "runner" in b["builder"]
    assert b["subject_digest"] == "sha512:" + "ab" * 32


def test_extract_binding_slsa_v02():
    stmt = {
        "subject": [{"name": "x", "digest": {"sha256": "dd"}}],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "invocation": {"configSource": {
                "uri": "git+https://github.com/owner/repo@refs/heads/main",
                "digest": {"sha1": COMMIT}}},
            "builder": {"id": "https://github.com/actions/runner"},
        },
    }
    b = extract_intoto_binding(stmt)
    assert b["repo"] == OWNER_REPO
    assert b["commit"] == COMMIT


def test_parse_npm_attestations(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)
    assert len(mat) == 1
    assert mat[0]["predicate_type"] == "https://slsa.dev/provenance/v1"
    assert mat[0]["cert_der"] and mat[0]["signature"]
    assert mat[0]["rekor_index"] == "12345678"


def test_parse_pypi_provenance(signed_bundle):
    _, pypi_doc, _, _ = signed_bundle
    mat = parse_pypi_provenance(pypi_doc)
    assert len(mat) == 1
    assert mat[0]["cert_der"] and mat[0]["signature"]
    assert mat[0]["publisher"]["repository"] == "owner/repo"
    assert mat[0]["rekor_index"] == "999"


# ── real signature verification ──────────────────────────────────────────────
def test_verify_dsse_signature_valid(signed_bundle):
    npm_doc, _, statement, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)[0]
    assert verify_dsse_signature(
        mat["cert_der"], mat["payload_type"], mat["payload"], mat["signature"],
    ) is True


def test_verify_dsse_signature_tampered_payload(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)[0]
    tampered = mat["payload"] + b" "
    assert verify_dsse_signature(
        mat["cert_der"], mat["payload_type"], tampered, mat["signature"],
    ) is False


def test_verify_dsse_signature_wrong_key(signed_bundle):
    from cryptography.hazmat.primitives.asymmetric import ec

    npm_doc, _, statement, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)[0]
    # A cert with a DIFFERENT keypair must not validate the signature.
    other = ec.generate_private_key(ec.SECP256R1())
    other_cert = _make_leaf_cert(other)
    assert verify_dsse_signature(
        other_cert, mat["payload_type"], mat["payload"], mat["signature"],
    ) is False


def test_extract_cert_identity(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    cert_der = parse_npm_attestations(npm_doc)[0]["cert_der"]
    ident = extract_cert_identity(cert_der)
    assert ident["san"] == SAN_URI
    assert ident["issuer"] == GH_ISSUER


# ── verify_material end-to-end (offline) ─────────────────────────────────────
def test_verify_material_verified_npm(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    res = verify_material(
        parse_npm_attestations(npm_doc),
        surface="npm", coordinate="foo@1.0.0", claimed_repo=CLAIMED,
        scan_depth="artifact",
    )
    assert res.present is True
    assert res.signature_valid is True
    assert res.verified is True
    assert res.verification_level == "signature"
    assert res.binding["repo"] == OWNER_REPO
    assert res.binding["commit"] == COMMIT
    assert res.source_matches_claim is True
    assert res.builder_hosted is True
    # artifact scan_depth + hosted builder ⇒ meets the top-tier "certified" gate.
    assert res.certified_eligible is True


def test_verify_material_repo_only_not_certified(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    res = verify_material(
        parse_npm_attestations(npm_doc),
        surface="npm", coordinate="foo@1.0.0", claimed_repo=CLAIMED,
        scan_depth="repo-only",
    )
    assert res.verified is True
    # A+ / "certified" requires scan_depth=artifact — repo-only is capped below it.
    assert res.certified_eligible is False


def test_verify_material_pypi(signed_bundle):
    _, pypi_doc, _, _ = signed_bundle
    res = verify_material(
        parse_pypi_provenance(pypi_doc),
        surface="pypi", coordinate="foo@1.0.0/foo-1.0.0.tar.gz",
        claimed_repo=CLAIMED, scan_depth="artifact",
    )
    assert res.verified is True
    assert res.binding["repo"] == OWNER_REPO


def test_verify_material_source_mismatch(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    # Claim a DIFFERENT repo than the attestation binds → mismatch, not verified.
    res = verify_material(
        parse_npm_attestations(npm_doc),
        surface="npm", coordinate="foo@1.0.0",
        claimed_repo="https://github.com/evil/other", scan_depth="artifact",
    )
    assert res.present is True
    assert res.signature_valid is True   # the signature itself is valid…
    assert res.verified is False         # …but it does not bind to the claimed source
    assert res.source_matches_claim is False
    assert coverage_binding_value(res) == "mismatch"


def test_verify_material_subject_digest_gate(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    # Provide an artifact digest that does NOT match the attestation subject.
    res = verify_material(
        parse_npm_attestations(npm_doc),
        surface="npm", coordinate="foo@1.0.0", claimed_repo=CLAIMED,
        artifact_digest="sha512:" + "ff" * 32, scan_depth="artifact",
    )
    assert res.verified is True
    assert res.subject_matches is False   # different bytes than we graded
    delta, _ = provenance_score_delta(res)
    assert delta < 0                      # verified-but-different-digest = penalty


def test_verify_material_bad_signature_unverified(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)
    mat[0]["signature"] = b"\x00" * 64   # corrupt the signature
    res = verify_material(
        mat, surface="npm", coordinate="foo@1.0.0", claimed_repo=CLAIMED,
    )
    assert res.present is True
    assert res.signature_valid is False
    assert res.verified is False
    assert coverage_binding_value(res) == "unverified"


def test_verify_material_absent():
    res = verify_material([], surface="npm", coordinate="foo@1.0.0")
    assert res.present is False
    assert res.verified is False
    assert res.verification_level == "none"
    assert coverage_binding_value(res) == "absent"


# ── scoring policy (Kenne decision #4) ───────────────────────────────────────
def test_score_absent_is_na_never_penalty():
    res = ProvenanceResult(surface="npm", present=False)
    assert provenance_score_delta(res) == (0, "no provenance (N/A — not penalized)")


def test_score_verified_is_bonus(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    res = verify_material(
        parse_npm_attestations(npm_doc), surface="npm",
        coordinate="foo@1.0.0", claimed_repo=CLAIMED, scan_depth="artifact",
    )
    delta, _ = provenance_score_delta(res)
    assert delta > 0


def test_score_claims_but_fails_is_penalty(signed_bundle):
    npm_doc, _, _, _ = signed_bundle
    mat = parse_npm_attestations(npm_doc)
    mat[0]["signature"] = b"\x00" * 64
    res = verify_material(mat, surface="npm", coordinate="foo@1.0.0",
                          claimed_repo=CLAIMED)
    delta, _ = provenance_score_delta(res)
    assert delta < 0


# ── async orchestrator (MockTransport) ───────────────────────────────────────
def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_analyze_provenance_npm_happy(signed_bundle):
    npm_doc, _, _, _ = signed_bundle

    def handler(request: httpx.Request) -> httpx.Response:
        if "/attestations/" in request.url.path:
            return httpx.Response(200, json=npm_doc)
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await analyze_provenance(
            "npm", "foo", "1.0.0", claimed_repo=CLAIMED,
            scan_depth="artifact", client=client,
        )
    assert res.verified is True
    assert res.snapshot.get("rekor_log_index") == "12345678"
    assert res.snapshot.get("fetched_at")  # pinned for recompute


@pytest.mark.asyncio
async def test_analyze_provenance_absent_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await analyze_provenance(
            "npm", "foo", "1.0.0", claimed_repo=CLAIMED, client=client,
        )
    assert res.present is False
    assert coverage_binding_value(res) == "absent"


@pytest.mark.asyncio
async def test_analyze_provenance_fails_open_on_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async with _mock_client(handler) as client:
        res = await analyze_provenance(
            "npm", "foo", "1.0.0", claimed_repo=CLAIMED, client=client,
        )
    # 500 → fetch returns None → not present, benign N/A. Never raises.
    assert res.present is False
    assert provenance_score_delta(res)[0] == 0


@pytest.mark.asyncio
async def test_analyze_provenance_pypi_needs_filename():
    async with _mock_client(lambda r: httpx.Response(404)) as client:
        res = await analyze_provenance(
            "pypi", "foo", "1.0.0", claimed_repo=CLAIMED, client=client,
        )
    # PEP 740 provenance is per-file; without a filename we cannot fetch → N/A.
    assert res.present is False
