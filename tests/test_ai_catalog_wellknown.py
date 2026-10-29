"""``/.well-known/ai-catalog.json`` — build, sign, verify, and negative cases.

Exercises ``scripts/ai_catalog_wellknown.py`` against the Agent-Card/ai-catalog
specification as merged at 9aac2c1b (PR #117: ADR-0028 independent Trust
Manifests with whole-object JCS signatures, ADR-0029 Policy URLs extension).

Every signature is ES256 with a throwaway P-256 key and a fake DID document;
no production key is touched. Runs with ``--noconftest`` (no database).
"""
from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import ai_catalog_wellknown as ac
from src import signing
from src.config import settings
from src.scanner.scan import _compute_manifest_digest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
TOOLS = FIXTURES / "ai_catalog_tools_list.json"
CARD = FIXTURES / "ai_catalog_github_mcp_server_card.json"
VERDICT = FIXTURES / "ai_catalog_github_mcp_verdict.json"
COMMITTED = ROOT / "web" / "public" / ".well-known" / "ai-catalog.json"
ES_KID = "catalog-es256-v1"
IDENTITY = "did:web:agentavow.com"
OWN_ID = "urn:air:agentavow.com:mcp:agentavow-trust"
ASSESSED_ID = "https://agentavow.com/ids/mcp/io.github.github/github-mcp-server"
CARD_URL = "https://api.githubcopilot.com/mcp/server-card"
# GitHub serves this card with ETag = the SHA-256 of its body, so the digest is
# independently checkable against the publisher's own header.
CARD_ETAG_SHA256 = "2082331fd2c4b5fa3ba11be9f74371ed16d2883a9ff5668d9828c483c57d9c10"

ISSUED = datetime(2026, 10, 28, 18, 0, tzinfo=timezone.utc)
NOW = ISSUED + timedelta(hours=1)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def tools_fixture() -> dict:
    return json.loads(TOOLS.read_text())


@pytest.fixture
def card_bytes() -> bytes:
    return CARD.read_bytes()


@pytest.fixture
def assessed(card_bytes) -> dict:
    return ac.build_assessed_entry(card_bytes, card_url=CARD_URL, repo="github/github-mcp-server",
                                   verdict=json.loads(VERDICT.read_text()),
                                   publisher="agentavow.com", observed=ISSUED)


@pytest.fixture
def catalog(tools_fixture, assessed) -> dict:
    return ac.build_catalog(tools_fixture["tools"], tools_fixture["serverInfo"],
                            issued_at=ISSUED, assessed=assessed)


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def did_doc(key) -> dict:
    return ac.test_did_document(IDENTITY, ES_KID, key.public_key())


@pytest.fixture
def signed(catalog, key) -> dict:
    return ac.sign_catalog(copy.deepcopy(catalog), key, ES_KID, "signed-test-key", now=ISSUED)


@pytest.fixture
def artifacts(card_bytes) -> dict:
    return {CARD_URL: card_bytes}


def _verify(cat, did_doc, artifacts, **kw):
    kw.setdefault("now", NOW)
    return ac.verify_catalog(cat, did_doc=did_doc, artifacts=artifacts, **kw)


def _header(jws: str) -> dict:
    return json.loads(ac.b64url_decode(jws.split(".")[0]))


def _resign_manifest(cat, entry_i, key, *, kid=None, typ=ac.TYP_MANIFEST, header_extra=None):
    """Re-sign one manifest as-is (a valid JWS over whatever it now contains)."""
    tm = cat["entries"][entry_i]["trustManifests"][0]
    tm["signature"].pop("jws", None)
    hdr = {"alg": "ES256", "kid": kid or f"{tm['signature']['signer']}#{ES_KID}", "typ": typ,
           **(header_extra or {})}
    h = ac.b64url(ac.jcs(hdr))
    sig = signing.sign_es256(f"{h}.{ac.b64url(ac.signed_payload(tm))}".encode("ascii"), key)
    tm["signature"]["jws"] = f"{h}..{ac.b64url(sig)}"
    return tm


def _p256_b64(k: ec.EllipticCurvePrivateKey) -> str:
    der = k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    return base64.b64encode(der).decode()


@pytest.fixture
def prod_keys(monkeypatch):
    """A throwaway P-256 key configured where prod's CATALOG_SIGNING_KEY_P256 lives."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    monkeypatch.setattr(signing, "_private_key", Ed25519PrivateKey.generate())
    k = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(settings, "catalog_signing_key_p256", _p256_b64(k))
    monkeypatch.setattr(signing, "_catalog_key", None)
    yield k
    monkeypatch.setattr(signing, "_catalog_key", None)


# ── build: merged shape ──────────────────────────────────────────────────────


def test_publisher_entry_follows_adr_0028_and_0029(catalog):
    assert catalog["specVersion"] == "1.0"
    assert catalog["host"]["identifier"] == IDENTITY
    entry = catalog["entries"][0]
    assert entry["identifier"] == OWN_ID
    assert "data" in entry and "url" not in entry
    assert entry["digest"] == ac.sha256_digest(ac.jcs(entry["data"]))
    assert "trustManifest" not in entry and len(entry["trustManifests"]) == 1
    assert entry["extensions"][ac.POLICY_URLS_EXT] == {
        "privacyPolicyUrl": "https://agentavow.com/legal/privacy",
        "termsOfServiceUrl": "https://agentavow.com/legal/terms",
    }
    tm = entry["trustManifests"][0]
    assert tm["contributor"] == IDENTITY
    assert tm["subject"] == {"identifier": OWN_ID, "type": ac.MCP_SERVER_CARD_TYPE,
                             "digest": entry["digest"]}
    for legacy in ("identity", "identityType", "privacyPolicyUrl", "termsOfServiceUrl",
                   "issuedAt", "expiresAt", "signature"):
        assert legacy not in tm, legacy
    assert "version" not in entry and "version" not in tm["subject"]
    assert tm["trustSchema"] and tm["provenance"]  # substantive while unsigned
    assert "signature" not in catalog


def test_build_carries_all_eight_tools_and_digests(catalog, tools_fixture):
    card = catalog["entries"][0]["data"]
    tools = card["_meta"]["agentavow.com/tools"]
    assert [t["name"] for t in tools] == [t["name"] for t in tools_fixture["tools"]]
    assert len(tools) == 8
    ext = catalog["entries"][0]["trustManifests"][0]["extensions"][ac.TOOL_MANIFEST_EXT_KEY]
    assert ext["profile"] == ac.MCP_TOOL_DIGEST_PROFILE
    assert set(ext["toolDigests"]) == {f"tool:{t['name']}" for t in tools}
    assert ext["toolManifestDigest"] == _compute_manifest_digest(ext["toolDigests"])


def test_unsigned_draft_verifies_structurally(catalog, artifacts):
    r = ac.verify_catalog(catalog, unsigned_ok=True, now=NOW, artifacts=artifacts)
    assert r.ok, r.render()


def test_unsigned_draft_is_not_accepted_as_signed(catalog, artifacts):
    r = ac.verify_catalog(catalog, now=NOW, artifacts=artifacts)
    assert "catalog.signature-present" in r.failures()
    assert "entries[0].at-least-one-accepted-signed-manifest" in r.failures()


def test_build_declares_profile_and_signer(catalog):
    build = catalog["extensions"][ac.BUILD_EXT_KEY]
    assert build["signerKid"] == f"{IDENTITY}#{ES_KID}"
    assert build["signatureProfile"] == "did-web-v1"
    assert "9aac2c1b" in build["specTarget"]


# ── build: assessed third-party entry ────────────────────────────────────────


def test_assessed_entry_is_an_operator_projection(assessed, card_bytes):
    assert card_bytes.decode().startswith('{"$schema"') and not card_bytes.endswith(b"\n")
    assert assessed["identifier"] == ASSESSED_ID
    assert not assessed["identifier"].startswith("urn:air:"), "not the publisher: no urn:air"
    assert "publisher" not in assessed, "publisher authority is never inferred"
    assert assessed["url"] == CARD_URL and "data" not in assessed
    assert assessed["digest"] == f"sha256:{CARD_ETAG_SHA256}" == ac.sha256_digest(card_bytes)
    assert "version" not in assessed
    src = assessed["extensions"][ac.SOURCE_COORDS_EXT_KEY]
    assert src["serverCardName"] == "io.github.github/github-mcp-server"


def test_assessed_manifest_is_an_independent_assessor_contribution(assessed):
    (tm,) = assessed["trustManifests"]
    assert tm["contributor"] == IDENTITY
    assert tm["subject"] == {"identifier": ASSESSED_ID, "type": ac.MCP_SERVER_CARD_TYPE,
                             "digest": assessed["digest"]}
    verdict_att = tm["attestations"][0]
    assert verdict_att["type"] == ac.SCAN_VERDICT_TYPE
    assert verdict_att["uri"] == ("https://agentavow.com/api/v1/public/scan/"
                                  "github/github-mcp-server/verdict.json")
    pinned = tm["attestations"][1]
    assert pinned["uri"].startswith("data:application/jose,")
    assert pinned["digest"] == ac.sha256_digest(pinned["uri"].split(",", 1)[1].encode())
    a = tm["extensions"][ac.ASSESSMENT_EXT_KEY]
    assert a["role"] == "independent-assessor" and "not the remote deployment" in a["scope"]


def test_assessed_entry_refuses_unscanned_repo(card_bytes):
    with pytest.raises(ValueError, match="no signed verdict"):
        ac.build_assessed_entry(card_bytes, card_url=CARD_URL, repo="github/github-mcp-server",
                                verdict={"jws": None, "error": "not_scanned"},
                                publisher="agentavow.com", observed=ISSUED)


def test_assessed_entry_refuses_repo_the_card_does_not_name(card_bytes):
    with pytest.raises(ValueError, match="card repository"):
        ac.build_assessed_entry(card_bytes, card_url=CARD_URL, repo="someone/else",
                                verdict=json.loads(VERDICT.read_text()),
                                publisher="agentavow.com", observed=ISSUED)


def test_assessed_identifier_rejects_odd_names():
    with pytest.raises(ValueError):
        ac.assessed_identifier("agentavow.com", "../../etc")


def test_cli_build_offline_with_assessed_entry(tmp_path):
    out = tmp_path / "c.json"
    rc = ac.main(["--out", str(out), "build", "--tools-json", str(TOOLS),
                  "--assess-card-file", str(CARD), "--assess-verdict-json", str(VERDICT)])
    assert rc == 0
    cat = json.loads(out.read_text())
    assert [e["identifier"] for e in cat["entries"]] == [OWN_ID, ASSESSED_ID]


def test_cli_build_omits_assessed_entry_when_fetch_fails(tmp_path, monkeypatch):
    def boom(url):
        raise OSError("network down")

    monkeypatch.setattr(ac, "_fetch_card", boom)
    out = tmp_path / "c.json"
    rc = ac.main(["--out", str(out), "build", "--tools-json", str(TOOLS),
                  "--assess-card-url", CARD_URL, "--assess-verdict-json", str(VERDICT)])
    assert rc == 0
    assert [e["identifier"] for e in json.loads(out.read_text())["entries"]] == [OWN_ID]


# ── sign / verify ────────────────────────────────────────────────────────────


def test_sign_then_verify_strictly(signed, did_doc, artifacts):
    r = _verify(signed, did_doc, artifacts)
    assert r.ok, r.render()
    assert any("publisher endorsement" in n for n in r.notes)
    assert any("entries[1]" in n and "independent contribution" in n for n in r.notes)


def test_signature_objects_and_headers(signed):
    for entry, ttl in ((signed["entries"][0], ac.PUBLISHER_TTL),
                       (signed["entries"][1], ac.ASSESSOR_TTL)):
        sig = entry["trustManifests"][0]["signature"]
        assert sig["signer"] == IDENTITY and sig["profile"] == "did-web-v1"
        assert ac.parse_rfc3339(sig["expiresAt"]) - ac.parse_rfc3339(sig["issuedAt"]) == ttl
        head, payload, raw = sig["jws"].split(".")
        assert payload == "", "detached"
        assert _header(sig["jws"]) == {"alg": "ES256", "kid": f"{IDENTITY}#{ES_KID}",
                                       "typ": "ai-catalog-trust-manifest+jws"}
        assert len(ac.b64url_decode(raw)) == 64, "r || s, not DER"
    assert _header(signed["signature"]["jws"])["typ"] == "ai-catalog+jws"
    assert signed["extensions"][ac.BUILD_EXT_KEY]["status"] == "signed-test-key"


def test_payload_is_the_whole_manifest_minus_only_jws(signed):
    tm = signed["entries"][0]["trustManifests"][0]
    expected = {k: v for k, v in tm.items()}
    expected["signature"] = {k: v for k, v in tm["signature"].items() if k != "jws"}
    assert ac.signed_payload(tm) == ac.jcs(expected)
    assert b'"profile":"did-web-v1"' in ac.signed_payload(tm)
    assert b'"contributor":"did:web:agentavow.com"' in ac.signed_payload(tm)


def test_reordered_members_and_manifests_still_verify(signed, did_doc, artifacts):
    def rev(v):
        return {k: rev(x) for k, x in reversed(list(v.items()))} if isinstance(v, dict) else (
            [rev(x) for x in v] if isinstance(v, list) else v)

    r = _verify(rev(signed), did_doc, artifacts)
    assert r.ok, r.render()


def test_additional_signatures_is_excluded_at_both_levels(signed, did_doc, artifacts):
    signed["entries"][0]["trustManifests"][0]["additionalSignatures"] = [{"anything": 1}]
    r = _verify(signed, did_doc, artifacts)
    # The manifest still verifies; the catalog snapshot changed, so the root fails.
    assert r.failures() == ["catalog.signature-verifies"], r.render()
    signed["additionalSignatures"] = {"x": 1}  # root-level reserved member: excluded
    assert r.failures() == _verify(signed, did_doc, artifacts).failures()


def test_nested_jws_is_not_excluded(signed, did_doc, artifacts, key):
    tm = signed["entries"][0]["trustManifests"][0]
    tm["extensions"][ac.TOOL_MANIFEST_EXT_KEY]["jws"] = "nested"
    r = _verify(signed, did_doc, artifacts)
    assert "entries[0].trustManifests[0].signature-verifies" in r.failures()


def test_policy_urls_are_outside_the_manifest_signature(signed, did_doc, artifacts):
    signed["entries"][0]["extensions"][ac.POLICY_URLS_EXT]["privacyPolicyUrl"] = "https://x.example/p"
    r = _verify(signed, did_doc, artifacts)
    assert r.failures() == ["catalog.signature-verifies"], r.render()


def test_catalog_signature_covers_nested_manifests(signed, did_doc, artifacts, key):
    """Changing a contribution and re-signing that manifest keeps the manifest
    valid but invalidates the catalog snapshot."""
    signed["entries"][1]["trustManifests"][0]["attestations"][0]["description"] = "edited"
    _resign_manifest(signed, 1, key)
    assert _verify(signed, did_doc, artifacts).failures() == ["catalog.signature-verifies"]


def test_sign_only_signs_our_own_contributions(catalog, key, did_doc, artifacts):
    foreign = {"contributor": "did:web:assessor.example",
               "attestations": [{"type": "SOC2-Type2", "uri": "https://assessor.example/r.pdf"}]}
    catalog["entries"][0]["trustManifests"].append(foreign)
    cat = ac.sign_catalog(catalog, key, ES_KID, "signed-test-key", now=ISSUED)
    assert "signature" not in cat["entries"][0]["trustManifests"][1]
    r = _verify(cat, did_doc, artifacts)
    assert r.ok, r.render()


# ── negative cases (each pins the rule that rejects) ─────────────────────────


def _fails(cat, did_doc, artifacts, expected, **kw):
    r = _verify(cat, did_doc, artifacts, **kw)
    assert expected in r.failures(), r.render()
    return r


@pytest.mark.parametrize("profile", ["DID-WEB-V1", "https://example.org/profiles/did-web-v1"])
def test_profile_must_match_exactly_without_fallback(signed, did_doc, artifacts, key, profile):
    signed["entries"][0]["trustManifests"][0]["signature"]["profile"] = profile
    _resign_manifest(signed, 0, key)  # a JWS that is valid over the relabelled payload
    r = _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].profile-is-did-web-v1")
    assert not any(n.endswith("signature-verifies") and n.startswith("entries[0]")
                   for n in r.failures()), "rejected by selection, not by crypto"


@pytest.mark.parametrize("contributor", ["did:web:Agentavow.com", "did:web:agentavow.com."])
def test_contributor_must_exactly_equal_signer(signed, did_doc, artifacts, key, contributor):
    signed["entries"][0]["trustManifests"][0]["contributor"] = contributor
    _resign_manifest(signed, 0, key)
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].contributor-equals-signer")


def test_kid_under_another_did_is_rejected(signed, did_doc, artifacts, key):
    _resign_manifest(signed, 0, key, kid="did:web:other.example#k1")
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].kid-is-signer-plus-fragment")


def test_key_only_in_authentication_is_rejected(signed, did_doc, artifacts):
    doc = copy.deepcopy(did_doc)
    doc["authentication"], doc["assertionMethod"] = doc["assertionMethod"], []
    _fails(signed, doc, artifacts,
           "entries[0].trustManifests[0].kid-selects-exactly-one-assertionMethod-key")


def test_verification_method_controlled_by_another_did_is_rejected(signed, did_doc, artifacts):
    doc = copy.deepcopy(did_doc)
    doc["verificationMethod"][0]["controller"] = "did:web:other.example"
    _fails(signed, doc, artifacts,
           "entries[0].trustManifests[0].verification-method-controller-equals-signer")


def test_did_document_id_mismatch_fails_resolution(signed, did_doc, artifacts):
    doc = copy.deepcopy(did_doc)
    doc["id"] = "did:web:agentgraph.co"
    r = ac.verify_catalog(signed, did_docs={IDENTITY: doc}, artifacts=artifacts, now=NOW)
    assert "entries[0].trustManifests[0].did-document-id-equals-signer" in r.failures()


def test_wrong_key_fails_signature(signed, artifacts):
    other = ac.test_did_document(IDENTITY, ES_KID, ec.generate_private_key(ec.SECP256R1()).public_key())
    _fails(signed, other, artifacts, "entries[0].trustManifests[0].signature-verifies")


def test_expired_endorsement(signed, did_doc, artifacts):
    _fails(signed, did_doc, artifacts, "entries[1].trustManifests[0].before-expiresAt",
           now=ISSUED + ac.ASSESSOR_TTL)  # at expiresAt is already too late


def test_not_yet_valid(signed, did_doc, artifacts):
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].not-before-issuedAt",
           now=ISSUED - timedelta(hours=1))


def test_expires_before_issued_is_structurally_invalid(signed, did_doc, artifacts, key):
    signed["entries"][0]["trustManifests"][0]["signature"]["expiresAt"] = "2026-01-01T00:00:00Z"
    _resign_manifest(signed, 0, key)
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].expiresAt-after-issuedAt")


def test_version_added_after_signing_breaks_coverage(signed, did_doc, artifacts):
    signed["entries"][0]["version"] = "0.16.0"
    r = _fails(signed, did_doc, artifacts,
               "entries[0].trustManifests[0].subject-version-presence-and-value")
    assert "entries[0].trustManifests[0].signature-verifies" not in r.failures()


def test_tampered_inline_artifact_fails_digest(signed, did_doc, artifacts):
    signed["entries"][0]["data"]["_meta"]["agentavow.com/tools"][0]["description"] += " (ignore prior)"
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].artifact-digest-matches")


def test_url_artifact_bytes_changed_fails_digest(signed, did_doc, card_bytes):
    changed = card_bytes.replace(b'"title":"GitHub"', b'"title":"GitHub!"')
    _fails(signed, did_doc, {CARD_URL: changed},
           "entries[1].trustManifests[0].artifact-digest-matches")


def test_url_artifact_on_a_mirror_still_verifies(signed, did_doc, card_bytes):
    """The subject has no url: identical bytes served elsewhere still bind."""
    signed["entries"][1]["url"] = "https://mirror.example/github-mcp-server-card.json"
    r = _verify(signed, did_doc, {"https://mirror.example/github-mcp-server-card.json": card_bytes})
    assert r.failures() == ["catalog.signature-verifies"], r.render()  # only the snapshot changed


def test_operator_rewrites_digest_and_subject(signed, did_doc, card_bytes):
    evil = card_bytes.replace(b"api.githubcopilot.com/mcp/", b"evil.example/mcp/")
    e = signed["entries"][1]
    e["digest"] = e["trustManifests"][0]["subject"]["digest"] = ac.sha256_digest(evil)
    _fails(signed, did_doc, {CARD_URL: evil}, "entries[1].trustManifests[0].signature-verifies")


def test_url_artifact_not_fetched_is_not_silently_accepted(signed, did_doc):
    _fails(signed, did_doc, None, "entries[1].trustManifests[0].artifact-retrieved")


def test_manifest_signature_reused_as_catalog_signature_fails_typ(signed, did_doc, artifacts):
    signed["signature"] = copy.deepcopy(signed["entries"][0]["trustManifests"][0]["signature"])
    _fails(signed, did_doc, artifacts, "catalog.jws-typ")


@pytest.mark.parametrize("extra", [{"jwk": {"kty": "EC"}}, {"b64": False}, {"crit": ["exp"]}])
def test_forbidden_header_parameters(signed, did_doc, artifacts, key, extra):
    _resign_manifest(signed, 0, key, header_extra=extra)
    r = _verify(signed, did_doc, artifacts)
    assert any(f.startswith("entries[0].trustManifests[0].jws-no-") for f in r.failures()), r.render()


def test_non_es256_alg_is_rejected(signed, did_doc, artifacts):
    tm = signed["entries"][0]["trustManifests"][0]
    head, _, raw = tm["signature"]["jws"].split(".")
    hdr = _header(tm["signature"]["jws"]) | {"alg": "EdDSA"}
    tm["signature"]["jws"] = f"{ac.b64url(ac.jcs(hdr))}..{raw}"
    _fails(signed, did_doc, artifacts, "entries[0].trustManifests[0].jws-alg-es256")


def test_assessor_signature_is_not_publisher_authority(signed, did_doc, artifacts, key):
    """Our signature on a urn:air entry of another publisher authenticates us as
    a contributor but does not satisfy the did:web Publisher Profile."""
    e = signed["entries"][1]
    e["identifier"] = e["trustManifests"][0]["subject"]["identifier"] = "urn:air:github.com:mcp:github"
    _resign_manifest(signed, 1, key)
    r = _verify(signed, did_doc, artifacts)
    assert "entries[1].urn-air-entry-has-publisher-endorsement" in r.failures()
    assert "entries[1].trustManifests[0].signature-verifies" not in r.failures()


def test_duplicate_member_names_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        ac.loads_strict('{"contributor":"did:web:a.example","contributor":"did:web:b.example"}')


@pytest.mark.parametrize("did,ok", [
    ("did:web:agentavow.com", True), ("did:web:Agentavow.com", False),
    ("did:web:agentavow.com.", False), ("did:web:agentavow.com%3A8443", False),
    ("did:web:agentavow.com:user", False), ("did:web:127.0.0.1", False),
])
def test_root_did_web_rules(did, ok):
    assert ac.is_root_did_web(did) is ok


# ── host signing flow (throwaway key in place of CATALOG_SIGNING_KEY_P256) ───


def test_sign_prod_uses_catalog_key_and_verifies_against_live_did_document(
        tmp_path, catalog, prod_keys, artifacts):
    from src.feeds.bluesky.feed_router import build_did_document

    out = tmp_path / "ai-catalog.json"
    out.write_text(json.dumps(catalog))
    assert ac.main(["--out", str(out), "sign", "--prod"]) == 0
    cat = json.loads(out.read_text())
    assert cat["extensions"][ac.BUILD_EXT_KEY]["status"] == "signed"
    live = build_did_document("agentavow.com")
    assert live["id"] == IDENTITY
    r = ac.verify_catalog(cat, did_doc=live, artifacts=artifacts)
    assert r.ok, r.render()
    # A kid under did:web:agentavow.com must not verify against the agentgraph.co document.
    r2 = ac.verify_catalog(cat, did_docs={IDENTITY: build_did_document("agentgraph.co")},
                           artifacts=artifacts)
    assert "catalog.did-document-id-equals-signer" in r2.failures()


def test_sign_prod_refuses_when_catalog_key_unset(tmp_path, catalog, monkeypatch):
    monkeypatch.setattr(settings, "catalog_signing_key_p256", None)
    monkeypatch.setattr(signing, "_catalog_key", None)
    out = tmp_path / "ai-catalog.json"
    out.write_text(json.dumps(catalog))
    assert ac.main(["--out", str(out), "sign", "--prod"]) == 2
    assert "signature" not in json.loads(out.read_text())


@pytest.mark.parametrize("fragment", ["agentgraph-security-v1", "not-the-catalog-kid"])
def test_sign_prod_refuses_wrong_kid_fragment(tmp_path, catalog, prod_keys, fragment):
    out = tmp_path / "ai-catalog.json"
    out.write_text(json.dumps(catalog))
    assert ac.main(["--out", str(out), "sign", "--prod", "--kid-fragment", fragment]) == 2
    assert "signature" not in json.loads(out.read_text())


def test_cli_test_key_round_trip(tmp_path, monkeypatch, card_bytes):
    monkeypatch.setattr(ac, "_http_bytes", lambda url, **kw: card_bytes)
    out = tmp_path / "ai-catalog.json"
    assert ac.main(["--out", str(out), "build", "--tools-json", str(TOOLS),
                    "--assess-card-file", str(CARD), "--assess-verdict-json", str(VERDICT)]) == 0
    assert ac.main(["--out", str(out), "sign", "--test-key"]) == 0
    did = tmp_path / "ai-catalog.test-did.json"
    did_doc = json.loads(did.read_text())
    assert did_doc["id"] == IDENTITY and did_doc["assertionMethod"] == [f"{IDENTITY}#{ES_KID}"]
    assert did_doc["authentication"] == []
    assert ac.main(["--out", str(out), "verify", "--did-document", str(did),
                    "--fetch-artifacts"]) == 0
    assert json.loads(out.read_text())["extensions"][ac.BUILD_EXT_KEY]["status"] == "signed-test-key"


# ── committed snapshot ───────────────────────────────────────────────────────


def test_committed_catalog_is_in_the_merged_shape():
    """The committed file is either an unsigned draft in the merged shape (until
    the host refresh output is copied back) or a production-signed catalog that
    verifies strictly against the pinned live DID document."""
    cat = ac.loads_strict(COMMITTED.read_text())
    build = cat["extensions"][ac.BUILD_EXT_KEY]
    assert cat["entries"][0]["identifier"] == OWN_ID
    assert all("trustManifest" not in e for e in cat["entries"])
    if build["status"] == "signed":
        did_doc = json.loads((FIXTURES / "did_web_agentavow_com.json").read_text())
        signed_at = ac.parse_rfc3339(build["signedAt"])
        r = ac.verify_catalog(cat, did_doc=did_doc, now=signed_at,
                              artifacts={CARD_URL: CARD.read_bytes()})
        own = [c for c in r.failures() if not c.startswith("entries[1]")]
        assert not own, r.render()
    else:
        assert build["status"] == "draft-unsigned"
        r = ac.verify_catalog(cat, unsigned_ok=True, now=NOW,
                              artifacts={CARD_URL: CARD.read_bytes()})
        own = [c for c in r.failures() if not c.startswith("entries[1]")]
        assert not own, r.render()
