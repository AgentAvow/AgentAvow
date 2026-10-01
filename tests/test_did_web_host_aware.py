"""Host-aware ``/.well-known/did.json`` and the optional ES256 catalog key.

``agentavow.com`` and ``agentgraph.co`` are one deployment behind one nginx.
The DID document must answer with the DID that matches the host the client
asked for, publish the SAME Ed25519 key under both, and cross-reference the
two through ``alsoKnownAs``. When ``CATALOG_SIGNING_KEY_P256`` is configured
both documents and the JWKS additionally publish ``#catalog-es256-v1`` (P-256,
``assertionMethod`` only); when it is unset nothing about them changes.

Pure unit tests: a throwaway FastAPI app with only the two routers, no DB.
Runs with or without ``conftest.py`` (``pytest --noconftest`` works).
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src import signing
from src.api.jwks_router import router as jwks_router
from src.config import settings
from src.feeds.bluesky import feed_router
from src.feeds.bluesky.feed_router import build_did_document, request_host

ED_KID = "agentgraph-security-v1"
ES_KID = "catalog-es256-v1"
AGENTGRAPH_DID = f"did:web:{settings.domain}"
AGENTAVOW_DID = "did:web:agentavow.com"


def _p256_env_value(fmt: str = "b64") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    if fmt == "pem":
        return key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    der = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(der).decode()


@pytest.fixture(autouse=True)
def _platform_key(monkeypatch):
    """A transient Ed25519 platform key so the tests don't depend on .env/DEBUG."""
    monkeypatch.setattr(signing, "_private_key", Ed25519PrivateKey.generate())
    monkeypatch.setattr(signing, "_catalog_key", None)
    monkeypatch.setattr(settings, "catalog_signing_key_p256", None)
    yield
    monkeypatch.setattr(signing, "_catalog_key", None)


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(feed_router.router)
    app.include_router(jwks_router)
    return TestClient(app)


def _did(client: TestClient, **headers: str) -> dict:
    resp = client.get("/.well-known/did.json", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "public, max-age=3600"
    return resp.json()


def _vm_ids(doc: dict) -> list[str]:
    return [vm["id"] for vm in doc["verificationMethod"]]


# ── host routing ─────────────────────────────────────────────────────────────


def test_request_host_normalizes_forwarded_host_and_ports():
    from starlette.requests import Request

    def req(headers: dict[str, str]) -> Request:
        raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
        return Request({"type": "http", "headers": raw, "method": "GET", "path": "/"})

    assert request_host(req({"Host": "AgentAvow.com"})) == "agentavow.com"
    assert request_host(req({"Host": "agentavow.com:443"})) == "agentavow.com"
    assert request_host(req({"X-Forwarded-Host": "agentavow.com, backend:8000",
                             "Host": "backend:8000"})) == "agentavow.com"
    assert request_host(req({"Host": "[::1]:8000"})) == "[::1]"
    assert request_host(req({})) == ""


@pytest.mark.parametrize("host", ["agentavow.com", "www.agentavow.com", "AGENTAVOW.COM:443"])
def test_agentavow_host_serves_agentavow_did(client, host):
    doc = _did(client, Host=host)
    assert doc["id"] == AGENTAVOW_DID
    assert doc["alsoKnownAs"] == [AGENTGRAPH_DID]
    assert doc["@context"] == [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
    ]
    assert _vm_ids(doc) == [f"{AGENTAVOW_DID}#{ED_KID}"]
    vm = doc["verificationMethod"][0]
    assert vm["type"] == "JsonWebKey2020"
    assert vm["controller"] == AGENTAVOW_DID
    assert vm["publicKeyJwk"] == signing.get_jwk()
    assert doc["assertionMethod"] == [vm["id"]]
    assert doc["authentication"] == [vm["id"]]
    services = {s["id"]: s for s in doc["service"]}
    assert services[f"{AGENTAVOW_DID}#jwks"] == {
        "id": f"{AGENTAVOW_DID}#jwks", "type": "JsonWebKeySet",
        "serviceEndpoint": f"https://{settings.domain}/.well-known/jwks.json",
    }
    assert services[f"{AGENTAVOW_DID}#mcp"]["serviceEndpoint"] == "https://agentavow.com/mcp"
    assert services[f"{AGENTAVOW_DID}#site"]["serviceEndpoint"] == "https://agentavow.com"
    assert services[f"{AGENTAVOW_DID}#site"]["type"] == "LinkedDomains"
    # No Bluesky feed-generator or gateway entries leak onto the rebrand DID.
    assert not any(k.endswith("#bsky_fg") or k.endswith("#gateway-reverify") for k in services)


def test_x_forwarded_host_wins_over_host(client):
    doc = _did(client, **{"Host": "backend:8000", "X-Forwarded-Host": "agentavow.com"})
    assert doc["id"] == AGENTAVOW_DID


@pytest.mark.parametrize("host", ["agentgraph.co", "www.agentgraph.co", "localhost:8000",
                                  "evil.example", "agentavow.com.evil.example"])
def test_other_hosts_serve_agentgraph_did_unchanged(client, host):
    doc = _did(client, Host=host)
    assert doc["id"] == AGENTGRAPH_DID
    assert doc["alsoKnownAs"] == [AGENTAVOW_DID]
    assert _vm_ids(doc) == [f"{AGENTGRAPH_DID}#{ED_KID}"]
    vm = doc["verificationMethod"][0]
    assert vm["controller"] == AGENTGRAPH_DID
    assert vm["publicKeyJwk"] == signing.get_jwk()
    assert doc["assertionMethod"] == [vm["id"]]
    assert doc["authentication"] == [vm["id"]]
    services = {s["id"]: s for s in doc["service"]}
    # The Bluesky feed generator + CTEF gateway + JWKS entries are preserved verbatim.
    assert services[f"{AGENTGRAPH_DID}#bsky_fg"]["type"] == "BskyFeedGenerator"
    assert services[f"{AGENTGRAPH_DID}#bsky_fg"]["serviceEndpoint"] == f"https://{settings.domain}"
    assert services[f"{AGENTGRAPH_DID}#gateway-reverify"]["serviceEndpoint"].endswith(
        "/api/v1/gateway/re-verify")
    assert services[f"{AGENTGRAPH_DID}#jwks"]["serviceEndpoint"] == (
        f"https://{settings.domain}/.well-known/jwks.json")


def test_no_host_header_falls_back_to_agentgraph():
    assert build_did_document(None)["id"] == AGENTGRAPH_DID
    assert build_did_document("")["id"] == AGENTGRAPH_DID


def test_both_documents_publish_the_same_ed25519_key(client):
    a = _did(client, Host="agentavow.com")
    g = _did(client, Host="agentgraph.co")
    assert a["verificationMethod"][0]["publicKeyJwk"] == g["verificationMethod"][0]["publicKeyJwk"]
    jwks = client.get("/.well-known/jwks.json").json()
    assert jwks["keys"][0] == a["verificationMethod"][0]["publicKeyJwk"]


# ── ES256 catalog key ────────────────────────────────────────────────────────


def test_catalog_key_absent_means_no_es256_anywhere(client):
    assert signing.get_catalog_es256_jwk() is None
    for host in ("agentavow.com", "agentgraph.co"):
        doc = _did(client, Host=host)
        assert not any(vm["id"].endswith(f"#{ES_KID}") for vm in doc["verificationMethod"])
        assert not any(m.endswith(f"#{ES_KID}") for m in doc["assertionMethod"])
    jwks = client.get("/.well-known/jwks.json").json()
    assert [k["kid"] for k in jwks["keys"]] == [ED_KID] or ES_KID not in [k["kid"] for k in jwks["keys"]]
    with pytest.raises(RuntimeError, match="CATALOG_SIGNING_KEY_P256 is not set"):
        signing.get_catalog_es256_key()


@pytest.mark.parametrize("fmt", ["b64", "pem"])
def test_catalog_key_configured_publishes_es256_in_did_and_jwks(client, monkeypatch, fmt):
    monkeypatch.setattr(settings, "catalog_signing_key_p256", _p256_env_value(fmt))
    monkeypatch.setattr(signing, "_catalog_key", None)

    es_jwk = signing.get_catalog_es256_jwk()
    assert es_jwk is not None
    assert {k: es_jwk[k] for k in ("kty", "crv", "kid", "use", "alg")} == {
        "kty": "EC", "crv": "P-256", "kid": ES_KID, "use": "sig", "alg": "ES256",
    }
    assert "d" not in es_jwk
    assert len(base64.urlsafe_b64decode(es_jwk["x"] + "==")) == 32
    assert len(base64.urlsafe_b64decode(es_jwk["y"] + "==")) == 32

    for did, host in ((AGENTAVOW_DID, "agentavow.com"), (AGENTGRAPH_DID, "agentgraph.co")):
        doc = _did(client, Host=host)
        es_id = f"{did}#{ES_KID}"
        ed_id = f"{did}#{ED_KID}"
        assert _vm_ids(doc) == [ed_id, es_id]
        es_vm = doc["verificationMethod"][1]
        assert es_vm == {"id": es_id, "type": "JsonWebKey2020", "controller": did,
                         "publicKeyJwk": es_jwk}
        assert doc["assertionMethod"] == [ed_id, es_id]
        assert doc["authentication"] == [ed_id], "catalog key is assertion-only"

    jwks = client.get("/.well-known/jwks.json").json()
    by_kid = {k["kid"]: k for k in jwks["keys"]}
    assert by_kid[ED_KID] == signing.get_jwk()
    assert by_kid[ES_KID] == es_jwk
    assert jwks["keys"][0]["kid"] == ED_KID, "platform key stays first"


def test_malformed_catalog_key_does_not_break_did_or_jwks(client, monkeypatch, caplog):
    monkeypatch.setattr(settings, "catalog_signing_key_p256", "bm90LWEta2V5")  # base64 'not-a-key'
    monkeypatch.setattr(signing, "_catalog_key", None)
    with pytest.raises(RuntimeError, match="not a PEM or base64 PKCS8"):
        signing.get_catalog_es256_key()
    assert signing.get_catalog_es256_jwk() is None
    doc = _did(client, Host="agentavow.com")
    assert _vm_ids(doc) == [f"{AGENTAVOW_DID}#{ED_KID}"]
    assert client.get("/.well-known/jwks.json").status_code == 200


def test_wrong_curve_is_rejected(monkeypatch):
    key = ec.generate_private_key(ec.SECP384R1())
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    monkeypatch.setattr(settings, "catalog_signing_key_p256", base64.b64encode(der).decode())
    monkeypatch.setattr(signing, "_catalog_key", None)
    with pytest.raises(RuntimeError, match="P-256"):
        signing.get_catalog_es256_key()
    with pytest.raises(RuntimeError, match="P-256"):
        signing.load_p256_private_key(base64.b64encode(der).decode())


def test_es256_sign_verify_round_trip_and_jwk_rebuild(monkeypatch):
    monkeypatch.setattr(settings, "catalog_signing_key_p256", _p256_env_value())
    monkeypatch.setattr(signing, "_catalog_key", None)
    key = signing.get_catalog_es256_key()
    msg = b"eyJhbGciOiJFUzI1NiJ9.eyJ4IjoxfQ"
    sig = signing.sign_es256(msg, key)
    assert len(sig) == 64, "JWS wants raw r || s, not DER"
    pub = signing.p256_public_key_from_jwk(signing.get_catalog_es256_jwk())
    signing.verify_es256(msg, sig, pub)
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        signing.verify_es256(msg + b"x", sig, pub)
    with pytest.raises(InvalidSignature):
        signing.verify_es256(msg, sig[:-1], pub)


def test_jwk_thumbprint_is_rfc7638():
    # RFC 7638 §3.1 example (RSA is not supported here) — use the EC vector shape:
    # thumbprint input is JCS of {crv, kty, x, y} only, in that order.
    jwk = {"kty": "EC", "crv": "P-256", "kid": "ignored", "use": "sig", "alg": "ES256",
           "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
           "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
    import hashlib
    expected = base64.urlsafe_b64encode(hashlib.sha256(
        b'{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",'
        b'"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}'
    ).digest()).rstrip(b"=").decode()
    assert signing.jwk_thumbprint(jwk) == expected
    assert signing.jwk_thumbprint(signing.get_jwk())  # OKP path works too


def test_gen_catalog_key_output_loads(capsys):
    from scripts import gen_catalog_key

    assert gen_catalog_key.main([]) == 0
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if ln.startswith("CATALOG_SIGNING_KEY_P256="))
    value = line.split("=", 1)[1]
    key = signing.load_p256_private_key(value)
    jwk_text = out[out.index("{"): out.index("}") + 1]
    jwk = json.loads(jwk_text)
    assert jwk == signing.p256_jwk_for(key.public_key(), ES_KID)
    assert f"# RFC 7638 thumbprint: {signing.jwk_thumbprint(jwk)}" in out
    assert "PRIVATE KEY" not in out  # no PEM unless --pem
