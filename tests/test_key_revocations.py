"""The signed key revocation list at /.well-known/key-revocations.json.

Pure unit tests: a throwaway FastAPI app with only the JWKS router, no DB.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src import key_revocations as kr
from src import signing
from src.api.jwks_router import router as jwks_router
from src.config import settings

PATH = "/.well-known/key-revocations.json"
ENTRY = {
    "kid": "agentgraph-security-v1",
    "thumbprint": "6U8Zqv4KpmzaI_MMt0-72wwKx7p72zvQdULYhS3uUWQ",
    "effectiveFrom": "2026-11-01T00:00:00Z",
    "reason": "key_compromise",
    "notice": "https://agentavow.com/docs/verify-attestations#key-changes-and-pinning",
}
GONE = {
    "kid": "old-key",
    "thumbprint": "A" * 43,
    "effectiveFrom": "2026-11-01T00:00:00.250Z",
    "reason": "key_compromise",
    "notice": "https://agentavow.com/docs/verify-attestations#key-changes-and-pinning",
}


@pytest.fixture(autouse=True)
def _platform_key(monkeypatch):
    monkeypatch.setattr(signing, "_private_key", Ed25519PrivateKey.generate())
    monkeypatch.setattr(signing, "_catalog_key", None)
    monkeypatch.setattr(signing, "_trust_v2_key", None)
    monkeypatch.setattr(settings, "catalog_signing_key_p256", None)
    monkeypatch.setattr(settings, "trust_v2_signing_key_ed25519", None)
    yield
    monkeypatch.setattr(signing, "_catalog_key", None)
    monkeypatch.setattr(signing, "_trust_v2_key", None)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(jwks_router)
    return TestClient(app)


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _key_for(jwks: dict, kid: str) -> Ed25519PublicKey:
    jwk = next(k for k in jwks["keys"] if k["kid"] == kid)
    return Ed25519PublicKey.from_public_bytes(_b64d(jwk["x"]))


def test_served_list_verifies_against_the_jwks(client):
    resp = client.get(PATH)
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "*"
    body = resp.json()
    assert set(body) == {"payload", "jws"}
    header_b64, payload_b64, sig_b64 = body["jws"].split(".")
    header = json.loads(_b64d(header_b64))
    assert header == {"alg": "EdDSA", "kid": "agentgraph-security-v1"}
    key = _key_for(client.get("/.well-known/jwks.json").json(), header["kid"])
    key.verify(_b64d(sig_b64), f"{header_b64}.{payload_b64}".encode())
    # The signed bytes are the RFC 8785 form of the payload served beside them.
    assert _b64d(payload_b64) == signing.canonicalize_jcs_strict(body["payload"])


def test_empty_list_covers_every_jwks_key(client):
    payload = client.get(PATH).json()["payload"]
    jwks = client.get("/.well-known/jwks.json").json()["keys"]
    assert payload["type"] == "agentavow-key-revocations-v1"
    assert payload["issuer"] == "did:web:agentgraph.co"
    assert payload["revocations"] == []
    covered = {k["thumbprint"] for k in payload["keysCovered"]}
    assert covered == {signing.jwk_thumbprint(k) for k in jwks}
    # The scan key is listed once, under its stable name, though the JWKS lists it twice.
    assert [k["kid"] for k in payload["keysCovered"]] == ["agentgraph-security-v1"]


def test_covers_the_catalog_key_when_configured(client, monkeypatch):
    monkeypatch.setattr(signing, "_catalog_key", ec.generate_private_key(ec.SECP256R1()))
    monkeypatch.setattr(settings, "catalog_signing_key_p256", "set")
    kids = [k["kid"] for k in client.get(PATH).json()["payload"]["keysCovered"]]
    assert kids == ["agentgraph-security-v1", "catalog-es256-v1"]


def test_a_revoked_key_gone_from_the_jwks_stays_covered():
    payload = kr.build_payload([signing.get_jwk()], revocations=(GONE,))
    assert {"kid": "old-key", "thumbprint": "A" * 43} in payload["keysCovered"]
    assert payload["revocations"] == [GONE]


def test_dates_are_utc_and_next_update_is_a_day_later():
    now = datetime(2026, 11, 20, 12, 0, 0, 123456, tzinfo=timezone.utc)
    payload = kr.build_payload([signing.get_jwk()], now=now)
    assert payload["issuedAt"] == "2026-11-20T12:00:00.123Z"
    assert payload["nextUpdate"] == "2026-11-21T12:00:00.123Z"
    assert kr.VALIDITY == timedelta(hours=24)


def test_record_in_the_repo_is_valid():
    kr.validate_record(kr.REVOCATIONS)


def test_an_entry_is_carried_through():
    payload = kr.build_payload([signing.get_jwk()], revocations=(ENTRY,))
    assert payload["revocations"] == [ENTRY]


@pytest.mark.parametrize("bad", [
    {k: v for k, v in ENTRY.items() if k != "effectiveFrom"},
    {**ENTRY, "extra": "x"},
    {**ENTRY, "reason": "oops"},
    {**ENTRY, "notice": "http://example.com"},
    {**ENTRY, "kid": ""},
    {**ENTRY, "thumbprint": "not-a-thumbprint"},
    {**ENTRY, "thumbprint": "6U8Zqv4KpmzaI_MMt0-72wwKx7p72zvQdULYhS3uUWQ="},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00+00:00"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00+02:00"},
    {**ENTRY, "effectiveFrom": "20261101T000000Z"},
    {**ENTRY, "effectiveFrom": "2026-11-01 00:00:00Z"},
    {**ENTRY, "effectiveFrom": "2026-W44-7T00:00:00Z"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00Z"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00.123456789Z"},
    {**ENTRY, "effectiveFrom": "2026-02-30T00:00:00Z"},
])
def test_malformed_entries_are_refused(bad):
    with pytest.raises(ValueError):
        kr.build_payload([signing.get_jwk()], revocations=(bad,))


def test_two_entries_for_one_key_are_refused():
    with pytest.raises(ValueError):
        kr.build_payload([signing.get_jwk()], revocations=(ENTRY, {**ENTRY, "reason": "superseded"}))


# ── The JWKS itself is unchanged ────────────────────────────────────────────
# Golden bytes from origin/main at b3099a90 (before the revocation list), fixed keys.

JWKS_BASE = (
    '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",'
    '"kid":"agentgraph-security-v1","use":"sig","alg":"EdDSA"},{"kty":"OKP","crv":"Ed25519",'
    '"x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","kid":"UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4",'
    '"use":"sig","alg":"EdDSA"}'
)
JWKS_ALL_EXTRA = (
    ',{"kty":"OKP","crv":"Ed25519","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",'
    '"kid":"trust-v2-2026","use":"sig","alg":"EdDSA"},{"kty":"EC","crv":"P-256",'
    '"x":"Xsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_Ww","y":"hzRkDEmY_343SwbOGmSi7NgqsDY4T7g9mnmxJ6J9UDI",'
    '"kid":"catalog-es256-v1","use":"sig","alg":"ES256"}'
)


@pytest.fixture()
def fixed_keys(monkeypatch):
    monkeypatch.setattr(signing, "_private_key", Ed25519PrivateKey.from_private_bytes(bytes([1] * 32)))


def test_jwks_bytes_unchanged_base(client, fixed_keys):
    resp = client.get("/.well-known/jwks.json")
    assert resp.text == JWKS_BASE + "]}"
    assert resp.headers["cache-control"] == "public, max-age=3600"
    assert resp.headers["access-control-allow-origin"] == "*"
    assert resp.headers["content-type"] == "application/json"


def test_jwks_bytes_unchanged_all_keys(client, fixed_keys, monkeypatch):
    monkeypatch.setattr(settings, "trust_v2_signing_key_ed25519", base64.b64encode(bytes([2] * 32)).decode())
    monkeypatch.setattr(settings, "catalog_signing_key_p256", "set")
    monkeypatch.setattr(signing, "_catalog_key", ec.derive_private_key(3, ec.SECP256R1()))
    assert client.get("/.well-known/jwks.json").text == JWKS_BASE + JWKS_ALL_EXTRA + "]}"
