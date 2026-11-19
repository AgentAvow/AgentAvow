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


@pytest.fixture(autouse=True)
def _platform_key(monkeypatch):
    monkeypatch.setattr(signing, "_private_key", Ed25519PrivateKey.generate())
    monkeypatch.setattr(signing, "_catalog_key", None)
    monkeypatch.setattr(settings, "catalog_signing_key_p256", None)
    yield
    monkeypatch.setattr(signing, "_catalog_key", None)


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
    header_b64, payload_b64, sig_b64 = body["jws"].split(".")
    header = json.loads(_b64d(header_b64))
    assert header == {"alg": "EdDSA", "kid": "agentgraph-security-v1"}
    assert body["kid"] == header["kid"]
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


def test_dates_are_utc_and_next_update_is_a_day_later():
    now = datetime(2026, 11, 20, 12, 0, 0, 123456, tzinfo=timezone.utc)
    payload = kr.build_payload([signing.get_jwk()], now=now)
    assert payload["issuedAt"] == "2026-11-20T12:00:00.123Z"
    assert payload["nextUpdate"] == "2026-11-21T12:00:00.123Z"


def test_list_does_not_change_the_jwks(client):
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert [k["kid"] for k in keys] == [
        "agentgraph-security-v1", signing.jwk_thumbprint(signing.get_jwk()),
    ]


def test_record_in_the_repo_is_valid():
    for entry in kr.REVOCATIONS:
        kr.validate_entry(entry)


def test_an_entry_is_carried_through():
    payload = kr.build_payload([signing.get_jwk()], revocations=(ENTRY,))
    assert payload["revocations"] == [ENTRY]


@pytest.mark.parametrize("bad", [
    {k: v for k, v in ENTRY.items() if k != "effectiveFrom"},
    {**ENTRY, "extra": "x"},
    {**ENTRY, "reason": "oops"},
    {**ENTRY, "notice": "http://example.com"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00"},
    {**ENTRY, "effectiveFrom": "2026-11-01T00:00:00+02:00"},
    {**ENTRY, "kid": ""},
])
def test_malformed_entries_are_refused(bad):
    with pytest.raises(ValueError):
        kr.build_payload([signing.get_jwk()], revocations=(bad,))


def test_next_update_window_is_one_day():
    assert kr.VALIDITY == timedelta(hours=24)
