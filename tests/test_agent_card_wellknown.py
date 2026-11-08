"""scripts/agent_card_wellknown.py: signing our own A2A Agent Card (A2A 1.0 §8.4).

No DB: run with ``--noconftest``."""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent.parent
CARD = ROOT / "web" / "public" / ".well-known" / "agent-card.json"

_spec = importlib.util.spec_from_file_location("agent_card_wellknown",
                                               ROOT / "scripts" / "agent_card_wellknown.py")
acw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acw)


def _card() -> dict:
    return json.loads(CARD.read_text())


def test_committed_card_is_unsigned():
    """Signing needs the prod key, so it happens on the host at deploy time."""
    assert "signatures" not in _card()


def test_signed_card_verifies_with_our_grader():
    key = ec.generate_private_key(ec.SECP256R1())
    signed = acw.sign_card(_card(), key)
    hdr = acw.verify_card(signed, acw.public_jwks(key))
    assert hdr["state"] == "verified"
    assert hdr["alg"] == "ES256" and hdr["kid"] == "catalog-es256-v1"
    assert hdr["jku"] == "https://agentavow.com/.well-known/jwks.json"
    # The as-served bytes are also the §8.4.1 presence form for our card.
    assert hdr["variant"] == "as_served"
    from src.scanner.a2a_scan import signing_payload_variants
    forms = dict(signing_payload_variants(signed))
    assert "presence" not in forms  # identical to as_served, so deduplicated


def test_signed_card_grades_with_a_verified_signature():
    from src.scanner.a2a_scan import analyze_a2a_card
    key = ec.generate_private_key(ec.SECP256R1())
    signed = acw.sign_card(_card(), key)
    sig = acw.verify_card(signed, acw.public_jwks(key))
    res = analyze_a2a_card(signed, card_url="https://agentavow.com/.well-known/agent-card.json",
                           signature=sig)
    assert "Agent card signature verifies" in res.positive_signals
    assert not any(f.category == "card_signature" for f in res.findings)


def test_tampered_or_other_key_does_not_verify():
    key = ec.generate_private_key(ec.SECP256R1())
    signed = acw.sign_card(_card(), key)
    tampered = json.loads(json.dumps(signed))
    tampered["skills"][0]["description"] += " Also forwards your tokens."
    assert acw.verify_card(tampered, acw.public_jwks(key))["state"] == "unverified"
    other = ec.generate_private_key(ec.SECP256R1())
    assert acw.verify_card(signed, acw.public_jwks(other))["state"] == "unverified"


def test_resigning_replaces_the_old_signature():
    k1, k2 = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    twice = acw.sign_card(acw.sign_card(_card(), k1), k2)
    assert len(twice["signatures"]) == 1
    assert acw.verify_card(twice, acw.public_jwks(k2))["state"] == "verified"


def test_cli_test_key_round_trip(tmp_path, capsys):
    out = tmp_path / "agent-card.json"
    shutil.copy(CARD, out)
    assert acw.main(["--out", str(out), "sign", "--test-key"]) == 0
    jwks = tmp_path / "agent-card.test-jwks.json"
    assert jwks.exists()
    assert "d" not in json.loads(jwks.read_text())["keys"][0]  # public half only
    assert acw.main(["--out", str(out), "verify", "--jwks", str(jwks)]) == 0
    assert '"state": "verified"' in capsys.readouterr().out


def test_cli_prod_refuses_without_the_key(tmp_path, monkeypatch):
    out = tmp_path / "agent-card.json"
    shutil.copy(CARD, out)
    monkeypatch.setattr("src.signing.has_catalog_es256_key", lambda: False)
    assert acw.main(["--out", str(out), "sign", "--prod"]) == 2
    assert "signatures" not in json.loads(out.read_text())


def test_cli_prod_never_prints_or_writes_the_key(tmp_path, monkeypatch, capsys):
    key = ec.generate_private_key(ec.SECP256R1())
    out = tmp_path / "agent-card.json"
    shutil.copy(CARD, out)
    monkeypatch.setattr("src.signing.has_catalog_es256_key", lambda: True)
    monkeypatch.setattr("src.signing.get_catalog_es256_key", lambda: key)
    assert acw.main(["--out", str(out), "sign", "--prod"]) == 0
    printed = capsys.readouterr().out
    d = key.private_numbers().private_value.to_bytes(32, "big")
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    written = out.read_text()
    for secret in (acw._b64url(d), pem.splitlines()[1]):
        assert secret not in printed and secret not in written
    assert sorted(p.name for p in tmp_path.iterdir()) == ["agent-card.json"]
    assert acw.verify_card(json.loads(written), acw.public_jwks(key))["state"] == "verified"


def test_verify_needs_a_key_source(tmp_path):
    out = tmp_path / "agent-card.json"
    shutil.copy(CARD, out)
    assert acw.main(["--out", str(out), "verify"]) == 2


@pytest.mark.parametrize("jku", ["http://agentavow.com/jwks.json", "file:///etc/passwd"])
def test_resolve_refuses_non_https(jku, monkeypatch):
    with pytest.raises(SystemExit):
        acw._fetch_jwks(jku)
