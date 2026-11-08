"""Sign and verify AgentAvow's own A2A Agent Card (``/.well-known/agent-card.json``).

A2A 1.0 §8.4: an ``AgentCardSignature`` is a detached JWS (RFC 7515) over the RFC 8785
JCS form of the card with ``signatures`` removed. We sign with the same P-256 key that
signs ``/.well-known/ai-catalog.json`` (``CATALOG_SIGNING_KEY_P256``, kid
``catalog-es256-v1``), whose public half the live JWKS already publishes at
``https://agentavow.com/.well-known/jwks.json``. The protected header names that JWKS
as ``jku``, so any A2A verifier, including our own check
(``src.scanner.a2a_scan.check_signatures``), can fetch the key.

The committed ``web/public`` copy stays UNSIGNED. Signing needs the production key,
which only the prod host has, so it is a deploy-time step: ``scripts/refresh_agent_card.sh``
runs ``sign --prod`` and ``verify --resolve`` on the host and installs the result into
``web/dist`` (``scripts/deploy-prod.sh`` calls it after every frontend build). The key is
never printed, logged or written anywhere.

Payload: the card exactly as served, minus ``signatures``. Our card has no default-
valued field apart from the REQUIRED ``supportedInterfaces: []``, so that bytes string
is also the §8.4.1 presence form. A verifier that strips every default (§8.4.2 read
literally) drops ``supportedInterfaces`` and will not match; ``check_signatures`` tries
all three forms.

Subcommands
-----------
``sign --prod``      sign with CATALOG_SIGNING_KEY_P256 (host only; refuses without it)
``sign --test-key``  sign with a throwaway P-256 key and write the matching JWKS next to
                     the output as ``<name>.test-jwks.json`` (not publishable)
``verify``           check the signature offline against ``--jwks FILE``, or
                     ``--resolve`` the ``jku`` over HTTPS

Examples
--------
    .venv312/bin/python3 scripts/agent_card_wellknown.py sign --test-key --out /tmp/card.json
    .venv312/bin/python3 scripts/agent_card_wellknown.py verify --out /tmp/card.json \\
        --jwks /tmp/card.test-jwks.json
    python3 scripts/agent_card_wellknown.py sign --prod          # on the host
    python3 scripts/agent_card_wellknown.py verify --resolve
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import rfc8785  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

DEFAULT_OUT = REPO_ROOT / "web" / "public" / ".well-known" / "agent-card.json"
JKU = "https://agentavow.com/.well-known/jwks.json"
KID = "catalog-es256-v1"  # src.signing.CATALOG_ES256_KID


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _load(path: Path) -> dict:
    card = json.loads(path.read_text())
    if not isinstance(card, dict) or not card.get("name"):
        raise SystemExit(f"{path} is not an A2A Agent Card")
    return card


def _dump(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def signing_payload(card: dict) -> bytes:
    """JCS bytes of the card without ``signatures`` (A2A 1.0 §8.4.1 rule 3)."""
    return rfc8785.dumps({k: v for k, v in card.items() if k != "signatures"})


def sign_card(card: dict, key: ec.EllipticCurvePrivateKey, *, kid: str = KID,
              jku: str = JKU) -> dict:
    """Return a copy of ``card`` with one ES256 ``signatures`` entry (replacing any)."""
    header = {"alg": "ES256", "typ": "JOSE", "kid": kid, "jku": jku}
    protected = _b64url(json.dumps(header, separators=(",", ":")).encode())
    signing_input = (protected + "." + _b64url(signing_payload(card))).encode("ascii")
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    signature = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    out = {k: v for k, v in card.items() if k != "signatures"}
    out["signatures"] = [{"protected": protected, "signature": signature}]
    return out


def public_jwks(key: ec.EllipticCurvePrivateKey, kid: str = KID) -> dict:
    from src.signing import p256_jwk_for
    return {"keys": [p256_jwk_for(key.public_key(), kid)]}


def verify_card(card: dict, jwks: dict | None) -> dict:
    """The same check our public A2A grader runs (``check_signatures``)."""
    from src.scanner.a2a_scan import check_signatures
    jku = None
    for sig in card.get("signatures") or []:
        try:
            p = sig["protected"]
            jku = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("jku")
        except Exception:  # noqa: BLE001
            continue
        break
    return check_signatures(card, {jku: jwks} if jku and jwks else {})


def _fetch_jwks(url: str) -> dict:
    if not url.startswith("https://"):
        raise SystemExit(f"refusing to fetch a non-https jku: {url}")
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "agentavow-card-verify"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read(65536).decode("utf-8"))


def cmd_sign(args: argparse.Namespace) -> int:
    out = Path(args.out)
    card = _load(out)
    if args.prod:
        from src.signing import get_catalog_es256_key, has_catalog_es256_key
        if not has_catalog_es256_key():
            print("refusing: CATALOG_SIGNING_KEY_P256 is not set on this host "
                  "(it lives in .env.secrets on prod; see scripts/gen_catalog_key.py)")
            return 2
        key = get_catalog_es256_key()  # raises on a malformed secret; never printed
        signed = sign_card(card, key)
        # Self-check against the public half before writing anything.
        got = verify_card(signed, public_jwks(key))
        if got.get("state") != "verified":
            print(f"refusing: the fresh signature does not verify ({got.get('reason')})")
            return 1
        _dump(out, signed)
        print(f"signed {out} with {KID} (jku {JKU})")
        return 0
    key = ec.generate_private_key(ec.SECP256R1())
    signed = sign_card(card, key, jku=args.test_jku)
    _dump(out, signed)
    jwks_path = out.with_name(out.stem + ".test-jwks.json")
    _dump(jwks_path, public_jwks(key))
    print(f"TEST KEY ONLY, not publishable. Signed {out}; matching JWKS: {jwks_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    card = _load(Path(args.out))
    if args.jwks:
        jwks = json.loads(Path(args.jwks).read_text())
    elif args.resolve:
        jwks = _fetch_jwks(JKU)
    else:
        print("give --jwks FILE or --resolve")
        return 2
    got = verify_card(card, jwks)
    print(json.dumps({k: v for k, v in got.items()
                      if k in ("state", "alg", "kid", "jku", "variant", "reason")}))
    return 0 if got.get("state") == "verified" else 1


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help="card path (default: web/public/.well-known/agent-card.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign", help="sign the card in place")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--prod", action="store_true",
                   help="ES256 with CATALOG_SIGNING_KEY_P256 (src.signing; host only)")
    g.add_argument("--test-key", action="store_true", help="throwaway P-256 key")
    s.add_argument("--test-jku", default="https://agentavow.test/.well-known/jwks.json",
                   help="jku written into a test-key signature")
    v = sub.add_parser("verify", help="verify the card's signature")
    v.add_argument("--jwks", help="JWKS file to verify against (offline)")
    v.add_argument("--resolve", action="store_true", help=f"fetch {JKU}")
    args = ap.parse_args(argv)
    return {"sign": cmd_sign, "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
