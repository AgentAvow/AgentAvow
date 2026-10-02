"""Generate the ES256 (P-256) key that signs ``/.well-known/ai-catalog.json``.

Prints to STDOUT only; nothing is written to disk. Paste the ``CATALOG_SIGNING_
KEY_P256=`` line into ``.env.secrets`` on the prod host (and the Parameter
Store copy ``/agentavow/prod/env.secrets``), recreate the backend, and the
public half appears in both DID documents (``#catalog-es256-v1``, assertion-
only) and in ``/.well-known/jwks.json``.

The Agent-Card/ai-catalog ``did:web`` Publisher Profile is ES256-only, which
is why this is a separate key from the Ed25519 attestation key.

Usage
-----
    .venv/bin/python3 scripts/gen_catalog_key.py            # base64 PKCS8 (one line)
    .venv/bin/python3 scripts/gen_catalog_key.py --pem      # PEM, for reference
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ENV_NAME = "CATALOG_SIGNING_KEY_P256"
KID = "catalog-es256-v1"


def generate() -> tuple[str, dict, str]:
    """Return (base64 PKCS8 DER, public JWK, RFC 7638 thumbprint)."""
    from src.signing import jwk_thumbprint, p256_jwk_for

    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = p256_jwk_for(key.public_key(), KID)
    return base64.b64encode(der).decode("ascii"), jwk, jwk_thumbprint(jwk)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pem", action="store_true",
                    help="also print the private key as PEM (multi-line; the env line stays base64)")
    args = ap.parse_args(argv)

    b64, jwk, thumb = generate()
    print(f"# {ENV_NAME}: OPTIONAL, default unset. Paste into .env.secrets on the host")
    print("# AND the Parameter Store copy /agentavow/prod/env.secrets. Never commit it.")
    print(f"{ENV_NAME}={b64}")
    print()
    print(f"# Public JWK (kid {KID}) — published at /.well-known/did.json and jwks.json")
    print(json.dumps(jwk, indent=2))
    print(f"# RFC 7638 thumbprint: {thumb}")
    if args.pem:
        key = serialization.load_der_private_key(base64.b64decode(b64), password=None)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode("ascii")
        print()
        print("# Same private key as PEM (the loader accepts either form):")
        print(pem, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
