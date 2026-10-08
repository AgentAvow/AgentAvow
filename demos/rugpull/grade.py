#!/usr/bin/env python3
"""Grade the fixture MCP server with AgentAvow's own scanner and sign the result
with a throwaway DEMO key, so the demo runs offline.

What is real here: the handshake, the tool-definition analysis, the trust score,
the per-tool digests, the attestation payload, the JCS canonicalization, the JWS
encoding and the three-phrase decision all come from this repository's production
code (``scan_mcp``, ``_build_scan_payload``, ``canonicalize``, ``create_jws``,
``_package_response``), unmodified.

What is not: the signing key. It is a fresh Ed25519 key generated in memory for
this run and never written to disk. The attestation names issuer
``did:web:demo.invalid`` and kid ``demo-not-agentavow``, so nothing signed here
verifies against AgentAvow's JWKS, and a gate left on its defaults rejects it.

Two other differences from the hosted API, both because the server is on
localhost: the SSRF guard that refuses non-https and private addresses (it
protects the hosted scanner from user-supplied URLs) is bypassed for the fetch,
and the result is written to files instead of a cache.

    python grade.py --endpoint http://127.0.0.1:8787/mcp --out .state
    python grade.py --endpoint http://127.0.0.1:8787/mcp --report-only   # no signing
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
os.environ.setdefault("DEBUG", "true")  # settings refuse the default JWT secret otherwise

DEMO_KID = "demo-not-agentavow"
DEMO_ISSUER = {
    "id": "did:web:demo.invalid",
    "name": "Offline demo grader (NOT AgentAvow)",
    "url": "https://demo.invalid",
}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


async def _fetch_local(url: str) -> dict | None:
    """The same handshake ``fetch_mcp_tools`` runs, over a plain client (localhost)."""
    import httpx

    from src.scanner.mcp_scan import McpSession

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        s = McpSession(client, url)
        if await s.initialize() >= 400 or s.init_status == 0:
            return None
        tools = await s.list("tools/list", "tools")
        resources = await s.list("resources/list", "resources")
        prompts = await s.list("prompts/list", "prompts")
        return {"tools": tools, "resources": resources, "prompts": prompts,
                "server_info": s.server_info}


async def grade(endpoint: str, out: Path | None) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import src.scanner.mcp_scan as mcp_scan
    import src.signing as signing
    from src.api import public_scan_router as api
    from src.scanner.scan import scan_mcp

    served = await _fetch_local(endpoint)
    if not served:
        raise SystemExit(f"could not handshake {endpoint}")

    async def _served(_url: str) -> dict:
        return served

    mcp_scan.fetch_mcp_tools = _served  # scan_mcp imports it at call time
    result = await scan_mcp(endpoint)
    if result.error:
        raise SystemExit(f"scan error: {result.error}")

    full = f"mcp:{endpoint}"
    data = api._scan_result_to_dict(result)
    payload = api._build_scan_payload(full, data)
    payload["issuer"] = DEMO_ISSUER

    jws = None
    jwks = None
    if out is not None:
        key = Ed25519PrivateKey.generate()  # in memory only; gone when this exits
        signing.KID = DEMO_KID
        signing.get_signing_key = lambda: key
        jws = signing.create_jws(signing.canonicalize(payload))
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(pub),
                          "kid": DEMO_KID, "use": "sig", "alg": "EdDSA"}]}

    resp = api._package_response(full, data, jws or "", cached=False).model_dump(mode="json")
    resp["key_id"] = DEMO_KID
    resp["jwks_url"] = "(local demo JWKS; see .state/jwks.json)"
    resp["_demo"] = ("Signed by a throwaway demo key, not by AgentAvow. "
                     "Issuer did:web:demo.invalid, kid demo-not-agentavow.")
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "grade.json").write_text(json.dumps(resp, indent=2) + "\n")
        (out / "jwks.json").write_text(json.dumps(jwks, indent=2) + "\n")
    return {"response": resp, "payload": payload, "served": served}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--out", default=".state")
    ap.add_argument("--report-only", action="store_true",
                    help="analyze and print; sign nothing, write nothing")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    a = ap.parse_args()
    r = asyncio.run(grade(a.endpoint, None if a.report_only else Path(a.out)))
    resp = r["response"]
    findings = [f"{f.get('severity')}: {f.get('name')}"
                for f in (resp.get("findings") or {}).get("items", [])]
    summary = {
        "endpoint": a.endpoint,
        "trust_score": resp["trust_score"],
        "trust_tier": resp["trust_tier"],
        "decision": resp["decision"],
        "decision_reason": resp["decision_reason"],
        "findings": findings,
        "tool_digests": r["payload"]["scan"]["toolDigests"],
        "signed": not a.report_only,
    }
    if a.json:
        print(json.dumps(summary))
        return
    phrase = {"safe": "Safe to connect", "review": "Review before you connect",
              "do_not_connect": "Do not connect"}[summary["decision"]]
    print(f"  trust score {summary['trust_score']}/100 ({summary['trust_tier']}): {phrase}")
    print(f"  reason: {summary['decision_reason'] or '(none)'}")
    for f in findings or ["no findings"]:
        print(f"  finding: {f}")
    for k, v in summary["tool_digests"].items():
        print(f"  {k}  {v}")
    if summary["signed"]:
        print(f"  signed with the throwaway demo key (kid {DEMO_KID}, issuer "
              f"{DEMO_ISSUER['id']}); wrote grade.json and jwks.json")


if __name__ == "__main__":
    main()
