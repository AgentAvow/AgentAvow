"""The signed observation of a live tools/list read (TRACE #443, first slice).

Pagination is followed and every page is bound to one observation; each page carries
the TLS facts of the connection that returned it; the block rides the signed scan."""
from __future__ import annotations

import datetime as dt
import hashlib
import json

import httpx
import pytest

from src.scanner import mcp_scan as ms
from src.scanner.mcp_observation import (
    PROFILE,
    build_observation,
    sha256_hex,
    spki_sha256,
    tls_facts,
)

URL = "https://mcp.example.com:8443/v1/mcp?x=1"


def _client(pages: dict[str | None, dict], *, fail_cursor: str | None = None):
    """tools/list pages keyed by the cursor that asks for them."""
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        method = body.get("method")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "x", "version": "1"}}})
        if method == "tools/list":
            cur = (body.get("params") or {}).get("cursor")
            seen.append(cur)
            if cur is not None and cur == fail_cursor:
                return httpx.Response(500)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                             "result": pages[cur]})
        return httpx.Response(202)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


def _page(names, nxt=None):
    out = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in names]}
    if nxt:
        out["nextCursor"] = nxt
    return out


@pytest.mark.asyncio
async def test_all_pages_are_read_in_order():
    c, seen = _client({None: _page(["a", "b"], "c2"), "c2": _page(["c"], "c3"),
                       "c3": _page(["d"])})
    async with c:
        s = ms.McpSession(c, URL)
        await s.initialize()
        tools = await s.list("tools/list", "tools")
    assert [t["name"] for t in tools] == ["a", "b", "c", "d"]
    assert seen == [None, "c2", "c3"]
    assert "tools/list" not in s.list_more_pages and "tools/list" not in s.list_failed
    pages = s.pages["tools/list"]
    assert [p["itemCount"] for p in pages] == [2, 1, 1]
    assert pages[0]["cursorSha256"] is None
    assert pages[1]["cursorSha256"] == sha256_hex("c2") == pages[0]["nextCursorSha256"]
    assert pages[2]["nextCursorSha256"] is None
    assert len({p["requestId"] for p in pages}) == 3


@pytest.mark.asyncio
async def test_later_page_failure_keeps_earlier_pages_and_is_partial():
    c, _ = _client({None: _page(["a"], "c2")}, fail_cursor="c2")
    async with c:
        s = ms.McpSession(c, URL)
        await s.initialize()
        tools = await s.list("tools/list", "tools")
    assert [t["name"] for t in tools] == ["a"]
    assert "tools/list" in s.list_more_pages and "tools/list" not in s.list_failed


@pytest.mark.asyncio
async def test_page_cap_is_partial(monkeypatch):
    monkeypatch.setattr(ms, "_MCP_MAX_PAGES", 3)
    pages = {None: _page(["t0"], "c1")}
    pages.update({f"c{i}": _page([f"t{i}"], f"c{i + 1}") for i in range(1, 10)})
    c, seen = _client(pages)
    async with c:
        s = ms.McpSession(c, URL)
        await s.initialize()
        tools = await s.list("tools/list", "tools")
    assert len(tools) == 3 and len(seen) == 3
    assert "tools/list" in s.list_more_pages


def test_response_hash_is_over_the_raw_body():
    body = b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
    assert sha256_hex(body) == hashlib.sha256(body).hexdigest()


def _self_signed():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_bytes(serialization.Encoding.DER), hashlib.sha256(spki).hexdigest()


def test_spki_hash_is_over_the_subject_public_key_info():
    der, want = _self_signed()
    assert spki_sha256(der) == want
    assert spki_sha256(b"not a cert") is None


class _Ctx:
    def __init__(self, required=True, check=True):
        import ssl
        self.verify_mode = ssl.CERT_REQUIRED if required else ssl.CERT_NONE
        self.check_hostname = check


class _SslObj:
    def __init__(self, der, ctx):
        self._der, self.context, self.server_hostname = der, ctx, "mcp.example.com"

    def getpeercert(self, binary_form=False):
        return self._der

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)


class _Stream:
    def __init__(self, ssl_obj):
        self._s = ssl_obj

    def get_extra_info(self, name):
        return self._s if name == "ssl_object" else None


def test_tls_facts_read_the_live_connection():
    der, spki = _self_signed()
    t = tls_facts(_Stream(_SslObj(der, _Ctx())))
    assert t == {"tlsVersion": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
                 "referenceIdentity": "mcp.example.com", "certificatePathValidated": True,
                 "identityMatched": True, "leafCertificateSha256": sha256_hex(der),
                 "spkiSha256": spki}
    # Verification off: the facts are still recorded, but nothing reads as validated.
    off = tls_facts(_Stream(_SslObj(der, _Ctx(required=False, check=False))))
    assert off["certificatePathValidated"] is False and off["identityMatched"] is False
    assert tls_facts(None) is None and tls_facts(_Stream(None)) is None


def _pg(rid, tls, nxt=None, cur=None):
    return {"requestId": rid, "cursorSha256": cur, "nextCursorSha256": nxt, "itemCount": 1,
            "responseSha256": "ab" * 32, "tls": tls}


def test_observation_block_shape_and_connection_agreement():
    der, spki = _self_signed()
    t = tls_facts(_Stream(_SslObj(der, _Ctx())))
    obs = build_observation(URL, [_pg(2, t, nxt="n"), _pg(3, t, cur="n")],
                            started="2026-10-20T00:00:00.000Z",
                            finished="2026-10-20T00:00:01.000Z", complete=True)
    assert obs["profile"] == PROFILE and len(obs["observationId"]) == 32
    assert obs["request"] == {"scheme": "https", "host": "mcp.example.com", "port": 8443,
                              "path": "/v1/mcp"}  # no query: it can carry a credential
    assert obs["redirectsFollowed"] is False and obs["sameConnectionFacts"] is True
    assert obs["transport"]["spkiSha256"] == spki
    assert [p["spkiSha256"] for p in obs["toolsList"]["pages"]] == [spki, spki]
    assert "tls" not in obs["toolsList"]["pages"][0]
    assert "not a server signature" in obs["limits"]
    # A page with other TLS facts (or none) leaves transport unset and says so.
    other = {**t, "spkiSha256": "cd" * 32}
    mixed = build_observation(URL, [_pg(2, t), _pg(3, other)], started="a", finished="b",
                              complete=True)
    assert mixed["sameConnectionFacts"] is False and mixed["transport"] is None
    none = build_observation(URL, [_pg(2, None)], started="a", finished="b", complete=False)
    assert none["transport"] is None and none["toolsList"]["complete"] is False


@pytest.mark.asyncio
async def test_scan_mcp_signs_the_observation(monkeypatch):
    from src.api.public_scan_router import _build_scan_payload
    from src.scanner import scan

    obs = build_observation("https://x.example/mcp", [_pg(2, None)], started="a",
                            finished="b", complete=True)

    async def fake_fetch(_url):
        return {"tools": [{"name": "t", "inputSchema": {"type": "object"}}],
                "resources": [], "prompts": [], "server_info": {"name": "x"},
                "client_view": None, "observation": obs}

    monkeypatch.setattr(ms, "fetch_mcp_tools", fake_fetch)
    result = await scan.scan_mcp("https://x.example/mcp")
    assert result.mcp_observation["toolManifestDigest"] == result.tool_manifest_digest
    data = {"trust_score": 80, "trust_tier": "trusted", "scan_result": "clean",
            "findings": {}, "positive_signals": [],
            "metadata": {"files_scanned": 1, "primary_language": "MCP"},
            "tool_digests": result.tool_digests,
            "tool_manifest_digest": result.tool_manifest_digest,
            "mcp_observation": result.mcp_observation, "recommended_limits": {}}
    payload = _build_scan_payload("mcp:https://x.example/mcp", data)
    assert payload["scan"]["observation"]["observationId"] == obs["observationId"]
    assert payload["scan"]["observation"]["toolManifestDigest"] == \
        payload["scan"]["toolManifestDigest"]


def test_example_packet_verifies():
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    here = Path(__file__).resolve().parents[1] / "docs/standards/mcp-catalog-observation-v0"
    out = subprocess.run([node, "verify.mjs"], cwd=here, capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0, out.stdout[-2000:]
    assert "all checks passed" in out.stdout


def test_example_packet_signs_rfc8785_bytes_like_production():
    import base64
    from pathlib import Path

    import rfc8785

    pkt = json.loads((Path(__file__).resolve().parents[1] /
                      "docs/standards/mcp-catalog-observation-v0/"
                      "mcp-catalog-observation-v0-packet.json").read_text())
    payload_b64 = pkt["reference"]["jws"].split(".")[1]
    raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    assert rfc8785.dumps(json.loads(raw)) == raw
