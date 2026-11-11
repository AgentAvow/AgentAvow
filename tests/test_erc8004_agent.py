"""ERC-8004 agent lookups (src/scanner/erc8004_agent.py, src/api/erc8004_router.py).
Design: docs/internal/erc8004-step2-design-2026-11-11.md, reviewed by agentgraph-83.

Shapes follow live Ethereum registry reads (2026-11-11): agent #53824 lists an MCP
endpoint and an OASF schema link, #33256 a web page and an A2A card, #1 has no file."""
from __future__ import annotations

import base64
import json

import pytest

from src.scanner import erc8004_agent as ea


def _abi_string(s: str) -> str:
    b = s.encode()
    pad = (32 - len(b) % 32) % 32
    return "0x" + (32).to_bytes(32, "big").hex() + len(b).to_bytes(32, "big").hex() + \
        (b + b"\0" * pad).hex()


def _abi_addr(a: str) -> str:
    return "0x" + "00" * 12 + a[2:].lower()


# ── ABI decoding ──────────────────────────────────────────────────────────────

def test_decode_string_and_address():
    assert ea.decode_string(_abi_string("https://x.example/a.json")) == "https://x.example/a.json"
    assert ea.decode_string("0x") == ""
    assert ea.decode_address(_abi_addr("0x" + "ab" * 20)) == "0x" + "ab" * 20
    assert ea.decode_address("0x" + "00" * 32) is None


# ── read_agent over a mocked RPC ──────────────────────────────────────────────

class _FakeResp:
    def __init__(self, body):
        self._b = body
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._b


class _FakeRpc:
    def __init__(self, minted=True, uri="https://agent.example/reg.json"):
        self.minted, self.uri, self.calls = minted, uri, []

    async def post(self, url, json=None):
        self.calls.append(json)
        m = json["method"]
        if m == "eth_blockNumber":
            return _FakeResp({"result": "0x100"})
        sel = json["params"][0]["data"][:10]
        assert json["params"][1] == "0x100", "every call reads the same block"
        if sel == "0x6352211e":
            return _FakeResp({"result": _abi_addr("0x" + "11" * 20)} if self.minted
                             else {"error": {"code": 3, "message": "execution reverted"}})
        if sel == "0xc87b56dd":
            return _FakeResp({"result": _abi_string(self.uri)})
        if sel == "0x00339509":
            return _FakeResp({"result": "0x" + "00" * 32})
        raise AssertionError(sel)


async def test_read_agent_pins_one_block():
    rpc = _FakeRpc()
    a = await ea.read_agent("ethereum", 33256, "https://rpc.example", client=rpc)
    assert a.block == 256 and a.owner == "0x" + "11" * 20
    assert a.registration_uri == "https://agent.example/reg.json" and a.agent_wallet is None
    assert a.chain_id == 1


async def test_unminted_agent_is_not_found():
    with pytest.raises(ea.AgentNotFoundError):
        await ea.read_agent("ethereum", 5, "https://rpc.example", client=_FakeRpc(minted=False))


def test_rpc_url_per_chain():
    key = "https://eth-mainnet.g.alchemy.com/v2/abcDEF_123-x"
    env = {"ETH_RPC_URL": key}
    assert ea.rpc_url_for("ethereum", env) == key
    assert ea.rpc_url_for("base", env) == "https://base-mainnet.g.alchemy.com/v2/abcDEF_123-x"
    assert ea.rpc_url_for("bnb", env) == "https://bnb-mainnet.g.alchemy.com/v2/abcDEF_123-x"
    assert ea.rpc_url_for("base", {**env, "BASE_RPC_URL": "https://b.example"}) == \
        "https://b.example"
    # a non-Alchemy Ethereum RPC is not reused for other chains
    assert ea.rpc_url_for("base", {"ETH_RPC_URL": "https://rpc.example/eth"}) is None
    assert ea.rpc_url_for("solana", env) is None


async def test_base_and_bnb_read_with_their_chain_ids():
    for chain, cid in (("base", 8453), ("bnb", 56)):
        a = await ea.read_agent(chain, 7, "https://rpc.example", client=_FakeRpc())
        assert a.chain == chain and a.chain_id == cid


async def test_unknown_chain_or_no_rpc_is_unavailable():
    with pytest.raises(ea.ChainUnavailableError):
        await ea.read_agent("solana", 1, "https://rpc.example", client=_FakeRpc())
    with pytest.raises(ea.ChainUnavailableError):
        await ea.read_agent("ethereum", 1, None, client=_FakeRpc())


# ── registration file ─────────────────────────────────────────────────────────

REG_53824 = {"type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
             "name": "PCGx", "description": "Agent", "active": True, "x402Support": True,
             "services": [{"name": "MCP", "endpoint":
                           "https://api.alpharc.app/v1/agents/1/0xf2b72c4b56ddad85216eb881"},
                          {"name": "OASF", "endpoint": "https://github.com/agntcy/oasf/"}]}
REG_33256 = {"name": "Normie #6574", "services": [
    {"name": "web", "endpoint": "https://api.normies.art/agents/info/6574"},
    {"name": "A2A", "endpoint": "https://api.normies.art/agents/agent-card/6574"}]}


def test_parse_classifies_tools_and_not_tools():
    reg = ea.parse_registration(json.dumps(REG_53824).encode())
    kinds = [(s.name, s.kind) for s in reg.services]
    # an OASF schema link on GitHub is not the agent's repository
    assert kinds == [("MCP", "mcp"), ("OASF", None)]
    assert reg.x402_support is True and reg.sha256
    reg2 = ea.parse_registration(json.dumps(REG_33256).encode())
    assert [(s.name, s.kind) for s in reg2.services] == [("web", None), ("A2A", "a2a")]


def test_repository_named_github_service_is_a_tool():
    reg = ea.parse_registration(json.dumps({"services": [
        {"name": "source code", "endpoint": "https://github.com/acme/agent"}]}).encode())
    assert reg.services[0].kind == "github"


def test_text_is_plain_and_clipped():
    reg = ea.parse_registration(json.dumps({
        "name": "<script>x</script>\x07" + "a" * 1000, "services": []}).encode())
    assert "\x07" not in reg.name and len(reg.name) <= 300
    assert reg.name.startswith("<script>")  # kept as text; the client escapes it


@pytest.mark.parametrize("raw", [b"not json", b"[1,2]", b"\xff\xfe"])
def test_bad_files_are_unreadable_not_fatal(raw):
    reg = ea.parse_registration(raw)
    assert reg.ok is False and reg.error


async def test_data_uri_and_inline_json():
    b64 = "data:application/json;base64," + base64.b64encode(
        json.dumps(REG_33256).encode()).decode()
    reg = await ea.resolve_registration(b64, ipfs_gateway="https://ipfs.example/ipfs/")
    assert reg.ok and reg.name == "Normie #6574"
    reg2 = await ea.resolve_registration(json.dumps(REG_53824),
                                         ipfs_gateway="https://ipfs.example/ipfs/")
    assert reg2.ok and reg2.name == "PCGx"


@pytest.mark.parametrize("uri,err", [
    ("", "no registration file"),
    ("http://agent.example/reg.json", "unsupported URI scheme"),
    ("ftp://agent.example/reg.json", "unsupported URI scheme"),
])
async def test_unsupported_uris(uri, err):
    reg = await ea.resolve_registration(uri, ipfs_gateway="https://ipfs.example/ipfs/")
    assert reg.ok is False and reg.error == err


async def test_private_host_is_refused_by_the_ssrf_guard():
    # Attack twin: a registration URI pointing into our own network.
    for uri in ("https://127.0.0.1/reg.json", "https://169.254.169.254/latest/meta-data",
                "https://10.0.0.4/reg.json"):
        reg = await ea.resolve_registration(uri, ipfs_gateway="https://ipfs.example/ipfs/")
        assert reg.ok is False and "unreadable" in (reg.error or ""), uri


async def test_oversized_file_is_refused(monkeypatch):
    async def big(url):
        return b"{" + b" " * (ea.REG_FILE_MAX_BYTES + 10) + b"}"
    monkeypatch.setattr(ea, "_fetch_capped", big)
    reg = await ea.resolve_registration("https://agent.example/reg.json",
                                        ipfs_gateway="https://ipfs.example/ipfs/")
    assert reg.ok is False and reg.error == "larger than 256 KB"


async def test_ipfs_goes_through_the_gateway(monkeypatch):
    seen = []

    async def fetch(url):
        seen.append(url)
        return json.dumps(REG_33256).encode()
    monkeypatch.setattr(ea, "_fetch_capped", fetch)
    reg = await ea.resolve_registration("ipfs://bafyabc/reg.json",
                                        ipfs_gateway="https://ipfs.example/ipfs/")
    assert reg.ok and seen == ["https://ipfs.example/ipfs/bafyabc/reg.json"]


# ── registration-file findings ────────────────────────────────────────────────

def _reg(services, active=True):
    return ea.parse_registration(json.dumps({"active": active, "services": services}).encode())


def test_plain_http_tool_endpoint_is_high():
    f = ea.file_findings(_reg([{"name": "MCP", "endpoint": "http://mcp.example/mcp"}]))
    assert any(x["severity"] == "high" for x in f)


def test_private_tool_endpoint_is_high():
    f = ea.file_findings(_reg([{"name": "A2A", "endpoint": "https://10.0.0.5/card"}]))
    assert any(x["severity"] == "high" for x in f)


def test_raw_public_ip_is_low():
    # agent #54189 shape
    f = ea.file_findings(_reg([{"name": "A2A", "endpoint": "https://2.29.107.238/zelda/a2a"}]))
    assert [x["severity"] for x in f] == ["low"]


def test_inactive_is_info_and_web_links_are_not_checked():
    f = ea.file_findings(_reg([{"name": "web", "endpoint": "http://site.example"}],
                              active=False))
    assert [x["severity"] for x in f] == ["info"]   # a plain-http website is not a tool


# ── headline (design review rules) ────────────────────────────────────────────

def _t(decision=None, state="done"):
    return {"decision": decision, "state": state}


def test_safe_only_when_every_tool_checked_and_safe():
    h = ea.headline([_t("safe"), _t("safe")], [])
    assert h["decision"] == "safe" and h["coverage_note"] == "2 of 2 listed tools checked"
    assert h["certified"] is False


def test_one_unchecked_tool_caps_at_review():
    h = ea.headline([_t("safe"), _t(None, "not_checked")], [])
    assert h["decision"] == "review" and h["coverage_note"] == "1 of 2 listed tools checked"


def test_tools_still_being_checked_have_no_answer_yet():
    # base/1178486 a minute after minting: both scans queued must not read Review.
    h = ea.headline([_t(None, "checking"), _t(None, "checking")], [])
    assert h["decision"] is None and h["checking"] == 2
    assert h["reason"] == "checking 2 of 2 listed tools"
    assert h["coverage_note"] == "0 of 2 listed tools checked"
    h1 = ea.headline([_t("safe"), _t(None, "checking")], [])
    assert h1["decision"] is None and h1["reason"] == "checking 1 of 2 listed tools"
    assert ea.headline([_t(None, "checking")], [])["reason"] == "checking 1 of 1 listed tool"


def test_pending_tool_never_hides_a_review_cap_once_done():
    # still checking + one review: no answer yet (the pending one could be worse)
    assert ea.headline([_t("review"), _t(None, "checking")], [])["decision"] is None
    # all settled again: the usual rules
    h = ea.headline([_t("safe"), _t(None, "not_checked")], [])
    assert h["decision"] == "review" and h["checking"] == 0


def test_do_not_connect_is_final_even_while_others_are_checked():
    h = ea.headline([_t("do_not_connect"), _t(None, "checking")], [])
    assert h["decision"] == "do_not_connect" and h["checking"] == 1


def test_worst_tool_leads():
    h = ea.headline([_t("safe"), _t("review"), _t("safe")], [])
    assert h["decision"] == "review" and h["reason"] == "1 of 3 listed tools needs a look"
    h2 = ea.headline([_t("review"), _t("do_not_connect")], [])
    assert h2["decision"] == "do_not_connect"


def test_never_safe_from_identity_alone():
    assert ea.headline([], [])["decision"] == "review"
    assert ea.headline([_t(None, "not_checked")], [])["decision"] == "review"


def test_high_file_finding_holds_safe_tools_at_review():
    h = ea.headline([_t("safe")], [{"severity": "high", "name": "x"}])
    assert h["decision"] == "review"


# ── the route ─────────────────────────────────────────────────────────────────

class _Req:
    client = type("C", (), {"host": "203.0.113.9"})()
    headers: dict = {}


@pytest.fixture
def route(monkeypatch):
    from src.api import erc8004_router as r
    from src.api import public_scan_router as psr

    store: dict = {}
    monkeypatch.setenv("ETH_RPC_URL", "https://rpc.example")

    async def cget(k):
        return store.get(k)

    async def cset(k, v, ttl=None):
        store[k] = v
    monkeypatch.setattr("src.cache.get", cget)
    monkeypatch.setattr("src.cache.set", cset)

    async def read_agent(chain, aid, rpc, client=None):
        if aid == 404:
            raise ea.AgentNotFoundError(aid)
        return ea.OnChainAgent(chain=chain, chain_id=1, agent_id=aid, owner="0x" + "11" * 20,
                               agent_wallet=None, registration_uri="https://a.example/r.json",
                               block=7)
    monkeypatch.setattr(ea, "read_agent", read_agent)

    files = {"reg": REG_33256}

    async def resolve(uri, ipfs_gateway):
        return ea.parse_registration(json.dumps(files["reg"]).encode())
    monkeypatch.setattr(ea, "resolve_registration", resolve)

    tool_cache: dict = {}

    async def get_cached(owner, key):
        return tool_cache.get((owner, key))
    monkeypatch.setattr(psr, "_get_cached", get_cached)
    scheduled = []

    async def schedule(kind, url, key):
        scheduled.append((kind, url))
        return True
    monkeypatch.setattr(r, "_schedule_check", schedule)
    budget = {"ok": True}

    async def bud(req):
        return budget["ok"]
    monkeypatch.setattr(r, "_bg_budget_ok", bud)
    return {"r": r, "files": files, "tool_cache": tool_cache, "scheduled": scheduled,
            "budget": budget, "store": store}


async def test_uncached_tool_is_checked_in_the_background(route):
    resp = await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    (tool,) = resp.tools
    assert tool.kind == "a2a" and tool.state == "checking"
    assert route["scheduled"] == [("a2a", "https://api.normies.art/agents/agent-card/6574")]
    assert resp.headline["decision"] is None and resp.headline["checking"] == 1
    assert resp.coverage_gaps["tools_being_checked"] == 1
    assert [s.name for s in resp.other_services] == ["web"]


async def test_cached_tool_answer_is_the_same_as_its_own_page(route):
    from src.api import erc8004_router as r
    from src.api import public_scan_router as psr
    url, key, api = r._tool_identity("a2a", "https://api.normies.art/agents/agent-card/6574")
    data = {"trust_score": 82, "findings": {"items": []}, "metadata": {"files_scanned": 9},
            "coverage": {"surface": "a2a"}}
    route["tool_cache"][("a2a", key)] = data
    resp = await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    (tool,) = resp.tools
    assert tool.state == "done" and tool.decision == psr._decide(data).decision
    assert tool.decision_reason == psr._decide(data).reason
    assert resp.headline["decision"] == tool.decision == "safe"
    assert api.startswith("/api/v1/public/scan/a2a?card=")


async def test_budget_exhausted_leaves_the_tool_unchecked(route):
    route["budget"]["ok"] = False
    resp = await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    assert resp.tools[0].state == "not_checked" and not route["scheduled"]
    assert resp.headline["decision"] == "review"


async def test_more_than_ten_tools(route):
    route["files"]["reg"] = {"services": [
        {"name": "MCP", "endpoint": f"https://m{i}.example/mcp"} for i in range(12)]}
    resp = await route["r"].scan_erc8004_agent("ethereum", 7, _Req(), force=False)
    assert len(resp.tools) == 12 and len(route["scheduled"]) == 10
    assert sum(1 for t in resp.tools if t.why_not_checked
               and "10-tool limit" in t.why_not_checked) == 2
    assert resp.headline["coverage_note"] == "0 of 12 listed tools checked"


async def test_github_repo_tools_are_listed_not_checked_yet(route):
    route["files"]["reg"] = {"services": [
        {"name": "repository", "endpoint": "https://github.com/acme/agent"}]}
    resp = await route["r"].scan_erc8004_agent("ethereum", 8, _Req(), force=False)
    assert resp.tools[0].state == "not_checked" and resp.headline["decision"] == "review"


async def test_unknown_chain_and_unminted_agent(route):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        await route["r"].scan_erc8004_agent("solana", 1, _Req(), force=False)
    assert e.value.status_code == 404
    with pytest.raises(HTTPException) as e2:
        await route["r"].scan_erc8004_agent("ethereum", 404, _Req(), force=False)
    assert e2.value.status_code == 404


async def test_agent_read_is_cached(route):
    await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    assert "erc8004:agent:ethereum:33256" in route["store"]
    resp = await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    assert resp.cached is True


async def test_no_rpc_key_says_lookups_are_not_enabled(monkeypatch):
    from fastapi import HTTPException

    from src.api import erc8004_router as r

    async def none(k):
        return None
    monkeypatch.setattr("src.cache.get", none)
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    with pytest.raises(HTTPException) as e:
        await r.scan_erc8004_agent("ethereum", 1, _Req(), force=False)
    assert e.value.status_code == 503
    assert "aren't enabled yet" in e.value.detail


async def test_a_failed_check_says_why_instead_of_checking_forever(route):
    from src.api import erc8004_router as r
    url, key, _api = r._tool_identity("a2a", "https://api.normies.art/agents/agent-card/6574")
    route["store"][f"erc8004:toolerr:{key}"] = "no A2A agent card could be read there"
    resp = await route["r"].scan_erc8004_agent("ethereum", 33256, _Req(), force=False)
    (tool,) = resp.tools
    assert tool.state == "not_checked"
    assert tool.why_not_checked == "no A2A agent card could be read there"
    assert not route["scheduled"]


@pytest.mark.parametrize("detail,reason", [
    ("Scan error: This MCP server requires sign-in (OAuth), so its tool list isn't public",
     "it requires sign-in, so its tools aren't public"),
    ("Scan error: Could not read an A2A Agent Card there.", "no A2A agent card could be read there"),
    ("MCP handshake timed out — please retry shortly.", "it did not answer in time"),
    ("Scan error: something else", "it could not be reached or read"),
])
def test_short_reasons(detail, reason):
    from src.api import erc8004_router as r
    assert r._short_reason(detail) == reason


async def test_background_failure_is_remembered(monkeypatch):
    from fastapi import HTTPException

    from src.api import erc8004_router as r
    from src.api import public_scan_router as psr
    store = {}

    async def cset(k, v, ttl=None):
        store[k] = (v, ttl)
    monkeypatch.setattr("src.cache.set", cset)

    async def boom(**kw):
        raise HTTPException(422, "Scan error: This MCP server requires sign-in (OAuth)")
    monkeypatch.setattr(psr, "scan_mcp_endpoint", boom)

    class _S:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *a):
            return False
    monkeypatch.setattr("src.database.async_session", lambda: _S())
    await r._bg_check("mcp", "https://m.example/mcp", "mcp_abc")
    assert store["erc8004:toolerr:mcp_abc"] == ("it requires sign-in, so its tools aren't public",
                                                3600)
