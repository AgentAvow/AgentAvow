"""ERC-8004 agents: read an on-chain agent, resolve its registration file, and list the
tools it declares (design: docs/internal/erc8004-step2-design-2026-11-11.md, reviewed
by agentgraph-83 2026-11-11).

Read-only. The registration file is untrusted input: fetched through the SSRF guard
with a size cap, parsed as JSON, never rendered as HTML. On-chain identity is never an
input to any score (it can be spammed and changes every block). Each listed tool keeps
its own signed verdict; the agent headline only summarises them.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

# Chains we read. Base and BNB are added once the RPC app serves them and the registry
# code is verified at the same address (design review: Ethereum only until then).
IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
CHAINS: dict[str, dict[str, Any]] = {
    "ethereum": {"chain_id": 1, "rpc_env": "ETH_RPC_URL", "identity": IDENTITY_REGISTRY,
                 "label": "Ethereum", "alchemy_host": "eth-mainnet"},
    # Same registry address and code on Base and BNB Chain (verified 2026-11-11:
    # eth_getCode identical, name() == "AgentIdentity").
    "base": {"chain_id": 8453, "rpc_env": "BASE_RPC_URL", "identity": IDENTITY_REGISTRY,
             "label": "Base", "alchemy_host": "base-mainnet"},
    "bnb": {"chain_id": 56, "rpc_env": "BNB_RPC_URL", "identity": IDENTITY_REGISTRY,
            "label": "BNB Chain", "alchemy_host": "bnb-mainnet"},
}
_ALCHEMY_RE = re.compile(r"^https://([a-z0-9-]+)\.g\.alchemy\.com/v2/([A-Za-z0-9_-]+)$")


def rpc_url_for(chain: str, env: dict[str, str]) -> str | None:
    """The chain's own RPC env var, else the same Alchemy key as ETH_RPC_URL on that
    chain's Alchemy host (one key serves every network enabled on the app)."""
    cfg = CHAINS.get(chain)
    if cfg is None:
        return None
    own = (env.get(cfg["rpc_env"]) or "").strip()
    if own:
        return own
    m = _ALCHEMY_RE.match((env.get("ETH_RPC_URL") or "").strip())
    if m:
        return f"https://{cfg['alchemy_host']}.g.alchemy.com/v2/{m.group(2)}"
    return None

REG_FILE_MAX_BYTES = 256 * 1024
MAX_CHECKED_TOOLS = 10
_TEXT_MAX = 300  # name / description as returned: plain text, clipped

# Service names that are tools we check, by kind. Anything else (web, metadata, OASF,
# agent-info, custom ERC-8257 names, ...) is listed but is not a tool.
_TOOL_KINDS = {"mcp": "mcp", "a2a": "a2a"}
_GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})/?$")

# Function selectors (keccak-256 of the signature, first 4 bytes).
_SEL_OWNER_OF = "0x6352211e"      # ownerOf(uint256)
_SEL_TOKEN_URI = "0xc87b56dd"     # tokenURI(uint256)
_SEL_AGENT_WALLET = "0x00339509"  # getAgentWallet(uint256)


class AgentNotFoundError(Exception):
    """The token is not minted on that chain."""


class ChainUnavailableError(Exception):
    """No RPC configured, or the RPC failed."""


@dataclass
class OnChainAgent:
    chain: str
    chain_id: int
    agent_id: int
    owner: str
    agent_wallet: str | None
    registration_uri: str
    block: int | None


@dataclass
class Service:
    name: str
    endpoint: str
    kind: str | None          # "mcp" | "a2a" | "github" | None (not a tool)


@dataclass
class Registration:
    ok: bool
    sha256: str | None = None
    name: str = ""
    description: str = ""
    active: bool | None = None
    x402_support: bool | None = None
    services: list[Service] = field(default_factory=list)
    error: str | None = None


# ── on chain ───────────────────────────────────────────────────────────────────

def _word(i: int) -> str:
    return i.to_bytes(32, "big").hex()


def decode_string(result_hex: str) -> str:
    """ABI-decode a single dynamic ``string`` return value."""
    b = bytes.fromhex((result_hex or "0x")[2:])
    if len(b) < 64:
        return ""
    off = int.from_bytes(b[0:32], "big")
    if off + 32 > len(b):
        return ""
    ln = int.from_bytes(b[off:off + 32], "big")
    return b[off + 32: off + 32 + ln].decode("utf-8", "replace")


def decode_address(result_hex: str) -> str | None:
    b = bytes.fromhex((result_hex or "0x")[2:])
    if len(b) < 32:
        return None
    addr = b[12:32]
    return None if not any(addr) else "0x" + addr.hex()


async def _rpc(client: httpx.AsyncClient, rpc_url: str, method: str, params: list) -> Any:
    r = await client.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                         "params": params})
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        return {"__error__": body["error"]}
    return body.get("result")


async def read_agent(chain: str, agent_id: int, rpc_url: str | None,
                     *, client: httpx.AsyncClient | None = None) -> OnChainAgent:
    """ownerOf / tokenURI / getAgentWallet at one block. Raises AgentNotFoundError when the
    token is not minted, ChainUnavailableError when the RPC cannot be used."""
    cfg = CHAINS.get(chain)
    if cfg is None or not rpc_url:
        raise ChainUnavailableError(chain)
    if agent_id < 0 or agent_id >= 2 ** 64:
        raise AgentNotFoundError(agent_id)
    own = client is None
    client = client or httpx.AsyncClient(timeout=15.0)
    try:
        head = await _rpc(client, rpc_url, "eth_blockNumber", [])
        if not isinstance(head, str):
            raise ChainUnavailableError(chain)
        block = hex(int(head, 16))
        to = cfg["identity"]

        async def call(sel: str):
            return await _rpc(client, rpc_url, "eth_call",
                              [{"to": to, "data": sel + _word(agent_id)}, block])

        owner = await call(_SEL_OWNER_OF)
        if not isinstance(owner, str):
            raise AgentNotFoundError(agent_id)   # ownerOf reverts for an unminted token
        uri = await call(_SEL_TOKEN_URI)
        wallet = await call(_SEL_AGENT_WALLET)
        return OnChainAgent(
            chain=chain, chain_id=cfg["chain_id"], agent_id=agent_id,
            owner=decode_address(owner) or "",
            agent_wallet=decode_address(wallet) if isinstance(wallet, str) else None,
            registration_uri=decode_string(uri) if isinstance(uri, str) else "",
            block=int(block, 16))
    except (httpx.HTTPError, ValueError) as exc:
        raise ChainUnavailableError(str(exc)[:100]) from exc
    finally:
        if own:
            await client.aclose()


# ── registration file ──────────────────────────────────────────────────────────

def _clean_text(v: Any) -> str:
    """Plain text only: control characters stripped, clipped. Never HTML-rendered by
    us; the caller escapes it like any other text."""
    s = str(v or "")
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", s)
    return s[:_TEXT_MAX]


# A GitHub URL is the agent's own code only under a repository-like service name; an
# `OASF` entry links the OASF schema repo (agent #53824), not the agent.
_REPO_NAMES = frozenset({"github", "repository", "repo", "source", "source code",
                         "sourcecode", "code"})


def _service_kind(name: str, endpoint: str) -> str | None:
    k = _TOOL_KINDS.get(name.strip().lower())
    if k:
        return k
    if name.strip().lower() in _REPO_NAMES and _GITHUB_RE.match(endpoint.strip()):
        return "github"
    return None


def parse_registration(raw: bytes) -> Registration:
    sha = hashlib.sha256(raw).hexdigest()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return Registration(ok=False, sha256=sha, error="not JSON")
    if not isinstance(doc, dict):
        return Registration(ok=False, sha256=sha, error="not a JSON object")
    services_raw = doc.get("services")
    if not isinstance(services_raw, list):
        services_raw = doc.get("endpoints") if isinstance(doc.get("endpoints"), list) else []
    services: list[Service] = []
    for s in services_raw[:50]:
        if not isinstance(s, dict):
            continue
        name = _clean_text(s.get("name") or s.get("type"))[:60]
        endpoint = str(s.get("endpoint") or s.get("url") or "").strip()[:500]
        if not name and not endpoint:
            continue
        services.append(Service(name=name, endpoint=endpoint,
                                kind=_service_kind(name, endpoint)))
    active = doc.get("active")
    x402 = doc.get("x402Support")
    return Registration(
        ok=True, sha256=sha, name=_clean_text(doc.get("name")),
        description=_clean_text(doc.get("description")),
        active=active if isinstance(active, bool) else None,
        x402_support=x402 if isinstance(x402, bool) else None,
        services=services)


def _data_uri_bytes(uri: str) -> bytes | None:
    if not uri.startswith("data:") or "," not in uri:
        return None
    meta, body = uri.split(",", 1)
    try:
        raw = base64.b64decode(body, validate=False) if ";base64" in meta \
            else unquote(body).encode("utf-8")
    except (binascii.Error, ValueError):
        return None
    return raw[:REG_FILE_MAX_BYTES + 1]


async def _fetch_capped(url: str) -> bytes:
    """GET through the SSRF guard: every hop validated, private hosts refused, at most
    REG_FILE_MAX_BYTES read."""
    from src.ssrf import ssrf_safe_async_client, ssrf_safe_follow, validate_url_https
    validate_url_https(url, field_name="registration_uri")
    async with ssrf_safe_async_client(timeout=10.0, follow_redirects=False) as client:
        resp, _final = await ssrf_safe_follow(
            client, "GET", url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        body = resp.content
    return body[:REG_FILE_MAX_BYTES + 1]


async def resolve_registration(uri: str, *, ipfs_gateway: str) -> Registration:
    uri = (uri or "").strip()
    if not uri:
        return Registration(ok=False, error="no registration file")
    try:
        if uri.startswith("data:"):
            raw = _data_uri_bytes(uri)
            if raw is None:
                return Registration(ok=False, error="unreadable data: URI")
        elif uri.startswith("{"):
            raw = uri.encode("utf-8")[:REG_FILE_MAX_BYTES + 1]
        elif uri.startswith("ipfs://"):
            cid_path = uri[len("ipfs://"):].lstrip("/")
            if cid_path.startswith("ipfs/"):
                cid_path = cid_path[len("ipfs/"):]
            raw = await _fetch_capped(ipfs_gateway.rstrip("/") + "/" + cid_path)
        elif uri.startswith("https://"):
            raw = await _fetch_capped(uri)
        else:
            return Registration(ok=False, error="unsupported URI scheme")
    except Exception as exc:  # noqa: BLE001 — any fetch failure is "unreadable"
        return Registration(ok=False, error=f"unreadable ({type(exc).__name__})")
    if len(raw) > REG_FILE_MAX_BYTES:
        return Registration(ok=False, error="larger than 256 KB")
    return parse_registration(raw)


# ── findings on the registration file ──────────────────────────────────────────

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def file_findings(reg: Registration) -> list[dict]:
    """Transport / host findings for the tool endpoints the file lists (the a2a
    ``_url_findings`` rules), a raw public IP (low), and an agent that marks itself
    inactive (info)."""
    from src.scanner.a2a_scan import _url_findings
    out: list[dict] = []
    for i, s in enumerate(reg.services):
        if s.kind is None or not s.endpoint:
            continue
        where = f"registration:service:{i}"
        for f in _url_findings(s.endpoint, where, f"{s.name or 'service'} endpoint", ""):
            if f.category == "endpoint_origin":
                continue  # no card host to compare against
            out.append({"severity": f.severity, "name": f.name, "category": f.category,
                        "where": where})
        host = (urlsplit(s.endpoint).hostname or "") if "://" in s.endpoint else ""
        if host and _IPV4_RE.match(host):
            from src.scanner.mcp_icons import _is_private_host
            if not _is_private_host(host):
                out.append({"severity": "low", "category": "endpoint_origin",
                            "name": f"{s.name or 'service'} endpoint is a raw IP address "
                                    f"({host})", "where": where})
    if reg.active is False:
        out.append({"severity": "info", "category": "maintenance",
                    "name": "the agent marks itself inactive", "where": "registration"})
    return out


# ── headline ───────────────────────────────────────────────────────────────────

_RANK = {"safe": 0, "review": 1, "do_not_connect": 2}


def headline(tools: list[dict], findings: list[dict]) -> dict:
    """The agent headline, about its tools (design review 2026-11-11):

    * worst answer among the checked tools;
    * a high/critical finding on the registration file is at least Review;
    * Safe ONLY when every listed tool was checked and each reads Safe;
    * any tool not checked (unreachable, unsupported, over the cap) caps it at Review
      with "N of M listed tools checked";
    * no tools at all, or none checked: Review, never Safe from identity alone;
    * while a listed tool is still being checked there is no answer yet
      (``decision`` None, ``checking`` > 0): a first look at a new agent must not
      read Review just because its scans are queued. A checked tool that already
      reads Do not connect is final, so that answer shows at once.
    Never Certified at the agent level."""
    total = len(tools)
    checked = [t for t in tools if t.get("decision") in _RANK]
    n = len(checked)
    pending = sum(1 for t in tools if t.get("state") == "checking"
                  and t.get("decision") not in _RANK)
    file_bad = any(f["severity"] in ("critical", "high") for f in findings)
    note = f"{n} of {total} listed tools checked" if total else ""
    if total == 0:
        return {"decision": "review", "reason": "it lists no tools we can check",
                "coverage_note": note, "certified": False, "checking": 0}
    worst = (max(checked, key=lambda t: _RANK[t["decision"]])["decision"]
             if checked else None)
    if pending and worst != "do_not_connect":
        tools_word = "tool" if total == 1 else "tools"
        return {"decision": None,
                "reason": f"checking {pending} of {total} listed {tools_word}",
                "coverage_note": note, "certified": False, "checking": pending}
    if n == 0:
        return {"decision": "review", "reason": "none of the tools it lists could be checked",
                "coverage_note": note, "certified": False, "checking": 0}
    bad = [t for t in checked if t["decision"] == worst and worst != "safe"]
    if worst == "do_not_connect":
        reason = (f"{len(bad)} of {total} listed tools read Do not connect")
    elif worst == "review":
        reason = f"{len(bad)} of {total} listed tools needs a look" if len(bad) == 1 \
            else f"{len(bad)} of {total} listed tools need a look"
    else:
        reason = f"all {total} listed tools read Safe to connect"
    decision = worst
    if decision == "safe" and n < total:
        decision, reason = "review", f"{n} of {total} listed tools checked; the rest could not be"
    elif decision == "safe" and file_bad:
        decision, reason = "review", "its registration file has a high finding"
    return {"decision": decision, "reason": reason, "coverage_note": note,
            "certified": False, "checking": pending}
