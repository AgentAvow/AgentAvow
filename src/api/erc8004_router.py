"""GET /public/scan/erc8004/{chain}/{agent_id}: an on-chain ERC-8004 agent and an
answer for every tool it lists (design: docs/internal/erc8004-step2-design-2026-11-11.md;
reviewed by agentgraph-83 2026-11-11).

* The on-chain read and the registration file are cached for 1 h. ``force=true``
  follows the same fresh-scan limit as every other surface.
* Each listed MCP endpoint / A2A card is answered from the same cache and the same
  route function as its own page, so the answer here is the answer there. A tool not
  cached yet is checked in the background: at most MAX_CHECKED_TOOLS per agent, at
  most 20 new background checks per client IP per hour, deduped by a Redis lock, and
  sharing the public scan router's refresh semaphore (no new queue).
* The headline is about the tools (``erc8004_agent.headline``): Safe only when every
  listed tool was checked and reads Safe; never Safe from identity, never Certified.
* On-chain identity is never an input to any score.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from src.api.rate_limit import rate_limit_reads
from src.scanner import erc8004_agent as ea

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public/scan/erc8004", tags=["public-scan"])

_AGENT_CACHE_TTL = 3600
_BG_PER_IP_PER_HOUR = 20
_BG_LOCK_TTL = 300
_BG_MAX_PENDING = 50
_bg_pending = 0


class AgentIdentity(BaseModel):
    chain: str
    chain_id: int
    agent_id: int
    owner: str
    agent_wallet: str | None = None
    registration_uri: str = ""
    registration_sha256: str | None = None
    block: int | None = None
    name: str = ""
    description: str = ""
    active: bool | None = None
    x402_support: bool | None = None


class AgentTool(BaseModel):
    name: str
    endpoint: str
    kind: str                      # mcp | a2a | github
    state: str                     # done | checking | not_checked
    why_not_checked: str | None = None
    decision: str | None = None
    decision_reason: str | None = None
    trust_score: int | None = None
    scan_api: str | None = None    # the API path that returns this tool's own answer


class AgentService(BaseModel):
    name: str
    endpoint: str


class AgentResponse(BaseModel):
    surface: str = "erc8004"
    agent: AgentIdentity
    tools: list[AgentTool]
    other_services: list[AgentService]   # listed, not tools (web, metadata, OASF, ...)
    file_findings: list[dict]
    registration_error: str | None = None
    headline: dict
    coverage_gaps: dict
    cached: bool = False


def _rpc_url(chain: str) -> str | None:
    return ea.rpc_url_for(chain, dict(os.environ))


def _ipfs_gateway() -> str:
    return os.environ.get("IPFS_GATEWAY_URL") or "https://ipfs.io/ipfs/"


async def _load_agent(chain: str, agent_id: int, force: bool) -> tuple[dict, bool]:
    """(agent + registration as a dict, from_cache)."""
    from src import cache
    key = f"erc8004:agent:{chain}:{agent_id}"
    if not force:
        hit = await cache.get(key)
        if isinstance(hit, dict):
            return hit, True
    rpc = _rpc_url(chain)
    if not rpc:
        raise HTTPException(503, "On-chain lookups aren't enabled yet on this server.",
                            headers={"Retry-After": "3600"})
    try:
        onchain = await ea.read_agent(chain, agent_id, rpc)
    except ea.AgentNotFoundError:
        raise HTTPException(404, f"No agent #{agent_id} on {ea.CHAINS[chain]['label']}.")
    except ea.ChainUnavailableError:
        raise HTTPException(503, "The chain could not be read right now. Please retry.",
                            headers={"Retry-After": "30"})
    reg = await ea.resolve_registration(onchain.registration_uri,
                                        ipfs_gateway=_ipfs_gateway())
    data = {
        "agent": {**onchain.__dict__},
        "registration": {
            "ok": reg.ok, "sha256": reg.sha256, "name": reg.name,
            "description": reg.description, "active": reg.active,
            "x402_support": reg.x402_support, "error": reg.error,
            "services": [s.__dict__ for s in reg.services],
        },
        "read_at": int(time.time()),
    }
    await cache.set(key, data, ttl=_AGENT_CACHE_TTL)
    return data, False


# ── per-tool answers ───────────────────────────────────────────────────────────

def _tool_identity(kind: str, endpoint: str) -> tuple[str, str, str] | None:
    """(normalized url, cache key, api path) as the tool's own route computes them;
    None for an endpoint that route would refuse (not https, credentialed, ...)."""
    import hashlib
    from urllib.parse import quote

    from src.ssrf import mcp_endpoint_identity, validate_url_https
    try:
        url = mcp_endpoint_identity(validate_url_https(endpoint, field_name="endpoint"))
    except Exception:  # noqa: BLE001
        return None
    if kind == "mcp":
        return (url, "mcp_" + hashlib.sha256(url.encode()).hexdigest()[:22],
                f"/api/v1/public/scan/mcp?endpoint={quote(url, safe='')}")
    if kind == "a2a":
        return (url, "a2a_" + hashlib.sha256(url.encode()).hexdigest()[:22],
                f"/api/v1/public/scan/a2a?card={quote(url, safe='')}")
    return None


async def _bg_budget_ok(request: Request | None) -> bool:
    """At most _BG_PER_IP_PER_HOUR new background checks per client IP per hour."""
    if request is None:
        return True
    try:
        from src.api.rate_limit import _get_client_ip
        from src.redis_client import get_redis
        ip = _get_client_ip(request)
        k = f"erc8004_bg:{ip}:{int(time.time() // 3600)}"
        r = get_redis()
        n = await r.incr(k)
        if n == 1:
            await r.expire(k, 3700)
        return int(n) <= _BG_PER_IP_PER_HOUR
    except Exception:  # noqa: BLE001 — no Redis: fail closed for background work
        return False


_TOOL_ERR_TTL = 3600


def _short_reason(detail: str) -> str:
    """A tool's own route error, as a short plain reason for the agent page."""
    d = (detail or "").lower()
    if "sign-in" in d or "oauth" in d:
        return "it requires sign-in, so its tools aren't public"
    if "agent card" in d:
        return "no A2A agent card could be read there"
    if "timed out" in d:
        return "it did not answer in time"
    return "it could not be reached or read"


async def _remember_failure(key: str, reason: str) -> None:
    """A failed check is remembered for an hour, so the agent page says why instead
    of 'being checked now' forever (prod, 2026-11-11: an OAuth-only MCP server and a
    URL with no card both read 'checking' indefinitely)."""
    try:
        from src import cache
        await cache.set(f"erc8004:toolerr:{key}", reason, ttl=_TOOL_ERR_TTL)
    except Exception:  # noqa: BLE001
        pass


async def _bg_check(kind: str, url: str, key: str = "") -> None:
    global _bg_pending
    try:
        from src.api import public_scan_router as psr
        from src.database import async_session
        async with psr._refresh_sem:
            async with async_session() as db:
                if kind == "mcp":
                    await psr.scan_mcp_endpoint(endpoint=url, request=None, force=False,
                                                probe=False, db=db)
                else:
                    await psr.scan_a2a_endpoint(card=url, request=None, force=False, db=db)
    except HTTPException as exc:
        logger.info("erc8004 background %s check failed for %s", kind, url[:120])
        if key:
            await _remember_failure(key, _short_reason(str(exc.detail)))
    except Exception:  # noqa: BLE001 — best effort; the next lookup retries
        logger.info("erc8004 background %s check failed for %s", kind, url[:120])
        if key:
            await _remember_failure(key, _short_reason(""))
    finally:
        _bg_pending = max(0, _bg_pending - 1)


async def _schedule_check(kind: str, url: str, key: str) -> bool:
    """Start one background check unless one is already running (Redis lock) or the
    process already has _BG_MAX_PENDING queued."""
    global _bg_pending
    if _bg_pending >= _BG_MAX_PENDING:
        return False
    try:
        from src.redis_client import get_redis
        if not await get_redis().set(f"erc8004_bg_lock:{key}", "1", nx=True,
                                     ex=_BG_LOCK_TTL):
            return True   # already being checked
    except Exception:  # noqa: BLE001
        return False
    try:
        asyncio.get_running_loop().create_task(_bg_check(kind, url, key))
        _bg_pending += 1
        return True
    except RuntimeError:
        return False


async def _answer_tools(services: list[dict], request: Request | None
                        ) -> tuple[list[AgentTool], list[AgentService]]:
    from src.api import public_scan_router as psr
    tools: list[AgentTool] = []
    others: list[AgentService] = []
    for s in services:
        kind, name, endpoint = s.get("kind"), s.get("name") or "", s.get("endpoint") or ""
        if kind not in ("mcp", "a2a", "github"):
            others.append(AgentService(name=name, endpoint=endpoint))
            continue
        tool = AgentTool(name=name, endpoint=endpoint, kind=kind, state="not_checked")
        tools.append(tool)
        if len([t for t in tools if t.kind in ("mcp", "a2a", "github")]) > ea.MAX_CHECKED_TOOLS:
            tool.why_not_checked = f"over the {ea.MAX_CHECKED_TOOLS}-tool limit"
            continue
        if kind == "github":
            tool.why_not_checked = "repositories listed by an agent are not checked yet"
            continue
        ident = _tool_identity(kind, endpoint)
        if ident is None:
            tool.why_not_checked = "not a valid https:// endpoint"
            continue
        url, key, api = ident
        tool.scan_api = api
        cached = await psr._get_cached(kind, key)
        if cached:
            d = psr._decide(cached)
            tool.state, tool.decision, tool.decision_reason = "done", d.decision, d.reason
            ts = cached.get("trust_score")
            tool.trust_score = ts if isinstance(ts, int) and not isinstance(ts, bool) else None
            continue
        try:
            from src import cache
            failed = await cache.get(f"erc8004:toolerr:{key}")
        except Exception:  # noqa: BLE001
            failed = None
        if isinstance(failed, str) and failed:
            tool.why_not_checked = failed
            continue
        if await _bg_budget_ok(request) and await _schedule_check(kind, url, key):
            tool.state, tool.why_not_checked = "checking", "being checked now"
        else:
            tool.why_not_checked = "the check limit for now was reached; retry later"
    return tools, others


@router.get("/{chain}/{agent_id}", response_model=AgentResponse,
            dependencies=[Depends(rate_limit_reads)])
async def scan_erc8004_agent(
    chain: str, agent_id: int, request: Request,
    force: bool = Query(False, description="Re-read the chain and the registration file"),
) -> AgentResponse:
    """An ERC-8004 agent on chain: its identity, its registration file (untrusted,
    read through the SSRF guard), and an answer for every MCP server and A2A agent it
    lists. Identity is shown, never scored. E.g. ``/public/scan/erc8004/ethereum/33256``."""
    chain = chain.strip().lower()
    if chain not in ea.CHAINS:
        raise HTTPException(404, "Supported chains: " + ", ".join(sorted(ea.CHAINS)))
    if str(force).lower() in ("1", "true", "yes"):
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)
        force = True
    else:
        force = False
    data, from_cache = await _load_agent(chain, agent_id, force)
    a, r = data["agent"], data["registration"]
    services = r.get("services") or []
    reg = ea.Registration(ok=bool(r.get("ok")), active=r.get("active"),
                          services=[ea.Service(**s) for s in services])
    findings = ea.file_findings(reg)
    tools, others = await _answer_tools(services, request)
    tool_dicts = [t.model_dump() for t in tools]
    head = ea.headline(tool_dicts, findings)
    gaps: dict[str, Any] = {}
    if not r.get("ok"):
        gaps["registration_file_unreadable"] = True
    not_checked = sum(1 for t in tools if t.state != "done")
    if not_checked:
        gaps["tools_not_checked"] = not_checked
    return AgentResponse(
        agent=AgentIdentity(
            chain=a["chain"], chain_id=a["chain_id"], agent_id=a["agent_id"],
            owner=a["owner"], agent_wallet=a.get("agent_wallet"),
            registration_uri=str(a.get("registration_uri") or "")[:500],
            registration_sha256=r.get("sha256"), block=a.get("block"),
            name=r.get("name") or "", description=r.get("description") or "",
            active=r.get("active"), x402_support=r.get("x402_support")),
        tools=tools, other_services=others, file_findings=findings,
        registration_error=r.get("error"), headline=head, coverage_gaps=gaps,
        cached=from_cache)
