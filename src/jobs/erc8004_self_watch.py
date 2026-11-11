"""Watch AgentAvow's own ERC-8004 identity on Base (design note
docs/internal/erc8004-self-registration-design-2026-11-11.md, section 4).

AgentAvow is agent 1178486 on Base, minted 2026-11-11 (tx 0xa91945e9…f1f2). Its
tokenURI points at a file we host, so every content change is a file edit. Only a
change of the on-chain URI or of the owner needs the wallet. Either one, when we did
not make it, means the key was used by someone else (design note section 7, "Key
stolen"). One RPC read per run (ownerOf + tokenURI at one block) is compared with the
expected values below, and the admin is alerted (admin notification + the HMAC-signed
alert webhook, the sandbox watchdog's path), at most once a day per condition.

Conditions:
  ``uri_changed``    tokenURI is not our registration file URL
  ``owner_changed``  ownerOf is not our wallet
  ``not_found``      the token reads as unminted (ownerOf reverts)
  ``unreadable``     no successful read for READ_STALE_HOURS (RPC down or not set)

If we change the URI or transfer the agent on purpose, update the constants in the same
PR. Runs from the scheduler loop (every 6 h). Never raises.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CHAIN = "base"
AGENT_ID = 1178486
EXPECTED_URI = "https://agentavow.com/.well-known/agent-registration.json"
EXPECTED_OWNER = "0xc842b9e3b99be67201e3cd520dc8c600f148bc03"

READ_STALE_HOURS = 48
DEDUPE_TTL = 24 * 3600
DEDUPE_PREFIX = "ag:ops:erc8004_self:alerted:"
LAST_OK_KEY = "ag:ops:erc8004_self:last_ok"
WEBHOOK_TYPE = "agentavow.ops.erc8004_self_watch"

_WHERE = f"ERC-8004 agent #{AGENT_ID} on Base"


def _dec(v):
    return v.decode() if isinstance(v, bytes) else v


def compare(owner: str | None, uri: str | None) -> list[tuple[str, str, str]]:
    """Pure check of one successful read. Returns (condition, title, body) for each
    mismatch."""
    out: list[tuple[str, str, str]] = []
    if (uri or "").strip() != EXPECTED_URI:
        out.append(("uri_changed", f"{_WHERE}: its on-chain URI changed",
                    f"tokenURI is now {(uri or '(empty)')[:300]!r}; expected {EXPECTED_URI}. "
                    "If we didn't change it, treat the wallet key as compromised: say so "
                    "publicly, mark the registration file inactive, and register a fresh "
                    "agent (design note, section 7)."))
    if (owner or "").lower() != EXPECTED_OWNER:
        out.append(("owner_changed", f"{_WHERE}: its owner changed",
                    f"ownerOf is now {owner or '(none)'}; expected {EXPECTED_OWNER}. "
                    "If we didn't transfer it, treat the wallet key as compromised "
                    "(design note, section 7)."))
    return out


def stale(last_ok_iso: str | None, now: datetime, first_seen_iso: str | None) -> bool:
    """True when no read has succeeded for READ_STALE_HOURS. Before the first success,
    staleness counts from when the watch first ran."""
    ref = last_ok_iso or first_seen_iso
    if not ref:
        return False
    try:
        t = datetime.fromisoformat(ref)
    except ValueError:
        return True
    return (now - t).total_seconds() > READ_STALE_HOURS * 3600


async def evaluate(now: datetime | None = None, *, read=None, redis=None
                   ) -> list[tuple[str, str, str]]:
    """Read the chain once and return the conditions that hold."""
    from src.scanner import erc8004_agent as ea

    now = now or datetime.now(timezone.utc)
    if redis is None:
        from src.redis_client import get_redis
        redis = get_redis()
    if read is None:
        async def read():
            url = ea.rpc_url_for(CHAIN, dict(os.environ))
            return await ea.read_agent(CHAIN, AGENT_ID, url)
    try:
        agent = await read()
    except ea.AgentNotFoundError:
        return [("not_found", f"{_WHERE} reads as not minted",
                 "ownerOf reverted for our agent id. Check the registry on Basescan.")]
    except Exception as exc:  # noqa: BLE001 - RPC down, not configured, bad reply
        logger.info("erc8004 self watch: read failed: %s", str(exc)[:120])
        first_key = LAST_OK_KEY + ":first_run"
        await redis.set(first_key, now.isoformat(), nx=True)
        last_ok = await redis.get(LAST_OK_KEY)
        first = await redis.get(first_key)
        if stale(_dec(last_ok), now, _dec(first)):
            return [("unreadable", f"{_WHERE}: no successful read for "
                     f"{READ_STALE_HOURS} h",
                     "The daily check of our on-chain identity can't read Base. Check "
                     "ETH_RPC_URL / BASE_RPC_URL and the Alchemy app (Base enabled).")]
        return []
    await redis.set(LAST_OK_KEY, now.isoformat())
    return compare(agent.owner, agent.registration_uri)


async def run_self_watch(now: datetime | None = None) -> list[str]:
    """Evaluate and alert (deduped per condition for 24 h). Returns the conditions
    alerted this call. Never raises."""
    alerted: list[str] = []
    try:
        from src.jobs.behavioral_eval import notify_admins
        from src.redis_client import get_redis

        r = get_redis()
        for cond, title, body in await evaluate(now, redis=r):
            if not await r.set(f"{DEDUPE_PREFIX}{cond}", "1", nx=True, ex=DEDUPE_TTL):
                continue
            logger.warning("erc8004 self watch: %s: %s", title, body)
            await notify_admins(title, body, reference_id=f"erc8004-self:{cond}",
                                payload={"type": WEBHOOK_TYPE, "event": cond,
                                         "chain": CHAIN, "agent_id": AGENT_ID,
                                         "title": title, "body": body})
            alerted.append(cond)
    except Exception:
        logger.debug("erc8004 self watch failed", exc_info=True)
    return alerted
