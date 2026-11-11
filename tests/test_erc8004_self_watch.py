"""The watch on AgentAvow's own ERC-8004 identity (design note section 4): one read of
ownerOf + tokenURI on Base, compared with what we registered; alerts deduped daily."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.jobs import erc8004_self_watch as w
from src.scanner import erc8004_agent as ea

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 12, 12, tzinfo=timezone.utc)


class _Redis:
    def __init__(self):
        self.d = {}

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.d:
            return False
        self.d[k] = v
        return True

    async def get(self, k):
        return self.d.get(k)


def _agent(owner=w.EXPECTED_OWNER, uri=w.EXPECTED_URI):
    return ea.OnChainAgent(chain="base", chain_id=8453, agent_id=w.AGENT_ID, owner=owner,
                           agent_wallet=owner, registration_uri=uri, block=1)


def _read(value=None, exc=None):
    async def read():
        if exc:
            raise exc
        return value
    return read


async def test_unchanged_identity_is_quiet():
    r = _Redis()
    assert await w.evaluate(NOW, read=_read(_agent()), redis=r) == []
    assert r.d[w.LAST_OK_KEY] == NOW.isoformat()


async def test_owner_compare_ignores_checksum_case():
    assert await w.evaluate(NOW, read=_read(_agent(owner=w.EXPECTED_OWNER.upper()
                                                   .replace("0X", "0x"))),
                            redis=_Redis()) == []


@pytest.mark.parametrize("kw,cond", [
    ({"uri": "https://evil.example/agent.json"}, "uri_changed"),
    ({"uri": ""}, "uri_changed"),
    ({"owner": "0x" + "1" * 40}, "owner_changed"),
])
async def test_changes_alert(kw, cond):
    out = await w.evaluate(NOW, read=_read(_agent(**kw)), redis=_Redis())
    assert [c for c, _, _ in out] == [cond]


async def test_unminted_alerts():
    out = await w.evaluate(NOW, read=_read(exc=ea.AgentNotFoundError(1)), redis=_Redis())
    assert [c for c, _, _ in out] == ["not_found"]


async def test_rpc_outage_alerts_only_after_48h():
    r = _Redis()
    down = _read(exc=ea.ChainUnavailableError("base"))
    assert await w.evaluate(NOW, read=down, redis=r) == []          # first failure
    assert await w.evaluate(NOW + timedelta(hours=47), read=down, redis=r) == []
    out = await w.evaluate(NOW + timedelta(hours=49), read=down, redis=r)
    assert [c for c, _, _ in out] == ["unreadable"]
    # a success resets the clock
    await w.evaluate(NOW + timedelta(hours=50), read=_read(_agent()), redis=r)
    assert await w.evaluate(NOW + timedelta(hours=60), read=down, redis=r) == []


async def test_alerts_are_deduped_daily(monkeypatch):
    r = _Redis()
    sent = []

    async def notify(title, body, *, reference_id, payload):
        sent.append(payload["event"])
        return {}
    import src.jobs.behavioral_eval as be
    import src.redis_client as rc
    monkeypatch.setattr(be, "notify_admins", notify)
    monkeypatch.setattr(rc, "get_redis", lambda: r)

    async def bad(now=None, *, read=None, redis=None):
        return w.compare("0x" + "2" * 40, "https://x.example")
    monkeypatch.setattr(w, "evaluate", bad)
    assert sorted(await w.run_self_watch(NOW)) == ["owner_changed", "uri_changed"]
    assert await w.run_self_watch(NOW) == []
    assert sorted(sent) == ["owner_changed", "uri_changed"]


def test_expected_uri_is_the_file_we_serve_and_lists_this_agent():
    # The constants must match the hosted registration file (PR #321 fills registrations).
    doc = json.loads((ROOT / "web/public/.well-known/agent-registration.json").read_text())
    assert w.EXPECTED_URI == "https://agentavow.com/.well-known/agent-registration.json"
    regs = doc.get("registrations") or []
    assert all(r["agentId"] == w.AGENT_ID for r in regs)
    assert w.EXPECTED_OWNER == w.EXPECTED_OWNER.lower() and len(w.EXPECTED_OWNER) == 42
