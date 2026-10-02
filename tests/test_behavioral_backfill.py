"""The ranked, low-priority backfill: most-used first, skips what is done or cached, stops
when the sandbox is busy, and reports progress."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest

from src.jobs import behavioral_backfill as bf


class _Redis:
    def __init__(self):
        self.h: dict[str, dict[str, str]] = {}
        self.counters: dict[str, int] = {}

    async def hgetall(self, key):
        return dict(self.h.get(key, {}))

    async def hset(self, key, field=None, value=None, mapping=None, **kw):
        bucket = self.h.setdefault(key, {})
        if field is not None:
            bucket[field] = str(value)
        bucket.update({k: str(v) for k, v in (mapping or {}).items()})

    async def incrby(self, key, by):
        self.counters[key] = self.counters.get(key, 0) + by
        return self.counters[key]

    async def expire(self, key, ttl):
        return True

    async def sadd(self, key, *members):
        self.h.setdefault(key, {}).update({m: "1" for m in members})
        return len(members)


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _DB:
    """Rows in the order the eligibility query would return them (adoption desc)."""
    def __init__(self, rows):
        self.rows = rows

    async def scalar(self, q):
        return len(self.rows)

    async def execute(self, q):
        # eligible_rows_query(limit, offset): emulate paging from the compiled statement
        lim = getattr(q, "_limit_clause", None)
        off = getattr(q, "_offset_clause", None)
        limit = int(lim.value) if lim is not None else len(self.rows)
        offset = int(off.value) if off is not None else 0
        return _Result(self.rows[offset: offset + limit])


@pytest.fixture
def env(monkeypatch):
    r = _Redis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    import src.config as config
    monkeypatch.setattr(config.settings, "scanner_behavioral_enabled", True, raising=False)
    monkeypatch.setattr(config.settings, "behavioral_backfill_enabled", True, raising=False)
    return r


def _wire(monkeypatch, rows, scan_data, cached, outcomes):
    """rows: [(surface, owner, repo)]; scan_data: member -> dict|None; cached: set of names
    with a cached block; outcomes: list of enqueue results in order."""
    import src.database as database
    from src.api import public_scan_router as psr
    from src.scanner.behavioral import trigger

    @asynccontextmanager
    async def session():
        yield _DB(rows)
    monkeypatch.setattr(database, "async_session", session)

    async def fake_cached_scan(surface, owner, repo, stale=True):
        return scan_data.get(f"{surface}:{owner}/{repo}")
    monkeypatch.setattr(trigger, "cached_scan_data", fake_cached_scan)

    async def fake_block(surface, name, declared, plan=None):
        return {"ran": True} if name in cached else None
    monkeypatch.setattr(psr, "_get_cached_behavioral", fake_block)
    calls = []

    async def fake_enqueue(data, *, reason, priority="normal"):
        calls.append((data["package_coordinate"]["name"], reason, priority))
        return outcomes[len(calls) - 1] if len(calls) - 1 < len(outcomes) else "started"
    monkeypatch.setattr(trigger, "enqueue_behavioral", fake_enqueue)
    return calls


def _pkg(name):
    return {"package_coordinate": {"surface": "npm", "name": name}}


def test_backfill_walks_most_used_first_and_skips_done_cached_and_unscanned(env, monkeypatch):
    rows = [("npm", "npm", "a"), ("npm", "npm", "b"), ("npm", "npm", "c"), ("npm", "npm", "d")]
    scan = {"npm:npm/a": _pkg("a"), "npm:npm/b": _pkg("b"), "npm:npm/c": None,
            "npm:npm/d": _pkg("d")}
    env.h[bf.DONE_AT] = {"npm:npm/a": "2099-01-01T00:00:00+00:00|started"}
    calls = _wire(monkeypatch, rows, scan, cached={"b"}, outcomes=["started"])
    stats = asyncio.run(bf.run_behavioral_backfill(batch=6))
    assert calls == [("d", "backfill", "low")]          # a: done recently, b: cached, c: no scan
    assert stats["started"] == 1 and stats["skipped"] == 2 and stats["attempted"] == 1
    assert env.h[bf.DONE_AT]["npm:npm/d"]
    prog = env.h[bf.PROGRESS]
    assert prog["total_eligible"] == "4" and prog["last_started"] == "1"


def test_backfill_stops_at_the_first_deferral(env, monkeypatch):
    rows = [("npm", "npm", "a"), ("npm", "npm", "b"), ("npm", "npm", "c")]
    scan = {k: _pkg(k[-1]) for k in ("npm:npm/a", "npm:npm/b", "npm:npm/c")}
    calls = _wire(monkeypatch, rows, scan, cached=set(), outcomes=["started", "deferred"])
    stats = asyncio.run(bf.run_behavioral_backfill(batch=6))
    assert [c[0] for c in calls] == ["a", "b"]           # c never attempted this pass
    assert stats["deferred"] == 1 and stats["started"] == 1
    assert "npm:npm/b" not in env.h.get(bf.DONE_AT, {})  # a deferral is retried next pass


def test_backfill_respects_the_batch_size(env, monkeypatch):
    rows = [("npm", "npm", str(i)) for i in range(10)]
    scan = {f"npm:npm/{i}": _pkg(str(i)) for i in range(10)}
    calls = _wire(monkeypatch, rows, scan, cached=set(), outcomes=[])
    stats = asyncio.run(bf.run_behavioral_backfill(batch=3))
    assert len(calls) == 3 and stats["attempted"] == 3


def test_backfill_is_off_when_disabled(env, monkeypatch):
    import src.config as config
    monkeypatch.setattr(config.settings, "behavioral_backfill_enabled", False, raising=False)
    calls = _wire(monkeypatch, [("npm", "npm", "a")], {"npm:npm/a": _pkg("a")}, set(), [])
    stats = asyncio.run(bf.run_behavioral_backfill())
    assert stats.get("disabled") is True and calls == []


def test_recent_attempt_window():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(days=2)).isoformat() + "|started"
    old = (now - timedelta(days=9)).isoformat() + "|started"
    assert bf.attempted_recently(fresh, now, 7) is True
    assert bf.attempted_recently(old, now, 7) is False
    assert bf.attempted_recently("garbage", now, 7) is False
