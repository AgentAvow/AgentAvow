"""Leak-proof sandbox slots, the wait queue, truthful pending (src/scanner/behavioral/slots.py
and the router around it).

The 2026-10-08 incident: the old INCR counter leaked to max when a deploy killed two
runs, and its TTL never ran out because rejected attempts refreshed it. These tests pin
the replacement: per-slot keys that expire on their own, compare-and-delete release, no
TTL write on a rejected attempt, slot 0 kept for user-facing runs, a deduped priority
queue instead of dropping, and a pending state that tells the truth and ends.

Most tests use the dict fake (``--noconftest`` safe); the ``real_redis`` ones run the
Lua scripts and ZADD LT against the Redis at ``REDIS_URL`` and skip without one.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

import pytest

import src.api.public_scan_router as router
from src.scanner.behavioral import runner as behavioral_runner
from src.scanner.behavioral import slots
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.verdict import decide
from tests.behavioral_fake_redis import SlotFakeRedis


@pytest.fixture
def fake_redis(monkeypatch):
    r = SlotFakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    monkeypatch.setattr(router.settings, "scanner_behavioral_max_concurrent", 2, raising=False)
    return r


@pytest.fixture
def runs(monkeypatch):
    """Fake sandbox: records calls; ``gate`` (an Event) holds a run until set."""
    state = {"calls": [], "gate": None}

    async def fake_run(surface, coordinate, **kw):
        state["calls"].append(coordinate)
        if state["gate"] is not None:
            await state["gate"].wait()
        return BehavioralResult(ran=True, surface=surface, coordinate=coordinate,
                                plan=kw.get("plan") or surface, egress_hosts=[])

    monkeypatch.setattr(behavioral_runner, "run_behavioral", fake_run)
    return state


async def _settle(n: int = 10):
    for _ in range(n):
        await asyncio.sleep(0)


def _pkg(name: str) -> dict:
    return {"package_coordinate": {"surface": "npm", "name": name}}


def _member(name: str) -> str:
    return router._behavioral_cache_key("npm", name)


def _hold(r, *tokens, ttl: float = 300):
    """Leases other runs hold (expiring ``ttl`` s from now; negative = already expired)."""
    z = r.zsets.setdefault(slots.LEASES_KEY, {})
    for t in tokens:
        z[t] = time.time() + ttl


def _leases(r) -> dict:
    return dict(r.zsets.get(slots.LEASES_KEY, {}))


# ── slots: acquire / release / expiry ────────────────────────────────────────
async def test_acquire_takes_leases_up_to_the_cap(fake_redis):
    a = await slots.acquire_slot(lock_key="L")
    b = await slots.acquire_slot()
    assert a.token != b.token and a.token.endswith("|L")
    assert await slots.acquire_slot() is None
    assert set(_leases(fake_redis)) == {a.token, b.token}  # the rejected taker left none
    assert await slots.release_slot(a) is True
    assert await slots.acquire_slot() is not None


async def test_release_removes_only_its_own_lease(fake_redis):
    a = await slots.acquire_slot()
    b = await slots.acquire_slot()
    assert await slots.release_slot(a) is True
    assert await slots.release_slot(a) is False  # twice is a no-op
    assert set(_leases(fake_redis)) == {b.token}
    assert await router.behavioral_slots_in_use() == 1


async def test_a_dead_holders_lease_expires_on_its_own(fake_redis):
    """The incident: a deploy killed two runs mid-flight. Their leases simply expire and
    are swept by the next acquire — however much traffic arrives meanwhile."""
    _hold(fake_redis, "dead-1|", "dead-2|", ttl=-1)
    a = await slots.acquire_slot()
    assert a is not None
    assert set(_leases(fake_redis)) == {a.token}


async def test_rejected_attempts_do_not_extend_a_lease(fake_redis):
    _hold(fake_redis, "a|", "b|", ttl=100)
    before = _leases(fake_redis)
    ttl_writes = list(fake_redis.ttl_writes)
    for _ in range(5):
        assert await slots.acquire_slot() is None
        assert await slots.acquire_slot("low") is None
    assert _leases(fake_redis) == before
    assert fake_redis.ttl_writes == ttl_writes  # not even the key TTL


async def test_heartbeat_refreshes_only_its_own_lease(fake_redis):
    a = await slots.acquire_slot(lock_key="behavioral:npm:x:lock")
    fake_redis.store["behavioral:npm:x:lock"] = "1"
    fake_redis.zsets[slots.LEASES_KEY][a.token] = time.time() + 5
    assert await slots.refresh_slot(a, lock_ttl=600) is True
    assert _leases(fake_redis)[a.token] > time.time() + slots.SLOT_TTL - 5
    assert fake_redis.ttls["behavioral:npm:x:lock"] == 600
    # swept (it expired): the heartbeat must not resurrect it
    del fake_redis.zsets[slots.LEASES_KEY][a.token]
    assert await slots.refresh_slot(a, lock_ttl=600) is False
    assert a.token not in _leases(fake_redis)


async def test_low_priority_keeps_one_slot_free(fake_redis):
    low = await slots.acquire_slot("low")
    assert low is not None
    assert await slots.acquire_slot("low") is None  # only one left: kept for viewers
    assert await slots.acquire_slot("normal") is not None  # a viewer still gets in


async def test_low_waits_while_a_viewer_holds_a_slot(fake_redis):
    _hold(fake_redis, "viewer|")
    assert await slots.acquire_slot("low") is None


async def test_low_never_runs_with_a_single_slot(fake_redis, monkeypatch):
    monkeypatch.setattr(router.settings, "scanner_behavioral_max_concurrent", 1, raising=False)
    assert await slots.acquire_slot("low") is None
    assert _leases(fake_redis) == {}


async def test_normal_fails_open_and_low_fails_closed_without_redis(monkeypatch):
    def boom():
        raise ConnectionError("down")

    monkeypatch.setattr("src.redis_client.get_redis", boom)
    h = await slots.acquire_slot()
    assert h is not None and h.leased is False
    assert await slots.release_slot(h) is False  # nothing to release, no raise
    assert await slots.acquire_slot("low") is None


async def test_legacy_counter_is_deleted_and_logged(fake_redis, caplog):
    fake_redis.store[slots.LEGACY_SLOTS_KEY] = "2"
    with caplog.at_level(logging.WARNING):
        assert await slots.cleanup_legacy_counter() is True
    assert slots.LEGACY_SLOTS_KEY not in fake_redis.store
    assert "legacy slot counter" in caplog.text
    assert await slots.cleanup_legacy_counter() is False
    # and the new code ignores it: a stale "2" never blocks a slot
    fake_redis.store[slots.LEGACY_SLOTS_KEY] = "2"
    assert await slots.acquire_slot() is not None


# ── queue ────────────────────────────────────────────────────────────────────
async def test_queue_dedupes_and_viewers_rank_first(fake_redis):
    assert await slots.enqueue("m-low", {"n": 1}, "low") == 0
    assert await slots.enqueue("m-a", {"n": 2}, "normal") == 0
    assert await slots.enqueue("m-b", {"n": 3}, "normal") == 1
    assert await slots.enqueue("m-a", {"n": 2}, "normal") == 0  # repeat collapses
    assert await slots.queue_depth() == 3
    # a low entry asked for again by a viewer moves up to the viewer band
    assert await slots.enqueue("m-low", {"n": 1}, "normal") == 2
    assert slots.score_priority(fake_redis.zsets[slots.QUEUE_KEY]["m-low"]) == "normal"
    # and a later low request never demotes it
    await slots.enqueue("m-low", {"n": 1}, "low")
    assert slots.score_priority(fake_redis.zsets[slots.QUEUE_KEY]["m-low"]) == "normal"


async def test_forced_request_survives_a_plain_repeat(fake_redis):
    await slots.enqueue("m", {"x": 1, "force": True}, "normal")
    await slots.enqueue("m", {"x": 1}, "normal")
    assert json.loads(fake_redis.hashes[slots.QUEUE_PAYLOAD_KEY]["m"])["force"] is True


async def test_full_queue_drops_the_oldest_lowest_priority(fake_redis, monkeypatch):
    monkeypatch.setattr(slots, "QUEUE_MAX", 3)
    t = iter(range(100, 200))
    monkeypatch.setattr(slots.time, "time", lambda: float(next(t)))
    await slots.enqueue("low-old", {}, "low")
    await slots.enqueue("low-new", {}, "low")
    await slots.enqueue("viewer-1", {}, "normal")
    await slots.enqueue("viewer-2", {}, "normal")
    members = set(fake_redis.zsets[slots.QUEUE_KEY])
    assert members == {"low-new", "viewer-1", "viewer-2"}
    assert "low-old" not in fake_redis.hashes[slots.QUEUE_PAYLOAD_KEY]


async def test_drain_order_and_stops_when_no_slot(fake_redis, monkeypatch):
    t = iter(range(100, 200))
    monkeypatch.setattr(slots.time, "time", lambda: float(next(t)))
    for m, p in (("low-1", "low"), ("viewer-1", "normal"), ("viewer-2", "normal")):
        await slots.enqueue(m, {"m": m}, p)
    seen: list[tuple[str, str]] = []
    free = {"n": 2}

    async def start(payload, priority):
        seen.append((payload["m"], priority))
        if free["n"] == 0:
            return "no_slot"
        free["n"] -= 1
        return "started"

    assert await slots.drain(start) == 2
    assert seen == [("viewer-1", "normal"), ("viewer-2", "normal"), ("low-1", "low")]
    assert list(fake_redis.zsets[slots.QUEUE_KEY]) == ["low-1"]  # waits for a slot


async def test_drain_skips_entries_that_no_longer_need_a_run(fake_redis):
    await slots.enqueue("cached", {"m": "cached"}, "normal")
    await slots.enqueue("running", {"m": "running"}, "normal")

    async def start(payload, priority):
        return "cached" if payload["m"] == "cached" else "locked"

    assert await slots.drain(start) == 0
    assert await slots.queue_depth() == 0


# ── router: pending tells the truth ──────────────────────────────────────────
async def test_viewer_with_no_slot_is_queued_not_running(fake_redis, runs):
    _hold(fake_redis, "a|", "b|")
    block = await router._behavioral_block(_pkg("busy"))
    assert block["pending"] is True and block["state"] == "queued"
    assert block["queue_position"] == 1
    assert "waiting for a sandbox slot" in block["reason"]
    assert "reload in ~1 min" not in block["reason"]
    assert runs["calls"] == []
    d = decide({"trust_score": 90, "metadata": {"files_scanned": 300}, "behavioral": block})
    assert d.final is False and d.reason.endswith("; waiting for a sandbox slot")


async def test_running_state_only_when_a_run_is_in_flight(fake_redis, runs):
    runs["gate"] = asyncio.Event()
    first = await router._behavioral_block(_pkg("p"))
    assert first["state"] == "running"
    await _settle()
    again = await router._behavioral_block(_pkg("p"))  # lock held → genuinely running
    assert again["state"] == "running" and again["reason"] == router.BEHAVIORAL_RUNNING_REASON
    runs["gate"].set()
    await _settle()
    done = await router._behavioral_block(_pkg("p"))
    assert done["ran"] is True
    assert slots.PENDING_PREFIX + _member("p") not in fake_redis.store  # cleared on success


async def test_pending_age_limit_makes_the_static_result_final(fake_redis, runs):
    _hold(fake_redis, "a|", "b|")
    first = await router._behavioral_block(_pkg("stuck"))
    assert first["pending"] is True
    since = float(fake_redis.store[slots.PENDING_PREFIX + _member("stuck")])
    fake_redis.store[slots.PENDING_PREFIX + _member("stuck")] = str(
        since - slots.PENDING_MAX_AGE - 1)
    late = await router._behavioral_block(_pkg("stuck"))
    assert late == {"ran": False, "pending": False, "state": "unavailable",
                    "reason": "sandbox unavailable, static analysis only"}
    d = decide({"trust_score": 90, "metadata": {"files_scanned": 300}, "behavioral": late})
    assert d.final is True and "sandbox" not in d.reason
    # still queued, so it runs once a slot frees
    assert await slots.queue_position(_member("stuck")) == 0


async def test_slot_release_drains_the_queue(fake_redis, runs):
    runs["gate"] = asyncio.Event()
    await router._behavioral_block(_pkg("one"))
    await router._behavioral_block(_pkg("two"))
    await _settle()
    queued = await router._behavioral_block(_pkg("three"))
    assert queued["state"] == "queued"
    assert runs["calls"] == ["one", "two"]
    runs["gate"].set()
    await _settle(30)
    assert runs["calls"] == ["one", "two", "three"]
    assert await slots.queue_depth() == 0
    assert _leases(fake_redis) == {}


async def test_low_priority_context_queues_in_the_low_band(fake_redis, runs):
    _hold(fake_redis, "viewer|")
    with slots.low_priority():
        block = await router._behavioral_block(_pkg("catalog"))
    assert block["state"] == "queued"
    assert set(_leases(fake_redis)) == {"viewer|"}  # the last slot stayed free for viewers
    assert slots.score_priority(fake_redis.zsets[slots.QUEUE_KEY][_member("catalog")]) == "low"


async def test_shutdown_cancels_runs_frees_slots_and_requeues(fake_redis, runs):
    runs["gate"] = asyncio.Event()  # never set: the run would hang
    await router._behavioral_block(_pkg("inflight"))
    await _settle()
    assert _leases(fake_redis)
    assert await slots.shutdown(timeout=1) == 1
    assert _leases(fake_redis) == {}
    assert _member("inflight") + ":lock" not in fake_redis.store
    assert await slots.queue_position(_member("inflight")) == 0  # runs after the restart


async def test_a_killed_task_gives_its_slot_back(fake_redis, runs):
    runs["gate"] = asyncio.Event()
    await router._behavioral_block(_pkg("k"))
    await _settle()
    task = next(iter(slots._RUN_TASKS))
    task.cancel()
    await _settle()
    assert _leases(fake_redis) == {}


# ── watchdog ─────────────────────────────────────────────────────────────────
async def test_watchdog_warns_when_slots_are_held_with_no_run(fake_redis, caplog):
    _hold(fake_redis, "r1|behavioral:npm:a:lock", "r2|behavioral:npm:b:lock", ttl=10**6)
    with caplog.at_level(logging.WARNING):
        assert await slots.check_health(now=1000.0) == []
        assert await slots.check_health(now=1000.0 + 16 * 60)
    assert "no run in flight" in caplog.text
    # a live lock behind a slot means a real run: no warning, and the clock resets
    fake_redis.store["behavioral:npm:a:lock"] = "1"
    assert await slots.check_health(now=1000.0 + 40 * 60) == []
    assert slots.STUCK_KEY not in fake_redis.store


async def test_watchdog_warns_when_rejections_rise_and_runs_stay_flat(fake_redis, caplog):
    tot = f"{slots.METRICS_PREFIX}:total"
    fake_redis.store[f"{tot}:slot_rejected"] = "5"
    fake_redis.store[f"{tot}:runs"] = "40"
    await slots.check_health(now=0.0)
    fake_redis.store[f"{tot}:slot_rejected"] = "60"
    assert await slots.check_health(now=1800.0) == []  # under an hour: not judged yet
    with caplog.at_level(logging.WARNING):
        out = await slots.check_health(now=3700.0)
    assert out and "55 slot rejections" in out[0]
    fake_redis.store[f"{tot}:slot_rejected"] = "100"
    fake_redis.store[f"{tot}:runs"] = "41"
    assert await slots.check_health(now=7400.0) == []  # runs moved: healthy


async def test_rejections_feed_the_lifetime_total(fake_redis):
    await router._bump_behavioral("slot_rejected")
    assert int(fake_redis.store[f"{slots.METRICS_PREFIX}:total:slot_rejected"]) == 1


# ── MCP text ─────────────────────────────────────────────────────────────────
def test_mcp_sandbox_text_for_each_pending_state():
    from src.bridges.mcp_streamable import _sandbox_section, _sandbox_struct
    queued = {"behavioral": {"ran": False, "pending": True, "state": "queued",
                             "queue_position": 2, "reason": "waiting"}}
    line = _sandbox_section(queued)[0]
    assert "waiting for a free sandbox slot (position 2 in the queue)" in line
    assert "running now" not in line
    assert _sandbox_struct(queued)["state"] == "queued"
    assert _sandbox_struct(queued)["queue_position"] == 2
    running = {"behavioral": {"ran": False, "pending": True, "state": "running"}}
    assert "running now" in _sandbox_section(running)[0]
    gone = {"behavioral": {"ran": False, "pending": False, "state": "unavailable",
                           "reason": "sandbox unavailable, static analysis only"}}
    assert "static analysis only" in _sandbox_section(gone)[0]
    assert _sandbox_struct(gone)["pending"] is False


# ── internal callers of public_scan ──────────────────────────────────────────
async def test_internal_public_scan_call_no_longer_forces(monkeypatch):
    """An omitted ``force`` / ``behavioral`` is FastAPI's Query(False) object — truthy.
    It used to force a fresh scan plus an inline sandbox run on every internal call."""
    class ReachedError(Exception):
        pass

    async def fake_get_cached(owner, repo):
        raise ReachedError

    monkeypatch.setattr(router, "_get_cached", fake_get_cached)
    with pytest.raises(ReachedError):  # the cache is consulted: not forced
        await router.public_scan(owner="acme", repo="widget", db=None)


# ── real Redis: the Lua scripts and ZADD LT ──────────────────────────────────
@pytest.fixture
async def real_redis(monkeypatch):
    url = os.environ.get("REDIS_URL")
    if not url:
        pytest.skip("REDIS_URL not set")
    import redis.asyncio as aioredis
    r = aioredis.from_url(url, decode_responses=True)
    try:
        await r.ping()
    except Exception:
        pytest.skip("no Redis")
    keys = [slots.LEASES_KEY, slots.QUEUE_KEY, slots.QUEUE_PAYLOAD_KEY, slots.LEGACY_SLOTS_KEY]
    await r.delete(*keys)
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    monkeypatch.setattr(router.settings, "scanner_behavioral_max_concurrent", 2, raising=False)
    yield r
    await r.delete(*keys)
    await r.aclose()


async def test_real_redis_lease_lifecycle(real_redis):
    r = real_redis
    a = await slots.acquire_slot(lock_key="L")
    b = await slots.acquire_slot()
    assert await r.zcard(slots.LEASES_KEY) == 2
    exp_a = await r.zscore(slots.LEASES_KEY, a.token)
    assert await slots.acquire_slot() is None                     # rejected...
    assert await r.zscore(slots.LEASES_KEY, a.token) == exp_a      # ...extended nothing
    assert await r.zcard(slots.LEASES_KEY) == 2                    # ...and left nothing
    await r.zadd(slots.LEASES_KEY, {a.token: 1.0})                  # a's lease expired
    c = await slots.acquire_slot()                                 # swept + taken
    assert c is not None and await r.zscore(slots.LEASES_KEY, a.token) is None
    assert await slots.refresh_slot(a) is False                    # no resurrection
    assert await r.zscore(slots.LEASES_KEY, a.token) is None
    assert await slots.refresh_slot(b) is True
    assert await slots.release_slot(b) is True and await slots.release_slot(c) is True
    assert await r.zcard(slots.LEASES_KEY) == 0


async def test_real_redis_queue_lt_and_drop(real_redis, monkeypatch):
    monkeypatch.setattr(slots, "QUEUE_MAX", 2)
    await slots.enqueue("x", {}, "low")
    await slots.enqueue("y", {}, "low")
    await slots.enqueue("x", {}, "normal")  # upgrade via LT
    assert slots.score_priority(await real_redis.zscore(slots.QUEUE_KEY, "x")) == "normal"
    await slots.enqueue("z", {}, "normal")  # full: drops the oldest low ("y")
    assert set(await real_redis.zrange(slots.QUEUE_KEY, 0, -1)) == {"x", "z"}
