"""Sandbox slots that cannot leak, the wait queue, and a slot watchdog.

The sandbox box runs at most ``scanner_behavioral_max_concurrent`` runs at once. This
used to be one Redis INCR counter given back in a task's ``finally``. A deploy that
killed the task never gave the slot back, and the counter's TTL never ran out because
every attempt (including rejected ones) refreshed it, so the tier went quiet for good.

Slots (a sorted set of leases, ``behavioral:slots:leases``)
  member = ``<run id>|<coordinate lock key>``, score = the unix time the lease expires.
  Expired leases are swept on every acquire, so a holder that died (a deploy killed the
  container mid-run) frees its slot within ``SLOT_TTL`` however much traffic arrives.
  Add-then-count keeps the cap exact under races; a taker that finds the cap reached
  removes its own lease again and writes nothing else (no TTL is refreshed). A run's
  heartbeat pushes out ONLY its own lease (``ZADD XX``), release removes only its own
  member, so nobody can free or extend someone else's slot. Low priority takes a lease
  only while one slot would still be free after it (slot 0 stays open for user-facing
  runs); normal may take the last one.

Queue (instead of dropping a request that finds no slot)
  ``behavioral:queue`` ZSET, member = the coordinate's cache key, score =
  ``band * BAND + epoch seconds`` (band 0 = viewer / watch, 1 = re-score / backfill),
  so viewer requests drain first and, within a band, oldest first. A repeat collapses
  onto the existing member (ZADD LT keeps the better score). The run arguments live in
  ``behavioral:queue:payload`` (hash). Bounded at ``QUEUE_MAX``: the oldest entry of the
  lowest-priority band is dropped. Drained when a slot frees and by the periodic loop.

Pending age
  ``behavioral:pending_since:<cache key>`` = when a viewer first got "pending" for a
  coordinate. Past ``PENDING_MAX_AGE`` with no run in flight the API stops saying pending
  and serves the static result as final.

Every function is best-effort: Redis trouble never raises into a request.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

LEASES_KEY = "behavioral:slots:leases"
LEGACY_SLOTS_KEY = "behavioral:slots:active"
# > the longest run (135 s + 300 s memory retry + SSM slack, ~480 s seen) with the
# heartbeat keeping a live run's lease fresh; a dead holder's slot is free in <= 10 min.
SLOT_TTL = 600
HEARTBEAT_SEC = 120

QUEUE_KEY = "behavioral:queue"
QUEUE_PAYLOAD_KEY = "behavioral:queue:payload"
QUEUE_MAX = 500
BAND = 10_000_000_000  # > any epoch-seconds value, so the band dominates the score
PRIORITY_BAND = {"normal": 0, "low": 1}

PENDING_PREFIX = "behavioral:pending_since:"
PENDING_MAX_AGE = 2 * 3600
PENDING_KEY_TTL = 24 * 3600

STUCK_KEY = "behavioral:health:stuck_since"
STUCK_WARN_SEC = 15 * 60
HEALTH_SNAP_KEY = "behavioral:health:snap"
HEALTH_SNAP_SEC = 3600
HEALTH_MIN_REJECTIONS = 10
METRICS_PREFIX = "ag:metrics:behavioral"


# Who is asking for a run. The catalog re-score calls the public scan endpoint itself;
# it wraps the call in ``low_priority()`` so the sandbox run it triggers is LOW.
_priority: contextvars.ContextVar[str] = contextvars.ContextVar(
    "behavioral_priority", default="normal")


@contextlib.contextmanager
def low_priority():
    token = _priority.set("low")
    try:
        yield
    finally:
        _priority.reset(token)


def current_priority() -> str:
    return _priority.get()


def _redis():
    from src.redis_client import get_redis
    return get_redis()


def max_slots() -> int:
    from src.config import settings
    return max(1, int(getattr(settings, "scanner_behavioral_max_concurrent", 2) or 2))


@dataclass
class SlotHandle:
    token: str          # the lease member: "<run id>|<lock key>"
    lock_key: str = ""
    leased: bool = True  # False = Redis was unreachable and the caller ran fail-open


def _s(v: object) -> str | None:
    if v is None:
        return None
    return v.decode() if isinstance(v, bytes) else str(v)


def _lock_of(member: str) -> str:
    return member.split("|", 1)[1] if "|" in member else ""


# ── slots ────────────────────────────────────────────────────────────────────
async def acquire_slot(priority: str = "normal", *, lock_key: str = "") -> SlotHandle | None:
    """Take a lease or return None (having written nothing that outlives the call).

    ``low`` succeeds only while one slot would stay free after it; ``normal`` may take
    the last slot. Normal fails OPEN on a Redis error (a cache outage never silences the
    tier); low fails CLOSED."""
    limit = max_slots()
    token = f"{uuid.uuid4().hex}|{lock_key}"
    free_after = 1 if priority == "low" else 0
    try:
        if limit - free_after < 1:
            return None
        r = _redis()
        now = time.time()
        await r.zremrangebyscore(LEASES_KEY, "-inf", now)
        await r.zadd(LEASES_KEY, {token: now + SLOT_TTL})
        if int(await r.zcard(LEASES_KEY) or 0) > limit - free_after:
            await r.zrem(LEASES_KEY, token)
            return None
        await r.expire(LEASES_KEY, SLOT_TTL * 2)  # only on success; the scores decide
        return SlotHandle(token, lock_key)
    except Exception:
        logger.debug("slot acquire failed", exc_info=True)
        return SlotHandle(token, lock_key, leased=False) if priority != "low" else None


async def release_slot(handle: SlotHandle | None) -> bool:
    """Give back our own lease (and only ours: the member is unique to this run)."""
    if not isinstance(handle, SlotHandle) or not handle.leased:
        return False
    try:
        return bool(await _redis().zrem(LEASES_KEY, handle.token))
    except Exception:
        logger.debug("slot release failed", exc_info=True)
        return False


async def refresh_slot(handle: SlotHandle | None, *, lock_ttl: int | None = None) -> bool:
    """Heartbeat: push our own lease's expiry out again (``ZADD XX`` never re-creates a
    lease that was swept), and the coordinate lock's, which must outlive a long run."""
    if not isinstance(handle, SlotHandle) or not handle.leased:
        return False
    try:
        r = _redis()
        if await r.zscore(LEASES_KEY, handle.token) is None:
            return False
        await r.zadd(LEASES_KEY, {handle.token: time.time() + SLOT_TTL}, xx=True)
        await r.expire(LEASES_KEY, SLOT_TTL * 2)
        if handle.lock_key and lock_ttl:
            await r.expire(handle.lock_key, lock_ttl)
        return True
    except Exception:
        return False


async def _heartbeat(handle: SlotHandle, lock_ttl: int | None) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_SEC)
        await refresh_slot(handle, lock_ttl=lock_ttl)


def start_heartbeat(handle: object, *, lock_ttl: int | None = None) -> asyncio.Task | None:
    if not isinstance(handle, SlotHandle) or not handle.leased:
        return None
    return asyncio.create_task(_heartbeat(handle, lock_ttl))


# In-process bookkeeping so app shutdown can cancel runs and hand their slots back.
_HELD: dict[str, SlotHandle] = {}
_RUN_TASKS: set[asyncio.Task] = set()


@contextlib.asynccontextmanager
async def holding(handle: SlotHandle | None, *, lock_ttl: int | None = None
                  ) -> AsyncIterator[None]:
    """Hold ``handle`` for the body: heartbeat while inside, release on the way out
    (also on cancellation)."""
    hb = start_heartbeat(handle, lock_ttl=lock_ttl)
    if isinstance(handle, SlotHandle):
        _HELD[handle.token] = handle
    try:
        yield
    finally:
        if hb is not None:
            hb.cancel()
        if isinstance(handle, SlotHandle):
            _HELD.pop(handle.token, None)
            await release_slot(handle)


def spawn(coro: Awaitable) -> asyncio.Task:
    """``asyncio.create_task`` that shutdown can find and cancel."""
    task = asyncio.ensure_future(coro)
    _RUN_TASKS.add(task)
    task.add_done_callback(_RUN_TASKS.discard)
    return task


async def shutdown(timeout: float = 5.0) -> int:
    """App shutdown (best effort): cancel in-flight run tasks so their ``finally`` gives
    the slots back, then release anything still registered. Returns tasks cancelled."""
    tasks = [t for t in list(_RUN_TASKS) if not t.done()]
    for t in tasks:
        t.cancel()
    if tasks:
        with contextlib.suppress(Exception):
            await asyncio.wait(tasks, timeout=timeout)
    for h in list(_HELD.values()):
        await release_slot(h)
        _HELD.pop(h.token, None)
    if tasks:
        logger.info("behavioral: cancelled %d in-flight sandbox run(s) on shutdown", len(tasks))
    return len(tasks)


async def cleanup_legacy_counter() -> bool:
    """Delete the pre-2026-10-08 INCR counter so a leaked value cannot outlive the deploy
    (the new code never reads it). True when a key was found."""
    try:
        r = _redis()
        val = await r.get(LEGACY_SLOTS_KEY)
        if val is None:
            return False
        await r.delete(LEGACY_SLOTS_KEY)
        logger.warning("behavioral: deleted legacy slot counter %s (value was %s)",
                       LEGACY_SLOTS_KEY, _s(val))
        return True
    except Exception:
        return False


async def slot_holders() -> list[str]:
    """The live (unexpired) lease members."""
    try:
        r = _redis()
        await r.zremrangebyscore(LEASES_KEY, "-inf", time.time())
        return [_s(m) for m in await r.zrange(LEASES_KEY, 0, -1)]
    except Exception:
        return []


async def slots_in_use() -> int:
    return len(await slot_holders())


# ── queue ────────────────────────────────────────────────────────────────────
def queue_score(priority: str, now: float | None = None) -> float:
    return PRIORITY_BAND.get(priority, 1) * BAND + (time.time() if now is None else now)


def score_priority(score: float) -> str:
    return "normal" if int(float(score) // BAND) == 0 else "low"


async def enqueue(member: str, payload: dict, priority: str = "normal") -> int | None:
    """Add (or collapse onto) a queue entry; returns its 0-based position, or None when
    the queue could not be written. A repeat keeps the better (lower) score; a forced
    re-run request sticks even when a later plain request collapses onto it."""
    try:
        r = _redis()
        old = _s(await r.hget(QUEUE_PAYLOAD_KEY, member))
        if old:
            with contextlib.suppress(Exception):
                if json.loads(old).get("force"):
                    payload = {**payload, "force": True}
        await r.hset(QUEUE_PAYLOAD_KEY, member, json.dumps(payload))
        await r.zadd(QUEUE_KEY, {member: queue_score(priority)}, lt=True)
        await _bump("queued")
        n = int(await r.zcard(QUEUE_KEY) or 0)
        while n > QUEUE_MAX:
            if not await _drop_one(r):
                break
            n -= 1
        pos = await r.zrank(QUEUE_KEY, member)
        return int(pos) if pos is not None else None
    except Exception:
        logger.debug("behavioral queue write failed", exc_info=True)
        return None


async def _drop_one(r) -> bool:
    """Drop the OLDEST entry of the LOWEST-priority band present."""
    last = await r.zrange(QUEUE_KEY, -1, -1, withscores=True)
    if not last:
        return False
    band = int(float(last[0][1]) // BAND)
    victim = await r.zrangebyscore(QUEUE_KEY, band * BAND, "+inf", start=0, num=1)
    if not victim:
        return False
    m = _s(victim[0])
    await r.zrem(QUEUE_KEY, m)
    await r.hdel(QUEUE_PAYLOAD_KEY, m)
    await _bump("queue_dropped")
    logger.info("behavioral queue full (%d): dropped %s", QUEUE_MAX, m)
    return True


async def queue_position(member: str) -> int | None:
    try:
        pos = await _redis().zrank(QUEUE_KEY, member)
        return int(pos) if pos is not None else None
    except Exception:
        return None


async def queue_depth() -> int:
    try:
        return int(await _redis().zcard(QUEUE_KEY) or 0)
    except Exception:
        return 0


# start(payload, priority) -> "started" | "no_slot" | anything else (= skip: cached,
# already running, ineligible). Defined by the router, which owns cache/lock/run.
StartFn = Callable[[dict, str], Awaitable[str]]


async def drain(start: StartFn, *, max_items: int = QUEUE_MAX) -> int:
    """Start queued runs, best first, until no slot is free. Returns runs started."""
    started = 0
    try:
        r = _redis()
        for _ in range(max_items):
            top = await r.zrange(QUEUE_KEY, 0, 0, withscores=True)
            if not top:
                break
            member, score = _s(top[0][0]), float(top[0][1])
            raw = _s(await r.hget(QUEUE_PAYLOAD_KEY, member))
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = None
            outcome = "skip"
            if isinstance(payload, dict):
                outcome = await start(payload, score_priority(score))
            if outcome == "no_slot":
                break
            await r.zrem(QUEUE_KEY, member)
            await r.hdel(QUEUE_PAYLOAD_KEY, member)
            if outcome == "started":
                started += 1
                await _bump("queue_started")
    except Exception:
        logger.debug("behavioral queue drain failed", exc_info=True)
    return started


# ── pending age ──────────────────────────────────────────────────────────────
async def pending_age(member: str) -> float:
    """Seconds since a viewer was first told this coordinate is pending (marks now when
    unmarked). 0 when Redis is unreachable."""
    try:
        r = _redis()
        now = time.time()
        await r.set(PENDING_PREFIX + member, str(now), nx=True, ex=PENDING_KEY_TTL)
        since = _s(await r.get(PENDING_PREFIX + member))
        return max(0.0, now - float(since)) if since else 0.0
    except Exception:
        return 0.0


async def clear_pending(member: str) -> None:
    with contextlib.suppress(Exception):
        await _redis().delete(PENDING_PREFIX + member)


# ── metrics + watchdog ───────────────────────────────────────────────────────
async def _bump(name: str, by: int = 1) -> None:
    with contextlib.suppress(Exception):
        from src.api.public_scan_router import _bump_behavioral
        await _bump_behavioral(name, by)


async def check_health(now: float | None = None) -> list[str]:
    """Periodic watchdog. WARNING (Sentry picks it up) when every slot has been held
    with no live run lock behind it for more than 15 min, or when rejections kept
    rising for an hour while no run completed. Returns the warnings logged."""
    now = time.time() if now is None else now
    warnings: list[str] = []
    try:
        r = _redis()
        holders = await slot_holders()
        orphaned = len(holders) >= max_slots()
        if orphaned:
            lock_keys = [_lock_of(h) for h in holders]
            if any(not k for k in lock_keys):
                orphaned = False  # a holder without a lock key: can't tell, assume live
            else:
                live = await r.mget(lock_keys)
                orphaned = all(v is None for v in live)
        if orphaned:
            await r.set(STUCK_KEY, str(now), nx=True, ex=24 * 3600)
            since = float(_s(await r.get(STUCK_KEY)) or now)
            if now - since > STUCK_WARN_SEC:
                msg = (f"behavioral sandbox: all {len(holders)} slots held with no run in "
                       f"flight for {int((now - since) / 60)} min — slots should expire on "
                       "their own; check the heartbeat / SLOT_TTL")
                logger.warning(msg)
                warnings.append(msg)
        else:
            await r.delete(STUCK_KEY)

        rej = int(_s(await r.get(f"{METRICS_PREFIX}:total:slot_rejected")) or 0)
        runs = int(_s(await r.get(f"{METRICS_PREFIX}:total:runs")) or 0)
        snap = await r.hgetall(HEALTH_SNAP_KEY) or {}
        snap = {_s(k): _s(v) for k, v in snap.items()}
        if not snap.get("ts"):
            await r.hset(HEALTH_SNAP_KEY, mapping={"ts": now, "rejected": rej, "runs": runs})
        elif now - float(snap["ts"]) >= HEALTH_SNAP_SEC:
            d_rej = rej - int(float(snap.get("rejected") or 0))
            d_runs = runs - int(float(snap.get("runs") or 0))
            if d_rej >= HEALTH_MIN_REJECTIONS and d_runs <= 0:
                msg = (f"behavioral sandbox: {d_rej} slot rejections and no completed run "
                       "in the last hour — slots may be stuck or the box is down")
                logger.warning(msg)
                warnings.append(msg)
            await r.hset(HEALTH_SNAP_KEY, mapping={"ts": now, "rejected": rej, "runs": runs})
    except Exception:
        logger.debug("behavioral slot health check failed", exc_info=True)
    return warnings
