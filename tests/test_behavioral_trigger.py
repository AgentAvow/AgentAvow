"""On-change sandbox trigger (src/scanner/behavioral/trigger.py).

``enqueue_behavioral`` resolves a run exactly like the viewer path and honours the
priority contract: a ``normal`` run takes any free slot, a ``low`` run only when one
slot would still be free for real scans. ``on_scan_change`` drops the cached block
and re-enqueues when a coordinate's version / tool digest moved; a watched coordinate
with no block is enqueued too. The scheduler loops call the hooks with the previous
cached scan as the baseline. Same style as test_behavioral_declared_scope.py: the
runner is a fake, redis is a dict. No DB (``--noconftest`` safe).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import src.api.public_scan_router as router
from src.scanner.behavioral import runner as behavioral_runner
from src.scanner.behavioral import trigger
from src.scanner.behavioral.runner import BehavioralResult

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
BM = "ag:metrics:behavioral"


class _FakeRedis:
    """Enough of redis.asyncio for the trigger + the router helpers it reuses."""

    def __init__(self):
        self.store: dict[str, object] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.sets: dict[str, set[str]] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def delete(self, *keys):
        n = 0
        for k in keys:
            n += 1 if self.store.pop(k, None) is not None else 0
        return n

    async def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def incrby(self, key, by):
        self.store[key] = int(self.store.get(key, 0)) + int(by)
        return self.store[key]

    async def decr(self, key):
        self.store[key] = int(self.store.get(key, 0)) - 1
        return self.store[key]

    async def expire(self, key, ttl):
        return True

    async def scan(self, cursor=0, match=None, count=None):
        import fnmatch
        keys = [k for k in list(self.store) if match is None or fnmatch.fnmatchcase(k, match)]
        return 0, keys

    async def mget(self, keys):
        return [self.store.get(k) for k in keys]

    async def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({str(k): str(v) for k, v in mapping.items()})
        if field is not None:
            h[str(field)] = str(value)
        return 1

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def sadd(self, key, *members):
        self.sets.setdefault(key, set()).update(members)
        return len(members)

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    # sorted sets (the sandbox slot leases)
    async def zadd(self, key, mapping):
        z = self.zsets.setdefault(key, {})
        z.update({m: float(s) for m, s in mapping.items()})
        return len(mapping)

    async def zrem(self, key, *members):
        z = self.zsets.get(key, {})
        return sum(1 for m in members if z.pop(m, None) is not None)

    async def zcard(self, key):
        return len(self.zsets.get(key, {}))

    async def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        lo = float("-inf") if lo == "-inf" else float(lo)
        dead = [m for m, s in z.items() if lo <= s <= float(hi)]
        for m in dead:
            z.pop(m)
        return len(dead)

    @property
    def zsets(self) -> dict[str, dict[str, float]]:
        if not hasattr(self, "_zsets"):
            self._zsets: dict[str, dict[str, float]] = {}
        return self._zsets


def _hold(r, n, *, expires_in=300.0):
    """Seed ``n`` live (or, with a negative ``expires_in``, already-expired) leases."""
    import time as _t
    z = r.zsets.setdefault(router._BEHAVIORAL_SLOTS_KEY, {})
    for _ in range(n):
        z[uuid.uuid4().hex] = _t.time() + expires_in


def _live(r):
    import time as _t
    return sum(1 for s in r.zsets.get(router._BEHAVIORAL_SLOTS_KEY, {}).values() if s > _t.time())


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    return r


@pytest.fixture
def captured_runs(monkeypatch):
    calls: list[dict] = []

    async def fake_run(surface, coordinate, **kw):
        calls.append({"surface": surface, "coordinate": coordinate, **kw})
        return BehavioralResult(ran=True, surface=surface, coordinate=coordinate,
                                plan=kw.get("plan") or surface, egress_hosts=[])

    monkeypatch.setattr(behavioral_runner, "run_behavioral", fake_run)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    monkeypatch.setattr(router.settings, "scanner_behavioral_max_concurrent", 2, raising=False)
    return calls


NPM = {"package_coordinate": {"surface": "npm", "name": "left-pad"},
       "artifact_scan": {"version": "1.3.0", "digest": "sha256:aaa"},
       "package_version": "1.3.0", "tool_manifest_digest": "sha256:m1"}


async def _settle():
    """Let the background run task (create_task) finish."""
    for _ in range(5):
        await asyncio.sleep(0)


def _counter(r, name):
    return int(r.store.get(f"{BM}:{name}:{TODAY}", 0))


# ── enqueue: returns + priority semantics ────────────────────────────────────
async def test_enqueue_normal_starts_a_run_and_counts_the_reason(fake_redis, captured_runs):
    out = await trigger.enqueue_behavioral(NPM, reason="unit")
    assert out == "started"
    await _settle()
    assert [c["coordinate"] for c in captured_runs] == ["left-pad"]
    assert fake_redis.store.get(router._behavioral_cache_key("npm", "left-pad"))  # cached
    assert _counter(fake_redis, "trigger:unit") == 1
    assert _counter(fake_redis, "trigger:unit:started") == 1
    # the slot lease was released when the run finished
    assert _live(fake_redis) == 0


async def test_enqueue_returns_cached_when_a_block_exists(fake_redis, captured_runs):
    fake_redis.store[router._behavioral_cache_key("npm", "left-pad")] = json.dumps({"ran": True})
    assert await trigger.enqueue_behavioral(NPM, reason="unit") == "cached"
    await _settle()
    assert captured_runs == []
    assert _counter(fake_redis, "trigger:unit:cached") == 1


async def test_enqueue_returns_locked_when_a_run_is_in_flight(fake_redis, captured_runs):
    fake_redis.store[router._behavioral_cache_key("npm", "left-pad") + ":lock"] = "1"
    assert await trigger.enqueue_behavioral(NPM, reason="unit") == "locked"
    await _settle()
    assert captured_runs == []


async def test_normal_defers_only_when_every_slot_is_busy(fake_redis, captured_runs):
    _hold(fake_redis, 1)  # one of two busy
    assert await trigger.enqueue_behavioral(NPM, reason="unit") == "started"
    await _settle()
    _hold(fake_redis, 1)  # both busy now (the first run released its own lease)
    assert await trigger.enqueue_behavioral(
        {**NPM, "package_coordinate": {"surface": "npm", "name": "other"}}, reason="unit",
    ) == "deferred"
    assert _counter(fake_redis, "slot_rejected") == 1
    assert _live(fake_redis) == 2  # the rejected taker removed its own lease
    # the lock was released so the next request can try again
    assert router._behavioral_cache_key("npm", "other") + ":lock" not in fake_redis.store


async def test_low_defers_unless_a_slot_would_stay_free(fake_redis, captured_runs):
    _hold(fake_redis, 1)  # 1 of 2 busy → low must not take the last
    assert await trigger.enqueue_behavioral(NPM, reason="backfill", priority="low") == "deferred"
    assert _live(fake_redis) == 1
    assert _counter(fake_redis, "slot_rejected") == 0  # not a real request turned away
    assert _counter(fake_redis, "trigger:backfill:deferred") == 1
    fake_redis.zsets[router._BEHAVIORAL_SLOTS_KEY].clear()  # idle → ok
    assert await trigger.enqueue_behavioral(NPM, reason="backfill", priority="low") == "started"
    await _settle()
    assert len(captured_runs) == 1


async def test_low_never_runs_when_max_concurrent_is_one(fake_redis, captured_runs, monkeypatch):
    monkeypatch.setattr(router.settings, "scanner_behavioral_max_concurrent", 1, raising=False)
    assert await trigger.enqueue_behavioral(NPM, reason="backfill", priority="low") == "deferred"


async def test_low_fails_closed_without_redis(captured_runs, monkeypatch):
    def _boom():
        raise ConnectionError("no redis")

    monkeypatch.setattr("src.redis_client.get_redis", _boom)
    assert await trigger.enqueue_behavioral(NPM, reason="backfill", priority="low") == "deferred"


async def test_enqueue_ineligible_when_off_or_nothing_to_install(fake_redis, captured_runs,
                                                                monkeypatch):
    assert await trigger.enqueue_behavioral({"repo_full_name": "acme/book"}, reason="x") == (
        "ineligible")
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", False, raising=False)
    assert await trigger.enqueue_behavioral(NPM, reason="x") == "ineligible"
    assert _counter(fake_redis, "trigger:x") == 2
    assert _counter(fake_redis, "trigger:x:ineligible") == 2


async def test_enqueue_rejects_an_unknown_priority(fake_redis, captured_runs):
    with pytest.raises(ValueError):
        await trigger.enqueue_behavioral(NPM, reason="x", priority="urgent")


async def test_enqueue_uses_the_declared_scope_and_plan_like_the_viewer_path(
        fake_redis, captured_runs):
    data = {**NPM, "declared_scope": {"egress": ["api.example.com"]},
            "artifact_scan": {"is_mcp_server": True}, "env_reads": ["TOKEN"]}
    assert await trigger.enqueue_behavioral(data, reason="unit") == "started"
    await _settle()
    assert captured_runs[0]["plan"] == "npm-mcp"
    assert captured_runs[0]["expected_hosts"] == {"api.example.com"}
    assert captured_runs[0]["env_names"] == ["TOKEN"]
    key = router._behavioral_cache_key("npm", "left-pad", {"api.example.com"}, "npm-mcp")
    assert key in fake_redis.store


# ── change detection ─────────────────────────────────────────────────────────
def test_scan_changed_names_the_moved_fields_and_ignores_missing_sides():
    assert trigger.scan_changed(NPM, NPM) == []
    assert trigger.scan_changed(NPM, {**NPM, "package_version": "1.4.0"}) == ["version"]
    assert trigger.scan_changed(NPM, {**NPM, "tool_manifest_digest": "sha256:m2"}) == (
        ["manifest_digest"])
    assert trigger.scan_changed(
        NPM, {**NPM, "artifact_scan": {"version": "1.3.0", "digest": "sha256:bbb"}},
    ) == ["artifact_digest"]
    # a side that did not observe the field is not a change
    assert trigger.scan_changed(NPM, {**NPM, "tool_manifest_digest": None}) == []
    assert trigger.scan_changed({}, NPM) == [] and trigger.scan_changed(None, NPM) == []
    # the version falls back to artifact_scan.version (WatchScan data has no package_version)
    assert trigger.scan_changed(NPM, {"artifact_scan": {"version": "2.0.0"}}) == ["version"]


def test_behavioral_scan_data_shapes_each_surface():
    pkg = trigger.behavioral_scan_data("npm", "npm", "chalk", {"trust_score": 90})
    assert pkg["package_coordinate"] == {"surface": "npm", "name": "chalk"}
    assert router._behavioral_target(pkg) == ("npm", "chalk")
    skill = trigger.behavioral_scan_data("openclaw", "acme", "skill", {})
    assert router._behavioral_target(skill) == ("skill", "acme/skill")
    repo = trigger.behavioral_scan_data(
        "github", "acme", "widget", {"metadata": {"primary_language": "TypeScript"}})
    assert repo["primary_language"] == "TypeScript"
    assert router._behavioral_target(repo) == ("github", "acme/widget")
    go = trigger.behavioral_scan_data("github", "acme", "svc", {"metadata": {"primary_language": "Go"}})
    assert router._behavioral_target(go) is None


def test_scan_cache_coords_match_the_public_endpoints():
    assert trigger.scan_cache_coords("github", "acme", "widget") == ("acme", "widget")
    assert trigger.scan_cache_coords("npm", "npm", "chalk") == ("npm", "chalk")
    assert trigger.scan_cache_coords("openclaw", "acme", "skill") == ("skill", "acme/skill")


# ── cache invalidation ───────────────────────────────────────────────────────
async def test_invalidate_drops_every_variant_but_not_locks_or_other_names(fake_redis):
    base = router._behavioral_cache_key("npm", "left-pad")
    keep_lock = base + ":lock"
    other = router._behavioral_cache_key("npm", "left-pad-extra")
    for k in (base, base + ":abc123def456", base + ":npm-mcp", base + ":abc123def456:npm-mcp",
              keep_lock, other):
        fake_redis.store[k] = "{}"
    assert await trigger.invalidate_behavioral_cache("npm", "left-pad") == 4
    assert set(fake_redis.store) == {keep_lock, other}


# ── on-change hook ───────────────────────────────────────────────────────────
async def test_version_change_drops_the_block_and_enqueues(fake_redis, captured_runs):
    key = router._behavioral_cache_key("npm", "left-pad")
    fake_redis.store[key] = json.dumps({"ran": True, "plan": "npm"})
    new = {**NPM, "package_version": "1.4.0", "artifact_scan": {"version": "1.4.0"}}
    out = await trigger.on_scan_change("npm", "npm", "left-pad", NPM, new)
    assert out == "started"
    await _settle()
    assert [c["coordinate"] for c in captured_runs] == ["left-pad"]
    assert _counter(fake_redis, "trigger:version_change") == 1
    fresh = json.loads(fake_redis.store[key])  # the public block has no coordinate key
    assert fresh["ran"] is True and "declared_egress" in fresh  # fresh block written


async def test_no_change_does_nothing_and_keeps_the_block(fake_redis, captured_runs):
    key = router._behavioral_cache_key("npm", "left-pad")
    fake_redis.store[key] = json.dumps({"ran": True, "marker": "old"})
    assert await trigger.on_scan_change("npm", "npm", "left-pad", NPM, dict(NPM)) is None
    await _settle()
    assert captured_runs == []
    assert json.loads(fake_redis.store[key])["marker"] == "old"
    assert _counter(fake_redis, "trigger:version_change") == 0


async def test_no_baseline_is_not_a_change(fake_redis, captured_runs):
    assert await trigger.on_scan_change("npm", "npm", "left-pad", None, NPM) is None
    assert captured_runs == []


async def test_watched_coordinate_without_a_block_is_enqueued(fake_redis, captured_runs):
    out = await trigger.on_scan_change("npm", "npm", "left-pad", NPM, dict(NPM), watched=True)
    assert out == "started"
    await _settle()
    assert len(captured_runs) == 1
    assert _counter(fake_redis, "trigger:watch") == 1


async def test_watched_coordinate_with_a_block_is_left_alone(fake_redis, captured_runs):
    fake_redis.store[router._behavioral_cache_key("npm", "left-pad")] = json.dumps({"ran": True})
    assert await trigger.on_scan_change(
        "npm", "npm", "left-pad", NPM, dict(NPM), watched=True) is None
    assert captured_runs == []


async def test_hook_is_silent_when_the_tier_is_off_or_target_is_ineligible(
        fake_redis, captured_runs, monkeypatch):
    rust = {"repo_full_name": "acme/book", "metadata": {"primary_language": "Rust"},
            "package_version": "2"}
    assert await trigger.on_scan_change("github", "acme", "book", {"package_version": "1"},
                                        rust, watched=True) is None
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", False, raising=False)
    assert await trigger.on_scan_change("npm", "npm", "left-pad", NPM,
                                        {**NPM, "package_version": "9"}) is None
    assert captured_runs == []


async def test_on_watch_rescan_uses_watchscan_data_and_the_stored_digest(
        fake_redis, captured_runs):
    """Packages: the watch loop never writes the scan cache, so the WatchScan data
    (artifact_scan.version) is the fresh side and the watch's stored manifest digest
    stands in for a missing previous scan."""
    ws_data = {"package_coordinate": {"surface": "npm", "name": "left-pad"},
               "artifact_scan": {"version": "1.4.0"}}
    fake_redis.store[router._behavioral_cache_key("npm", "left-pad")] = json.dumps({"ran": True})
    # digest moved vs the watch's baseline → block dropped + re-run
    out = await trigger.on_watch_rescan("npm", "npm", "left-pad", None, ws_data,
                                        new_digest="sha256:new", last_manifest_digest="sha256:old")
    assert out == "started"
    await _settle()
    assert _counter(fake_redis, "trigger:version_change") == 1
    # same digest, block present → nothing
    fake_redis.store[router._behavioral_cache_key("npm", "left-pad")] = json.dumps({"ran": True})
    assert await trigger.on_watch_rescan("npm", "npm", "left-pad", None, ws_data,
                                         new_digest="sha256:new",
                                         last_manifest_digest="sha256:new") is None
    # previous cached scan present: the version moved → change. The per-coordinate lock
    # from the first run would still be held (600 s TTL in prod); simulate its expiry.
    for k in [k for k in fake_redis.store if k.endswith(":lock")]:
        del fake_redis.store[k]
    out = await trigger.on_watch_rescan("npm", "npm", "left-pad", NPM, ws_data)
    assert out == "started"
    await _settle()
    assert _counter(fake_redis, "trigger:version_change") == 2


# ── the loops call the hooks with the previous cached scan as baseline ───────
@pytest.fixture
def hook_spy(monkeypatch):
    calls: dict = {"change": [], "cache_set": [], "watch": []}

    async def _cached(surface, owner, repo, *, stale=True):
        return calls.get("prev")

    async def _on_change(surface, owner, repo, prev, data, *, watched=False):
        calls["change"].append((surface, owner, repo, prev, data, watched))
        return None

    async def _set(surface, owner, repo, data):
        calls["cache_set"].append((surface, owner, repo, data))

    async def _on_watch(surface, owner, repo, prev, ws_data, *, new_digest=None,
                        last_manifest_digest=None):
        calls["watch"].append((surface, owner, repo, prev, ws_data, new_digest,
                               last_manifest_digest))
        return None

    monkeypatch.setattr(trigger, "cached_scan_data", _cached)
    monkeypatch.setattr(trigger, "on_scan_change", _on_change)
    monkeypatch.setattr(trigger, "set_scan_cache", _set)
    monkeypatch.setattr(trigger, "on_watch_rescan", _on_watch)
    return calls


async def test_catalog_rescan_package_path_fires_the_hook_after_the_fresh_scan(
        hook_spy, monkeypatch):
    from src.jobs import scheduler as sch

    hook_spy["prev"] = {"package_version": "1.0.0"}

    async def fake_scan_package(surface, name):
        return SimpleNamespace(error=None, trust_score=94)

    async def fake_capture(owner, repo, data, db, surface="github"):
        pass

    async def fake_adoption(surface, owner, repo, db):
        pass

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    monkeypatch.setattr("src.api.public_scan_router._capture_community_scan", fake_capture)
    monkeypatch.setattr("src.api.public_scan_router._scan_result_to_dict",
                        lambda r: {"trust_score": 94, "package_version": "1.1.0"})
    monkeypatch.setattr(sch, "_store_catalog_adoption", fake_adoption)
    assert await sch._rescan_catalog_row("npm", "npm", "chalk", db=None) is True
    assert hook_spy["cache_set"] == [("npm", "npm", "chalk", {"trust_score": 94,
                                                             "package_version": "1.1.0"})]
    assert hook_spy["change"] == [("npm", "npm", "chalk", {"package_version": "1.0.0"},
                                   {"trust_score": 94, "package_version": "1.1.0"}, False)]


async def test_catalog_rescan_github_path_diffs_the_rewritten_cache(hook_spy, monkeypatch):
    from src.jobs import scheduler as sch

    hook_spy["prev"] = {"package_version": "1.0.0"}

    async def fake_public_scan(owner, repo, force, db):
        hook_spy["prev"] = {"package_version": "2.0.0"}  # public_scan rewrote the cache
        return SimpleNamespace(trust_score=90)

    async def fake_adoption(surface, owner, repo, db):
        pass

    monkeypatch.setattr("src.api.public_scan_router.public_scan", fake_public_scan)
    monkeypatch.setattr(sch, "_store_catalog_adoption", fake_adoption)
    assert await sch._rescan_catalog_row("github", "acme", "widget", db=None) is True
    assert hook_spy["change"] == [("github", "acme", "widget", {"package_version": "1.0.0"},
                                   {"package_version": "2.0.0"}, False)]
    assert hook_spy["cache_set"] == []  # public_scan already wrote it


async def test_catalog_rescan_skips_the_hook_on_a_failed_scan(hook_spy, monkeypatch):
    from src.jobs import scheduler as sch

    async def fake_scan_package(surface, name):
        return SimpleNamespace(error="registry 500", trust_score=None)

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    assert await sch._rescan_catalog_row("npm", "npm", "broken", db=None) is False
    assert hook_spy["change"] == [] and hook_spy["cache_set"] == []


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        return _Result(self.state["watches"] if "tool_watches" in str(stmt) else [])

    async def get(self, model, key):
        if model.__name__ == "ToolWatch":
            return next((w for w in self.state["watches"] if w.id == key), None)
        return None

    async def commit(self):
        pass


async def test_watch_rescan_fires_the_hook_with_the_watch_baseline(hook_spy, monkeypatch):
    from src.jobs import scheduler as sch
    from src.models import ToolWatch

    watch = ToolWatch(id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="npm", owner="npm",
                      repo="left-pad", last_score=90, last_manifest_digest="sha256:old",
                      last_behavioral_digest=None, active=True)
    monkeypatch.setattr("src.database.async_session",
                        lambda: _FakeSession({"watches": [watch]}))
    hook_spy["prev"] = {"package_version": "1.0.0"}

    async def _scan(surface, owner, repo, db):
        from src.api.watch_router import WatchScan
        return WatchScan(90, "sha256:new", {"package_coordinate": {"surface": "npm",
                                                                    "name": repo}})

    monkeypatch.setattr("src.api.watch_router.scan_watch_target_detail", _scan)

    async def _no_block(surface, name, expected_hosts=None, plan=None):
        return None

    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _no_block)
    await sch._run_watch_rescan()
    assert hook_spy["watch"] == [(
        "npm", "npm", "left-pad", {"package_version": "1.0.0"},
        {"package_coordinate": {"surface": "npm", "name": "left-pad"}}, "sha256:new", "sha256:old",
    )]


async def test_watch_rescan_skips_the_hook_when_the_scan_failed(hook_spy, monkeypatch):
    from src.jobs import scheduler as sch
    from src.models import ToolWatch

    watch = ToolWatch(id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="npm", owner="npm",
                      repo="left-pad", last_score=90, active=True)
    monkeypatch.setattr("src.database.async_session",
                        lambda: _FakeSession({"watches": [watch]}))

    async def _scan(surface, owner, repo, db):
        from src.api.watch_router import WatchScan
        return WatchScan(None, None)

    monkeypatch.setattr("src.api.watch_router.scan_watch_target_detail", _scan)
    await sch._run_watch_rescan()
    assert hook_spy["watch"] == []


# ── slot leases: a crashed run can never wedge the cap (2026-10-08 incident) ────────
async def test_expired_leases_from_a_killed_run_do_not_block_new_runs(fake_redis, captured_runs):
    # A deploy killed the container mid-run: two leases were never released.
    _hold(fake_redis, 2, expires_in=-1.0)  # already past their expiry
    assert await trigger.enqueue_behavioral(NPM, reason="unit") == "started"
    await _settle()
    assert len(captured_runs) == 1
    assert _live(fake_redis) == 0  # the stale leases were swept; the new one released


async def test_rejected_attempts_do_not_extend_a_leaked_lease(fake_redis, captured_runs):
    # Two live leases (both slots busy). Rejected attempts must not push their expiry
    # out — the old counter refreshed its TTL on every attempt, so a leaked count never
    # expired while traffic kept arriving.
    _hold(fake_redis, 2, expires_in=120.0)
    before = sorted(fake_redis.zsets[router._BEHAVIORAL_SLOTS_KEY].values())
    for i in range(5):
        out = await trigger.enqueue_behavioral(
            {**NPM, "package_coordinate": {"surface": "npm", "name": f"p{i}"}}, reason="unit")
        assert out == "deferred"
    assert sorted(fake_redis.zsets[router._BEHAVIORAL_SLOTS_KEY].values()) == before
    assert captured_runs == []


async def test_release_removes_only_its_own_lease(fake_redis, captured_runs):
    a = await router._acquire_behavioral_slot()
    b = await router._acquire_behavioral_slot()
    assert a and b and a != b
    assert await router._acquire_behavioral_slot() is None  # cap 2
    await router._release_behavioral_slot(a)
    assert _live(fake_redis) == 1
    assert b in fake_redis.zsets[router._BEHAVIORAL_SLOTS_KEY]
    assert await router.behavioral_slots_in_use() == 1


async def test_slot_acquire_fails_open_when_redis_is_down(monkeypatch):
    class _Down:
        def __getattr__(self, name):
            async def boom(*a, **k):
                raise ConnectionError("redis down")
            return boom
    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Down())
    lease = await router._acquire_behavioral_slot()
    assert lease  # viewer path fails OPEN
    await router._release_behavioral_slot(lease)  # never raises
    assert await trigger._acquire_low_priority_slot() is None  # low priority fails CLOSED
