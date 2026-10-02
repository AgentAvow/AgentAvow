"""Watch re-scan: alert on behavioral (sandbox) drift.

The loop never runs the sandbox; it reads the block the public scan cached and
compares a compact fingerprint against ``ToolWatch.last_behavioral_digest``. A NEW
finding / undeclared host / canary hit is an alert (notification + signed webhook,
event ``behavioral_change``); findings going away is a good-news note; a cycle with
no cached block keeps the baseline. No DB: the session is faked.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from src.jobs import scheduler
from src.jobs.scheduler import (
    _behavioral_alert_payload,
    _behavioral_change,
    _behavioral_fingerprint,
    _watch_behavioral_block,
)


def _block(rules=(), unexpected=(), canary=(), tools=(), ran=True, calls=()) -> dict:
    return {
        "ran": ran, "plan": "npm-mcp",
        "findings": [{"rule": r, "severity": "high", "name": r.replace("_", " ")}
                     for r in rules],
        "unexpected_egress": list(unexpected),
        "canary_exfil": list(canary),
        "exercise": {
            "launch_ok": True,
            "tools": [{"name": n, "annotations": {"readOnlyHint": ro}} for n, ro in tools],
            "calls": [{"tool": t, "ok": True} for t in calls],
        },
    }


# ── fingerprint ──────────────────────────────────────────────────────────────
def test_fingerprint_is_none_unless_the_block_ran():
    assert _behavioral_fingerprint(None) is None
    assert _behavioral_fingerprint({"ran": False, "pending": True}) is None
    assert _behavioral_fingerprint({"ran": False, "reason": "off"}) is None


def test_fingerprint_is_stable_under_ordering_and_fits_the_column():
    a = _behavioral_fingerprint(_block(["r2", "r1"], ["b.net", "A.net"], tools=[("t", True)]))
    b = _behavioral_fingerprint(_block(["r1", "r2"], ["a.net", "B.NET"], tools=[("t", True)]))
    assert a == b
    assert a.startswith("v1:r=") and ";r=2;u=2;c=0" in a
    assert len(a) <= 128


def test_fingerprint_tracks_each_component():
    base = _behavioral_fingerprint(_block(["r1"], tools=[("t", True)]))
    assert _behavioral_fingerprint(_block(["r1", "r2"], tools=[("t", True)])) != base
    assert _behavioral_fingerprint(_block(["r1"], ["x.io"], tools=[("t", True)])) != base
    assert _behavioral_fingerprint(_block(["r1"], canary=["AWS_KEY"], tools=[("t", True)])) != base
    # a readOnlyHint flip on the same tool is a different definition
    assert _behavioral_fingerprint(_block(["r1"], tools=[("t", False)])) != base


# ── change decision ──────────────────────────────────────────────────────────
def test_first_observation_sets_the_baseline_silently():
    fp = _behavioral_fingerprint(_block(["r1"]))
    assert _behavioral_change(None, fp) == (None, fp)


def test_no_cached_block_keeps_the_baseline():
    fp = _behavioral_fingerprint(_block(["r1"]))
    assert _behavioral_change(fp, None) == (None, fp)
    assert _behavioral_change(None, None) == (None, None)


def test_same_block_is_no_change():
    fp = _behavioral_fingerprint(_block(["r1"], ["x.io"]))
    assert _behavioral_change(fp, fp) == (None, fp)


def test_new_finding_alerts():
    old = _behavioral_fingerprint(_block([]))
    new = _behavioral_fingerprint(_block(["behavioral_undeclared_egress"]))
    assert _behavioral_change(old, new) == ("alert", new)


def test_new_host_or_canary_alerts_even_with_the_same_rules():
    old = _behavioral_fingerprint(_block(["r1"], ["a.net"]))
    assert _behavioral_change(old, _behavioral_fingerprint(_block(["r1"], ["a.net", "b.net"])))[0] == "alert"
    assert _behavioral_change(old, _behavioral_fingerprint(_block(["r1"], ["a.net"], ["TOKEN"])))[0] == "alert"


def test_swapped_rule_set_of_equal_size_alerts():
    """{r1} -> {r2}: r2 is new even though the count did not grow."""
    old = _behavioral_fingerprint(_block(["r1"]))
    new = _behavioral_fingerprint(_block(["r2"]))
    assert _behavioral_change(old, new) == ("alert", new)


def test_findings_going_away_is_improved_not_alert():
    old = _behavioral_fingerprint(_block(["r1", "r2"], ["x.io"]))
    new = _behavioral_fingerprint(_block(["r1"]))
    assert _behavioral_change(old, new) == ("improved", new)
    clean = _behavioral_fingerprint(_block([]))
    assert _behavioral_change(old, clean) == ("improved", clean)


def test_tools_only_change_is_neither():
    old = _behavioral_fingerprint(_block(["r1"], tools=[("a", True)]))
    new = _behavioral_fingerprint(_block(["r1"], tools=[("a", True), ("b", False)]))
    assert _behavioral_change(old, new) == (None, new)


def test_unreadable_baseline_rebaselines_silently():
    new = _behavioral_fingerprint(_block(["r1"]))
    assert _behavioral_change("sha256:legacy", new) == (None, new)


# ── cache lookup ─────────────────────────────────────────────────────────────
async def test_block_lookup_prefers_the_inline_block(monkeypatch):
    async def _never(*a, **k):
        raise AssertionError("cache must not be read when the scan carried the block")

    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _never)
    inline = _block(["r1"])
    got = await _watch_behavioral_block(
        {"package_coordinate": {"surface": "npm", "name": "x"}, "behavioral": inline})
    assert got is inline


async def test_block_lookup_reads_the_cache_under_the_scan_key(monkeypatch):
    seen = {}

    async def _cached(surface, name, expected_hosts=None, plan=None):
        seen.update(surface=surface, name=name, hosts=expected_hosts, plan=plan)
        return _block(["r1"])

    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _cached)
    data = {"package_coordinate": {"surface": "npm", "name": "mcp-thing"},
            "declared_scope": {"egress": ["api.example.com"]},
            "artifact_scan": {"is_mcp_server": True}}
    got = await _watch_behavioral_block(data)
    assert got and got["ran"]
    assert seen == {"surface": "npm", "name": "mcp-thing", "hosts": {"api.example.com"},
                    "plan": "npm-mcp"}


async def test_block_lookup_skips_pending_and_non_package_surfaces(monkeypatch):
    async def _pending(*a, **k):
        return {"ran": False, "pending": True}

    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _pending)
    assert await _watch_behavioral_block(
        {"package_coordinate": {"surface": "npm", "name": "x"}}) is None
    assert await _watch_behavioral_block({"package_coordinate": {}}) is None
    assert await _watch_behavioral_block(
        {"package_coordinate": {"surface": "crates", "name": "serde"}}) is None
    assert await _watch_behavioral_block(None) is None


# ── payload ──────────────────────────────────────────────────────────────────
def test_behavioral_payload_shape():
    w = SimpleNamespace(owner="npm", repo="left-pad", surface="npm")
    block = _block(["annotation_readonly_violated"], ["evil.net"], ["GH_TOKEN"],
                   tools=[("read_file", True)], calls=["read_file", "read_file"])
    p = _behavioral_alert_payload(w, block, 77, {"surface": "npm", "name": "left-pad"})
    assert p["type"] == "agentavow.alert.behavioral_change"
    assert p["event"] == "behavioral_change"
    assert (p["owner"], p["repo"], p["surface"], p["score"]) == ("npm", "left-pad", "npm", 77)
    assert p["finding_rules"] == ["annotation_readonly_violated"]
    assert p["findings"] == [{"rule": "annotation_readonly_violated", "severity": "high",
                              "name": "annotation readonly violated"}]
    assert p["unexpected_egress"] == ["evil.net"]
    assert p["canary_exfil"] == ["GH_TOKEN"]
    assert p["tools_exercised"] == ["read_file"]
    assert p["package"] == {"surface": "npm", "name": "left-pad"}
    assert p["plan"] == "npm-mcp"


# ── the loop, end to end with a fake session ─────────────────────────────────
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
    """Just enough AsyncSession for _run_watch_rescan: the watch list, the webhook
    lookup, ``get`` for the watch/entity, and commit."""

    def __init__(self, state):
        self.state = state

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        desc = str(stmt)
        if "tool_watches" in desc:
            return _Result(self.state["watches"])
        if "alert_webhooks" in desc:
            return _Result([self.state["hook"]] if self.state.get("hook") else [])
        return _Result([])

    async def get(self, model, key):
        if model.__name__ == "ToolWatch":
            return next((w for w in self.state["watches"] if w.id == key), None)
        return None  # no Entity → no email path

    async def commit(self):
        self.state["commits"] = self.state.get("commits", 0) + 1


@pytest.fixture
def loop_env(monkeypatch):
    from src.models import AlertWebhook, ToolWatch

    watch = ToolWatch(
        id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="npm", owner="npm",
        repo="mcp-thing", last_score=90, last_manifest_digest=None,
        last_behavioral_digest=None, active=True,
    )
    hook = AlertWebhook(id=uuid.uuid4(), entity_id=watch.watcher_id,
                        url="https://hooks.example/x", active=True)
    state = {"watches": [watch], "hook": hook, "notes": [], "delivered": [], "cache": None}
    monkeypatch.setattr("src.database.async_session", lambda: _FakeSession(state))

    async def _scan(surface, owner, repo, db):
        from src.api.watch_router import WatchScan
        return WatchScan(90, None, {"package_coordinate": {"surface": "npm", "name": repo},
                                    "artifact_scan": {"is_mcp_server": True}})

    monkeypatch.setattr("src.api.watch_router.scan_watch_target_detail", _scan)

    async def _cached(surface, name, expected_hosts=None, plan=None):
        return state["cache"]

    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _cached)

    async def _notify(db, entity_id, kind, title, body, reference_id=None, **kw):
        state["notes"].append((kind, title))

    monkeypatch.setattr("src.api.notification_router.create_notification", _notify)

    async def _deliver(hook_, payload):
        state["delivered"].append(payload)
        return 204

    monkeypatch.setattr("src.api.account_webhook_router.deliver_to_hook", _deliver)
    return state, watch


async def test_loop_first_block_sets_baseline_without_alert(loop_env):
    state, watch = loop_env
    state["cache"] = _block(["r1"])
    await scheduler._run_watch_rescan()
    assert watch.last_behavioral_digest == _behavioral_fingerprint(_block(["r1"]))
    assert state["notes"] == [] and state["delivered"] == []


async def test_loop_alerts_on_a_new_finding_with_notification_and_webhook(loop_env):
    state, watch = loop_env
    watch.last_behavioral_digest = _behavioral_fingerprint(_block([]))
    state["cache"] = _block(["behavioral_undeclared_egress"], ["evil.net"])
    await scheduler._run_watch_rescan()
    assert [k for k, _ in state["notes"]] == ["watch_alert"]
    assert "sandbox behavior changed" in state["notes"][0][1]
    assert len(state["delivered"]) == 1
    p = state["delivered"][0]
    assert p["event"] == "behavioral_change"
    assert p["finding_rules"] == ["behavioral_undeclared_egress"]
    assert p["unexpected_egress"] == ["evil.net"]
    assert p["package"] == {"surface": "npm", "name": "mcp-thing"}
    assert watch.last_behavioral_digest == _behavioral_fingerprint(state["cache"])
    assert state["hook"].last_status == 204


async def test_loop_improvement_is_a_good_news_note_not_a_webhook(loop_env):
    state, watch = loop_env
    watch.last_behavioral_digest = _behavioral_fingerprint(_block(["r1"], ["evil.net"]))
    state["cache"] = _block([])
    await scheduler._run_watch_rescan()
    assert [k for k, _ in state["notes"]] == ["watch_good_news"]
    assert state["delivered"] == []
    assert watch.last_behavioral_digest == _behavioral_fingerprint(_block([]))


async def test_loop_without_a_cached_block_keeps_the_baseline(loop_env):
    state, watch = loop_env
    before = _behavioral_fingerprint(_block(["r1"]))
    watch.last_behavioral_digest = before
    state["cache"] = None
    await scheduler._run_watch_rescan()
    assert watch.last_behavioral_digest == before
    assert state["notes"] == [] and state["delivered"] == []
    assert state["commits"] == 1


async def test_loop_unchanged_block_is_quiet(loop_env):
    state, watch = loop_env
    state["cache"] = _block(["r1"])
    watch.last_behavioral_digest = _behavioral_fingerprint(state["cache"])
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
