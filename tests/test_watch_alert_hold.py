"""The watch score-alert hold (tracked follow-up #5): during a planned catalog re-score,
score-change alerts are held back and the new score is absorbed as the baseline;
signed-definition drift still alerts. No DB: the session is faked."""
from __future__ import annotations

import uuid

import pytest

from src.jobs import scheduler
from src.jobs import watch_alert_hold as hold
from tests.test_watch_behavioral_drift import _FakeSession


@pytest.fixture
def env(monkeypatch):
    from src.api.watch_router import WatchScan
    from src.models import AlertWebhook, ToolWatch

    watch = ToolWatch(
        id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="npm", owner="npm",
        repo="thing", last_score=50, last_manifest_digest="sha256:old",
        last_behavioral_digest=None, active=True,
    )
    hook = AlertWebhook(id=uuid.uuid4(), entity_id=watch.watcher_id,
                        url="https://hooks.example/x", active=True)
    state = {"watches": [watch], "hook": hook, "notes": [], "delivered": [],
             "scan": WatchScan(72, "sha256:old", {}), "held": False}
    monkeypatch.setattr("src.database.async_session", lambda: _FakeSession(state))

    async def _scan(surface, owner, repo, db):
        return state["scan"]

    async def _none(*a, **kw):
        return None

    async def _notify(db, entity_id, kind, title, body, reference_id=None, **kw):
        state["notes"].append((kind, title))

    async def _deliver(hook_, payload):
        state["delivered"].append(payload)
        return 204

    async def _held():
        return state["held"]

    monkeypatch.setattr("src.api.watch_router.scan_watch_target_detail", _scan)
    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _none)
    monkeypatch.setattr("src.scanner.behavioral.trigger.cached_scan_data", _none)
    monkeypatch.setattr("src.scanner.behavioral.trigger.on_watch_rescan", _none)
    monkeypatch.setattr("src.api.notification_router.create_notification", _notify)
    monkeypatch.setattr("src.api.account_webhook_router.deliver_to_hook", _deliver)
    monkeypatch.setattr("src.jobs.watch_alert_hold.score_alerts_held", _held)
    return state, watch


async def test_without_the_hold_a_score_change_alerts(env):
    state, watch = env
    await scheduler._run_watch_rescan()
    assert [k for k, _ in state["notes"]] == ["watch_good_news"]  # 50 -> 72
    assert watch.last_score == 72


async def test_hold_suppresses_an_improvement_and_absorbs_the_baseline(env):
    state, watch = env
    state["held"] = True
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_score == 72
    # after the hold clears, the absorbed baseline means no late alert
    state["held"] = False
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []


async def test_hold_suppresses_a_drop(env):
    state, watch = env
    watch.last_score = 90
    state["held"] = True
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_score == 72


async def test_definition_drift_still_alerts_during_the_hold(env):
    from src.api.watch_router import WatchScan

    state, watch = env
    watch.last_score = 90
    state["held"] = True
    state["scan"] = WatchScan(72, "sha256:new", {})
    await scheduler._run_watch_rescan()
    assert [k for k, _ in state["notes"]] == ["watch_alert"]
    assert "signed definition changed" in state["notes"][0][1]
    assert len(state["delivered"]) == 1
    assert state["delivered"][0]["reason"] == "signed definition changed"
    assert watch.last_manifest_digest == "sha256:new"


async def test_app_scan_honours_the_hold(monkeypatch):
    from src.jobs import app_scan

    notes = []

    async def _notify(db, entity_id, kind, title, body, reference_id=None, **kw):
        notes.append(kind)

    held = {"v": True}

    async def _held():
        return held["v"]

    monkeypatch.setattr("src.api.notification_router.create_notification", _notify)
    monkeypatch.setattr("src.jobs.watch_alert_hold.score_alerts_held", _held)
    args = (None, uuid.uuid4(), "o", "r", "o/r")
    assert await app_scan._maybe_notify(*args, 90, 70, {}, {}) == 0
    assert await app_scan._maybe_notify(*args, 50, 72, {}, {}) == 0
    assert await app_scan._maybe_notify(
        *args, 90, 70, {"tool_manifest_digest": "a"}, {"tool_manifest_digest": "b"}) == 1
    assert notes == ["watch_alert"]
    held["v"] = False
    assert await app_scan._maybe_notify(*args, 90, 70, {}, {}) == 1


async def test_hold_round_trip_in_redis():
    try:
        await hold.clear_hold()
    except Exception:  # noqa: BLE001
        pytest.skip("redis not reachable")
    assert await hold.score_alerts_held() is False
    assert await hold.hold_status() is None
    ttl = await hold.set_hold(3600, "curve re-score")
    assert ttl == 3600
    assert await hold.score_alerts_held() is True
    info = await hold.hold_status()
    assert info["reason"] == "curve re-score" and 0 < info["ttl"] <= 3600
    assert await hold.set_hold(10**9) == hold.MAX_HOLD_SECONDS
    assert await hold.clear_hold() is True
    assert await hold.score_alerts_held() is False
    assert await hold.clear_hold() is False


async def test_hold_check_fails_open(monkeypatch):
    def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr("src.redis_client.get_redis", _boom)
    assert await hold.score_alerts_held() is False
