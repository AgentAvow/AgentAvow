"""Sandbox watchdog (src/jobs/sandbox_watchdog.py): quiet sandbox failures page the admin,
at most once a day per condition. Fake redis; notify_admins captured."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import src.jobs.sandbox_watchdog as wd

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return None
        self.store[key] = str(value)
        return True

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


@pytest.fixture
def redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    return r


@pytest.fixture
def sent(monkeypatch):
    calls: list[dict] = []

    async def fake_notify(title, body, *, reference_id, payload):
        calls.append({"title": title, "body": body, "ref": reference_id, **payload})
        return {"notified": 1, "webhooks": 0}

    monkeypatch.setattr("src.jobs.behavioral_eval.notify_admins", fake_notify)
    return calls


def _eval_ran(r, when):
    r.store["ag:eval:behavioral:latest"] = json.dumps({"ran_at": when.isoformat()})


def _backfill(r, when, eligible=100, done=40):
    r.hashes["ag:backfill:behavioral:progress"] = {
        "last_run_at": when.isoformat(), "total_eligible": str(eligible), "done": str(done)}


async def test_healthy_state_alerts_nothing(redis, sent):
    _eval_ran(redis, NOW - timedelta(days=3))
    _backfill(redis, NOW - timedelta(minutes=10))
    assert await wd.run_watchdog(now=NOW) == []
    assert sent == []


async def test_stale_eval_alerts_once_a_day(redis, sent):
    _eval_ran(redis, NOW - timedelta(days=9))
    _backfill(redis, NOW - timedelta(minutes=10))
    assert await wd.run_watchdog(now=NOW) == ["eval_stale"]
    assert "9 days ago" in sent[0]["body"] and sent[0]["event"] == "eval_stale"
    assert sent[0]["type"] == wd.WEBHOOK_TYPE
    # the next tick in the same day does not repeat it
    assert await wd.run_watchdog(now=NOW + timedelta(minutes=10)) == []
    assert len(sent) == 1


async def test_backfill_stall_needs_remaining_work(redis, sent):
    _backfill(redis, NOW - timedelta(hours=30), eligible=100, done=40)
    assert await wd.run_watchdog(now=NOW) == ["backfill_stale"]
    assert "60 eligible rows" in sent[0]["body"]
    redis.store.clear()
    _backfill(redis, NOW - timedelta(hours=30), eligible=100, done=100)  # finished: fine
    assert await wd.run_watchdog(now=NOW) == []


async def test_disk_low_runner_errors_alert(redis, sent):
    redis.store[f"{wd.METRICS_PREFIX}:runner_error:sandbox_disk_low:2026-10-10"] = "3"
    assert await wd.run_watchdog(now=NOW) == ["disk_low"]
    assert "3 sandbox run(s)" in sent[0]["body"] and "/var/tmp/agentavow-beh" in sent[0]["body"]


async def test_slot_watchdog_warnings_are_escalated(redis, sent):
    assert await wd.run_watchdog(slot_warnings=["all 2 slots held"], now=NOW) == ["slots"]
    assert sent[0]["body"] == "all 2 slots held"


async def test_no_report_yet_is_not_stale_and_redis_down_never_raises(redis, sent, monkeypatch):
    assert await wd.run_watchdog(now=NOW) == []  # fresh install: nothing to compare

    class _Down:
        def __getattr__(self, name):
            async def boom(*a, **k):
                raise ConnectionError("redis down")
            return boom
    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Down())
    assert await wd.run_watchdog(now=NOW) == []
