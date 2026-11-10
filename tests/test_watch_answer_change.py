"""Watch alerts on the answer (safe / review / do_not_connect) and the Certified mark.

A worse answer or a lost mark alerts like a score drop (in-app ``watch_alert``, email,
signed ``agentavow.alert.grade_change`` webhook); a better one is good news only. One
re-scan sends one alert whatever combination of reasons it has. No DB: the session is
faked as in the behavioral-drift tests."""
from __future__ import annotations

import uuid

import pytest

from src.jobs import scheduler
from tests.test_watch_behavioral_drift import _FakeSession

SAFE_CERT = {"decision": "safe", "decision_final": True,
             "decision_reason": "no blocking findings", "certified": True}
SAFE = {**SAFE_CERT, "certified": False}
REVIEW = {"decision": "review", "decision_final": True,
          "decision_reason": "one high finding", "certified": False}
DNC = {"decision": "do_not_connect", "decision_final": True,
       "decision_reason": "a known-malicious dependency", "certified": False}


@pytest.fixture
def env(monkeypatch):
    from src.api.watch_router import WatchScan
    from src.models import AlertWebhook, ToolWatch

    watch = ToolWatch(
        id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface="npm", owner="npm",
        repo="thing", last_score=80, last_manifest_digest="sha256:old",
        last_behavioral_digest=None, last_decision="safe", last_certified=True,
        active=True,
    )
    hook = AlertWebhook(id=uuid.uuid4(), entity_id=watch.watcher_id,
                        url="https://hooks.example/x", active=True)
    state = {"watches": [watch], "hook": hook, "notes": [], "delivered": [],
             "scan": WatchScan(80, "sha256:old", {}), "held": False,
             "decision": SAFE_CERT}
    monkeypatch.setattr("src.database.async_session", lambda: _FakeSession(state))

    async def _scan(surface, owner, repo, db):
        return state["scan"]

    async def _none(*a, **kw):
        return None

    async def _notify(db, entity_id, kind, title, body, reference_id=None, **kw):
        state["notes"].append((kind, title, body))

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
    monkeypatch.setattr(scheduler, "_watch_decision", lambda data, block: state["decision"])
    return state, watch


def _kinds(state):
    return [k for k, _, _ in state["notes"]]


# ── worse answer / lost mark: alert ─────────────────────────────────────────────
@pytest.mark.parametrize("old, old_cert, new, triggers", [
    ("safe", False, REVIEW, ["answer_worse"]),
    ("safe", False, DNC, ["answer_worse"]),
    ("review", False, DNC, ["answer_worse"]),
    ("safe", True, SAFE, ["certified_lost"]),
    ("safe", True, REVIEW, ["answer_worse", "certified_lost"]),
])
async def test_worse_answer_or_lost_mark_alerts(env, old, old_cert, new, triggers):
    state, watch = env
    watch.last_decision, watch.last_certified = old, old_cert
    state["decision"] = new
    await scheduler._run_watch_rescan()

    assert _kinds(state) == ["watch_alert"]
    assert len(state["delivered"]) == 1
    p = state["delivered"][0]
    assert p["type"] == "agentavow.alert.grade_change"
    assert p["triggers"] == triggers
    assert p["reason"] == p["reasons"][0]
    assert p["old_decision"] == old and p["old_certified_mark"] is old_cert
    assert p["decision"] == new["decision"] and p["certified"] is new["certified"]
    # the baseline moves to the new answer, so the next pass is quiet
    assert watch.last_decision == new["decision"]
    assert watch.last_certified is new["certified"]
    state["notes"].clear()
    state["delivered"].clear()
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []


async def test_alert_text_names_the_old_answer(env):
    state, watch = env
    watch.last_certified = True
    state["decision"] = REVIEW
    await scheduler._run_watch_rescan()
    _, title, body = state["notes"][0]
    assert title == "npm/thing — answer changed"
    assert "Certified mark removed" in body
    assert "was: Safe to connect · Certified" in body
    assert "Now: Review before you connect" in body


# ── first run / no change: silent ───────────────────────────────────────────────
async def test_first_run_seeds_without_alert(env):
    state, watch = env
    watch.last_decision = watch.last_certified = None
    state["decision"] = DNC
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_decision == "do_not_connect" and watch.last_certified is False


async def test_no_change_no_alert(env):
    state, watch = env
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_decision == "safe" and watch.last_certified is True


async def test_unreadable_decision_is_no_change_and_keeps_the_baseline(env):
    state, watch = env
    state["decision"] = {"decision": None, "certified": False}
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_decision == "safe" and watch.last_certified is True


# ── improvements: good news, never the webhook ──────────────────────────────────
@pytest.mark.parametrize("old, old_cert, new, title_has", [
    ("review", False, SAFE, "answer improved"),
    ("do_not_connect", False, REVIEW, "answer improved"),
    ("safe", False, SAFE_CERT, "earned the Certified mark"),
])
async def test_improvement_is_good_news_only(env, old, old_cert, new, title_has):
    state, watch = env
    watch.last_decision, watch.last_certified = old, old_cert
    state["decision"] = new
    await scheduler._run_watch_rescan()
    assert _kinds(state) == ["watch_good_news"]
    assert title_has in state["notes"][0][1]
    assert state["delivered"] == []
    assert watch.last_decision == new["decision"]


async def test_score_and_answer_improving_is_one_good_news(env):
    from src.api.watch_router import WatchScan

    state, watch = env
    watch.last_score, watch.last_decision, watch.last_certified = 60, "review", False
    state["scan"] = WatchScan(90, "sha256:old", {})
    await scheduler._run_watch_rescan()
    assert _kinds(state) == ["watch_good_news"]
    assert "score improved" in state["notes"][0][1]
    assert "Was: Review before you connect" in state["notes"][0][2]


# ── one alert for several reasons ───────────────────────────────────────────────
async def test_score_drop_and_answer_change_send_one_alert(env):
    from src.api.watch_router import WatchScan

    state, watch = env
    watch.last_score, watch.last_certified = 90, False
    state["scan"] = WatchScan(70, "sha256:old", {})
    state["decision"] = REVIEW
    await scheduler._run_watch_rescan()
    assert _kinds(state) == ["watch_alert"]
    assert len(state["delivered"]) == 1
    p = state["delivered"][0]
    assert p["reason"] == "score dropped"
    assert p["triggers"] == ["score_drop", "answer_worse"]
    assert p["reasons"] == ["score dropped", "answer changed"]
    assert p["old_score"] == 90 and p["new_score"] == 70
    _, title, body = state["notes"][0]
    assert title == "npm/thing — score dropped"
    assert "(90 -> 70); answer changed (was: Safe to connect)" in body


async def test_drop_drift_and_lost_mark_send_one_alert(env):
    from src.api.watch_router import WatchScan

    state, watch = env
    watch.last_score = 90
    state["scan"] = WatchScan(70, "sha256:new", {})
    state["decision"] = SAFE
    await scheduler._run_watch_rescan()
    assert _kinds(state) == ["watch_alert"]
    assert len(state["delivered"]) == 1
    assert state["delivered"][0]["triggers"] == [
        "score_drop", "definition_change", "certified_lost"]


async def test_existing_drop_payload_keeps_its_fields(env):
    """A plain score drop still carries every pre-existing field with the same values;
    the new fields are added alongside."""
    from src.api.watch_router import WatchScan

    state, watch = env
    watch.last_score = 90
    state["scan"] = WatchScan(70, "sha256:old", {})
    await scheduler._run_watch_rescan()
    p = state["delivered"][0]
    assert {k: p[k] for k in ("type", "owner", "repo", "old_score", "new_score", "reason")} \
        == {"type": "agentavow.alert.grade_change", "owner": "npm", "repo": "thing",
            "old_score": 90, "new_score": 70, "reason": "score dropped"}
    assert p["triggers"] == ["score_drop"]
    assert p["old_decision"] == "safe" and p["old_certified_mark"] is True
    _, title, body = state["notes"][0]
    assert body == ("A tool you're watching changed: score dropped (90 -> 70). "
                    "Now: Safe to connect · Certified (no blocking findings).")


# ── the planned re-score hold absorbs answer moves too ──────────────────────────
async def test_hold_absorbs_an_answer_change(env):
    state, watch = env
    state["held"] = True
    state["decision"] = REVIEW
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []
    assert watch.last_decision == "review" and watch.last_certified is False
    state["held"] = False
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []


async def test_drift_still_alerts_during_hold_without_the_answer_reason(env):
    from src.api.watch_router import WatchScan

    state, watch = env
    state["held"] = True
    state["scan"] = WatchScan(80, "sha256:new", {})
    state["decision"] = REVIEW
    await scheduler._run_watch_rescan()
    assert _kinds(state) == ["watch_alert"]
    assert state["delivered"][0]["triggers"] == ["definition_change"]


# ── the webhook payload is signed like every other ──────────────────────────────
async def test_grade_change_payload_verifies_with_hmac(monkeypatch):
    import hashlib
    import hmac
    import json

    from src.api.account_webhook_router import deliver_alert_webhook
    from src.models import ToolWatch

    calls: list = []

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, content=None, headers=None):
            calls.append((content, headers))

            class _R:
                status_code = 204
            return _R()

    monkeypatch.setattr("src.ssrf.ssrf_safe_async_client", lambda **kw: _Client())
    monkeypatch.setattr("src.ssrf.validate_url_https", lambda url, field_name="url": url)
    w = ToolWatch(owner="o", repo="r", last_score=90, last_decision="safe",
                  last_certified=True)
    payload = scheduler._grade_change_payload(
        w, 70, "score dropped",
        [("score_drop", "score dropped"), ("answer_worse", "answer changed"),
         ("certified_lost", "Certified mark removed")], REVIEW)
    secret = "whsec_test"
    assert await deliver_alert_webhook("https://hooks.example/x", payload, secret) == 204

    body, headers = calls[0]
    expected = "sha256=" + hmac.new(
        secret.encode(), headers["X-AgentAvow-Timestamp"].encode() + b"." + body,
        hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, headers["X-AgentAvow-Signature"])
    sent = json.loads(body)
    assert sent["old_decision"] == "safe" and sent["old_certified_mark"] is True
    assert sent["triggers"] == ["score_drop", "answer_worse", "certified_lost"]
    assert sent["decision"] == "review" and sent["certified"] is False


# ── email ───────────────────────────────────────────────────────────────────────
def test_answer_email_names_old_and_new():
    from src.email import render_watch_notification

    subj, html = render_watch_notification(
        "answer", "npm", "thing", 80, 78, decision=REVIEW,
        old_decision={"decision": "safe", "certified": True})
    assert "answer changed" in subj and "Review before you connect" in subj
    assert "Safe to connect · Certified" in html

    subj, _ = render_watch_notification(
        "answer", "npm", "thing", 80, 80, decision=SAFE,
        old_decision={"decision": "safe", "certified": True})
    assert "lost its Certified mark" in subj

    subj, _ = render_watch_notification(
        "answer_improve", "npm", "thing", 60, 62, decision=SAFE,
        old_decision={"decision": "review", "certified": False})
    assert "improved" in subj and subj.startswith("AgentAvow · ")


def test_drop_email_unchanged_without_old_decision():
    from src.email import render_watch_notification

    a = render_watch_notification("drop", "npm", "thing", 90, 70, decision=REVIEW)
    b = render_watch_notification("drop", "npm", "thing", 90, 70, decision=REVIEW,
                                  old_decision=None)
    assert a == b and "also changed" not in a[1]
    _, html = render_watch_notification(
        "drop", "npm", "thing", 90, 70, decision=REVIEW,
        old_decision={"decision": "safe", "certified": False})
    assert "The answer also changed" in html
