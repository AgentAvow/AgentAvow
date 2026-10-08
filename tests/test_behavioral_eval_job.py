"""The scheduled behavioral eval job (src/jobs/behavioral_eval.py): report shape,
history, diff + alert rules, corpus overrides, slot discipline, and the admin
endpoints. The eval runner functions are monkeypatched — nothing touches a sandbox."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
import src.jobs.behavioral_eval as be
from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes

# --- fakes -------------------------------------------------------------------

class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, object] = {}
        self.lists: dict[str, list] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def delete(self, key):
        self.store.pop(key, None)

    async def mget(self, keys):
        return [self.store.get(k) for k in keys]

    async def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    async def ltrim(self, key, start, stop):
        self.lists[key] = self.lists.get(key, [])[start:stop + 1]

    async def lrange(self, key, start, stop):
        return self.lists.get(key, [])[start:stop + 1]

    async def expire(self, key, ttl):
        return True


class _Res:
    """Stand-in BehavioralResult."""

    def __init__(self, ran=True, error=None):
        self.ran, self.error = ran, error


class _Finding:
    def __init__(self, rule):
        self.rule = rule


class _FakeRunEval:
    """Replaces the imported run_eval module: scripted outcomes per fixture / package."""

    def __init__(self, corpus, *, fixture_fail=(), fixture_rules=None, kg=None):
        self._corpus = corpus
        self.fixture_fail = set(fixture_fail)
        self.fixture_rules = fixture_rules or {}
        self.kg = kg or {}
        self.calls: list[str] = []

    def load_corpus(self):
        return self._corpus

    async def run_fixture_entry_sandbox(self, entry):
        self.calls.append("fixture:" + (entry.get("file") or entry.get("dir")))
        return _Res()

    def grade(self, res):
        return [_Finding(r) for r in self.fixture_rules.get(id(res), [])]

    def check_expectations(self, entry, res):
        label = entry["label"]
        return [f"expected rule missing for {label}"] if label in self.fixture_fail else []

    async def run_known_good(self, pkg):
        self.calls.append(f"kg:{pkg['surface']}:{pkg['name']}")
        spec = self.kg.get(pkg["name"], {})
        rules = spec.get("rules", [])
        expect = pkg.get("expect_rules", [])
        return {
            "ran": spec.get("ran", True), "error": spec.get("error"),
            "summary": {"launch_ok": spec.get("launch_ok", True),
                        "start_reason": spec.get("start_reason", "started"),
                        "tools_called": spec.get("tools_called", 3)},
            "findings": [{"rule": r, "severity": "high", "name": r} for r in rules],
            "false_positives": [r for r in rules if r not in expect],
        }


CORPUS = {
    "fixtures": [{"file": "benign_server.py", "label": "benign"},
                 {"file": "lies_readonly_server.py", "label": "lies_about_readonly"}],
    "skill_fixtures": [{"dir": "benign-skill", "label": "benign_skill"}],
    "known_good": [
        {"surface": "npm", "name": "@mcp/server-a"},
        {"surface": "pypi", "name": "mcp-server-b"},
        {"surface": "npm", "name": "telemetry-server",
         "expect_rules": ["behavioral_undeclared_egress"], "note": "ships telemetry"},
    ],
    "known_good_skills": [{"repo": "owner/skill-one"}],
}


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


@pytest.fixture
def slots(monkeypatch):
    """Record every slot acquire/release; configurable to refuse."""
    log: list[str] = []
    state = {"refuse": 0}

    async def acquire():
        log.append("acquire")
        if state["refuse"] > 0:
            state["refuse"] -= 1
            return None
        return "lease-1"

    async def release(lease=None):
        log.append("release")
        state["released_lease"] = lease

    from src.config import settings

    monkeypatch.setattr("src.api.public_scan_router._acquire_behavioral_slot", acquire)
    monkeypatch.setattr("src.api.public_scan_router._release_behavioral_slot", release)
    monkeypatch.setattr(settings, "behavioral_eval_slot_wait_sec", 0.05, raising=False)
    return SimpleNamespace(log=log, state=state)


@pytest.fixture
def no_alert(monkeypatch):
    sent: list[dict] = []

    async def fake_alert(report):
        sent.append(report)
        return {"notified": 1, "webhooks": 0}

    monkeypatch.setattr(be, "alert_regression", fake_alert)
    return sent


def _use(monkeypatch, fake: _FakeRunEval):
    monkeypatch.setattr(be, "load_run_eval", lambda: fake)
    return fake


# --- corpus merge ------------------------------------------------------------

def test_corpus_key_and_normalize():
    assert be.corpus_key({"surface": "npm", "name": "x"}) == "npm:x"
    assert be.corpus_key({"repo": "o/r"}) == "skill:o/r"
    n = be._normalize({"repo": "o/r"}, "file")
    assert n["surface"] == "skill" and n["name"] == "o/r" and n["key"] == "skill:o/r"
    assert be._normalize({"surface": "cargo", "name": "x"}, "admin") is None
    assert be._normalize({"surface": "skill", "name": "not-a-repo"}, "admin") is None
    assert be._normalize({"surface": "npm"}, "admin") is None


async def test_merged_corpus_applies_add_and_remove(redis):
    redis.store[be.CORPUS_ADD_KEY] = json.dumps([
        {"surface": "npm", "name": "@extra/server"},
        {"surface": "npm", "name": "@mcp/server-a", "expect_rules": ["canary_echoed_in_result"]},
        {"surface": "bogus", "name": "ignored"},
    ])
    redis.store[be.CORPUS_REMOVE_KEY] = json.dumps(["pypi:mcp-server-b", "skill:owner/skill-one"])
    merged = await be.merged_corpus(CORPUS)
    keys = [e["key"] for e in merged]
    assert "npm:@extra/server" in keys
    assert "pypi:mcp-server-b" not in keys and "skill:owner/skill-one" not in keys
    a = next(e for e in merged if e["key"] == "npm:@mcp/server-a")
    assert a["source"] == "admin" and a["expect_rules"] == ["canary_echoed_in_result"]
    assert next(e for e in merged if e["key"] == "npm:telemetry-server")["source"] == "file"
    view = await be.corpus_view(CORPUS)
    removed = [e["key"] for e in view if e["removed"]]
    assert sorted(removed) == ["pypi:mcp-server-b", "skill:owner/skill-one"]


async def test_merged_corpus_tolerates_garbage_overrides(redis):
    redis.store[be.CORPUS_ADD_KEY] = b"{not json"
    redis.store[be.CORPUS_REMOVE_KEY] = json.dumps({"a": 1})
    assert len(await be.merged_corpus(CORPUS)) == 4


async def test_apply_corpus_edit_round_trip(redis, monkeypatch):
    monkeypatch.setattr(be, "file_known_good", lambda corpus=None: _file_kg(CORPUS))
    view = await be.apply_corpus_edit("add", "npm", "@new/one", ["behavioral_undeclared_egress"])
    added = next(e for e in view if e["key"] == "npm:@new/one")
    assert added["source"] == "admin" and added["expect_rules"] == ["behavioral_undeclared_egress"]
    # removing a file entry marks it removed; adding it back restores it
    view = await be.apply_corpus_edit("remove", "pypi", "mcp-server-b")
    assert next(e for e in view if e["key"] == "pypi:mcp-server-b")["removed"] is True
    assert "pypi:mcp-server-b" in json.loads(redis.store[be.CORPUS_REMOVE_KEY])
    view = await be.apply_corpus_edit("add", "pypi", "mcp-server-b")
    assert next(e for e in view if e["key"] == "pypi:mcp-server-b")["removed"] is False
    # removing an admin addition just drops it
    view = await be.apply_corpus_edit("remove", "npm", "@new/one")
    assert not any(e["key"] == "npm:@new/one" for e in view)
    assert "npm:@new/one" not in json.loads(redis.store[be.CORPUS_REMOVE_KEY])
    with pytest.raises(ValueError):
        await be.apply_corpus_edit("add", "cargo", "x")
    with pytest.raises(ValueError):
        await be.apply_corpus_edit("frobnicate", "npm", "x")


def _file_kg(corpus):
    out = []
    for e in corpus["known_good"]:
        out.append(be._normalize(e, "file"))
    for e in corpus["known_good_skills"]:
        out.append(be._normalize(dict(e, surface="skill"), "file"))
    return out


# --- the run: report shape, storage, slots ----------------------------------

async def test_run_report_shape_and_storage(redis, slots, no_alert, monkeypatch):
    fake = _use(monkeypatch, _FakeRunEval(CORPUS, fixture_fail={"lies_about_readonly"}, kg={
        "@mcp/server-a": {"rules": ["canary_echoed_in_result"]},
        "mcp-server-b": {"launch_ok": False, "start_reason": "needs_credentials"},
        "telemetry-server": {"rules": ["behavioral_undeclared_egress"]},
        "owner/skill-one": {"ran": False, "error": "clone failed", "launch_ok": False,
                            "start_reason": "install_failed"},
    }))
    report = await be.run_behavioral_eval(reason="test")
    assert report["reason"] == "test" and report["ran_at"] and "duration_s" in report
    assert report["fixtures"] == {"total": 3, "passed": 2, "failed": ["lies_about_readonly"]}
    kg = report["known_good"]
    assert kg["total"] == 4 and kg["ran"] == 3 and kg["exercised"] == 2
    assert kg["false_positives"] == [
        {"surface": "npm", "name": "@mcp/server-a", "rules": ["canary_echoed_in_result"]}]
    assert kg["expected_findings"] == 1
    assert {n["name"]: n["start_reason"] for n in kg["not_started"]} == {
        "mcp-server-b": "needs_credentials", "owner/skill-one": "install_failed"}
    assert len(report["rows"]) == 7
    skill_row = next(r for r in report["rows"] if r.get("name") == "owner/skill-one")
    assert skill_row["surface"] == "skill" and skill_row["error"] == "clone failed"
    # serialized: fixtures first, then known-good, in corpus order
    assert fake.calls == [
        "fixture:benign_server.py", "fixture:lies_readonly_server.py", "fixture:benign-skill",
        "kg:npm:@mcp/server-a", "kg:pypi:mcp-server-b", "kg:npm:telemetry-server",
        "kg:skill:owner/skill-one"]
    # one slot per item, released after each, never two held at once
    assert slots.log == ["acquire", "release"] * 7
    # stored
    latest = json.loads(redis.store[be.LATEST_KEY])
    assert latest["ran_at"] == report["ran_at"]
    assert len(redis.lists[be.HISTORY_KEY]) == 1
    # first run: diff present, no regression, no alert
    assert report["diff"]["first_run"] is True and report["diff"]["regression"] is False
    assert "alert" not in report and no_alert == []
    # running flag cleared
    assert be.RUNNING_KEY not in redis.store


async def test_history_trimmed_newest_first(redis, slots, no_alert, monkeypatch):
    _use(monkeypatch, _FakeRunEval(CORPUS))
    for i in range(be.HISTORY_MAX + 3):
        await be.run_behavioral_eval(reason=f"r{i}")
    hist = await be.read_history()
    assert len(hist) == be.HISTORY_MAX
    assert hist[0]["reason"] == f"r{be.HISTORY_MAX + 2}"
    assert (await be.read_latest())["reason"] == hist[0]["reason"]


async def test_running_flag_blocks_a_second_run(redis, slots, no_alert, monkeypatch):
    _use(monkeypatch, _FakeRunEval(CORPUS))
    assert await be.mark_running() is True
    with pytest.raises(be.EvalAlreadyRunningError):
        await be.run_behavioral_eval()
    # the holder can run with the flag it already took
    await be.run_behavioral_eval(_already_marked=True)
    assert be.RUNNING_KEY not in redis.store


async def test_slot_refused_item_is_skipped_not_crashed(redis, slots, no_alert, monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "behavioral_eval_slot_wait_sec", 0, raising=False)
    _use(monkeypatch, _FakeRunEval(CORPUS))
    slots.state["refuse"] = 1  # the first acquire fails: the first fixture is skipped
    report = await be.run_behavioral_eval()
    first = report["rows"][0]
    assert first["ok"] is False and first["failures"][0].startswith("skipped:")
    assert report["fixtures"]["passed"] == 2
    # a refused acquire never gets a release; the other 6 items do
    assert slots.log.count("release") == 6 and slots.log.count("acquire") == 7


async def test_hold_slot_waits_then_acquires(slots, monkeypatch):
    slots.state["refuse"] = 2
    async with be.hold_slot(wait_s=5, poll_s=0.001):
        pass
    assert slots.log == ["acquire", "acquire", "acquire", "release"]


async def test_item_crash_is_contained(redis, slots, no_alert, monkeypatch):
    fake = _FakeRunEval(CORPUS)

    async def boom(pkg):
        raise RuntimeError("sandbox exploded")

    fake.run_known_good = boom
    _use(monkeypatch, fake)
    report = await be.run_behavioral_eval()
    kg_rows = [r for r in report["rows"] if r["kind"] == "known_good"]
    assert all(r["error"].startswith("crashed:") for r in kg_rows)
    assert report["known_good"]["ran"] == 0
    assert slots.log.count("release") == 7  # released even when the item raised


# --- diff + alert rules ------------------------------------------------------

def _rep(*, failed=(), fps=(), exercised_names=(), ran_at="t"):
    rows = [{"kind": "known_good", "surface": "npm", "name": n, "launch_ok": True}
            for n in exercised_names]
    return {
        "ran_at": ran_at,
        "fixtures": {"total": 3, "passed": 3 - len(failed), "failed": list(failed)},
        "known_good": {"total": 10, "ran": 10, "exercised": len(exercised_names),
                       "false_positives": [{"surface": "npm", "name": n, "rules": list(r)}
                                           for n, r in fps],
                       "expected_findings": 0, "not_started": []},
        "rows": rows,
    }


def test_diff_first_run_never_regresses():
    d = be.compute_diff(None, _rep(failed=["benign"], fps=[("a", ["x"])]))
    assert d["first_run"] and d["regression"] is False
    assert d["fixture_failures"] == ["benign"] and d["new_false_positives"] == []


def test_diff_new_false_positive_alerts_only_for_new_rules():
    prev = _rep(fps=[("a", ["r1"])], exercised_names=["a", "b"])
    cur = _rep(fps=[("a", ["r1"])], exercised_names=["a", "b"])
    assert be.compute_diff(prev, cur)["regression"] is False
    cur = _rep(fps=[("a", ["r1", "r2"])], exercised_names=["a", "b"])
    d = be.compute_diff(prev, cur)
    assert d["new_false_positives"] == [{"surface": "npm", "name": "a", "rules": ["r2"]}]
    assert d["regression"] is True
    cur = _rep(fps=[], exercised_names=["a", "b"])
    d = be.compute_diff(prev, cur)
    assert d["cleared_false_positives"] == ["npm:a"] and d["regression"] is False


def test_diff_fixture_regression_and_persisting_failure():
    prev = _rep(exercised_names=["a"])
    d = be.compute_diff(prev, _rep(failed=["benign"], exercised_names=["a"]))
    assert d["fixture_regressions"] == ["benign"] and d["regression"] is True
    # still failing next week: not "new", but still an alert condition
    d = be.compute_diff(_rep(failed=["benign"], exercised_names=["a"]),
                        _rep(failed=["benign"], exercised_names=["a"]))
    assert d["fixture_regressions"] == [] and d["fixture_failures"] == ["benign"]
    assert d["regression"] is True
    d = be.compute_diff(_rep(failed=["benign"], exercised_names=["a"]),
                        _rep(exercised_names=["a"]))
    assert d["fixture_fixed"] == ["benign"] and d["regression"] is False


def test_diff_exercised_drop_threshold():
    prev = _rep(exercised_names=["a", "b", "c", "d"])
    d = be.compute_diff(prev, _rep(exercised_names=["a", "b", "c"]))
    assert d["exercised_delta"] == -1 and d["newly_not_exercised"] == ["npm:d"]
    assert d["regression"] is False
    d = be.compute_diff(prev, _rep(exercised_names=["a", "b"]))
    assert d["exercised_delta"] == -2 and d["regression"] is True
    assert d["newly_not_exercised"] == ["npm:c", "npm:d"]
    d = be.compute_diff(prev, _rep(exercised_names=["a", "b", "c", "d", "e"]))
    assert d["exercised_delta"] == 1 and d["newly_exercised"] == ["npm:e"]


def test_summarize_regression_names_every_cause():
    rep = _rep(failed=["benign"], fps=[("a", ["r2"])], exercised_names=["x"])
    rep["diff"] = {"fixture_failures": ["benign"], "exercised_delta": -3,
                   "new_false_positives": [{"surface": "npm", "name": "a", "rules": ["r2"]}],
                   "newly_not_exercised": ["npm:y"]}
    title, body = be.summarize_regression(rep)
    assert "regressed" in title
    assert "benign" in body and "npm:a (r2)" in body and "dropped by 3" in body


async def test_second_run_alerts_on_regression(redis, slots, no_alert, monkeypatch):
    _use(monkeypatch, _FakeRunEval(CORPUS))
    await be.run_behavioral_eval()
    assert no_alert == []
    _use(monkeypatch, _FakeRunEval(CORPUS, kg={"@mcp/server-a": {"rules": ["cloud_metadata_probe"]}}))
    report = await be.run_behavioral_eval()
    assert report["diff"]["new_false_positives"][0]["name"] == "@mcp/server-a"
    assert len(no_alert) == 1 and report["alert"] == {"notified": 1, "webhooks": 0}


async def test_alert_without_admin_logs_warning(monkeypatch, caplog):
    class _DB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def commit(self):
            pass

    async def no_admins(db):
        return []

    monkeypatch.setattr("src.database.async_session", lambda: _DB())
    monkeypatch.setattr(be, "_admin_entities", no_admins)
    rep = _rep(failed=["benign"])
    rep["diff"] = {"fixture_failures": ["benign"]}
    with caplog.at_level("WARNING"):
        out = await be.alert_regression(rep)
    assert out == {"notified": 0, "webhooks": 0}
    assert any(be.ALERT_LOG_PREFIX in r.message and "no admin" in r.message
               for r in caplog.records)


async def test_alert_notifies_admins_and_their_hook(monkeypatch):
    class _DB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def commit(self):
            pass

    admin = SimpleNamespace(id="admin-id", email="kenne@agentavow.com")
    notes, deliveries = [], []
    hook = SimpleNamespace(id="hook", url="https://ops.example/hook", last_status=None,
                           last_delivery_at=None)

    async def admins(db):
        return [admin]

    async def note(db, entity_id, kind, title, body, reference_id=None):
        notes.append((entity_id, kind, reference_id))

    async def watcher_hook(db, entity_id):
        return hook

    async def deliver(h, payload):
        deliveries.append(payload)
        return 200

    monkeypatch.setattr("src.database.async_session", lambda: _DB())
    monkeypatch.setattr(be, "_admin_entities", admins)
    monkeypatch.setattr("src.api.notification_router.create_notification", note)
    monkeypatch.setattr("src.jobs.scheduler._watcher_hook", watcher_hook)
    monkeypatch.setattr("src.api.account_webhook_router.deliver_to_hook", deliver)
    rep = _rep(failed=["benign"], ran_at="2026-10-02T00:00:00+00:00")
    rep["diff"] = {"fixture_failures": ["benign"], "regression": True}
    out = await be.alert_regression(rep)
    assert out == {"notified": 1, "webhooks": 1}
    assert notes == [("admin-id", be.NOTIFICATION_KIND, "behavioral-eval")]
    assert deliveries[0]["type"] == be.WEBHOOK_TYPE
    assert deliveries[0]["diff"]["fixture_failures"] == ["benign"]
    assert hook.last_status == 200 and hook.last_delivery_at is not None


# --- admin endpoints ---------------------------------------------------------

def _app(admin: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(md.router, prefix="/api/v1")
    app.dependency_overrides[get_current_entity] = lambda: SimpleNamespace(is_admin=admin)
    app.dependency_overrides[rate_limit_reads] = lambda: None
    app.dependency_overrides[rate_limit_writes] = lambda: None
    return app


async def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


async def test_behavioral_metrics_carry_last_eval_and_corpus(redis, slots, no_alert, monkeypatch):
    _use(monkeypatch, _FakeRunEval(CORPUS, fixture_fail={"benign"}))
    await be.run_behavioral_eval(reason="seed")
    redis.store[be.CORPUS_REMOVE_KEY] = json.dumps(["pypi:mcp-server-b"])
    monkeypatch.setattr(be, "file_known_good", lambda corpus=None: _file_kg(CORPUS))
    async with await _client(_app()) as c:
        r = await c.get("/api/v1/admin/metrics/behavioral", params={"window": "7d"})
    assert r.status_code == 200
    body = r.json()
    le = body["last_eval"]
    assert le["reason"] == "seed" and le["running"] is False and "rows" not in le
    assert le["fixtures"]["failed"] == ["benign"] and le["diff"]["first_run"] is True
    keys = {e["key"]: e for e in body["corpus"]}
    assert keys["pypi:mcp-server-b"]["removed"] is True
    assert keys["npm:@mcp/server-a"]["source"] == "file"


async def test_behavioral_metrics_without_a_report(redis):
    async with await _client(_app()) as c:
        r = await c.get("/api/v1/admin/metrics/behavioral")
    assert r.status_code == 200 and r.json()["last_eval"] is None
    assert isinstance(r.json()["corpus"], list)


async def test_trigger_eval_202_then_409_while_running(redis, monkeypatch):
    started = []

    async def fake_run(*, reason="scheduled", _already_marked=False):
        started.append((reason, _already_marked))
        return {}

    monkeypatch.setattr(be, "run_behavioral_eval", fake_run)
    async with await _client(_app()) as c:
        r = await c.post("/api/v1/admin/metrics/behavioral/eval")
        assert r.status_code == 202 and r.json()["status"] == "queued"
        for t in list(md._EVAL_TASKS):
            await t
        assert started == [("admin", True)]
        # the flag is still set (fake_run never clears it) → a second trigger is refused
        assert redis.store.get(be.RUNNING_KEY)
        r = await c.post("/api/v1/admin/metrics/behavioral/eval")
        assert r.status_code == 409


async def test_trigger_eval_requires_admin(redis):
    async with await _client(_app(admin=False)) as c:
        assert (await c.post("/api/v1/admin/metrics/behavioral/eval")).status_code == 403
        assert (await c.post("/api/v1/admin/metrics/behavioral/corpus",
                             json={"action": "add", "surface": "npm", "name": "x"})
                ).status_code == 403


async def test_corpus_endpoint_add_remove_and_validation(redis, monkeypatch):
    monkeypatch.setattr(be, "file_known_good", lambda corpus=None: _file_kg(CORPUS))
    async with await _client(_app()) as c:
        r = await c.post("/api/v1/admin/metrics/behavioral/corpus", json={
            "action": "add", "surface": "skill", "repo": "owner/new-skill",
            "expect_rules": ["behavioral_undeclared_egress", " "]})
        assert r.status_code == 200
        e = next(x for x in r.json()["corpus"] if x["key"] == "skill:owner/new-skill")
        assert e["source"] == "admin" and e["expect_rules"] == ["behavioral_undeclared_egress"]
        r = await c.post("/api/v1/admin/metrics/behavioral/corpus", json={
            "action": "remove", "surface": "npm", "name": "@mcp/server-a"})
        assert r.status_code == 200
        assert next(x for x in r.json()["corpus"] if x["key"] == "npm:@mcp/server-a")["removed"]
        # validation
        r = await c.post("/api/v1/admin/metrics/behavioral/corpus",
                         json={"action": "add", "surface": "npm"})
        assert r.status_code == 422
        r = await c.post("/api/v1/admin/metrics/behavioral/corpus",
                         json={"action": "add", "surface": "cargo", "name": "x"})
        assert r.status_code == 422
        r = await c.post("/api/v1/admin/metrics/behavioral/corpus",
                         json={"action": "nuke", "surface": "npm", "name": "x"})
        assert r.status_code == 422


# --- scheduler wiring --------------------------------------------------------

def test_settings_defaults():
    from src.config import Settings

    s = Settings(_env_file=None)
    assert s.behavioral_eval_enabled is True
    assert s.behavioral_eval_interval_hours == 168
    assert s.behavioral_eval_startup_delay_sec == 3600


async def test_loop_waits_then_runs_only_when_behavioral_enabled(monkeypatch):
    import asyncio

    import src.jobs.scheduler as sched
    from src.config import settings

    sleeps, runs = [], []

    async def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) >= 2:
            raise asyncio.CancelledError

    async def fake_run(*, reason="scheduled"):
        runs.append(reason)
        return {}

    monkeypatch.setattr(sched.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(be, "run_behavioral_eval", fake_run)
    monkeypatch.setattr(settings, "behavioral_eval_startup_delay_sec", 3600, raising=False)
    monkeypatch.setattr(settings, "scanner_behavioral_enabled", False)
    with pytest.raises(asyncio.CancelledError):
        await sched._behavioral_eval_loop()
    assert sleeps[0] == 3600 and runs == []  # first run delayed; tier off → no run
    sleeps.clear()
    monkeypatch.setattr(settings, "scanner_behavioral_enabled", True)
    with pytest.raises(asyncio.CancelledError):
        await sched._behavioral_eval_loop(interval=42)
    assert sleeps == [3600, 42] and runs == ["scheduled"]
