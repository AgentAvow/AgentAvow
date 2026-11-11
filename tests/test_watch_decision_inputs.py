"""The watch loop's answer is the public scan's answer.

Regression for #281: the loop decided over ``WatchScan.data``, which held only the
sandbox-lookup fields (no trust_score, findings or metadata), so ``decide()`` answered
"review, trust score 0/100 is under 51" for every tool. These tests stub only the
fetch layer (scan_repo / scan_package / scan_mcp / scan_skill), run the REAL
``scan_watch_target_detail`` and the REAL ``_watch_decision`` inside
``_run_watch_rescan``, and compare what the watch stores and alerts with what the
public endpoint returns for the same target.
"""
from __future__ import annotations

import copy
import uuid

import pytest

from src.jobs import scheduler
from src.scanner.scan import Finding, ScanResult
from src.scanner.verdict import decide
from tests.test_watch_behavioral_drift import _FakeSession


def _result(repo: str, score: int, findings: list[Finding], **kw) -> ScanResult:
    r = ScanResult(repo=repo, stars=0, description="a tool", framework="")
    r.trust_score = score
    r.findings = findings
    r.files_scanned = r.total_scannable_files = 30
    r.has_readme = r.has_license = r.has_tests = True
    r.primary_language = "Go"  # no sandbox target for a repo
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _high(path: str) -> Finding:
    return Finding(category="code_safety", name="shell command built from input",
                   severity="high", file_path=path, line_number=3, snippet="")


def _critical(path: str) -> Finding:
    return Finding(category="tool_poisoning", name="hidden instruction in tool description",
                   severity="critical", file_path=path, line_number=1, snippet="")


CANARY_BLOCK = {"ran": True, "plan": "npm-mcp", "canary_exfil": [{"host": "evil.example"}],
                "findings": [], "unexpected_egress": ["evil.example"]}


def _cases():
    tag = uuid.uuid4().hex[:10]
    return {
        # surface, owner, repo, scan result, sandbox block cached for it
        "github_safe_certified": (
            "github", "wd-owner", f"repo-{tag}",
            _result(f"wd-owner/repo-{tag}", 92, [], certified={"eligible": True}), None),
        "npm_review": (
            "npm", "npm", f"pkg-{tag}",
            _result(f"npm:pkg-{tag}", 62, [_high("lib/index.js")],
                    artifact_scan={"version": "1.2.3"}), None),
        "mcp_do_not_connect": (
            "mcp", "mcp", f"https://mcp-{tag}.example.com/mcp",
            _result(f"mcp:{tag}", 40, [_critical("tool:run_query")],
                    tool_manifest_digest="sha256:" + "a" * 64), None),
        "npm_sandbox_folded": (
            "npm", "npm", f"sbx-{tag}",
            _result(f"npm:sbx-{tag}", 90, [], artifact_scan={"version": "2.0.0"}),
            {**CANARY_BLOCK, "version": "2.0.0"}),
        "openclaw_safe": (
            "openclaw", "wd-skills", f"skill-{tag}",
            _result(f"skill:wd-skills/skill-{tag}", 88, []), None),
    }


@pytest.fixture
def fetch_layer(monkeypatch):
    """Stub every fetcher to return the case's ScanResult (a fresh copy per call)."""
    from src.config import settings

    state: dict = {"result": None, "block": None}

    def _copy():
        return copy.deepcopy(state["result"])

    async def _scan_repo(**_kw):
        return _copy()

    async def _scan_package(surface, name, version=None):
        return _copy()

    async def _scan_mcp(url):
        return _copy()

    async def _scan_skill(owner, repo, skill=None):
        return _copy()

    async def _token():
        return None

    async def _false(*a, **kw):
        return False

    async def _none(*a, **kw):
        return None

    async def _cached_block(*a, **kw):
        return copy.deepcopy(state["block"])

    monkeypatch.setattr("src.scanner.scan.scan_repo", _scan_repo)
    monkeypatch.setattr("src.scanner.scan.scan_package", _scan_package)
    monkeypatch.setattr("src.scanner.scan.scan_mcp", _scan_mcp)
    monkeypatch.setattr("src.scanner.scan.scan_skill", _scan_skill)
    monkeypatch.setattr("src.github_auth.get_github_token", _token)
    monkeypatch.setattr("src.jobs.scan_health.is_github_budget_low", _false)
    monkeypatch.setattr("src.ssrf.validate_url_https", lambda u, **kw: u)
    # The sandbox: cache-only reads return the case's block; never a run.
    monkeypatch.setattr("src.api.public_scan_router._get_cached_behavioral", _cached_block)
    monkeypatch.setattr("src.api.public_scan_router._start_behavioral_payload", _none)
    monkeypatch.setattr(settings, "scanner_behavioral_enabled", True)
    return state


async def _public(surface: str, owner: str, repo: str, db):
    """What /public/scan/... returns for the target (a fresh scan)."""
    from src.api import public_scan_router as p
    if surface == "github":
        return await p.public_scan(owner=owner, repo=repo, force=True, behavioral=False, db=db)
    if surface == "npm":
        return await p.scan_package_endpoint(
            surface="npm", name=repo, force=True, behavioral=False, version=None,
            stored=False, db=db)
    if surface == "mcp":
        return await p.scan_mcp_endpoint(endpoint=repo, force=True, probe=False, db=db)
    if surface == "openclaw":
        return await p._skill_scan(owner, repo, None, None, True, False)
    raise AssertionError(surface)


@pytest.fixture
def loop(monkeypatch, db):
    """``_run_watch_rescan`` over one watch, the real scan path underneath."""
    from src.api import watch_router
    from src.models import AlertWebhook, ToolWatch

    state: dict = {"notes": [], "delivered": [], "watches": [], "hook": None}
    monkeypatch.setattr("src.database.async_session", lambda: _FakeSession(state))
    real_detail = watch_router.scan_watch_target_detail

    async def _detail(surface, owner, repo, _fake_db):
        # The real function, with a real session for the GitHub path's lookups.
        return await real_detail(surface, owner, repo, db)

    async def _notify(db_, entity_id, kind, title, body, reference_id=None, **kw):
        state["notes"].append((kind, title, body))

    async def _deliver(hook_, payload):
        state["delivered"].append(payload)
        return 204

    async def _none(*a, **kw):
        return None

    async def _false():
        return False

    monkeypatch.setattr(watch_router, "scan_watch_target_detail", _detail)
    monkeypatch.setattr("src.scanner.behavioral.trigger.cached_scan_data", _none)
    monkeypatch.setattr("src.scanner.behavioral.trigger.on_watch_rescan", _none)
    monkeypatch.setattr("src.api.notification_router.create_notification", _notify)
    monkeypatch.setattr("src.api.account_webhook_router.deliver_to_hook", _deliver)
    monkeypatch.setattr("src.jobs.watch_alert_hold.score_alerts_held", _false)

    def _watch(surface, owner, repo, **kw):
        w = ToolWatch(id=uuid.uuid4(), watcher_id=uuid.uuid4(), surface=surface,
                      owner=owner, repo=repo, last_score=kw.pop("last_score", None),
                      last_manifest_digest=None, last_behavioral_digest=None,
                      active=True, **kw)
        state["watches"] = [w]
        state["hook"] = AlertWebhook(id=uuid.uuid4(), entity_id=w.watcher_id,
                                     url="https://hooks.example/x", active=True)
        state["notes"].clear()
        state["delivered"].clear()
        return w

    return state, _watch


def _settled(reason: str) -> str:
    from src.scanner.verdict import PENDING_SUFFIX, QUEUED_SUFFIX
    for suffix in (PENDING_SUFFIX, QUEUED_SUFFIX):
        if reason.endswith(suffix):
            return reason[: -len(suffix)]
    return reason


CASE_IDS = ["github_safe_certified", "npm_review", "mcp_do_not_connect",
            "npm_sandbox_folded", "openclaw_safe"]
EXPECTED = {"github_safe_certified": ("safe", True), "npm_review": ("review", False),
            "mcp_do_not_connect": ("do_not_connect", False),
            "npm_sandbox_folded": ("do_not_connect", False),
            "openclaw_safe": ("safe", False)}


@pytest.mark.parametrize("case", CASE_IDS)
async def test_watch_answer_equals_the_public_answer(case, fetch_layer, loop, db):
    surface, owner, repo, result, block = _cases()[case]
    fetch_layer["result"], fetch_layer["block"] = result, block
    state, make_watch = loop

    # 1) First re-scan: no stored answer, so it seeds silently with the real one.
    w = make_watch(surface, owner, repo)
    await scheduler._run_watch_rescan()
    assert state["notes"] == [] and state["delivered"] == []

    public = await _public(surface, owner, repo, db)
    assert (w.last_decision, w.last_certified) == (public.decision, public.certified_mark)
    # Non-trivial: the cases cover every answer, and the mark.
    assert (public.decision, public.certified_mark) == EXPECTED[case]
    # And the public answer is decide() over the public payload shape.
    from src.api.public_scan_router import _apply_behavioral_score, _scan_result_to_dict
    data = _scan_result_to_dict(copy.deepcopy(result))
    if surface != "mcp":
        data = _apply_behavioral_score(data, block)
    assert decide({**data, "behavioral": block}).decision == public.decision

    # 2) A re-scan against a different stored answer alerts / notes with the real one.
    other = "safe" if public.decision != "safe" else "do_not_connect"
    w = make_watch(surface, owner, repo, last_score=result.trust_score,
                   last_decision=other, last_certified=False)
    await scheduler._run_watch_rescan()
    assert len(state["notes"]) == 1
    _, _title, body = state["notes"][0]
    # The public page may still be waiting on a sandbox run it just queued (a
    # provisional reason suffix); the watch never starts a run and states the answer
    # without it. The answer itself is the same.
    reason = _settled(public.decision_reason)
    assert f"({reason})" in body
    assert "0/100" not in body
    if public.decision != "safe":  # worse than the stored "safe": the webhook too
        p = state["delivered"][0]
        assert p["decision"] == public.decision
        assert p["decision_reason"] == reason
        assert p["certified"] is public.certified_mark
        assert p["old_decision"] == "safe"
    assert w.last_decision == public.decision


def test_no_score_is_no_answer():
    """A payload without a trust score is not decided: never "review, 0/100"."""
    d = scheduler._watch_decision({"package_coordinate": {"surface": "npm", "name": "x"}},
                                  None)
    assert d["decision"] is None
    ch = scheduler.AnswerChange("safe", True, d)
    assert not ch.moved and ch.decision_baseline == "safe" and ch.certified_baseline is True
    assert "0/100" not in scheduler.w_decision_phrase(d)


async def test_unshaped_scan_result_keeps_the_score(monkeypatch):
    """A result the public shaper cannot read still yields the score and digest; the
    watch just records no answer this cycle."""
    from types import SimpleNamespace

    from src.api import watch_router

    async def _scan_package(surface, name, version=None):
        return SimpleNamespace(error=None, trust_score=77)

    monkeypatch.setattr("src.scanner.scan.scan_package", _scan_package)
    ws = await watch_router.scan_watch_target_detail("npm", "npm", "odd", None)
    assert ws.score == 77
    assert scheduler._watch_decision(ws.data, None)["decision"] is None


def test_github_response_decision_only_when_final():
    from types import SimpleNamespace

    from src.api.watch_router import _response_decision
    final = SimpleNamespace(decision="safe", decision_final=True,
                            decision_reason="no blocking findings", certified_mark=True)
    assert _response_decision(final) == {
        "decision": "safe", "decision_final": True,
        "decision_reason": "no blocking findings", "certified": True}
    assert _response_decision(SimpleNamespace(**{**vars(final), "decision_final": False})) \
        is None
