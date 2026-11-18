"""Install checks: a package left without a grade is never passed in silence.

Each install command gets one fresh scan (FRESH_MAX) and a time budget (PKG_BUDGET). A
package that AgentAvow has never graded and that gets no fresh scan, or whose turn
never comes because an earlier package used the time up, is "not checked yet": Claude
Code asks and Codex denies, naming it. Only when AgentAvow does not answer at all
(offline, timeouts, 5xx) does the install go ahead, with a note, so a slow or down
AgentAvow never blocks an install.
"""
from __future__ import annotations

import io
import json
import socket
import urllib.error

import pytest

from tests.test_agentavow_claude_pins import SCRIPTS, _load

SAFE = {"trust_score": 90, "decision": "safe", "decision_reason": "nothing found",
        "decision_final": True, "trust_tier": "trusted", "grade": "", "findings": {"items": []}}
BAD = {"trust_score": 20, "decision": "do_not_connect", "decision_reason": "1 critical finding",
       "decision_final": True, "trust_tier": "restricted", "grade": "",
       "findings": {"items": [{"severity": "critical"}]}}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def hook(tmp_path, monkeypatch):
    """The install hook with its own cache file, a fake clock and a fake scan API.
    ``api.plan[name]`` says what the API does for a package:
      "stored-safe"  a stored grade, Safe
      "new-safe"     never graded (202 queued); the fresh scan answers Safe
      "new-bad"      never graded; the fresh scan answers Do not connect
      "new-slow"     never graded; the fresh scan takes 13 s and times out
      "offline"      no connection
      "timeout"      the request times out
      "busy"         HTTP 503
    """
    pi = _load("ncy_pi", SCRIPTS / "agentavow_pre_install.py")
    pc = pi._precheck()
    monkeypatch.setattr(pc, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(pi, "_precheck", lambda: pc)
    clock = Clock()
    monkeypatch.setattr(pi.time, "monotonic", clock)
    calls: list[tuple[str, bool]] = []
    plan: dict[str, str] = {}

    def fetch(path, params):
        name = path.rsplit("/", 1)[-1]
        stored = params.get("stored") == "true"
        calls.append((name, stored))
        how = plan.get(name, "offline")
        if how == "offline":
            raise urllib.error.URLError(ConnectionRefusedError("refused"))
        if how == "timeout":
            clock.now += pc.TIMEOUT
            raise socket.timeout("timed out")
        if how == "busy":
            raise urllib.error.HTTPError(path, 503, "busy", {}, io.BytesIO(b"{}"))
        if how == "stored-safe":
            return json.loads(json.dumps(SAFE))
        if stored:
            raise pc._QueuedError("queued")
        if how == "new-slow":
            clock.now += 13
            raise socket.timeout("timed out")
        if how == "new-still-scanning":  # the fresh scan answers 202: still scanning
            raise pc._QueuedError("still checking")
        if how == "new-unreachable":  # the fresh scan cannot connect (or times out connecting)
            raise urllib.error.URLError(socket.timeout("connect timed out"))
        if how == "new-busy":
            raise urllib.error.HTTPError(path, 503, "busy", {}, io.BytesIO(b"{}"))
        return json.loads(json.dumps(BAD if how == "new-bad" else SAFE))

    monkeypatch.setattr(pc, "_fetch", fetch)
    return pi, pc, calls, plan


def _run(pi, monkeypatch, capsys, cmd: str, codex: bool = False) -> dict:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": cmd}}
    if codex:
        payload["turn_id"] = "01a1ec2c-c359-7aa3-aec3-321647527c0a"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.delenv("AGENTAVOW_HOST", raising=False)
    pi.main()
    out = capsys.readouterr().out
    return json.loads(out) if out else {}


def _decision(out: dict):
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


# --- attack twins: the second package must not pass ungraded -------------------------

@pytest.mark.parametrize("order", [("decoy", "target"), ("target", "decoy")])
def test_two_never_graded_packages_the_second_is_put_to_the_person(
        hook, monkeypatch, capsys, order):
    pi, pc, calls, plan = hook
    plan.update(decoy="new-safe", target="new-bad")
    out = _run(pi, monkeypatch, capsys, f"npm i {order[0]} {order[1]}")
    assert _decision(out) == "ask"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    first, second = order
    # the first takes the one fresh scan; the second is named as not checked yet
    assert (first, False) in calls and (second, False) not in calls
    assert f"❔ {pi.NOT_YET}: {second} — AgentAvow has no grade for it" in reason
    if first == "target":
        assert "Do not connect" in reason  # graded bad itself


@pytest.mark.parametrize("order", [("slow", "target"), ("target", "slow")])
def test_a_slow_package_does_not_let_the_next_one_through(hook, monkeypatch, capsys, order):
    pi, pc, calls, plan = hook
    plan.update(slow="new-slow", target="stored-safe")
    if order == ("target", "slow"):
        # target first: graded from its stored grade; the slow one is not checked yet
        out = _run(pi, monkeypatch, capsys, "npm i target slow")
        assert _decision(out) == "ask"
        assert f"❔ {pi.NOT_YET}: slow" in out["hookSpecificOutput"]["permissionDecisionReason"]
        return
    plan["target"] = "new-bad"  # would have been caught, had it been checked
    out = _run(pi, monkeypatch, capsys, "npm i slow target")
    assert _decision(out) == "ask"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert f"❔ {pi.NOT_YET}: slow, target" in reason
    assert reason.endswith(f"AgentAvow says: {pi.NOT_YET_SAID}. Continue anyway?")


def test_slow_decoy_then_stored_package_out_of_time_asks(hook, monkeypatch, capsys):
    """The slow fresh scan eats the budget before the next package is even asked about."""
    pi, pc, calls, plan = hook
    plan.update(slow="new-slow", target="stored-safe")
    monkeypatch.setattr(pi, "PKG_BUDGET", 14.0)
    out = _run(pi, monkeypatch, capsys, "npm i slow target")
    assert ("target", True) not in calls  # never asked: no time left
    assert _decision(out) == "ask"
    assert f"❔ {pi.NOT_YET}: slow, target" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_second_never_graded_package_is_denied(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(decoy="new-safe", target="new-bad")
    out = _run(pi, monkeypatch, capsys, "npm i decoy target", codex=True)
    assert _decision(out) == "deny"
    assert f"AgentAvow says: {pi.NOT_YET_SAID}, so it stopped" in out["systemMessage"]


def test_codex_slow_decoy_is_denied(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(slow="new-slow", target="new-bad")
    out = _run(pi, monkeypatch, capsys, "npm i slow target", codex=True)
    assert _decision(out) == "deny"
    assert f"{pi.NOT_YET}: slow, target" in out["systemMessage"]


# --- controls ---------------------------------------------------------------------

def test_one_never_graded_package_gets_the_fresh_scan_and_is_graded(hook, monkeypatch,
                                                                    capsys):
    pi, pc, calls, plan = hook
    plan.update(fresh="new-safe")
    assert _run(pi, monkeypatch, capsys, "npm i fresh") == {}  # Safe: silent
    assert calls == [("fresh", True), ("fresh", False)]
    plan.update(fresh2="new-bad")
    out = _run(pi, monkeypatch, capsys, "npm i fresh2")
    assert _decision(out) == "ask" and "Do not connect" in out["systemMessage"]


@pytest.mark.parametrize("how", ["new-slow", "new-still-scanning"])
def test_one_never_graded_package_whose_scan_does_not_finish_asks(hook, monkeypatch, capsys,
                                                                   how):
    """AgentAvow answered (202) but its own fresh scan did not finish in time."""
    pi, pc, calls, plan = hook
    plan.update(pkg=how)
    out = _run(pi, monkeypatch, capsys, "npm i pkg@1.0.15")
    assert _decision(out) == "ask"
    assert f"❔ {pi.NOT_YET}: pkg@1.0.15" in out["hookSpecificOutput"][
        "permissionDecisionReason"]


@pytest.mark.parametrize("how", ["new-slow", "new-still-scanning"])
def test_codex_still_checking_gives_a_way_forward(hook, monkeypatch, capsys, how):
    pi, pc, calls, plan = hook
    plan.update(pkg=how)
    out = _run(pi, monkeypatch, capsys, "npm i pkg@1.0.15", codex=True)
    assert _decision(out) == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert ("AgentAvow is checking pkg@1.0.15 now; run the same command again in a minute "
            "or two and it will have a grade.") in reason
    assert "switch AgentAvow's hooks off in Codex (/hooks) for this session" in reason
    assert f"AgentAvow says: {pi.NOT_YET_SAID}" in reason


def test_retry_once_the_grade_is_stored_passes_silently(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(pkg="new-still-scanning")
    assert _decision(_run(pi, monkeypatch, capsys, "npm i pkg@1.0.15", codex=True)) == "deny"
    plan.update(pkg="stored-safe")  # a minute later: the scan finished and is stored
    assert _run(pi, monkeypatch, capsys, "npm i pkg@1.0.15", codex=True) == {}
    assert _run(pi, monkeypatch, capsys, "npm i pkg@1.0.15") == {}  # Claude Code too


@pytest.mark.parametrize("how", ["new-unreachable", "new-busy"])
def test_fresh_scan_unreachable_is_a_note_only(hook, monkeypatch, capsys, how):
    """Connection failure, connection timeout or 5xx on the fresh scan: never a stop."""
    pi, pc, calls, plan = hook
    plan.update(pkg=how)
    for codex in (False, True):
        out = _run(pi, monkeypatch, capsys, "npm i pkg", codex=codex)
        assert _decision(out) is None
        assert "not checked (AgentAvow is busy right now)" in out["systemMessage"]


@pytest.mark.parametrize("how", ["offline", "timeout", "busy"])
def test_api_unreachable_never_blocks(hook, monkeypatch, capsys, how):
    pi, pc, calls, plan = hook
    plan.update(a=how, b=how, c=how)
    out = _run(pi, monkeypatch, capsys, "npm i a b c")
    assert _decision(out) is None
    msg = out.get("systemMessage", "")
    assert pi.NOT_YET not in msg
    if how == "busy":
        assert "busy right now" in msg


def test_api_unreachable_past_the_budget_is_a_note(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(a="timeout", b="timeout", c="timeout")
    monkeypatch.setattr(pi, "PKG_BUDGET", 14.0)
    out = _run(pi, monkeypatch, capsys, "npm i a b c")
    assert _decision(out) is None
    assert "AgentAvow did not answer in time for this command" in out["systemMessage"]


def test_codex_api_unreachable_never_denies(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(a="offline", b="offline")
    out = _run(pi, monkeypatch, capsys, "npm i a b", codex=True)
    assert _decision(out) is None


def test_stored_grades_need_no_fresh_scan(hook, monkeypatch, capsys):
    pi, pc, calls, plan = hook
    plan.update(a="stored-safe", b="stored-safe", c="stored-safe")
    assert _run(pi, monkeypatch, capsys, "npm i a b c") == {}


# --- doas ---------------------------------------------------------------------------

def test_doas_is_unwrapped(hook):
    pi = hook[0]
    assert pi._unwrap(["doas", "-u", "bob", "npm_config_registry=x", "npm", "i", "y"]) == (
        ["npm_config_registry=x"], ["npm", "i", "y"])
    assert pi._installer(["doas", "pip", "install", "x"])[0] == "pypi"
