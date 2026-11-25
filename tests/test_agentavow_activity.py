"""Tests for the activity log's recorder entry point and its hook wiring (plugin 0.1.47)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "plugins" / "agentavow-trust"
MODULE = PLUGIN_DIR / "scripts" / "agentavow_activity.py"
LAUNCHER = PLUGIN_DIR / "scripts" / "run_hook.sh"
PREFIX = 'sh "${CLAUDE_PLUGIN_ROOT}/scripts/run_hook.sh" "${CLAUDE_PLUGIN_ROOT}/scripts/'
RECORDER = PREFIX + 'agentavow_activity.py"'
SID = "5f0c1e2a-0000-4000-8000-00000000abcd"


def _load():
    spec = importlib.util.spec_from_file_location("agentavow_activity_t4", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = _load()


@pytest.fixture
def act(tmp_path, monkeypatch):
    """The module with its folder in tmp, a tmp HOME and the switch on."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AGENTAVOW_ACTIVITY", "on")
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "cache" / "activity")
    monkeypatch.setattr(A._gate(), "CACHE", tmp_path / "cache" / "scanned.json")
    return A


def _payload(event="PreToolUse", **extra) -> dict:
    p = {
        "session_id": SID,
        "cwd": "/work/project",
        "prompt_id": "p-1",
        "permission_mode": "default",
        "hook_event_name": event,
        "transcript_path": "/home/someone/.claude/projects/x/transcript.jsonl",
    }
    if event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        p.update(tool_name="Bash", tool_input={"command": "ls -la"}, tool_use_id="tu-1")
    p.update(extra)
    return p


def _run(mod, monkeypatch, capsys, payload, argv=()) -> tuple[int, str]:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    rc = mod.main(list(argv))
    return rc, capsys.readouterr().out


def _lines(mod) -> list[dict]:
    out = []
    for f in sorted(pathlib.Path(mod.ACTIVITY_DIR).glob("*/*.jsonl")):
        out.extend(json.loads(raw) for raw in f.read_text("utf-8").splitlines())
    return out


def _raw(mod) -> str:
    return "".join(f.read_text("utf-8") for f in pathlib.Path(mod.ACTIVITY_DIR).glob("*/*.jsonl"))


# --- the switch --------------------------------------------------------------------


def test_off_unless_switched_on(act, monkeypatch, capsys):
    for value in (None, "", "off", "1", "true", "yes", " on", "onn"):
        if value is None:
            monkeypatch.delenv("AGENTAVOW_ACTIVITY", raising=False)
        else:
            monkeypatch.setenv("AGENTAVOW_ACTIVITY", value)
        assert _run(act, monkeypatch, capsys, _payload()) == (0, "")
        assert not pathlib.Path(act.ACTIVITY_DIR).exists(), value
    monkeypatch.setenv("AGENTAVOW_ACTIVITY", "on")
    assert _run(act, monkeypatch, capsys, _payload()) == (0, "")
    [line] = _lines(act)
    assert line["event"] == "PreToolUse"
    assert line["tool"] == "Bash"
    assert line["input"]["command"] == "ls -la"
    assert line["session"] == SID
    assert line["agent"] == "claude-code"
    assert line["cwd"] == "/work/project"
    assert line["seq"] == 1 and line["v"] == 0
    monkeypatch.setenv("AGENTAVOW_ACTIVITY", "ON")
    _run(act, monkeypatch, capsys, _payload())
    assert len(_lines(act)) == 2


def test_windows_is_off(act, monkeypatch, capsys):
    folder = pathlib.Path(act.ACTIVITY_DIR)
    real_name = os.name
    rcs = []
    for argv in ([], ["--session-start"], ["--session-end"], ["--notes"], ["--report"]):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_payload())))
        monkeypatch.setattr(os, "name", "nt")
        try:
            rcs.append(act.main(argv))
        finally:
            monkeypatch.setattr(os, "name", real_name)
    assert rcs == [0] * 5
    assert capsys.readouterr().out == ""
    assert not folder.exists()


# --- what a line holds -------------------------------------------------------------


def test_records_post_tool_use_without_output(act, monkeypatch, capsys):
    response = {"stdout": "OUTPUT-TEXT-MUST-NOT-APPEAR", "stderr": "ERR-TEXT",
                "interrupted": False, "isImage": False}
    _run(act, monkeypatch, capsys, _payload("PostToolUse", tool_response=response,
                                            duration_ms=42))
    _run(act, monkeypatch, capsys, _payload("PostToolUseFailure", error="ERROR-TEXT boom",
                                            is_interrupt=False))
    ok, failed = _lines(act)
    assert ok["event"] == "PostToolUse" and ok["ok"] is True
    assert ok["out_bytes"] == len(json.dumps(response).encode())
    assert ok["duration_ms"] == 42
    assert failed["event"] == "PostToolUseFailure" and failed["ok"] is False
    raw = _raw(act)
    for text in ("OUTPUT-TEXT", "ERR-TEXT", "ERROR-TEXT", "transcript", "prompt_id",
                 "permission_mode", "tool_use_id"):
        assert text not in raw


def test_prompts_and_messages_are_never_recorded(act, monkeypatch, capsys):
    _run(act, monkeypatch, capsys, _payload("SubagentStop", agent_id="a1", agent_type="Explore",
                                            last_assistant_message="MESSAGE-TEXT",
                                            agent_transcript_path="/t/sub.jsonl",
                                            prompt="PROMPT-TEXT"))
    raw = _raw(act)
    assert "MESSAGE-TEXT" not in raw and "PROMPT-TEXT" not in raw and "sub.jsonl" not in raw


def test_session_events_carry_source_and_reason(act, monkeypatch, capsys):
    assert _run(act, monkeypatch, capsys, _payload("SessionStart", source="resume"),
                ["--session-start"]) == (0, "")
    assert _run(act, monkeypatch, capsys, _payload("SessionEnd", reason="prompt_input_exit"),
                ["--session-end"]) == (0, "")
    start, end = _lines(act)
    assert start["event"] == "SessionStart" and start["source"] == "resume"
    assert end["event"] == "SessionEnd" and end["reason"] == "prompt_input_exit"
    assert "reason" not in start and "source" not in end
    assert "tool" not in start and "input" not in end


def test_session_start_runs_cleanup(act, monkeypatch, capsys):
    old = (datetime.now(timezone.utc) - timedelta(days=40)).strftime("%Y-%m-%d")
    folder = pathlib.Path(act.ACTIVITY_DIR) / old
    folder.mkdir(parents=True)
    (folder / "old.jsonl").write_text("{}\n")
    _run(act, monkeypatch, capsys, _payload("SessionStart", source="startup"),
         ["--session-start"])
    assert not folder.exists()
    assert [line["event"] for line in _lines(act)] == ["SessionStart"]


def test_session_end_only_appends(act, monkeypatch, capsys):
    old = (datetime.now(timezone.utc) - timedelta(days=40)).strftime("%Y-%m-%d")
    folder = pathlib.Path(act.ACTIVITY_DIR) / old
    folder.mkdir(parents=True)
    _run(act, monkeypatch, capsys, _payload("SessionEnd", reason="clear"), ["--session-end"])
    assert folder.exists()
    assert [line["event"] for line in _lines(act)] == ["SessionEnd"]


def test_later_modes_are_silent_no_ops(act, monkeypatch, capsys):
    for argv in (["--notes"], ["--unknown"]):
        assert _run(act, monkeypatch, capsys, _payload("PostToolUse", tool_response={}),
                    argv) == (0, "")
    assert not pathlib.Path(act.ACTIVITY_DIR).exists() or _lines(act) == []


def test_codex_payload_is_tagged_codex(act, monkeypatch, capsys):
    _run(act, monkeypatch, capsys, _payload(turn_id="turn-7", model="gpt-x"))
    _run(act, monkeypatch, capsys, _payload())
    codex, claude = _lines(act)
    assert codex["agent"] == "codex"
    assert claude["agent"] == "claude-code"
    assert "turn_id" not in codex and "model" not in codex


def test_subagent_fields(act, monkeypatch, capsys):
    _run(act, monkeypatch, capsys, _payload("SubagentStart", agent_id="a-9", agent_type="Explore"))
    _run(act, monkeypatch, capsys, _payload(agent_id="a-9", agent_type="Explore"))
    _run(act, monkeypatch, capsys, _payload())
    start, inside, outside = _lines(act)
    assert start["event"] == "SubagentStart"
    assert start["subagent"] == {"id": "a-9", "type": "Explore"}
    assert inside["subagent"] == {"id": "a-9", "type": "Explore"}
    assert "subagent" not in outside


def test_mcp_call_carries_server_tool_and_answer(act, monkeypatch, capsys):
    cache = {
        "github": {"id": "https://api.example.test/mcp", "kind": "mcp", "approved_at": 1000.0,
                   "score": 74, "decision": "review", "decision_reason": "one high finding"},
        "_agentavow": {"approved_at": 1, "id": "x"},
    }
    act._gate().CACHE.parent.mkdir(parents=True, exist_ok=True)
    act._gate().CACHE.write_text(json.dumps(cache))
    before = act._gate().CACHE.read_bytes()
    args = {"title": "Bug", "body": "token=ghp_" + "a" * 36}
    _run(act, monkeypatch, capsys, _payload(tool_name="mcp__github__create__issue",
                                            tool_input=args))
    _run(act, monkeypatch, capsys, _payload("PostToolUse", tool_name="mcp__github__create__issue",
                                            tool_input=args, tool_response=[{"type": "text"}]))
    _run(act, monkeypatch, capsys, _payload(tool_name="mcp__unknown__run", tool_input={}))
    pre, post, unknown = _lines(act)
    for line in (pre, post):
        assert line["tool"] == "mcp__github__create__issue"
        assert line["mcp_server"] == "github" and line["mcp_tool"] == "create__issue"
        assert line["answer"] == "review"
        assert set(line["input"]["args"]) == {"title", "body"}
        assert "ghp_" not in json.dumps(line)
    assert unknown["mcp_server"] == "unknown" and unknown["mcp_tool"] == "run"
    assert "answer" not in unknown
    assert act._gate().CACHE.read_bytes() == before  # read-only


def test_a_broken_cache_just_omits_the_answer(act, monkeypatch, capsys):
    act._gate().CACHE.parent.mkdir(parents=True, exist_ok=True)
    act._gate().CACHE.write_text("{not json")
    _run(act, monkeypatch, capsys, _payload(tool_name="mcp__github__x", tool_input={}))
    [line] = _lines(act)
    assert line["mcp_server"] == "github" and "answer" not in line


def test_non_mcp_events_skip_the_cache(act, monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("scanned.json read for a non-MCP event")

    monkeypatch.setattr(act, "_answer", boom)
    _run(act, monkeypatch, capsys, _payload())
    assert len(_lines(act)) == 1


# --- fail-open ---------------------------------------------------------------------


ALL_EVENTS = [
    (_payload(), []),
    (_payload("PostToolUse", tool_response={"stdout": "x"}, duration_ms=3), []),
    (_payload("PostToolUseFailure", error="e"), []),
    (_payload("SubagentStart", agent_id="a", agent_type="t"), []),
    (_payload("SubagentStop", agent_id="a", agent_type="t"), []),
    (_payload("SessionStart", source="startup"), ["--session-start"]),
    (_payload("SessionEnd", reason="other"), ["--session-end"]),
    (_payload(tool_name="mcp__s__t", tool_input={"a": 1}), []),
]


def test_recorder_prints_nothing(act, monkeypatch, capsys):
    for payload, argv in ALL_EVENTS:
        rc, out = _run(act, monkeypatch, capsys, payload, argv)
        assert (rc, out) == (0, ""), payload["hook_event_name"]
        assert capsys.readouterr().err == ""
    assert len(_lines(act)) == len(ALL_EVENTS)


@pytest.mark.parametrize("argv", [[], ["--session-start"], ["--session-end"]])
def test_bad_payloads_are_silent(act, monkeypatch, capsys, argv):
    no_sid = _payload()
    del no_sid["session_id"]
    bad = ["", "not json", "[]", "null", "42", json.dumps({"hook_event_name": "Nope"}),
           json.dumps(_payload("Nope")), json.dumps(no_sid),
           json.dumps(_payload(session_id="")), json.dumps(_payload(session_id=7)),
           json.dumps(_payload(tool_name=None, tool_input="str")),
           "\udcff"]
    for text in bad:
        rc, out = _run(act, monkeypatch, capsys, text, argv)
        assert (rc, out) == (0, ""), text
    # Only the one payload that has an event and a session id was recorded.
    assert len(_lines(act)) <= 1


def test_unwritable_cache_fails_open(act, tmp_path, monkeypatch, capsys):
    if os.geteuid() == 0:
        pytest.skip("root ignores folder permissions")
    parent = tmp_path / "ro"
    parent.mkdir()
    monkeypatch.setattr(act, "ACTIVITY_DIR", parent / "activity")
    parent.chmod(0o500)
    try:
        for payload, argv in ALL_EVENTS:
            assert _run(act, monkeypatch, capsys, payload, argv) == (0, "")
        assert capsys.readouterr().err == ""
    finally:
        parent.chmod(0o700)
    assert not (parent / "activity").exists()


def test_huge_payload_is_fast(act, monkeypatch, capsys):
    command = "cat > big.txt <<'EOF'\n" + ("line of heredoc text\n" * 5000) + "EOF"
    assert len(command) > 100_000
    payload = _payload(tool_input={"command": command})
    _run(act, monkeypatch, capsys, _payload())  # first event creates the folders
    start = time.perf_counter()
    rc, out = _run(act, monkeypatch, capsys, payload)
    elapsed = time.perf_counter() - start
    assert (rc, out) == (0, "")
    assert elapsed < 0.2, elapsed
    line = _lines(act)[-1]
    assert len(line["input"]["command"]) <= 2000
    assert line["input"]["command"].endswith("…[cut]")


def test_build_event_shape():
    ev = A.build_event(_payload("PostToolUse", tool_response="abc", duration_ms=5,
                                agent_id="a", agent_type="t"))
    assert set(ev) == {"ts", "agent", "event", "session", "subagent", "cwd", "tool", "input",
                       "ok", "out_bytes", "duration_ms"}
    assert ev["out_bytes"] == 3
    assert datetime.fromisoformat(ev["ts"]).tzinfo is not None
    assert A.build_event(_payload("Nope")) is None
    assert A.build_event([]) is None


# --- wiring ------------------------------------------------------------------------


def _hooks() -> dict:
    return json.loads((PLUGIN_DIR / "hooks" / "hooks.json").read_text())["hooks"]


def test_hooks_json_wires_the_recorder():
    hooks = _hooks()
    assert hooks["PreToolUse"][0] == {
        "matcher": "mcp__.*",
        "hooks": [{"type": "command",
                   "command": PREFIX + 'agentavow_pretool_gate.py"', "timeout": 8}],
    }
    assert hooks["PreToolUse"][1] == {
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [{"type": "command",
                   "command": PREFIX + 'agentavow_pre_install.py"', "timeout": 20}],
    }
    assert hooks["SessionStart"][0] == {
        "matcher": "startup|resume|clear",
        "hooks": [{"type": "command",
                   "command": PREFIX + 'agentavow_precheck.py"', "timeout": 30}],
    }

    def recorder(event: str) -> tuple[dict, dict]:
        groups = [g for g in hooks[event]
                  if any("agentavow_activity.py" in h["command"] for h in g["hooks"])]
        assert len(groups) == 1, event
        [h] = groups[0]["hooks"]
        return groups[0], h

    # Only events both Claude Code and Codex list: Codex shares this file, and an event
    # it does not know could make it drop the whole file (gate and install check too).
    assert set(hooks) <= {"SessionStart", "SessionEnd", "PreToolUse", "PostToolUse",
                          "SubagentStart", "SubagentStop"}
    assert "PostToolUseFailure" not in hooks
    # No matcher means every tool in both agents; Codex validates a matcher as a regex,
    # so the recorder groups carry none. Codex runs async hooks inline, hence timeout 2.
    for event in ("PreToolUse", "PostToolUse", "SubagentStart", "SubagentStop"):
        group, h = recorder(event)
        assert "matcher" not in group, event
        assert h["command"] == RECORDER and h["async"] is True
        assert h["timeout"] == 2
    group, h = recorder("SessionEnd")
    assert h["command"] == RECORDER + " --session-end"
    assert not h.get("async") and h["timeout"] == 1
    group, h = recorder("SessionStart")
    assert hooks["SessionStart"][1] is group
    assert group["matcher"] == "startup|resume|clear"
    assert h["command"] == RECORDER + " --session-start"
    assert not h.get("async") and h["timeout"] == 5

    for groups in hooks.values():
        for g in groups:
            for h in g["hooks"]:
                assert h["type"] == "command" and h["command"].startswith(PREFIX)
                assert "timeout" in h


def test_run_hook_passes_arguments_and_skips_python_for_empty_notes(tmp_path):
    script = tmp_path / "argv.py"
    script.write_text("import sys; print(sys.argv[1:])\n")
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)}

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(LAUNCHER), str(script), *args], input="{}",
                              capture_output=True, text=True, timeout=30, env=env)

    r = run("--notes", "x")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    pending = home / ".cache" / "agentavow" / "activity" / "pending-notes.json"
    pending.parent.mkdir(parents=True)
    pending.write_text("")
    assert run("--notes", "x").stdout == ""
    pending.write_text('[{"rule": "r"}]')
    r = run("--notes", "x")
    assert (r.returncode, r.stdout.strip()) == (0, "['--notes', 'x']")
    pending.unlink()
    r = run("--session-start")
    assert r.stdout.strip() == "['--session-start']"
    r = run("a b", "c")
    assert r.stdout.strip() == "['a b', 'c']"
    assert run().stdout.strip() == "[]"


SWITCH_VALUES = [None, "", "off", "OFF", "on", "On", "ON", "oN", " on", "on ", "onn", "1", "yes"]


def test_run_hook_and_enabled_agree_on_the_switch(tmp_path, monkeypatch):
    """The launcher starts no Python for the recorder unless the switch is on, and its
    rule matches _enabled() for every value (release 2 flips both, in both places)."""
    folder = tmp_path / "scripts"
    folder.mkdir()
    stub = folder / "agentavow_activity.py"
    stub.write_text("import sys; print(sys.argv[1:])\n")
    other = folder / "agentavow_precheck.py"
    other.write_text("import sys; print('ran')\n")
    home = tmp_path / "home"
    home.mkdir()

    def run(script, value, *args) -> str:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)}
        if value is not None:
            env["AGENTAVOW_ACTIVITY"] = value
        r = subprocess.run(["sh", str(LAUNCHER), str(script), *args], input="{}",
                           capture_output=True, text=True, timeout=30, env=env)
        assert (r.returncode, r.stderr) == (0, "")
        return r.stdout.strip()

    for value in SWITCH_VALUES:
        if value is None:
            monkeypatch.delenv("AGENTAVOW_ACTIVITY", raising=False)
        else:
            monkeypatch.setenv("AGENTAVOW_ACTIVITY", value)
        on = A._enabled()
        assert on == (value is not None and value.lower() == "on"), value
        for args in ([], ["--session-start"], ["--session-end"]):
            assert run(stub, value, *args) == (str(args) if on else ""), (value, args)
        # --report always runs (it reads what is there); other scripts are not affected.
        assert run(stub, value, "--report") == "['--report']"
        assert run(other, value) == "ran"


def test_readme_names_every_hook_script():
    readme = (PLUGIN_DIR / "README.md").read_text()
    for script in sorted((PLUGIN_DIR / "scripts").glob("*.py")):
        assert f"scripts/{script.name}" in readme, script.name


def test_a_broken_sibling_module_still_fails_open(tmp_path):
    """A sibling that fails to import: exit 0, nothing on stdout or stderr."""
    folder = tmp_path / "scripts"
    folder.mkdir()
    (folder / "agentavow_activity.py").write_bytes(MODULE.read_bytes())
    payload = json.dumps(_payload())
    for broken in ("raise RuntimeError('broken')\n", "def (:\n", ""):
        (folder / "agentavow_activity_redact.py").write_text(broken)
        for argv in ([], ["--session-start"], ["--session-end"], ["--notes"]):
            r = subprocess.run(
                [sys.executable, str(folder / "agentavow_activity.py"), *argv],
                input=payload, capture_output=True, text=True, timeout=30,
                env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path / "home"),
                     "AGENTAVOW_ACTIVITY": "on"})
            assert (r.returncode, r.stdout, r.stderr) == (0, "", ""), (broken, argv)
    assert not (tmp_path / "home" / ".cache" / "agentavow" / "activity").exists() or not list(
        (tmp_path / "home" / ".cache" / "agentavow" / "activity").glob("*/*.jsonl"))
