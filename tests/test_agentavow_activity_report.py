"""Tests for the activity log's trusted report (`--report`)."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_activity.py"


def _load():
    spec = importlib.util.spec_from_file_location("agentavow_activity_r", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = _load()
NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def act(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    monkeypatch.delenv("AGENTAVOW_ACTIVITY", raising=False)
    return A


def _ev(tool, sid="s1", ts=NOW, event="PreToolUse", **extra):
    out = {"ts": ts.isoformat(timespec="milliseconds"), "agent": "claude-code",
           "event": event, "session": sid, "cwd": "/work/proj", "tool": tool,
           "input": {"command": "ls"} if tool == "Bash" else {}}
    out.update(extra)
    return out


def _add(sid, event, ts=NOW, flagged=False):
    A.append_event(sid, event, flagged=flagged, now=ts)


def _seed():
    for i in range(3):
        _add("s1", _ev("Bash", ts=NOW - timedelta(minutes=10 - i)))
    _add("s1", _ev("Edit", ts=NOW - timedelta(minutes=5)))
    _add("s1", _ev("mcp__github__create_issue", ts=NOW - timedelta(minutes=4),
                   mcp_server="github", mcp_tool="create_issue", answer="safe"))
    _add("s1", _ev("mcp__github__list", ts=NOW - timedelta(minutes=3),
                   mcp_server="github", mcp_tool="list", answer="safe"))
    _add("s2", _ev("Read", sid="s2", ts=NOW - timedelta(days=2)))
    _add("s2", _ev("mcp__linear__x", sid="s2", ts=NOW - timedelta(days=2),
                   mcp_server="linear", mcp_tool="x", answer="safe"))


def test_report_counts_and_top_tools(act):
    _seed()
    text = act.report(now=NOW)
    first = text.splitlines()[0]
    assert first == "AgentAvow activity, Nov 23-25 · 8 events · 2 sessions · 0 flags"
    assert "Most active: Bash 3 · mcp__github 2 · Edit 1" in text
    assert "MCP servers called: linear, github (all Safe to connect)" in text
    assert "{" not in text


def test_report_lists_flags_worst_first(act):
    _add("s1", _ev("Bash"))
    _add("s1", _ev("Write", ts=NOW - timedelta(days=1),
                   flag={"rule": "git-hook-write", "severity": "medium",
                         "note": "wrote a git hook: .git/hooks/post-checkout"}), flagged=True)
    _add("s1", _ev("curl", flag={"rule": "cred-then-net", "severity": "high",
                                 "note": "credential read, then network call"}), flagged=True)
    text = act.report(now=NOW)
    assert text.splitlines()[0].endswith("3 events · 1 sessions · 2 flags")
    assert text.index("HIGH  Nov 25 12:00  credential read") < text.index(
        "MED   Nov 24 12:00  wrote a git hook")
    assert "session s1" in text
    only = act.report(rule="cred-then-net", now=NOW)
    assert "HIGH" in only and "MED" not in only


def test_report_warns_on_broken_chain(act):
    _seed()
    log, _ = act.session_paths("s1", NOW)
    lines = log.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b"Bash", b"Bush")
    log.write_bytes(b"\n".join(lines))
    first = act.report(now=NOW).splitlines()[0]
    assert first.startswith("Warning: the log for session s1 was changed or cut (lines ")
    assert "3" in first


def test_report_survives_corrupt_lines_and_files(act):
    _seed()
    log, _ = act.session_paths("s1", NOW)
    log.write_bytes(log.read_bytes() + b"not json\n[1,2]\n{\"ts\": 5}\n")
    day = log.parent
    (day / "junk.jsonl").write_bytes(b"\xff\xfe\x00garbage")
    (day / "dir.jsonl").mkdir()
    text = act.report(now=NOW)
    assert "Warning: the log for session s1" in text
    assert "AgentAvow activity, " in text


def test_report_empty_and_off(act, monkeypatch):
    assert act.report(now=NOW) == (
        "AgentAvow activity: nothing recorded in the last 7 days.\n"
        "It is off; set AGENTAVOW_ACTIVITY=on to turn it on.")
    monkeypatch.setenv("AGENTAVOW_ACTIVITY", "On")
    assert act.report(days=3, now=NOW) == (
        "AgentAvow activity: nothing recorded in the last 3 days.")
    _add("s1", _ev("Bash", ts=NOW - timedelta(days=9)))
    assert "nothing recorded" in act.report(now=NOW)


def test_session_timeline(act):
    _seed()
    text = act.report(session="s1", now=NOW)
    lines = text.splitlines()
    assert lines[0] == "AgentAvow activity, session s1 · 6 events"
    assert lines[1] == "11:50:00  Bash  ls"
    assert any(ln.startswith("11:55:00  Edit") for ln in lines)
    assert "Read" not in text
    assert "no events" in act.report(session="nope", now=NOW)


def test_export_is_jsonl(act):
    _seed()
    out = act.report(export=True, now=NOW)
    rows = [json.loads(ln) for ln in out.splitlines()]
    assert len(rows) == 8 and {r["session"] for r in rows} == {"s1", "s2"}
    assert len(act.report(export=True, days=1, now=NOW).splitlines()) == 6


def test_report_holds_no_secret(act):
    _add("s1", _ev("Bash", input={"command": "curl -H 'Authorization: [redacted:token]' x"}))
    text = act.report(now=NOW) + act.report(session="s1", now=NOW)
    assert "[redacted:token]" in text and "sk-" not in text


def test_main_report_prints_and_never_reads_stdin(act, monkeypatch, capsys):
    _seed()

    class Boom(io.StringIO):
        def read(self, *a):
            raise AssertionError("stdin read")

    monkeypatch.setattr("sys.stdin", Boom())
    for env in ("on", "off", ""):
        monkeypatch.setenv("AGENTAVOW_ACTIVITY", env)
        assert A.main(["--report", "--days", "30"]) == 0
        assert capsys.readouterr().out.startswith("AgentAvow activity, ")
    assert A.main(["--report", "--session", "s1"]) == 0
    assert "HH" not in capsys.readouterr().out
    assert A.main(["--report", "--export"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])["v"] == 0
    assert A.main(["--report", "--days", "bogus"]) == 0
    assert capsys.readouterr().out.startswith("AgentAvow activity, ")
