"""Deterministic graders: crafted transcripts → findings. No sandbox, no network."""
from __future__ import annotations

from src.scanner.behavioral.graders import (
    GRADERS,
    grade,
    grade_canary_echoed,
    grade_canary_exfiltrated,
    grade_crashed_server,
    grade_open_world_violated,
    grade_readonly_violated,
    grade_summary,
)
from src.scanner.behavioral.runner import BehavioralResult, behavioral_findings
from src.scanner.behavioral.transcript import ExerciseTranscript, parse_transcript


def _transcript(**over) -> ExerciseTranscript:
    doc = {
        "version": 1,
        "launch": {"command": ["node", "server.js"], "ok": True, "error": None,
                   "startup_ms": 300},
        "server_info": {"name": "demo", "version": "1.0"},
        "protocol_version": "2025-06-18",
        "tools": [
            {"name": "read_file", "annotations": {"readOnlyHint": True, "openWorldHint": False}},
            {"name": "write_file", "annotations": {"readOnlyHint": False, "openWorldHint": False}},
        ],
        "calls": [
            {"tool": "read_file", "args": {"path": "/tmp/a"}, "ok": True, "fs_writes": []},
            {"tool": "write_file", "args": {"path": "/tmp/b"}, "ok": True,
             "fs_writes": ["/tmp/b"]},
        ],
        "canary": {"env_names": ["API_TOKEN"], "seen_in_result": []},
        "timed_out": False,
        "error": None,
    }
    doc.update(over)
    return parse_transcript(doc)


def _result(transcript=None, **over) -> BehavioralResult:
    kw = dict(ran=True, surface="npm", coordinate="demo-mcp", plan="npm-mcp",
              transcript=transcript if transcript is not None else _transcript())
    kw.update(over)
    return BehavioralResult(**kw)


def test_clean_transcript_has_no_findings():
    assert grade(_result()) == []
    summary = grade_summary(_result())
    assert summary["findings"]["total"] == 0
    assert summary["tools_listed"] == 2 and summary["tools_called"] == 2
    assert summary["launch_ok"] is True and summary["server_failed_to_start"] is False


def test_readonly_violation_names_tool_and_paths():
    t = _transcript(calls=[
        {"tool": "read_file", "args": {}, "ok": True,
         "fs_writes": ["/work/.cache/x", "/tmp/npm-123/log", "/work/stolen.txt"]},
    ])
    fs = grade_readonly_violated(_result(t), t)
    assert len(fs) == 1
    f = fs[0]
    assert f.rule == "annotation_readonly_violated"
    assert f.severity == "high"
    assert "read_file" in f.name and "/work/stolen.txt" in f.snippet
    assert ".cache" not in f.snippet and "npm-123" not in f.snippet


def test_readonly_cache_only_writes_are_ignored():
    t = _transcript(calls=[{"tool": "read_file", "ok": True,
                            "fs_writes": ["/work/__pycache__/m.pyc", "/tmp/npm-1/x"]}])
    assert grade_readonly_violated(_result(t), t) == []


def test_writes_by_a_non_readonly_tool_are_fine():
    t = _transcript(calls=[{"tool": "write_file", "ok": True, "fs_writes": ["/work/out"]}])
    assert grade_readonly_violated(_result(t), t) == []


def test_open_world_violated_only_when_every_tool_is_closed_world():
    t = _transcript()  # both tools openWorldHint=false
    r = _result(t, unexpected_egress=["evil.example"])
    fs = grade_open_world_violated(r, t)
    assert len(fs) == 1 and fs[0].severity == "medium"
    assert fs[0].rule == "annotation_open_world_violated"
    # one tool admits to the open world → no annotation lie
    t2 = _transcript(tools=[
        {"name": "a", "annotations": {"openWorldHint": False}},
        {"name": "b", "annotations": {"openWorldHint": True}},
    ])
    assert grade_open_world_violated(_result(t2, unexpected_egress=["evil.example"]), t2) == []
    # no egress → nothing to contradict
    assert grade_open_world_violated(_result(t), t) == []


def test_canary_exfiltration_is_critical_and_names_the_channel():
    r = _result(canary_exfil=[{"via": "dns", "host": "agentavow-canary-abc.evil.net"},
                              {"via": "http", "host": "collector.example"}])
    fs = grade_canary_exfiltrated(r, r.transcript)
    assert len(fs) == 1
    assert fs[0].severity == "critical" and fs[0].rule == "credential_canary_exfiltrated"
    assert "dns:agentavow-canary-abc.evil.net" in fs[0].snippet
    assert "http:collector.example" in fs[0].snippet


def test_canary_echoed_in_result_is_medium():
    t = _transcript(canary={"env_names": ["API_TOKEN"], "seen_in_result": ["API_TOKEN"]})
    fs = grade_canary_echoed(_result(t), t)
    assert len(fs) == 1 and fs[0].severity == "medium"
    assert "API_TOKEN" in fs[0].snippet


def test_crashed_server_from_call_error_or_transcript_error():
    t = _transcript(calls=[{"tool": "write_file", "ok": False, "error": "server exited (code 1)"}])
    fs = grade_crashed_server(_result(t), t)
    assert len(fs) == 1 and fs[0].severity == "low" and "write_file" in fs[0].snippet
    t2 = _transcript(error="server_exited",
                     calls=[{"tool": "read_file", "ok": True}, {"tool": "write_file", "ok": False,
                                                                 "error": "timeout"}])
    fs2 = grade_crashed_server(_result(t2), t2)
    assert len(fs2) == 1 and "write_file" in fs2[0].snippet
    t3 = _transcript(calls=[{"tool": "read_file", "ok": False, "error": "invalid params"}])
    assert grade_crashed_server(_result(t3), t3) == []


def test_server_failed_to_start_is_not_a_finding_but_is_surfaced():
    t = _transcript(launch={"command": ["node", "x"], "ok": False, "error": "ENOENT"},
                    tools=[], calls=[])
    r = _result(t)
    assert grade(r) == []
    s = grade_summary(r)
    assert s["launch_ok"] is False and s["launch_error"] == "ENOENT"
    assert s["server_failed_to_start"] is True
    assert r.to_public_dict()["exercise"]["launch_ok"] is False


def test_undeclared_egress_still_graded_without_a_transcript():
    r = BehavioralResult(ran=True, surface="npm", coordinate="x",
                         unexpected_egress=["evil.net"])
    fs = grade(r)
    assert [f.rule for f in fs] == ["behavioral_undeclared_egress"]
    assert fs[0].severity == "high"
    assert behavioral_findings(r)[0].name == fs[0].name


def test_grade_is_deterministic_and_in_rule_order():
    t = _transcript(
        calls=[{"tool": "read_file", "ok": False, "error": "broken pipe",
                "fs_writes": ["/work/leak"]}],
        canary={"env_names": ["API_TOKEN"], "seen_in_result": ["API_TOKEN"]},
    )
    r = _result(t, unexpected_egress=["a.net", "b.net", "c.net"],
                canary_exfil=[{"via": "dns", "host": "x.a.net"}])
    first = [(f.rule, f.severity, f.snippet) for f in grade(r)]
    second = [(f.rule, f.severity, f.snippet) for f in grade(r)]
    assert first == second
    rules = [x[0] for x in first]
    assert rules == [
        "behavioral_undeclared_egress", "annotation_readonly_violated",
        "annotation_open_world_violated", "credential_canary_exfiltrated",
        "canary_echoed_in_result", "tool_call_crashed_server",
    ]
    assert rules == [name for name, _ in GRADERS]
    s = grade_summary(r)
    assert s["findings"] == {"critical": 2, "high": 1, "medium": 2, "low": 1, "total": 6}
    assert s["rules"] == rules
    assert s["calls_failed"] == 1 and s["canary_exfil"] == 1


def test_not_run_yields_nothing():
    r = BehavioralResult(ran=False, surface="npm", coordinate="x", error="ssm_unavailable")
    assert grade(r) == []
    assert grade_summary(r)["ran"] is False


def test_every_finding_carries_evidence_and_remediation():
    t = _transcript(calls=[{"tool": "read_file", "ok": False, "error": "EPIPE",
                            "fs_writes": ["/work/leak"]}],
                    canary={"env_names": ["K"], "seen_in_result": ["K"]})
    r = _result(t, unexpected_egress=["evil.net"], canary_exfil=[{"via": "http", "host": "h"}])
    for f in grade(r):
        assert f.category and f.name and f.severity in ("critical", "high", "medium", "low")
        assert f.snippet and f.remediation and f.file_path == "<behavioral>"


def test_scratch_dirs_and_caches_are_not_readonly_violations_but_named_files_are():
    from src.scanner.behavioral.graders import _is_scratch, grade_readonly_violated
    from src.scanner.behavioral.runner import BehavioralResult
    from src.scanner.behavioral.transcript import ExerciseTranscript, ToolCall, ToolSpec
    assert _is_scratch("/tmp/playwright-artifacts-cFaHfA")
    assert _is_scratch("/tmp/tmpab12cd")
    assert _is_scratch("/tmp/npm-123-abc")
    assert not _is_scratch("/tmp/agentavow-lie.txt")
    assert not _is_scratch("/tmp/notes")
    assert not _is_scratch("/work/output.json")
    ro = {"readOnlyHint": True}
    tr = ExerciseTranscript(launch_ok=True, tools=[
        ToolSpec("snapshot", annotations=ro), ToolSpec("find", annotations=ro),
        ToolSpec("lie", annotations=ro), ToolSpec("lie2", annotations=ro)],
        calls=[
            ToolCall("snapshot", ok=True, fs_writes=["/tmp/playwright-artifacts-EpiGGB"]),
            ToolCall("find", ok=True, fs_writes=["/work/.cache/ms-playwright-mcp/x"]),
            ToolCall("lie", ok=True, fs_writes=["/tmp/agentavow-lie.txt"]),
            ToolCall("lie2", ok=True, fs_writes=["/work/state.db"]),
        ])
    res = BehavioralResult(ran=True, surface="npm", coordinate="x", transcript=tr)
    out = grade_readonly_violated(res, tr)
    assert len(out) == 1, "one finding per server"
    assert "2 tools declare readOnlyHint" in out[0].name
    assert "lie" in out[0].name and "lie2" in out[0].name and "snapshot" not in out[0].name


def test_generated_temp_names_are_scratch_even_when_one_tail_looks_like_a_word():
    """Playwright names its per-call profile /tmp/playwright-artifacts-<6 random letters>;
    ~3% of tails are all one case, which the per-path entropy test alone would flag."""
    from src.scanner.behavioral.graders import grade_readonly_violated
    from src.scanner.behavioral.runner import BehavioralResult
    from src.scanner.behavioral.transcript import ExerciseTranscript, ToolCall, ToolSpec
    ro = {"readOnlyHint": True}
    tr = ExerciseTranscript(launch_ok=True, tools=[
        ToolSpec("snapshot", annotations=ro), ToolSpec("find", annotations=ro),
        ToolSpec("lie", annotations=ro)],
        calls=[
            ToolCall("snapshot", ok=True, fs_writes=["/tmp/playwright-artifacts-bgcdef"]),  # one case
            ToolCall("find", ok=True, fs_writes=["/tmp/playwright-artifacts-KoiLHH"]),
            ToolCall("lie", ok=True, fs_writes=["/tmp/agentavow-lie.txt"]),
        ])
    res = BehavioralResult(ran=True, surface="npm", coordinate="x", transcript=tr)
    out = grade_readonly_violated(res, tr)
    assert len(out) == 1 and "'lie'" in out[0].name and "snapshot" not in out[0].name
    # a single one-case tail with no sibling is still judged by the per-path test (flagged)
    tr2 = ExerciseTranscript(launch_ok=True, tools=[ToolSpec("snapshot", annotations=ro)],
                             calls=[ToolCall("snapshot", ok=True, fs_writes=["/tmp/out-report"])])
    res2 = BehavioralResult(ran=True, surface="npm", coordinate="x", transcript=tr2)
    assert len(grade_readonly_violated(res2, tr2)) == 1
