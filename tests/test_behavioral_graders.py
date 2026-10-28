"""Deterministic graders: crafted transcripts → findings. No sandbox, no network."""
from __future__ import annotations

import pytest

from src.scanner.behavioral.graders import (
    GRADERS,
    grade,
    grade_canary_echoed,
    grade_canary_exfiltrated,
    grade_crashed_server,
    grade_open_world_violated,
    grade_readonly_violated,
    grade_ssrf_internal_fetch,
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


def test_ssrf_internal_fetch_is_high_and_names_the_probed_tool():
    t = _transcript(
        tools=[{"name": "fetch_url", "annotations": {"readOnlyHint": True}}],
        calls=[
            {"tool": "fetch_url", "args": {"url": "https://example.com/agentavow"}, "ok": True},
            {"tool": "fetch_url", "args": {"url": "http://169.254.254.254/agentavow-ssrf"},
             "ok": True, "ssrf_probe": True, "ssrf_target": "http://169.254.254.254/agentavow-ssrf"},
        ])
    r = _result(t, ssrf_hits=["169.254.254.254"])
    fs = grade_ssrf_internal_fetch(r, t)
    assert len(fs) == 1
    assert fs[0].severity == "high" and fs[0].rule == "ssrf_internal_fetch"
    assert "fetch_url" in fs[0].name
    assert "169.254.254.254" in fs[0].snippet
    # it also shows up in the full grade() and bumps the summary counter
    assert "ssrf_internal_fetch" in {f.rule for f in grade(r)}
    assert grade_summary(r)["ssrf_hits"] == 1


def test_no_ssrf_finding_without_a_sentinel_hit():
    t = _transcript(
        tools=[{"name": "fetch_url", "annotations": {"readOnlyHint": True}}],
        calls=[{"tool": "fetch_url", "args": {"url": "http://169.254.254.254/agentavow-ssrf"},
                "ok": True, "ssrf_probe": True}])
    # the server was PROBED but never connected (guarded): no ssrf_hits → no finding
    assert grade_ssrf_internal_fetch(_result(t, ssrf_hits=[]), t) == []


def test_ssrf_finding_is_generic_when_more_than_one_tool_probed():
    t = _transcript(
        tools=[{"name": "a"}, {"name": "b"}],
        calls=[{"tool": "a", "ok": True, "ssrf_probe": True},
               {"tool": "b", "ok": True, "ssrf_probe": True}])
    fs = grade_ssrf_internal_fetch(_result(t, ssrf_hits=["169.254.254.254"]), t)
    assert len(fs) == 1 and fs[0].name.startswith("A tool followed")


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
    # no IMDS here, no SSRF sentinel hit, and the skill-only grader never fires on an MCP
    # plan — those three produce nothing for this transcript
    assert rules == [name for name, _ in GRADERS
                     if name not in ("cloud_metadata_probe", "skill_script_egress",
                                     "ssrf_internal_fetch")]
    s = grade_summary(r)
    assert s["findings"] == {"critical": 1, "high": 2, "medium": 2, "low": 1, "total": 6}
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


def _ro_result(writes, *, server="desktop-commander", coord="@wonderwhy-er/desktop-commander"):
    t = _transcript(
        server_info={"name": server, "version": "0.2.52"},
        tools=[{"name": "get_config", "annotations": {"readOnlyHint": True}}],
        calls=[{"tool": "get_config", "ok": True, "fs_writes": writes}])
    return _result(t, coordinate=coord), t


def test_writes_to_the_servers_own_hidden_state_folder_are_not_violations():
    # 2026-10-09: desktop-commander's read-only tools log calls into ~/.claude-server-commander
    r, t = _ro_result(["/work/.claude-server-commander/claude_tool_call.log",
                       "/work/.claude-server-commander/tool-history.jsonl",
                       "/work/.claude-server-commander/config.json.lock"])
    assert grade_readonly_violated(r, t) == []


@pytest.mark.parametrize("path", [
    "/work/.ssh/authorized_keys",            # credentials: always a violation
    "/work/.aws/credentials",
    "/work/.config/desktop-commander/x",     # under ~/.config, not a hidden dir of its own
    "/work/.bashrc",                         # a hidden FILE in HOME
    "/work/.other-tool/state.json",          # hidden folder that is not this server's
    "/work/notes/commander.txt",             # a user file, even with the name in it
    "/work/.claude/settings.json",           # another agent's settings
    # own folder, but not bookkeeping-shaped: real state/config the user would care about
    "/work/.claude-server-commander/config.json",
    "/work/.claude-server-commander/keys/id.json",
])
def test_own_state_exemption_stays_narrow(path):
    r, t = _ro_result([path])
    fs = grade_readonly_violated(r, t)
    assert len(fs) == 1 and path in fs[0].snippet


@pytest.mark.parametrize("server,coord,path", [
    # a package sharing a name token with a credential / wallet folder is NEVER excused
    ("solana-mcp", "solana-mcp", "/work/.solana/id.json"),
    ("solana-mcp", "solana-mcp", "/work/.solana/validator.log"),  # even bookkeeping-shaped
    ("cargo-audit-mcp", "cargo-audit-mcp", "/work/.cargo/credentials.toml"),
    ("pulumi-mcp", "pulumi-mcp", "/work/.pulumi/credentials.json"),
    ("terraform-mcp", "terraform-mcp", "/work/.terraform.d/credentials.tfrc.json"),
    ("firefox-mcp", "firefox-mcp", "/work/.mozilla/firefox/abc.default/prefs.js"),
    ("electrum-mcp", "electrum-mcp", "/work/.electrum/wallets/default_wallet"),
    ("acme-mcp", "acme-mcp", "/work/.acme-wallet/history.jsonl"),     # sensitive word in name
    ("acme-mcp", "acme-mcp", "/work/.acme-keys/tool.log"),
])
def test_credential_and_wallet_folders_are_never_own_state(server, coord, path):
    r, t = _ro_result([path], server=server, coord=coord)
    fs = grade_readonly_violated(r, t)
    assert len(fs) == 1 and path in fs[0].snippet


def test_the_bare_own_state_folder_itself_is_fine():
    r, t = _ro_result(["/work/.claude-server-commander",
                       "/work/.claude-server-commander/tool-history.jsonl"])
    assert grade_readonly_violated(r, t) == []


def test_own_state_needs_a_distinctive_shared_name():
    # a server called "mcp-server" shares only generic tokens with ~/.mcp-server-data
    r, t = _ro_result(["/work/.mcp-server-data/log.txt"], server="mcp-server", coord="mcp-server")
    assert len(grade_readonly_violated(r, t)) == 1


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


def test_install_only_plans_have_no_start_reason():
    from src.scanner.behavioral.graders import classify_start, grade_summary
    from src.scanner.behavioral.runner import BehavioralResult
    r = BehavioralResult(ran=True, surface="npm", coordinate="left-pad", plan="npm", exit_code=0)
    assert classify_start(r)[0] == "not_applicable"
    assert grade_summary(r)["start_reason"] == "not_applicable"
    r2 = BehavioralResult(ran=True, surface="npm", coordinate="x", plan="npm-mcp", exit_code=1)
    assert classify_start(r2)[0] == "install_failed"



def test_cloud_metadata_is_a_low_labelled_note_not_undeclared_egress():
    from src.scanner.behavioral.graders import grade
    from src.scanner.behavioral.runner import BehavioralResult
    from src.scanner.behavioral.score_effect import behavioral_score_effect
    r = BehavioralResult(ran=True, surface="npm", coordinate="x",
                         egress_hosts=["169.254.169.254", "registry.npmjs.org"],
                         unexpected_egress=["169.254.169.254"])
    rules = [(f.rule, f.severity) for f in grade(r)]
    assert rules == [("cloud_metadata_probe", "low")]
    blk = {"ran": True, "findings": [{"rule": "cloud_metadata_probe", "severity": "low"}],
           "attestation": {"jws": "a.b.c"}, "exercise": {"launch_ok": True, "calls": [{}]}}
    assert behavioral_score_effect(67, blk)["score"] == 67  # low: no score effect
    r2 = BehavioralResult(ran=True, surface="npm", coordinate="x",
                          unexpected_egress=["169.254.169.254", "evil.net"])
    assert ("behavioral_undeclared_egress", "high") in [(f.rule, f.severity) for f in grade(r2)]



@pytest.mark.parametrize("path, cache", [
    ("/tmp/data-gym-cache/9b5ad71b2ce5302211f9c61530b329a4922fc6a4", True),
    ("/tmp/data-gym-cache", True),
    ("/work/.cache/x", True), ("/work/hf_cache/model.bin", True),
    ("/tmp/agentavow-lie.txt", False), ("/work/state.db", False),
    ("/work/notes/cached-results.txt", False),   # a FILE named 'cached…' is still a write
])
def test_cache_named_directories_are_cache(path, cache):
    from src.scanner.behavioral.graders import _is_cache_like
    assert _is_cache_like(path) is cache
