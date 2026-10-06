"""End-to-end tests for the in-sandbox MCP exerciser (scripts/sandbox/mcp_exercise.py and
its Node twin) against the fixture servers in tests/fixtures/behavioral. Each test runs the
exerciser as a subprocess the way the sandbox would and asserts the transcript through the
contract parser (src/scanner/behavioral/transcript.py)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src.scanner.behavioral.transcript import (
    ExerciseTranscript,
    extract_transcript_json,
    parse_transcript,
)

ROOT = Path(__file__).resolve().parents[1]
PY_EXERCISER = ROOT / "scripts" / "sandbox" / "mcp_exercise.py"
JS_EXERCISER = ROOT / "scripts" / "sandbox" / "mcp_exercise.js"
FIXTURES = ROOT / "tests" / "fixtures" / "behavioral"
SCHEMAS = FIXTURES / "schemas"
NODE = shutil.which("node")
CANARY = "agentavow-canary-test0001"


def _run(server: str, *, runner: str = "py", timeout: float = 10, per_call: float = 2,
         extra: list[str] | None = None, env: dict | None = None,
         mounts: Path | None = None) -> tuple[ExerciseTranscript, str, float]:
    exe = [sys.executable, str(PY_EXERCISER)] if runner == "py" else [NODE, str(JS_EXERCISER)]
    cmd = exe + ["--timeout", str(timeout), "--per-call-timeout", str(per_call),
                 "--canary-env", "GITHUB_TOKEN,NPM_TOKEN", "--canary-value", CANARY]
    if mounts is not None:
        cmd += ["--mounts", str(mounts)]
    cmd += (extra or []) + ["--", sys.executable, str(FIXTURES / server)]
    run_env = {**os.environ, **(env or {})}
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=run_env,
                          timeout=timeout + 30)
    elapsed = time.monotonic() - t0
    assert proc.returncode == 0, proc.stderr[-1000:]
    doc = extract_transcript_json(proc.stdout)
    assert doc is not None, proc.stdout[-1000:]
    return parse_transcript(doc), doc, elapsed


def test_benign_server_lists_and_calls_every_tool(tmp_path):
    tr, raw, _ = _run("benign_server.py", mounts=tmp_path)
    assert tr.launch_ok and tr.error is None and not tr.timed_out
    assert tr.server_name == "benign-fixture" and tr.server_version == "1.2.3"
    assert tr.protocol_version == "2025-06-18"
    assert [t.name for t in tr.tools] == ["echo", "add"]
    assert tr.tool("echo").hint("readOnlyHint") is True
    assert tr.tool("add").annotations is None
    assert tr.tool("add").input_schema["required"] == ["a", "b"]
    assert [c.tool for c in tr.calls] == ["echo", "add"]
    echo, add = tr.calls
    assert echo.ok and not echo.is_error and echo.args == {"message": "agentavow"}
    assert echo.result_sample == '{"echo": "agentavow"}'
    assert add.args == {"a": 1, "b": 10} and add.result_sample == "11"
    assert tr.canary_env_names == ["GITHUB_TOKEN", "NPM_TOKEN"]
    assert tr.canary_seen_in_result == []
    assert all(c.fs_writes == [] for c in tr.calls)
    assert json.loads(raw)["version"] == 1
    assert json.loads(raw)["launch"]["command"][0] == sys.executable


def test_lying_readonly_tool_gets_its_write_attributed(tmp_path):
    tr, _, _ = _run("lies_readonly_server.py", mounts=tmp_path,
                    env={"AGENTAVOW_FIXTURE_TMP": str(tmp_path)})
    assert tr.launch_ok
    assert tr.tool("list_files").hint("readOnlyHint") is True
    (call,) = tr.calls_for("list_files")
    assert call.ok and not call.is_error
    assert call.fs_writes == [str(tmp_path / "agentavow-lie.txt")]


def test_canary_leak_in_result_is_recorded(tmp_path):
    tr, _, _ = _run("canary_echo_server.py", mounts=tmp_path)
    (call,) = tr.calls_for("whoami")
    assert call.ok and CANARY in call.result_sample
    # one shared canary value → every injected name is implicated
    assert tr.canary_seen_in_result == ["GITHUB_TOKEN", "NPM_TOKEN"]


def test_slow_tool_times_out_without_hanging_the_run(tmp_path):
    tr, _, elapsed = _run("slow_server.py", mounts=tmp_path, timeout=10, per_call=1.5)
    assert tr.launch_ok and not tr.timed_out
    fast, slow = tr.calls_for("fast")[0], tr.calls_for("slow")[0]
    assert fast.ok and fast.result_sample == "quick"
    assert not slow.ok and slow.error == "call_timeout"
    assert 1400 <= slow.duration_ms < 4000
    assert elapsed < 8


def test_crash_on_call_fails_open_with_server_exited(tmp_path):
    tr, _, elapsed = _run("crash_on_call_server.py", mounts=tmp_path)
    assert tr.launch_ok and [t.name for t in tr.tools] == ["boom", "never_reached"]
    assert [c.tool for c in tr.calls] == ["boom"]
    assert not tr.calls[0].ok and tr.calls[0].error == "server_exited"
    assert tr.error == "server_exited"
    assert elapsed < 5


def test_never_initializing_server_is_an_initialize_timeout(tmp_path):
    tr, _, elapsed = _run("never_initializes_server.py", mounts=tmp_path, timeout=3,
                          per_call=1)
    assert not tr.launch_ok and tr.tools == [] and tr.calls == []
    assert tr.launch_error.startswith("initialize_timeout")
    assert "warming up" in tr.launch_error  # stderr tail kept on launch failure
    assert elapsed < 8


def test_missing_command_is_a_launch_failure_not_a_crash():
    cmd = [sys.executable, str(PY_EXERCISER), "--timeout", "3", "--", "/nonexistent/agentavow"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0
    tr = parse_transcript(extract_transcript_json(proc.stdout))
    assert not tr.launch_ok and tr.launch_error.startswith("spawn_failed")
    assert tr.launch_command == ["/nonexistent/agentavow"]


def test_no_command_still_prints_a_transcript():
    proc = subprocess.run([sys.executable, str(PY_EXERCISER)], capture_output=True, text=True,
                          timeout=20)
    assert proc.returncode == 0
    tr = parse_transcript(extract_transcript_json(proc.stdout))
    assert not tr.launch_ok and tr.launch_error == "no_command"


def test_max_tools_and_readme_examples(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("## echo\n\n```json\n{\"message\": \"from the readme\"}\n```\n")
    tr, _, _ = _run("benign_server.py", mounts=tmp_path,
                    extra=["--max-tools", "1", "--readme", str(readme)])
    assert [t.name for t in tr.tools] == ["echo", "add"]
    assert [c.tool for c in tr.calls] == ["echo"]
    assert tr.calls[0].args == {"message": "from the readme"}
    assert tr.calls[0].fs_writes == []  # the README itself is excluded from the diff


SSRF_SENTINEL = "http://169.254.254.254/agentavow-ssrf"


def test_ssrf_probe_adds_a_sentinel_call_to_url_taking_tools(tmp_path):
    # The url-taking fetch tool is called normally (example.com) and once more with the
    # link-local sentinel, tagged as the SSRF probe. NET=0 keeps it off the network.
    tr, _, _ = _run("ssrf_follows_server.py", mounts=tmp_path,
                    extra=["--ssrf-url", SSRF_SENTINEL], env={"AGENTAVOW_FIXTURE_NET": "0"})
    calls = tr.calls_for("fetch_url")
    assert len(calls) == 2
    normal, probe = calls
    assert not normal.ssrf_probe and normal.args["url"] == "https://example.com/agentavow"
    assert probe.ssrf_probe and probe.ssrf_target == SSRF_SENTINEL
    assert probe.args["url"] == SSRF_SENTINEL


def test_ssrf_probe_is_skipped_when_no_tool_takes_a_url(tmp_path):
    # benign_server has no url-shaped input, so the SSRF pass adds nothing.
    tr, _, _ = _run("benign_server.py", mounts=tmp_path, extra=["--ssrf-url", SSRF_SENTINEL])
    assert [c.tool for c in tr.calls] == ["echo", "add"]
    assert not any(c.ssrf_probe for c in tr.calls)


# --- JS twin parity -----------------------------------------------------------------------

needs_node = pytest.mark.skipif(NODE is None, reason="node not on PATH")


@needs_node
def test_js_ssrf_probe_matches_python(tmp_path):
    py, _, _ = _run("ssrf_follows_server.py", runner="py", mounts=tmp_path,
                    extra=["--ssrf-url", SSRF_SENTINEL], env={"AGENTAVOW_FIXTURE_NET": "0"})
    js, _, _ = _run("ssrf_follows_server.py", runner="js", mounts=tmp_path,
                    extra=["--ssrf-url", SSRF_SENTINEL], env={"AGENTAVOW_FIXTURE_NET": "0"})
    assert [(c.tool, c.ssrf_probe, c.ssrf_target, c.args) for c in js.calls] == \
        [(c.tool, c.ssrf_probe, c.ssrf_target, c.args) for c in py.calls]


@needs_node
def test_js_exerciser_matches_python_on_benign_server(tmp_path):
    py, _, _ = _run("benign_server.py", runner="py", mounts=tmp_path)
    js, raw, _ = _run("benign_server.py", runner="js", mounts=tmp_path)
    assert js.launch_ok and js.server_name == py.server_name
    assert js.protocol_version == py.protocol_version
    assert [(t.name, t.annotations, t.input_schema) for t in js.tools] == \
        [(t.name, t.annotations, t.input_schema) for t in py.tools]
    assert [(c.tool, c.args, c.ok, c.is_error, c.error, c.result_sample) for c in js.calls] == \
        [(c.tool, c.args, c.ok, c.is_error, c.error, c.result_sample) for c in py.calls]
    doc = json.loads(raw)
    assert set(doc) == {"version", "launch", "server_info", "protocol_version", "tools",
                        "calls", "canary", "timed_out", "error"}
    assert set(doc["calls"][0]) == {"tool", "args", "ok", "error", "is_error", "duration_ms",
                                    "fs_writes", "result_sample"}


@needs_node
@pytest.mark.parametrize("server,check", [
    ("canary_echo_server.py", lambda tr: tr.canary_seen_in_result == ["GITHUB_TOKEN", "NPM_TOKEN"]),
    ("crash_on_call_server.py", lambda tr: tr.error == "server_exited"),
    ("never_initializes_server.py", lambda tr: tr.launch_error.startswith("initialize_timeout")),
])
def test_js_exerciser_failure_modes(tmp_path, server, check):
    tr, _, elapsed = _run(server, runner="js", mounts=tmp_path, timeout=3, per_call=1)
    assert check(tr)
    assert elapsed < 8


@needs_node
def test_js_lying_tool_write_attribution(tmp_path):
    tr, _, _ = _run("lies_readonly_server.py", runner="js", mounts=tmp_path,
                    env={"AGENTAVOW_FIXTURE_TMP": str(tmp_path)})
    assert tr.calls_for("list_files")[0].fs_writes == [str(tmp_path / "agentavow-lie.txt")]


@needs_node
@pytest.mark.parametrize("schema", sorted(p for p in SCHEMAS.glob("*.json")
                                          if not p.name.endswith(".expected.json")),
                         ids=lambda p: p.stem)
def test_js_generator_parity_on_goldens(schema: Path):
    py = subprocess.run([sys.executable, str(PY_EXERCISER), "--gen-args", str(schema)],
                        capture_output=True, text=True, timeout=20, check=True).stdout
    js = subprocess.run([NODE, str(JS_EXERCISER), "--gen-args", str(schema)],
                        capture_output=True, text=True, timeout=20, check=True).stdout
    expected = json.loads(schema.with_suffix(".expected.json").read_text())
    assert json.loads(py) == expected
    assert json.loads(js) == expected
