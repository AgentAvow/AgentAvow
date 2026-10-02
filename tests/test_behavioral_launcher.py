"""The in-container launcher (scripts/sandbox/mcp_launch.sh) driven outside the sandbox
with a STUB exerciser: candidate discovery, the credential retries (env names mined from
the server's own error, then ``--flag <canary>``), the 4-launch cap, and the "report the
first bare failure" rule. ``MCP_LAUNCH_WORK`` points the script's scratch files at tmp_path.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.scanner.behavioral.graders import classify_start
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.behavioral.transcript import extract_transcript_json, parse_transcript

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "sandbox" / "mcp_launch.sh"
NODE = shutil.which("node")
CANARY = "agentavow-canary-abcdef012345"

BRAVE = ("server_exited: A Brave API key is required via --brave-api-key, BRAVE_API_KEY, "
         "--brave-api-key-file, or BRAVE_API_KEY_FILE")
SUPABASE = ("server_exited: Please provide a personal access token (PAT) with the "
            "--access-token flag or set the SUPABASE_ACCESS_TOKEN environment variable")
USAGE = "server_exited: Usage: mcp-remote <https://server-url> [callback-port] [--debug]"
TWO_FLAGS = ("server_exited: set MY_API_KEY or pass --api-key / --auth-token "
             "(token required)")

# The stub exerciser: same CLI contract as mcp_exercise.py (flags, then `-- <server cmd>`).
# STUB_MODE picks the server's behavior; every launch is appended to STUB_LOG as JSON.
STUB = r'''
import json, os, sys
argv = sys.argv[1:]
cmd = argv[argv.index("--") + 1:] if "--" in argv else []
flags = argv[:argv.index("--")] if "--" in argv else argv
opts = {}
i = 0
while i < len(flags):
    opts[flags[i]] = flags[i + 1] if i + 1 < len(flags) else ""
    i += 2
canary_env = [n for n in opts.get("--canary-env", "").split(",") if n]
canary_value = opts.get("--canary-value", "")
mode = os.environ.get("STUB_MODE", "ok")
want = os.environ.get("STUB_WANT_ENV", "")
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps({"cmd": cmd, "canary_env": canary_env,
                         "env_value": os.environ.get(want, None) if want else None}) + "\n")
ok, err = True, None
if mode == "brave":
    ok = os.environ.get("BRAVE_API_KEY") == canary_value
    err = None if ok else os.environ["STUB_ERR"]
elif mode == "flag":
    ok = os.environ["STUB_FLAG"] in cmd and cmd[cmd.index(os.environ["STUB_FLAG"]) + 1] == canary_value
    err = None if ok else os.environ["STUB_ERR"]
elif mode == "never":
    ok, err = False, os.environ["STUB_ERR"]
doc = {"version": 1,
       "launch": {"command": cmd, "ok": ok, "error": err, "startup_ms": 5},
       "server_info": {"name": "stub", "version": "0"}, "protocol_version": "2025-06-18",
       "tools": [{"name": "echo"}] if ok else [], "calls": [],
       "canary": {"env_names": canary_env, "seen_in_result": []},
       "timed_out": False, "error": None}
print("noise before")
print("AGENTAVOW_TRANSCRIPT_BEGIN")
print(json.dumps(doc))
print("AGENTAVOW_TRANSCRIPT_END")
'''


@pytest.fixture
def bench(tmp_path):
    """A fake installed package for both kinds + the stub exerciser + a launch log."""
    (tmp_path / "stub.py").write_text(STUB)
    # npm: node_modules/<pkg>/package.json with a bin
    pkg = tmp_path / "node_modules" / "demo-mcp"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "demo-mcp", "bin": "server.js"}))
    (pkg / "server.js").write_text("")
    # pypi: a dist-info on PYTHONPATH with one console script
    site = tmp_path / "site" / "demo_mcp-1.0.dist-info"
    site.mkdir(parents=True)
    (site / "METADATA").write_text("Metadata-Version: 2.1\nName: demo-mcp\nVersion: 1.0\n")
    (site / "entry_points.txt").write_text("[console_scripts]\ndemo-mcp = demo:main\n")
    (tmp_path / "work").mkdir()
    (tmp_path / "log").write_text("")
    return tmp_path


def _launch(bench: Path, kind: str, *, mode: str = "ok", err: str = "", canary: str | None = CANARY,
            extra_env: dict | None = None, exerciser_env: str = "GITHUB_TOKEN",
            pkg: str = "demo-mcp"):
    env = {**os.environ, "MCP_LAUNCH_WORK": str(bench / "work"), "STUB_MODE": mode,
           "STUB_ERR": err, "STUB_LOG": str(bench / "log"),
           "PYTHONPATH": str(bench / "site"), **(extra_env or {})}
    env.pop("BRAVE_API_KEY", None)
    argv = ["sh", str(LAUNCHER), kind, pkg]
    if canary is not None:
        argv += ["--canary-value", canary]
    argv += ["--", sys.executable, str(bench / "stub.py"), "--timeout", "5",
             "--canary-value", canary or "", "--canary-env", exerciser_env]
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=bench, env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr[-800:]
    doc = extract_transcript_json(proc.stdout)
    assert doc is not None, proc.stdout[-800:]
    launches = [json.loads(ln) for ln in (bench / "log").read_text().splitlines() if ln]
    return parse_transcript(doc), launches


KINDS = ["pypi"] + (["npm"] if NODE else [])


@pytest.mark.parametrize("kind", KINDS)
def test_first_candidate_that_initializes_wins(bench, kind):
    tr, launches = _launch(bench, kind)
    assert tr.launch_ok and len(launches) == 1
    assert launches[0]["canary_env"] == ["GITHUB_TOKEN"]
    # the bare candidate, not the "/work" positional variant
    assert launches[0]["cmd"][-1] != "/work"


@pytest.mark.parametrize("kind", KINDS)
def test_env_names_in_the_error_are_exported_as_the_canary_and_retried_once(bench, kind):
    tr, launches = _launch(bench, kind, mode="brave", err=BRAVE,
                           extra_env={"STUB_WANT_ENV": "BRAVE_API_KEY"})
    assert tr.launch_ok, tr.launch_error
    assert len(launches) == 2
    first, retry = launches
    assert first["env_value"] is None and retry["env_value"] == CANARY
    # same bare candidate, the exerciser's own list EXTENDED (not replaced)
    assert retry["cmd"] == first["cmd"]
    assert retry["canary_env"] == ["GITHUB_TOKEN", "BRAVE_API_KEY", "BRAVE_API_KEY_FILE"]
    assert tr.canary_env_names == ["GITHUB_TOKEN", "BRAVE_API_KEY", "BRAVE_API_KEY_FILE"]


def test_flag_in_the_error_is_retried_with_the_canary_after_the_env_retry(bench):
    tr, launches = _launch(bench, "pypi", mode="flag", err=SUPABASE,
                           extra_env={"STUB_FLAG": "--access-token",
                                      "STUB_WANT_ENV": "SUPABASE_ACCESS_TOKEN"})
    assert tr.launch_ok
    assert [ln["cmd"] for ln in launches] == [
        ["demo-mcp"],                                  # bare
        ["demo-mcp"],                                  # + SUPABASE_ACCESS_TOKEN=canary
        ["demo-mcp", "--access-token", CANARY],        # + flag
    ]
    assert launches[1]["env_value"] == CANARY
    assert tr.launch_command == ["demo-mcp", "--access-token", CANARY]


def test_no_credential_in_the_error_means_no_retry_and_the_first_failure_is_reported(bench):
    tr, launches = _launch(bench, "pypi", mode="never", err=USAGE)
    assert not tr.launch_ok and tr.launch_error == USAGE
    # just the two discovered candidates: bare, then "<bin> /work"
    assert [ln["cmd"] for ln in launches] == [["demo-mcp"], ["demo-mcp", "/work"]]
    assert [ln["canary_env"] for ln in launches] == [["GITHUB_TOKEN"]] * 2
    r = BehavioralResult(ran=True, surface="pypi", coordinate="demo-mcp", transcript=tr)
    assert classify_start(r)[0] == "needs_arguments"


def test_total_launches_are_capped_at_four(bench):
    tr, launches = _launch(bench, "pypi", mode="never", err=TWO_FLAGS)
    assert not tr.launch_ok and tr.launch_error == TWO_FLAGS  # the FIRST bare failure
    assert len(launches) == 4
    assert [ln["cmd"] for ln in launches] == [
        ["demo-mcp"], ["demo-mcp"],
        ["demo-mcp", "--api-key", CANARY], ["demo-mcp", "--auth-token", CANARY],
    ]
    assert launches[1]["canary_env"] == ["GITHUB_TOKEN", "MY_API_KEY"]
    r = BehavioralResult(ran=True, surface="pypi", coordinate="demo-mcp", transcript=tr)
    assert classify_start(r)[0] == "needs_credentials"


def test_missing_canary_value_still_retries_with_a_placeholder(bench):
    _, launches = _launch(bench, "pypi", mode="never", err=BRAVE, canary=None,
                          extra_env={"STUB_WANT_ENV": "BRAVE_API_KEY"})
    assert launches[1]["env_value"] == "agentavow-canary-launcher0"


def test_path_like_names_are_never_exported(bench):
    err = "server_exited: token missing; see $PATH, $HOME and MY_SECRET_PATH_TOKEN"
    _, launches = _launch(bench, "pypi", mode="never", err=err,
                          extra_env={"STUB_WANT_ENV": "PATH"})
    assert len(launches) >= 2
    assert launches[1]["canary_env"] == ["GITHUB_TOKEN", "MY_SECRET_PATH_TOKEN"]
    assert launches[1]["env_value"] != CANARY  # PATH untouched


def test_no_entrypoint_is_a_synthetic_transcript(bench):
    tr, launches = _launch(bench, "pypi", pkg="not-installed-anywhere")
    # importlib finds nothing → "python3 -m not_installed_anywhere" is the lone candidate
    # (a server can be a module without a console script), and it fails to start.
    assert [ln["cmd"] for ln in launches] == [["python3", "-m", "not_installed_anywhere"]]
    # (the bench's stub exerciser "starts" anything; the real one would report spawn_failed)
    # with an npm package that has no package.json there is no candidate at all.
    if NODE:
        tr, launches = _launch(bench, "npm", pkg="ghost-pkg")
        # the bench log is cumulative across _launch calls: nothing NEW for ghost-pkg
        assert not any("ghost" in " ".join(ln["cmd"]) for ln in launches)
        assert tr.launch_error == "no_entrypoint_found" and tr.error == "no_entrypoint_found"
        r = BehavioralResult(ran=True, surface="npm", coordinate="ghost-pkg", transcript=tr)
        assert classify_start(r)[0] == "no_entrypoint"
