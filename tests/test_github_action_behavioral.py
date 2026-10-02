"""github-action/scan.sh: the Sandbox line and the fail_on_behavioral gate.

Runs the real script with a fake ``curl`` on PATH that writes a canned API response,
so the jq parsing and the exit codes are what is tested. Needs bash + jq.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "github-action" / "scan.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None or shutil.which("bash") is None, reason="needs bash + jq")


def _run(tmp_path: Path, response: dict, **env: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fixture = tmp_path / "resp.json"
    fixture.write_text(json.dumps(response))
    curl = bindir / "curl"
    # mimic `curl -s -o <file> -w "%{http_code}" <url>`: write the fixture, print 200
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "out=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift;; esac; shift; done\n"
        f"[ -n \"$out\" ] && cp '{fixture}' \"$out\"\n"
        "printf 200\n")
    curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
    full_env = {
        **os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
        "REPO_OWNER": "acme", "REPO_NAME": "tool", "COMMENT_ON_PR": "false",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    full_env.update(env)
    return subprocess.run(
        ["bash", str(SCRIPT)], env=full_env, capture_output=True, text=True, timeout=60)


def _resp(behavioral=None) -> dict:
    r = {"score": 88, "summary": "ok", "categories": {"Code Safety": 90},
         "findings": {"critical": 0, "high": 0, "medium": 1, "low": 0}}
    if behavioral is not None:
        r["behavioral"] = behavioral
    return r


def test_sandbox_line_when_the_run_completed(tmp_path):
    b = {"ran": True, "plan": "npm-mcp",
         "exercise": {"launch_ok": True,
                      "calls": [{"tool": "read"}, {"tool": "write"}, {"tool": "read"}]},
         "findings": [{"rule": "behavioral_undeclared_egress", "severity": "medium"}],
         "unexpected_egress": ["evil.net"]}
    p = _run(tmp_path, _resp(b))
    assert p.returncode == 0, p.stderr
    assert ("Sandbox (gVisor, signed): called 2 tool(s), 1 behavioral finding(s), "
            "unexpected egress: evil.net") in p.stdout
    assert "Sandbox (gVisor, signed): called 2 tool(s)" in (tmp_path / "summary.md").read_text()


def test_sandbox_line_clean_run_and_pending(tmp_path):
    p = _run(tmp_path, _resp({"ran": True, "plan": "pypi", "findings": [],
                               "unexpected_egress": [], "exercise": None}))
    assert ("Sandbox (gVisor, signed): plan pypi, 0 tool(s) exercised, 0 behavioral finding(s), "
            "no unexpected egress") in p.stdout
    p = _run(tmp_path, _resp({"ran": False, "pending": True}))
    assert "Sandbox: running now" in p.stdout
    (tmp_path / "summary.md").unlink()  # the step summary is appended to across runs
    p = _run(tmp_path, _resp(None))
    assert "Sandbox:" not in p.stdout
    assert "Sandbox:" not in (tmp_path / "summary.md").read_text()
    assert p.returncode == 0


def test_fail_on_behavioral_gates_only_high_and_critical(tmp_path):
    severe = {"ran": True, "plan": "npm", "exercise": None, "unexpected_egress": [],
              "findings": [{"rule": "canary_exfil", "severity": "critical"}]}
    p = _run(tmp_path, _resp(severe), FAIL_ON_BEHAVIORAL="true")
    assert p.returncode == 1
    assert "::error::Sandbox observed 1 high/critical behavioral finding(s)" in p.stdout
    # default off: the same response passes
    assert _run(tmp_path, _resp(severe)).returncode == 0
    # a medium-only run passes even when opted in
    medium = dict(severe, findings=[{"rule": "x", "severity": "medium"}])
    assert _run(tmp_path, _resp(medium), FAIL_ON_BEHAVIORAL="true").returncode == 0
    # pending / absent never fail
    assert _run(tmp_path, _resp({"ran": False, "pending": True}),
                FAIL_ON_BEHAVIORAL="true").returncode == 0
    assert _run(tmp_path, _resp(None), FAIL_ON_BEHAVIORAL="true").returncode == 0



def test_sandbox_line_names_a_non_start_a_leak_and_the_score_effect(tmp_path):
    b = {"ran": True, "plan": "npm-mcp", "exercise": {"launch_ok": False, "calls": []},
         "grade_summary": {"start_reason": "needs_credentials"}, "findings": [],
         "unexpected_egress": []}
    p = _run(tmp_path, _resp(b))
    assert "server not started (needs credentials) — not a finding" in p.stdout
    leak = {"ran": True, "plan": "npm-mcp",
            "exercise": {"launch_ok": True, "calls": [{"tool": "a"}]},
            "findings": [{"rule": "credential_canary_exfiltrated", "severity": "critical"}],
            "canary_exfil": [{"via": "dns", "host": "x.evil.net"}], "unexpected_egress": []}
    resp = _resp(leak)
    resp["behavioral_score_effect"] = {"applied": True, "delta": -45}
    p = _run(tmp_path, resp)
    assert "CANARY CREDENTIAL LEAKED" in p.stdout
    assert "trust score -45 from the sandbox" in p.stdout
