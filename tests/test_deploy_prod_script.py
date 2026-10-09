"""Checks for scripts/deploy-prod.sh: it parses, the dry run reports the health wait,
and the deadline-based wait helper succeeds late and times out."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "deploy-prod.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _wait_until_source() -> str:
    text = SCRIPT.read_text()
    m = re.search(r"^wait_until\(\) \{.*?^\}", text, re.S | re.M)
    assert m, "wait_until helper missing"
    return m.group(0)


def test_script_parses():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_dry_run_reports_240s_wait(tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("x")
    out = subprocess.run(
        [str(SCRIPT), "--dry-run"],
        env={"AG_EC2_HOST": "203.0.113.1", "AG_SSH_KEY": str(key), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, check=True,
    ).stdout
    assert "up to 240 seconds" in out
    assert "120 seconds" not in out


def test_wait_until_succeeds_late_and_times_out():
    prog = _wait_until_source() + """
n=0; late() { n=$((n+1)); [ $n -ge 2 ]; }
wait_until Late late 10 && echo LATE_OK
never() { false; }
wait_until Never never 1 || echo NEVER_TIMEOUT
"""
    out = subprocess.run(["bash", "-c", prog], capture_output=True, text=True, check=True).stdout
    assert "LATE_OK" in out
    assert "NEVER_TIMEOUT" in out
