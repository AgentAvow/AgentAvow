"""The "Fix it with your AI" prompt on the score page (web/src/rebrand/lib/resultPage.ts
fixPrompt), run under node: defects only, worst first, each with where and how to fix,
and nothing at all when there is nothing to fix."""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from tests.test_result_page import DNC, LIB, SAFE_CERT, UNREAD

URL = "https://agentavow.com/check/npm/gadgethumans-mcp"

SCRIPT = (
    "const m = await import(process.argv[1]);"
    "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
    "const out=JSON.parse(s).map(([scan,name,url,max])=>m.fixPrompt(scan,name,url,max));"
    "process.stdout.write(JSON.stringify(out));});"
)

MANY = {**DNC, "findings": {"items": [
    {"name": f"Finding {i}", "severity": "medium", "kind": "defect",
     "remediation": "Do the thing", "file_path": f"src/f{i}.js", "line_number": i}
    for i in range(1, 5)]}}

TEST_FILE = {**DNC, "findings": {"items": [
    {"name": "Hard-coded token", "severity": "high", "kind": "defect", "shipped": False,
     "remediation": "A token in a test — load it from the environment", "file_path": "test/a.js"}]}}


def _run(cases: list) -> list[str]:
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", SCRIPT, str(LIB)],
        input=json.dumps(cases), capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_do_not_connect_prompt_names_the_answer_the_finding_and_the_fix():
    [p] = _run([[DNC, "gadgethumans-mcp", URL, 15]])
    lines = p.splitlines()
    assert lines[0] == 'AgentAvow checked gadgethumans-mcp. The answer is "Do not connect" (trust score 45/100).'
    assert lines[1] == ("Reason: One critical finding in its code: wallet private key sent "
                        "over the network.")
    assert "1. [CRITICAL] Wallet private key sent over the network in index.js:215" in lines
    assert "   Fix: Sign locally and send the signature." in lines
    # The capability ("Writes a file") is what the tool does, not a defect.
    assert "Writes a file" not in p
    assert lines[-1] == f"When the fix is released, open {URL} and press Re-check to get a fresh answer."


def test_nothing_to_fix_gives_no_prompt():
    # No findings, or capabilities only: the block is not shown.
    caps_only = {**SAFE_CERT, "findings": {"items": [
        i for i in SAFE_CERT["findings"]["items"] if i["kind"] == "capability"]}}
    assert _run([[UNREAD, "x", URL, 15], [caps_only, "notion", URL, 15]]) == ["", ""]


def test_long_lists_are_capped_with_a_pointer_to_the_page():
    [p] = _run([[MANY, "t", URL, 2]])
    assert "2. [MEDIUM] Finding 2 in src/f2.js:2" in p
    assert "Finding 3" not in p
    assert "(2 more on the report page.)" in p


def test_a_test_file_is_marked_and_the_fix_keeps_the_part_after_the_dash():
    [p] = _run([[TEST_FILE, "t", URL, 15]])
    assert "1. [HIGH] Hard-coded token in test/a.js (test or example file)" in p
    assert "   Fix: Load it from the environment." in p
