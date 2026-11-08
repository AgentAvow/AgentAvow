"""The score page's shared logic (web/src/rebrand/lib/resultPage.ts), run under node.

Every result type (repo, package, MCP server, skill, private scan) renders through one
ResultPage component; this checks the pure parts it reads for the six states in the
website build spec (2026-11-07): the Certified checklist rows and status line, the top
findings order and their fix lines. The answer itself is the API's decision read
through gradeSystem.decisionOf, never recomputed here.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "web" / "src" / "rebrand" / "lib" / "resultPage.ts"

CHECKS_ALL = {"artifact_scanned": True, "provenance_verified": True, "no_drift": True,
              "no_critical_or_high": True, "recompute_ready": True, "full_coverage": True}

SAFE_CERT = {  # @notionhq/notion-mcp-server 2.6.1, live read 2026-11-07
    "trust_score": 95, "decision": "safe", "decision_final": True,
    "decision_reason": "nothing found in 23 files; 1 file over 500 KB was not fully read",
    "certified": {"eligible": True, "checks": CHECKS_ALL}, "certified_mark": True,
    "certified_mark_reason": "", "coverage_gaps": {"oversized_files": 1},
    "provenance": {"present": True, "verified": True,
                   "binding": {"repo": "github.com/makenotion/notion-mcp-server"}},
    "metadata": {"files_scanned": 23},
    "behavioral": {"ran": True, "plan": "npm-mcp", "exercise": {"launch_ok": True, "calls": [{}] * 25},
                   "grade_summary": {"start_reason": "started", "tools_listed": 24, "calls_total": 25}},
    "findings": {"critical": 0, "high": 0, "total": 3, "items": [
        {"name": "fs.readFileSync / writeFileSync (Node.js)", "severity": "low", "kind": "capability",
         "remediation": "Writes a file at a runtime path", "file_path": "src/init-server.ts"},
        {"name": "Long hex-escaped byte literal", "severity": "info", "kind": "capability",
         "remediation": "Embeds long hex-escaped byte literals", "file_path": "bin/cli.mjs"},
        {"name": "Source file too large to scan in full", "severity": "low", "kind": "defect",
         "remediation": "A source file this large is only partly scanned — replace obfuscated code",
         "file_path": "bin/cli.mjs"},
    ]},
}

SAFE_NOT_CERT = {**SAFE_CERT, "certified_mark": False, "certified_mark_reason": "coverage_gaps",
                 "coverage_gaps": {"sandbox_not_observed": "crashed"},
                 "behavioral": {"ran": True, "plan": "npm-mcp", "exercise": {"launch_ok": False},
                                "grade_summary": {"start_reason": "crashed"}}}

PENDING = {**SAFE_CERT, "decision_final": False, "certified_mark": False,
           "certified_mark_reason": "sandbox_pending",
           "decision_reason": "nothing found in 23 files; sandbox still running",
           "behavioral": {"ran": False, "pending": True}}

REVIEW = {  # npm ai, live read 2026-11-07
    "trust_score": 70, "decision": "review", "decision_final": True,
    "decision_reason": "2 high findings in its code, including HTTP POST with sensitive data",
    "certified": {"eligible": False, "checks": {**CHECKS_ALL, "no_critical_or_high": False}},
    "certified_mark": False, "coverage_gaps": {"oversized_files": 1, "sandbox_not_observed": "crashed"},
    "findings": {"items": []},
}

DNC = {  # gadgethumans-mcp 1.0.15, live read 2026-11-07
    "trust_score": 45, "decision": "do_not_connect", "decision_final": True,
    "decision_reason": "one critical finding in its code: wallet private key sent over the network",
    "certified": {"eligible": False, "checks": {**CHECKS_ALL, "provenance_verified": False,
                                                "no_critical_or_high": False}},
    "certified_mark": False, "coverage_gaps": {"sandbox_not_observed": "other_version"},
    "provenance": {"present": False, "verified": False},
    "behavioral": {"ran": False, "pending": False, "other_version": True,
                   "reason": "the sandbox runs the latest release, not a pinned version"},
    "findings": {"critical": 1, "total": 2, "items": [
        {"name": "Writes a file", "severity": "low", "kind": "capability", "remediation": "x"},
        {"name": "Wallet private key sent over the network", "severity": "critical", "kind": "defect",
         "remediation": "Sign locally and send the signature.", "file_path": "index.js",
         "line_number": 215},
    ]},
}

UNREAD = {  # a live MCP server whose tool list couldn't be read
    "trust_score": 70, "decision": "review", "decision_final": True,
    "decision_reason": "the server's tool list could not be read",
    "certified": {"eligible": False, "checks": {}}, "certified_mark": False,
    "coverage_gaps": {"tool_list_unread": True}, "findings": {"items": []},
}

CASES = [
    ("safe_certified", SAFE_CERT, "package"),
    ("safe_not_certified", SAFE_NOT_CERT, "package"),
    ("pending", PENDING, "package"),
    ("review", REVIEW, "package"),
    ("do_not_connect", DNC, "package"),
    ("couldnt_read", UNREAD, "mcp"),
]

SCRIPT = (
    "const m = await import(process.argv[1]);"
    "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
    "const out=JSON.parse(s).map(([scan,kind])=>{const rows=m.certifiedRows(scan,kind);"
    "return {rows:rows.map(r=>[r.state,r.evidence]),status:m.certifiedStatus(scan,rows),"
    "top:m.topFindings(scan,3).map(f=>[f.name,m.fixText(f)])}});"
    "process.stdout.write(JSON.stringify(out));});"
)


@pytest.fixture(scope="module")
def results() -> dict:
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", SCRIPT, str(LIB)],
        input=json.dumps([[c[1], c[2]] for c in CASES]), capture_output=True, text=True,
        timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    return {c[0]: r for c, r in zip(CASES, json.loads(proc.stdout), strict=True)}


def states(r: dict) -> list[str]:
    return [s for s, _ in r["rows"]]


def test_safe_certified_passes_every_row(results):
    r = results["safe_certified"]
    assert r["status"] == {"lead": "Why it's Certified", "rest": ""}
    assert states(r) == ["pass", "pass", "pass", "pass"]
    assert r["rows"][1][1] == "Signed build provenance → makenotion/notion-mcp-server"
    assert r["rows"][3][1] == "started, 24 tools, 25 calls · signed result"


def test_safe_not_certified_names_the_missing_check(results):
    r = results["safe_not_certified"]
    assert r["status"] == {"lead": "Not Certified yet", "rest": "one check is missing"}
    assert states(r) == ["pass", "pass", "pass", "fail"]
    assert "crashed" in r["rows"][3][1]


def test_pending_waits_on_the_sandbox(results):
    r = results["pending"]
    assert r["status"] == {"lead": "Certified is pending", "rest": "waiting on the sandbox run"}
    assert states(r)[3] == "wait"


def test_review_and_do_not_connect_status_lines(results):
    assert results["review"]["status"] == {"lead": "Not Certified", "rest": "the answer is Review"}
    assert results["review"]["rows"][0] == [
        "fail", "Reads Review: 2 high findings in its code, including HTTP POST with sensitive data"]
    d = results["do_not_connect"]
    assert d["status"] == {"lead": "Not Certified", "rest": "the answer is Do not connect"}
    assert d["rows"][1] == ["fail", "No build provenance"]
    assert d["rows"][3] == ["fail", "the sandbox runs the latest release, not this pinned version"]


def test_unread_live_server(results):
    r = results["couldnt_read"]
    assert r["status"] == {"lead": "Not Certified", "rest": "the live server couldn't be read"}
    assert r["rows"][2] == ["fail", "The live tool list couldn't be read"]


def test_top_findings_lead_with_the_worst_and_say_the_fix(results):
    top = results["do_not_connect"]["top"]
    assert top[0] == ["Wallet private key sent over the network", "Sign locally and send the signature."]
    # A capability is what the tool does: no fix to make.
    assert top[1][1].startswith("No fix needed")
    # A defect before a capability at the same severity; "what — fix" keeps the fix.
    cert = results["safe_certified"]["top"]
    assert cert[0] == ["Source file too large to scan in full", "Replace obfuscated code"]


def test_every_result_type_renders_through_one_result_page():
    src = (ROOT / "web/src/rebrand/pages/Check.tsx").read_text()
    for kind in ("skill", "mcp", "package", "repo"):
        assert f'kind="{kind}"' in src, kind
    assert src.count("<ResultPage") == 4
    # The old per-surface score labels are gone: every page says "Trust score".
    for rel in ("web/src/rebrand/pages/Check.tsx", "web/src/rebrand/components/ResultPage.tsx"):
        text = (ROOT / rel).read_text()
        assert "Attestation Trust" not in text and "Capability Trust" not in text, rel
