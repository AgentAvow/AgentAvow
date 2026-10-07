"""The three-phrase decision (``src.scanner.verdict.decide``) — every branch, table-driven,
and the TS twin (``decide()`` in ``web/src/components/trust/gradeSystem.ts``) run on the
same table with byte-identical output."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.scanner.verdict import Decision, decide
from src.trust_tiers import (
    DECISIONS,
    REVIEW_PHRASE,
    decision_color,
    decision_label,
    headline,
    is_certified,
    verdict_phrase,
)

ROOT = Path(__file__).resolve().parent.parent


def _f(severity, name="Finding", **kw):
    return {"category": kw.pop("category", "code_safety"), "name": name,
            "severity": severity, "file_path": kw.pop("file_path", "src/x.py"),
            "line_number": 1, "shipped": kw.pop("shipped", True),
            "kind": kw.pop("kind", "defect"), "installed": kw.pop("installed", True), **kw}


def _scan(score=92, files=120, items=(), crit=None, high=None, **extra):
    findings = {"items": list(items)}
    if crit is not None:
        findings["critical"] = crit
    if high is not None:
        findings["high"] = high
    return {"trust_score": score, "findings": findings,
            "metadata": {"files_scanned": files}, **extra}


def _bev(findings=(), **kw):
    return {"ran": True, "findings": list(findings), "attestation": {"jws": "x"}, **kw}


CERTIFIED = {"eligible": True, "checks": {"no_critical_or_high": True}}

# (id, data, decision, final, reason)
CASES = [
    # ── safe ──────────────────────────────────────────────────────────────────────
    ("clean_large", _scan(92, 1200), "safe", True, "nothing found in 1,200 files"),
    ("clean_one_file_not_thin_when_medium", _scan(70, 1, [_f("medium", "Weak hash")]),
     "safe", True, "no critical or high findings in 1 file"),
    ("certified_safe", _scan(98, 340, certified=CERTIFIED), "safe", True,
     "nothing found in 340 files"),
    ("mediums_only_above_51", _scan(60, 40, [_f("medium")] * 3), "safe", True,
     "no critical or high findings in 40 files"),
    ("no_files_known", {"trust_score": 85}, "safe", True, "nothing found"),
    ("capability_never_counts", _scan(88, 30, [_f("low", "Spawns a process",
                                                  kind="capability")]),
     "safe", True, "nothing found in 30 files"),
    ("critical_in_tests_not_blocking", _scan(80, 30, [_f("critical", shipped=False,
                                                         file_path="tests/t.py")], crit=0),
     "safe", True, "no critical or high findings in 30 files"),
    ("cloud_metadata_probe_low", _scan(90, 50, behavioral=_bev(
        [{"rule": "cloud_metadata_probe", "severity": "low", "name": "IMDS"}])),
     "safe", True, "nothing found in 50 files"),
    ("static_ssrf_medium", _scan(75, 50, [_f("medium", "Possible SSRF", category="ssrf")]),
     "safe", True, "no critical or high findings in 50 files"),
    ("live_probe_is_advisory", _scan(90, 50, behavioral=_bev(
        [{"rule": "behavioral_undeclared_egress", "severity": "high"}], plan="live-probe")),
     "safe", True, "nothing found in 50 files"),
    ("sandbox_not_run", _scan(90, 50, behavioral={"ran": False, "reason": "needs_credentials"}),
     "safe", True, "nothing found in 50 files"),
    ("adoption_never_an_input", _scan(90, 50, adoption={"score": 0}), "safe", True,
     "nothing found in 50 files"),
    ("history_advisory_not_affecting", _scan(90, 50, advisories=[
        {"id": "GHSA-old", "affects_scanned_version": False}]), "safe", True,
     "nothing found in 50 files"),
    # ── review ────────────────────────────────────────────────────────────────────
    ("one_high", _scan(85, 200, [_f("high", "Shell command with user input")], high=1),
     "review", True, "one high finding: shell command with user input"),
    ("three_high", _scan(70, 200, [_f("high", "API key in source")] * 3, high=3),
     "review", True, "3 high findings, including API key in source"),
    ("behavioral_undeclared_egress", _scan(70, 200, behavioral=_bev(
        [{"rule": "behavioral_undeclared_egress", "severity": "high", "name": "Egress"}])),
     "review", True, "one high finding: undeclared network call"),
    ("ssrf_internal_fetch_high_is_review", _scan(70, 200, behavioral=_bev(
        [{"rule": "ssrf_internal_fetch", "severity": "high"}])),
     "review", True, "one high finding: fetched an internal network address"),
    ("readonly_violated", _scan(70, 200, behavioral=_bev(
        [{"rule": "annotation_readonly_violated", "severity": "high"}])),
     "review", True, "one high finding: a read-only tool wrote files"),
    ("advisory_affects_version", _scan(88, 200, advisories=[
        {"id": "GHSA-abcd", "affects_scanned_version": True}]),
     "review", True, "a published advisory affects this version (GHSA-abcd)"),
    ("advisory_in_incident_history", _scan(88, 200, incident_history={"advisories": [
        {"id": "PYSEC-1", "affects_scanned_version": True}]}),
     "review", True, "a published advisory affects this version (PYSEC-1)"),
    ("critical_own_advisory_is_review", _scan(40, 200, [_f(
        "critical", "Published advisory affects this version: RCE",
        category="known_vulnerability", file_path="registry advisory")], crit=1),
     "review", True, "a published advisory affects this version"),
    ("deprecated", _scan(90, 200, deprecation="use foo2"), "review", True,
     "the maintainer has deprecated this package"),
    ("score_under_51", _scan(50, 200, [_f("medium")] * 8), "review", True,
     "trust score 50/100 is under 51"),
    ("thin_coverage", _scan(95, 3), "review", True,
     "nothing found, but little code to inspect"),
    ("headline_high_without_item", _scan(70, 200, [], high=1), "review", True,
     "one high finding"),
    ("high_in_scripts_still_blocks", _scan(70, 200, [_f(
        "high", "Eval of input", shipped=False, file_path="scripts/run.py")], high=1),
     "review", True, "one high finding: eval of input"),
    ("items_only_shape", {"trust_score": 70, "findings": {"items": [_f("high", "X")]}},
     "review", True, "one high finding: X"),
    # ── do_not_connect ────────────────────────────────────────────────────────────
    ("one_critical", _scan(45, 200, [_f("critical", "Hardcoded private key")], crit=1),
     "do_not_connect", True, "one critical finding: hardcoded private key"),
    ("canary_exfil", _scan(45, 200, behavioral=_bev(
        [{"rule": "credential_canary_exfiltrated", "severity": "critical"}],
        canary_exfil=[{"via": "https", "host": "evil.example"}])),
     "do_not_connect", True, "a planted credential left the sandbox"),
    ("other_critical_behavior", _scan(45, 200, behavioral=_bev(
        [{"rule": "some_new_rule", "severity": "critical", "name": "Wiped the disk"}])),
     "do_not_connect", True, "the sandbox caught a critical behavior: wiped the disk"),
    ("malicious_dependency", _scan(30, 200, [_f(
        "critical", "Known-malicious package: evil@1.0.0 (MAL-2025-1)",
        category="dependency", file_path="package-lock.json")], crit=1),
     "do_not_connect", True,
     "a known-malicious dependency: evil@1.0.0 (MAL-2025-1)"),
    ("supply_chain_malicious_list", _scan(60, 200, supply_chain={"malicious": ["MAL-9"]}),
     "do_not_connect", True, "a known-malicious dependency: MAL-9"),
    ("own_mal_advisory", _scan(90, 200, incident_history={"current_version_affected": True}),
     "do_not_connect", True, "this version is listed as malicious (OpenSSF MAL advisory)"),
    ("critical_beats_high", _scan(40, 200, [_f("critical", "Alpha"), _f("high", "Beta")],
                                  crit=1, high=1),
     "do_not_connect", True, "one critical finding: alpha"),
    ("long_name_truncated", _scan(40, 200, [_f("critical", "Z" * 90)], crit=1),
     "do_not_connect", True, "one critical finding: " + "Z" * 69 + "…"),
    # ── pending sandbox: provisional, never a silent flip ─────────────────────────
    ("pending_safe", _scan(90, 300, behavioral={"ran": False, "pending": True}),
     "safe", False, "nothing found in 300 files; sandbox still running"),
    ("pending_review", _scan(70, 300, [_f("high", "X")], high=1,
                             behavioral={"ran": False, "pending": True}),
     "review", False, "one high finding: X; sandbox still running"),
    ("pending_with_stale_findings_ignored", _scan(90, 300, behavioral={
        "ran": True, "pending": True,
        "findings": [{"rule": "behavioral_undeclared_egress", "severity": "high"}]}),
     "safe", False, "nothing found in 300 files; sandbox still running"),
    # ── odd shapes never raise ────────────────────────────────────────────────────
    ("empty", {}, "review", True, "trust score 0/100 is under 51"),
    ("garbage", {"trust_score": "x", "findings": "nope", "metadata": None,
                 "behavioral": 3}, "review", True, "trust score 0/100 is under 51"),
]


@pytest.mark.parametrize("case_id,data,decision,final,reason", CASES,
                         ids=[c[0] for c in CASES])
def test_decide_table(case_id, data, decision, final, reason):
    got = decide(data)
    assert isinstance(got, Decision)
    assert (got.decision, got.final, got.reason) == (decision, final, reason)
    assert got.as_dict() == {"decision": decision, "decision_final": final,
                             "decision_reason": reason}


def test_every_branch_value_is_covered():
    assert {c[2] for c in CASES} == {d.value for d in DECISIONS}
    assert any(not c[3] for c in CASES)


def test_certified_is_a_separate_axis():
    data = _scan(98, 340, certified=CERTIFIED)
    assert decide(data).decision == "safe" and is_certified(data)
    assert headline(decide(data), certified=is_certified(data)) == "Safe to connect · Certified"
    # removing the mark never changes the phrase
    assert decide({**data, "certified": {}}) == decide(data)
    assert not is_certified({**data, "certified": {"eligible": "yes"}})


def test_phrase_table():
    assert [(d.value, d.phrase, d.label) for d in DECISIONS] == [
        ("safe", "Safe to connect", "Safe"),
        ("review", "Review before you connect", "Review"),
        ("do_not_connect", "Do not connect", "Blocked"),
    ]
    assert REVIEW_PHRASE == "Review before you connect"
    assert verdict_phrase("do_not_connect") == "Do not connect"
    assert verdict_phrase(decide(_scan(92, 10))) == "Safe to connect"
    # an API response that already carries the decision is read, not re-decided
    assert verdict_phrase({"trust_score": 99, "decision": "review"}) == REVIEW_PHRASE
    assert verdict_phrase(40) == REVIEW_PHRASE and verdict_phrase(90) == "Safe to connect"
    assert decision_label("do_not_connect") == "Blocked"
    assert decision_color("safe") == "#22C55E"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_twin_is_byte_identical():
    """Run the TS decide() (node type stripping) over the same table."""
    payload = json.dumps([c[1] for c in CASES])
    script = (
        "const m = await import(process.argv[1]);"
        "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
        "const out=JSON.parse(s).map(x=>m.decide(x));"
        "process.stdout.write(JSON.stringify(out));});"
    )
    ts = ROOT / "web" / "src" / "components" / "trust" / "gradeSystem.ts"
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", script, str(ts)],
        input=payload, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    want = [{"decision": c[2], "final": c[3], "reason": c[4]} for c in CASES]
    assert got == want


def test_ts_phrase_table_agrees():
    import re
    ts = (ROOT / "web/src/components/trust/gradeSystem.ts").read_text()
    rows = re.findall(r"\{ value: '([a-z_]+)', phrase: '([^']+)', label: '([^']+)', "
                      r"color: '(#[0-9A-F]{6})', colorText: '(#[0-9A-F]{6})' \}", ts)
    assert rows == [(d.value, d.phrase, d.label, d.color, d.color_light) for d in DECISIONS]
