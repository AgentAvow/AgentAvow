"""The graduated score curve (Kenne, 2026-10-08, tracked follow-up #4).

For a result with no critical or high code finding: base 84 (no drop to 68), each code
medium costs 4 (2 in an expected / declared category) times its shipped weight, total
capped at 16, lows free, no 42 cap and no file-ratio scaling. Anything with a critical
or high keeps the old formula exactly. README + LICENSE add 2 each, so a clean result
in these tests scores 88.
"""
from __future__ import annotations

import pytest

from src.scanner.scan import (
    _CRITICAL_CEILING,
    Finding,
    ScanResult,
    _calculate_trust_score,
    _finding_grade_weight,
)


def _f(severity: str, path: str = "src/lib.py", category: str = "code_safety",
       name: str = "Finding", line: int = 1) -> Finding:
    return Finding(category=category, name=name, severity=severity, file_path=path,
                   line_number=line, snippet="")


def _result(findings: list[Finding], files: int = 40, mcp: bool = False) -> ScanResult:
    r = ScanResult(repo="o/r", stars=0, description="", framework="")
    r.findings = findings
    r.files_scanned = files
    r.is_mcp_server = mcp
    r.has_readme = r.has_license = True
    return r


def _mediums(n: int) -> list[Finding]:
    # distinct lines so dedup never merges them
    return [_f("medium", line=i + 1) for i in range(n)]


@pytest.mark.parametrize("n,score", [(0, 88), (1, 84), (2, 80), (5, 72)])
def test_medium_count_curve(n, score):
    assert _calculate_trust_score(_result(_mediums(n))) == score


def test_medium_cost_is_capped_at_16():
    # browserslist: 11 copies of one medium rule in one file -> 88 - 16 = 72
    assert _calculate_trust_score(_result(_mediums(11), files=9)) == 72
    assert _calculate_trust_score(_result(_mediums(40), files=9)) == 72


def test_no_file_ratio_scaling_on_the_curve():
    # one medium costs the same in a 200-file package as in a 10-file one
    assert _calculate_trust_score(_result(_mediums(1), files=200)) == 84
    assert _calculate_trust_score(_result(_mediums(1), files=10)) == 84


def test_medium_in_an_expected_category_costs_half():
    # an MCP server's fs_access / unsafe_exec are expected categories
    r = _result([_f("medium", category="fs_access")], mcp=True)
    assert _calculate_trust_score(r) == 86
    # the same medium outside the expected set costs the full 4
    r = _result([_f("medium", category="code_safety")], mcp=True)
    assert _calculate_trust_score(r) == 84


def test_medium_in_a_declared_category_costs_half():
    r = _result([_f("medium", category="dynamic_remote_load")])
    r.declared_scope = {"present": True, "capabilities": ["network:egress"]}
    assert _calculate_trust_score(r) == 86


def test_lows_are_free():
    assert _calculate_trust_score(_result([_f("low", line=i) for i in range(1, 7)])) == 88


def test_non_shipped_medium_costs_its_weight():
    f = _f("medium", path="tests/test_lib.py")
    w = _finding_grade_weight(f)
    assert w < 1
    assert _calculate_trust_score(_result([f])) == int(round(88 - 4 * w))


def test_evidence_cap_still_applies():
    # 3 files or fewer: capped at 74 whatever the curve says
    assert _calculate_trust_score(_result([], files=3)) == 74
    assert _calculate_trust_score(_result(_mediums(1), files=2)) == 74
    assert _calculate_trust_score(_result([], files=5)) == 82


# ── criticals and highs keep the old formula exactly ─────────────────────────────

def _old_formula(r: ScanResult) -> int:
    """The pre-curve formula for a result with code findings and no dependency /
    provenance / positives terms (README + LICENSE only)."""
    code = [f for f in r.findings]
    w = _finding_grade_weight
    crit = sum(w(f) for f in code if f.severity == "critical")
    high = sum(w(f) for f in code if f.severity == "high")
    med = sum(w(f) for f in code if f.severity == "medium")
    total = crit + high + med
    score = 84 if total < 0.5 else 68
    hm = min(int(high * 8 + med * 3), 42)
    ratio = len({f.file_path for f in code}) / r.files_scanned
    hm = int(hm * min(1.0, 0.4 + ratio * 2.4))
    score = score - crit * 22 - hm + 4
    return max(0, min(100, int(round(score))))


@pytest.mark.parametrize("findings", [
    [_f("high")],
    [_f("high"), _f("medium", line=2)],
    [_f("high", path="a.py"), _f("high", path="b.py"), *_mediums(5)],
    [_f("critical")],
    [_f("critical"), *_mediums(3)],
])
def test_criticals_and_highs_untouched(findings):
    r = _result(findings, files=20)
    want = _old_formula(r)
    if any(f.severity == "critical" for f in findings):
        want = min(want, _CRITICAL_CEILING)
    elif any(f.severity == "high" for f in findings):
        want = min(want, 90)
    assert _calculate_trust_score(r) == want


def test_one_high_and_one_medium_example():
    # 68 base, int(min(11, 42) * 0.52) = 5 off, +4 README/LICENSE
    r = _result([_f("high"), _f("medium", line=2)], files=20)
    assert _calculate_trust_score(r) == 67


def test_capabilities_and_dependency_findings_are_not_curve_inputs():
    cap = _f("low", category="unsafe_exec")
    cap.kind = "capability"
    assert _calculate_trust_score(_result([cap])) == 88
