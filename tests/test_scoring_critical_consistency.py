"""Regression tests for the scoring-integrity fix (2026-08-19).

The bug: an MCP server could read trust_score=100 / tier=verified while its grade was
capped to B and it showed "1 critical" — four surfaces disagreeing, because the number
discounted a non-shipped critical the letter still counted. These lock the invariant:
a BLOCKING (shipped / known-malicious) critical drives score, grade, tier, and count
together; a non-shipped-only critical is discounted consistently everywhere.
"""
from __future__ import annotations

from src.scanner.scan import (
    _CRITICAL_CEILING,
    Finding,
    ScanResult,
    _calculate_trust_score,
)


def _f(severity: str, path: str, category: str = "unsafe_exec", name: str = "x") -> Finding:
    return Finding(category=category, name=name, severity=severity,
                   file_path=path, line_number=1, snippet="")


def _result(findings: list[Finding], mcp: bool = False) -> ScanResult:
    r = ScanResult(repo="o/r", stars=0, description="", framework="")
    r.findings = findings
    r.is_mcp_server = mcp
    r.has_readme = r.has_license = r.has_tests = True
    r.files_scanned = 20
    return r


def test_shipped_critical_floors_below_trusted():
    r = _result([_f("critical", "src/server.py")])
    assert r.shipped_critical_count == 1
    assert _calculate_trust_score(r) <= _CRITICAL_CEILING


def test_shipped_critical_floors_for_mcp_too():
    # the exact srdcheck class of bug — an MCP server with a shipped critical
    r = _result([_f("critical", "server.py")], mcp=True)
    assert r.shipped_critical_count == 1
    assert _calculate_trust_score(r) < 80  # can never sit in the Trusted band


def test_nonshipped_critical_is_not_blocking():
    # a subprocess critical in a benchmark harness — discounted, NOT a headline critical
    r = _result([_f("critical", "bench/harness.py")], mcp=True)
    assert r.shipped_critical_count == 0
    assert _calculate_trust_score(r) > _CRITICAL_CEILING


def test_known_malicious_blocks_even_in_a_test_path():
    r = _result([_f("critical", "tests/x.py", category="dependency",
                     name="Known-malicious package: evil@1")])
    assert r.shipped_critical_count == 1
    assert _calculate_trust_score(r) <= _CRITICAL_CEILING


def test_shipped_high_cannot_be_a_perfect_verified_score():
    from src.scanner.scan import _HIGH_CEILING
    r = _result([_f("high", "src/server.py")], mcp=True)
    assert r.shipped_high_count == 1
    assert _calculate_trust_score(r) <= _HIGH_CEILING  # out of the top verified band


def test_the_invariant_no_trusted_score_with_a_shipped_critical():
    # This is the CI assertion the audit asked for, at the unit level.
    for path in ("src/x.py", "server.js", "main.py", "lib/tool.ts"):
        r = _result([_f("critical", path)], mcp=True)
        assert not (_calculate_trust_score(r) >= 81 and r.shipped_critical_count > 0)
