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


def test_suppression_cannot_hide_a_critical():
    """Anti-gaming #1: a suppressed line matching a critical/high pattern is detected,
    so `ag-scan:ignore` can't silently hide a real critical."""
    from src.scanner.scan import _line_has_blocking_match
    assert _line_has_blocking_match("eval(user_input)  # ag-scan:ignore", "python") is True
    assert _line_has_blocking_match("x = 1  # ag-scan:ignore", "python") is False


def test_path_rename_cannot_dodge_the_floor():
    """Anti-gaming #2: a real critical in scripts//sandbox//demo_ still floors."""
    from src.scanner.scan import _is_blocking_exempt_path
    # runtime-plausible dirs / filenames are NOT exempt from the floor
    assert _is_blocking_exempt_path("scripts/server.py") is False
    assert _is_blocking_exempt_path("sandbox/main.py") is False
    assert _is_blocking_exempt_path("demo_server.py") is False
    assert _is_blocking_exempt_path("tooling/run.py") is False
    # genuine non-runtime code IS exempt
    assert _is_blocking_exempt_path("tests/test_x.py") is True
    assert _is_blocking_exempt_path("docs/guide.py") is True
    assert _is_blocking_exempt_path("examples/demo.py") is True
    assert _is_blocking_exempt_path("foo.test.ts") is True


def test_the_invariant_no_trusted_score_with_a_shipped_critical():
    # This is the CI assertion the audit asked for, at the unit level.
    for path in ("src/x.py", "server.js", "main.py", "lib/tool.ts"):
        r = _result([_f("critical", path)], mcp=True)
        assert not (_calculate_trust_score(r) >= 81 and r.shipped_critical_count > 0)


# ── Evidence-confidence cap (2026-08-19) ──────────────────────────────────────
# A clean scan with little to inspect can't read as "excellent". These lock the
# cap: a thin scan is bounded below the clean baseline, tests earn headroom back,
# a substantial clean repo is untouched, and the cap NEVER raises a score.
from src.scanner.scan import (  # noqa: E402
    _EVIDENCE_THIN_CAP,
    _EVIDENCE_VERY_THIN_CAP,
)


def _clean(files: int, tests: bool = False) -> ScanResult:
    r = ScanResult(repo="o/r", stars=0, description="", framework="")
    r.findings = []
    r.has_readme = r.has_license = True
    r.has_tests = tests
    r.files_scanned = files
    return r


def test_thin_clean_scan_is_capped_below_baseline():
    # 5 files, no tests, nothing found — clean but too thin to certify high.
    r = _clean(files=5, tests=False)
    assert _calculate_trust_score(r) <= _EVIDENCE_THIN_CAP


def test_very_thin_scan_capped_harder():
    r = _clean(files=2, tests=False)
    assert _calculate_trust_score(r) <= _EVIDENCE_VERY_THIN_CAP


def test_tests_earn_headroom_on_a_small_repo():
    # A tested small repo can score higher than an untested one of the same size.
    assert _calculate_trust_score(_clean(files=5, tests=True)) > \
        _calculate_trust_score(_clean(files=5, tests=False))


def test_substantial_clean_repo_is_not_capped():
    # 20 files scanned — plenty of basis; the cap must not touch it.
    r = _clean(files=20, tests=True)
    assert _calculate_trust_score(r) > _EVIDENCE_THIN_CAP


def test_cap_never_raises_a_score():
    # A thin repo that ALSO has a blocking critical stays floored — the cap is a
    # ceiling, never a floor, so it can't lift a bad score up to the cap.
    r = _clean(files=2, tests=False)
    r.findings = [_f("critical", "src/server.py")]
    assert _calculate_trust_score(r) <= _CRITICAL_CEILING


def test_zero_files_scanned_is_not_capped():
    # files_scanned=0 often means "not populated", not "empty repo" — don't cap on it.
    r = _clean(files=0, tests=False)
    # no exception + a real score; cap logic is skipped for files==0
    assert 0 <= _calculate_trust_score(r) <= 100
