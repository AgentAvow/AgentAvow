"""Unit tests for the shared safe/needs-review verdict helper (src/scanner/verdict.py).

This is the single source of truth used by BOTH the public API and the MCP connector,
so these cases lock the contract the two surfaces must agree on.
"""
from __future__ import annotations

import pytest

from src.scanner.verdict import SAFE_BAR, is_safe, verdict_label, verdict_reason


def _data(score, items=None, no_blocking=None, files=None):
    d = {"trust_score": score, "findings": {"items": items or []}}
    if no_blocking is not None:
        d["certified"] = {"checks": {"no_critical_or_high": no_blocking}}
    if files is not None:
        d["metadata"] = {"files_scanned": files}
    return d


@pytest.mark.parametrize(
    "data,exp_safe,exp_reason",
    [
        # safe: >= bar and no blocking findings -> clean
        (_data(82, no_blocking=True, files=4), True, "clean"),
        (_data(SAFE_BAR, no_blocking=True, files=20), True, "clean"),
        # blocking findings floor the verdict even when the score is high
        (_data(90, [{"severity": "critical"}], no_blocking=False, files=50), False, "blocking_findings"),
        (_data(45, [{"severity": "high"}], no_blocking=False, files=50), False, "blocking_findings"),
        # Since 2026-10-08 the verdict follows decide(): a clean result is safe even under
        # the old 81 bar (thin coverage reads Safe with its reason; Kenne's decision).
        (_data(74, no_blocking=True, files=3), True, "clean"),
        (_data(78, no_blocking=True, files=40), True, "clean"),
        (_data(70, no_blocking=True), True, "clean"),  # no files_scanned
        # Review without a finding: score under 51 (weak signals) or deprecated
        (_data(40, no_blocking=True, files=40), False, "low_signals"),
        (dict(_data(84, no_blocking=True, files=40), deprecation="no longer maintained"),
         False, "deprecated"),
        # fallback when the certified.checks flag is absent: count the items
        (_data(85, [{"severity": "medium"}], files=20), True, "clean"),
        (_data(85, [{"severity": "high"}], files=20), False, "blocking_findings"),
        # degenerate input never raises
        ({}, False, "low_signals"),
    ],
)
def test_verdict_matrix(data, exp_safe, exp_reason):
    safe = is_safe(data)
    assert safe is exp_safe
    assert verdict_reason(data, safe) == exp_reason
    assert verdict_reason(data) == exp_reason  # recomputes safe internally
    assert verdict_label(safe) == ("safe" if exp_safe else "needs_review")


def test_old_bar_no_longer_decides():
    """The verdict follows decide(), not the old SAFE_BAR: just under 81 with nothing
    found is safe; the legacy rule is kept as is_safe_legacy for reference."""
    from src.scanner.verdict import is_safe_legacy

    data = _data(SAFE_BAR - 1, no_blocking=True, files=20)
    assert is_safe(data) is True
    assert is_safe_legacy(data) is False


def test_verdict_agrees_with_decide():
    from src.scanner.verdict import decide

    cases = [
        _data(92, no_blocking=True, files=50),
        _data(74, no_blocking=True, files=3),
        _data(69, [{"severity": "high"}], no_blocking=False, files=50),
        _data(6, [{"severity": "critical"}], no_blocking=False, files=50),
        dict(_data(84, no_blocking=True, files=40), deprecation="retired"),
        _data(40, no_blocking=True, files=40),
    ]
    for d in cases:
        assert verdict_label(is_safe(d)) == ("safe" if decide(d).decision == "safe" else "needs_review")


def test_adoption_is_never_an_input():
    # Two identical scans; "adoption" must not change the verdict (popular != safe).
    base = _data(74, no_blocking=True, files=3)
    popular = dict(base, adoption={"count": 999_000_000, "unit": "downloads/wk"})
    assert is_safe(base) == is_safe(popular)
    assert verdict_reason(base) == verdict_reason(popular)
