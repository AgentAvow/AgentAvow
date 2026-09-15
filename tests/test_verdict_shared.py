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
        # clean but under the bar: distinguish coverage cap from weak signals
        (_data(74, no_blocking=True, files=3), False, "thin_coverage"),
        (_data(78, no_blocking=True, files=40), False, "low_signals"),
        (_data(70, no_blocking=True), False, "low_signals"),  # no files_scanned
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


def test_just_below_bar_is_not_safe():
    assert is_safe(_data(SAFE_BAR - 1, no_blocking=True, files=20)) is False


def test_adoption_is_never_an_input():
    # Two identical scans; "adoption" must not change the verdict (popular != safe).
    base = _data(74, no_blocking=True, files=3)
    popular = dict(base, adoption={"count": 999_000_000, "unit": "downloads/wk"})
    assert is_safe(base) == is_safe(popular)
    assert verdict_reason(base) == verdict_reason(popular)
