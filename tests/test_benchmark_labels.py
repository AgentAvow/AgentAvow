"""Benchmark label mapping, outcomes and metrics (scripts/benchmark/labels.py)."""
from __future__ import annotations

import pytest

from scripts.benchmark.labels import (
    NOT_CHECKED,
    outcome_for,
    summarize,
    truth_for,
    wilson,
)


@pytest.mark.parametrize("set_id,raw,truth", [
    ("A", "1", "malicious"),
    ("A", 1, "malicious"),
    ("A", "0", "benign"),
    ("B", "malicious", "malicious"),
    ("B", "benign", "benign"),
    ("B", "contextual_risk", "contextual"),
    ("C", "malicious_intent", "malicious"),
    ("C", "compromised_lib", "malicious"),
    ("D", "benign", "benign"),
])
def test_truth_mapping(set_id, raw, truth):
    assert truth_for(set_id, raw) == truth


@pytest.mark.parametrize("set_id,raw", [
    ("A", "2"), ("A", "malicious"), ("B", "suspicious"), ("C", "benign"),
    ("D", "malicious"), ("E", "1"),
])
def test_unknown_labels_fail_loudly(set_id, raw):
    with pytest.raises(ValueError):
        truth_for(set_id, raw)


def test_outcomes():
    assert outcome_for("do_not_connect") == "do_not_connect"
    assert outcome_for("review") == "review"
    assert outcome_for("safe") == "safe"
    # No answer is never quietly Safe.
    assert outcome_for(None) == NOT_CHECKED
    assert outcome_for("missing") == NOT_CHECKED
    assert outcome_for("unscannable") == NOT_CHECKED


def test_wilson_known_values():
    assert wilson(0, 0) == (0.0, 0.0)
    lo, hi = wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-4)
    assert hi == pytest.approx(0.7634, abs=1e-4)
    lo, hi = wilson(0, 20)
    assert lo == 0.0 and hi == pytest.approx(0.1611, abs=1e-4)
    lo, hi = wilson(20, 20)
    assert hi == 1.0 and lo == pytest.approx(0.8389, abs=1e-4)


def _rows(truth, **counts):
    return [{"truth": truth, "outcome": o} for o, n in counts.items() for _ in range(n)]


def test_summarize_counts_not_checked_apart():
    rows = (_rows("malicious", do_not_connect=6, review=2, safe=2, not_checked=3)
            + _rows("benign", safe=8, review=1, do_not_connect=1, not_checked=2)
            + _rows("contextual", review=1, safe=1))
    s = summarize(rows)
    m = s["malicious"]
    assert m["checked"] == 10 and m["not_checked"] == 3
    assert m["flag_do_not_connect"]["rate"] == pytest.approx(0.6)
    assert m["flag_review_or_worse"]["rate"] == pytest.approx(0.8)
    assert m["miss_safe"]["rate"] == pytest.approx(0.2)
    b = s["benign"]
    assert b["checked"] == 10 and b["not_checked"] == 2
    assert b["false_do_not_connect"]["rate"] == pytest.approx(0.1)
    assert b["review"]["rate"] == pytest.approx(0.1)
    assert b["fpr_review_or_worse"]["rate"] == pytest.approx(0.2)
    # Contextual cases never enter the recall or false-positive figures.
    assert s["contextual"] == {"safe": 1, "review": 1, "do_not_connect": 0, NOT_CHECKED: 0}


def test_summarize_empty():
    s = summarize([])
    assert s["malicious"]["checked"] == 0
    assert s["malicious"]["flag_review_or_worse"]["rate"] is None
