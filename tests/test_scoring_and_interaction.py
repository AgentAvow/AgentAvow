"""Tests for the two centralized helpers that ended the B3 (grade bands) and B2
(interaction-safety thresholds) divergences."""
from __future__ import annotations

import pytest

from src.interaction_safety import (
    INTERACTION_THRESHOLDS,
    interaction_recommendation,
    threshold_for,
)
from src.scoring import grade_from_score


# --- B3: canonical grade bands (A+96 / A81 / B61 / C41 / D21 / F) ---
@pytest.mark.parametrize("score,grade", [
    (100, "A+"), (96, "A+"), (95, "A"), (85, "A"), (81, "A"),   # 85 = "A" (email bug: was "B")
    (80, "B"), (61, "B"), (60, "C"), (41, "C"), (40, "D"), (21, "D"), (20, "F"), (0, "F"),
])
def test_grade_bands(score, grade):
    assert grade_from_score(score) == grade


def test_grade_degenerate():
    assert grade_from_score(None) == "F"
    assert grade_from_score(-5) == "F"


def test_email_matches_site_now():
    """The exact B3 bug: 85 must be the same grade in the email helper and everywhere else."""
    from src.email import _grade_and_color
    g, _color = _grade_and_color(85)
    assert g == "A" == grade_from_score(85)


# --- B2: per-interaction-type thresholds, one source of truth ---
def test_follow_at_55_is_safe():
    """The exact B2 contradiction: score 55, follow → safe (threshold 10), not caution."""
    r = interaction_recommendation(55, "follow")
    assert r["threshold"] == 10 and r["safe"] is True and r["recommendation"] == "proceed"


@pytest.mark.parametrize("score,itype,safe", [
    (55, "delegate", False),   # delegate bar = 60
    (60, "delegate", True),
    (55, "collaborate", True),  # collaborate bar = 40
    (85, "financial", True),    # financial bar = 80
    (79, "financial", False),
    (70, "data_transfer", True),
    (69, "data_transfer", False),
    (0, "discover", True),      # discover bar = 0
])
def test_interaction_thresholds(score, itype, safe):
    assert interaction_recommendation(score, itype)["safe"] is safe


def test_unknown_type_defaults_conservative():
    assert threshold_for("teleport") == 60  # unknown → delegate-level


def test_a2a_map_unchanged_and_single_sourced():
    """A2A's 0-1 defaults must still equal their historical values, now derived from the
    shared 0-100 source (no behaviour change, just single-sourced)."""
    from src.protocol.a2a_middleware import DEFAULT_TRUST_THRESHOLDS as A2A
    expected = {"delegate": 0.6, "negotiate": 0.5, "collaborate": 0.4, "discover": 0.0,
                "capability_exchange": 0.1, "data_transfer": 0.7, "financial": 0.8}
    assert A2A == expected
    # and each is exactly the shared 0-100 value / 100
    for k, v in expected.items():
        assert A2A[k] == INTERACTION_THRESHOLDS[k] / 100
