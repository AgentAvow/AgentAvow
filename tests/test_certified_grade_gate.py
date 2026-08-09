"""Tests for the A+ 'Certified' grade gate (roadmap §7).

A+ is a distinct, earned certification — not merely a high score. When the gate
is enabled, the top A+ label is reserved for tools that pass the full 6-point
certified gate; a repo-only scan scoring 96+ is capped at A. With the flag OFF
(the default), grades are exactly score-only (no behavior change).

Fully offline — no network, no DB. Exercises `_display_grade`, `_certified_status`,
and the serializer's `grade` field.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.api import public_scan_router as psr
from src.config import settings


@pytest.fixture
def gate_on(monkeypatch):
    monkeypatch.setattr(settings, "scanner_certified_grade_gate", True)


@pytest.fixture
def gate_off(monkeypatch):
    monkeypatch.setattr(settings, "scanner_certified_grade_gate", False)


# ── _display_grade ───────────────────────────────────────────────────────────

def test_gate_off_is_score_only(gate_off):
    # With the flag off, the gate is a no-op: identical to _grade_from_score.
    for score in (0, 20, 40, 60, 80, 95, 96, 100):
        assert psr._display_grade(score, certified_eligible=None) == psr._grade_from_score(score)
        assert psr._display_grade(score, certified_eligible=True) == psr._grade_from_score(score)


def test_gate_on_uncertified_96plus_capped_to_A(gate_on):
    # A repo-only (uncertified) scan, however clean, can never be A+.
    assert psr._display_grade(100, certified_eligible=False) == "A"
    assert psr._display_grade(96, certified_eligible=None) == "A"


def test_gate_on_certified_earns_a_plus(gate_on):
    # A certified scan in the A band or above earns A+.
    assert psr._display_grade(96, certified_eligible=True) == "A+"
    assert psr._display_grade(85, certified_eligible=True) == "A+"  # certified elevates a strong A
    assert psr._display_grade(81, certified_eligible=True) == "A+"


def test_gate_on_lower_bands_unaffected(gate_on):
    # Certification does not lift a B/C/D/F — the gate only governs the A+ label.
    assert psr._display_grade(80, certified_eligible=True) == "B"
    assert psr._display_grade(61, certified_eligible=True) == "B"
    assert psr._display_grade(50, certified_eligible=True) == "C"
    assert psr._display_grade(30, certified_eligible=True) == "D"
    assert psr._display_grade(10, certified_eligible=True) == "F"


# ── _certified_status gate (roadmap §7.2, 6 conjunctive checks) ───────────────

def _clean_result(**over):
    """A ScanResult-like object that PASSES all 6 certified checks by default."""
    base = dict(
        trust_score=98,
        critical_count=0,
        high_count=0,
        medium_count=0,
        findings=[],
        positive_signals=[],
        sampled=False,
        coverage={"scan_depth": "artifact", "db_snapshots": {"osv": "2026-08-08"}},
        provenance={"verified": True, "source_matches_claim": True},
        drift={"added_files": [], "modified_files": [], "has_install_hook": False},
        certified={},
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_certified_status_all_pass():
    from src.scanner.scan import _certified_status

    status = _certified_status(_clean_result())
    assert status["eligible"] is True
    assert all(status["checks"].values())


def test_certified_status_repo_only_fails():
    from src.scanner.scan import _certified_status

    status = _certified_status(_clean_result(coverage={"scan_depth": "repo-only"}))
    assert status["eligible"] is False
    assert status["checks"]["artifact_scanned"] is False


def test_certified_status_provenance_mismatch_fails():
    from src.scanner.scan import _certified_status

    status = _certified_status(_clean_result(
        provenance={"verified": True, "source_matches_claim": False},
    ))
    assert status["eligible"] is False
    assert status["checks"]["provenance_verified"] is False


def test_certified_status_drift_fails():
    from src.scanner.scan import _certified_status

    status = _certified_status(_clean_result(
        drift={"added_files": ["evil.js"], "modified_files": [], "has_install_hook": False},
    ))
    assert status["eligible"] is False
    assert status["checks"]["no_drift"] is False


def test_certified_status_sampled_fails_full_coverage():
    from src.scanner.scan import _certified_status

    status = _certified_status(_clean_result(sampled=True))
    assert status["eligible"] is False
    assert status["checks"]["full_coverage"] is False


# ── serializer wires the gated grade end-to-end ──────────────────────────────

def _scannable(**over):
    base = dict(
        trust_score=98, critical_count=0, high_count=0, medium_count=0,
        findings=[], suppressed_count=0, positive_signals=[], files_scanned=5,
        total_scannable_files=5, sampled=False, primary_language="Python",
        has_readme=True, has_license=True, has_tests=True,
        category_scores={}, tool_digests={}, tool_manifest_digest=None,
        coverage={"scan_depth": "artifact"},
        provenance={"verified": True, "source_matches_claim": True},
        drift={"added_files": [], "modified_files": [], "has_install_hook": False},
        certified={"eligible": True, "checks": {}},
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_serializer_grade_certified_a_plus(gate_on):
    data = psr._scan_result_to_dict(_scannable())
    assert data["grade"] == "A+"
    assert data["certified"]["eligible"] is True
    assert data["provenance"]["verified"] is True


def test_serializer_grade_uncertified_capped(gate_on):
    data = psr._scan_result_to_dict(_scannable(certified={"eligible": False, "checks": {}}))
    assert data["trust_score"] == 98  # score is untouched…
    assert data["grade"] == "A"       # …only the label is capped


def test_serializer_grade_unchanged_when_gate_off(gate_off):
    data = psr._scan_result_to_dict(_scannable(certified={"eligible": False, "checks": {}}))
    assert data["grade"] == "A+"  # score 98 → A+ regardless of certification
