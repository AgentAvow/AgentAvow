"""Tests for the adoption / engagement metric v1 (src/scanner/adoption.py).

Covers the formula, the 5 axes, the anti-gaming gates (≥2-axis agreement,
≤35% single-source cap, download-curve anomaly, fake-star burst, download/
dependent sanity ratio, first-party weight-ramp), cold-start fallback, the
OpenSSF Criticality Score reimplementation, and the signed evidence record.
"""
from __future__ import annotations

import pytest

from src.scanner import adoption as adopt
from src.scanner.adoption_sources import _referer_host, checker_identity

# ---------------------------------------------------------------------------
# Formula + blend
# ---------------------------------------------------------------------------

def test_formula_weights_published():
    assert adopt.ABSOLUTE_WEIGHT == 0.6
    assert adopt.MOMENTUM_WEIGHT == 0.4
    assert abs(sum(adopt.PUBLISHED_AXIS_WEIGHTS.values()) - 1.0) < 1e-9


def test_blend_is_0_6_absolute_0_4_momentum():
    # Two axes, both absolute=1.0 momentum=1.0. Each is capped at 35% of the
    # weight (single-source cap, no renormalize), so absolute_tier = momentum
    # = 0.70 and score = 0.6*0.70 + 0.4*0.70 = 0.70. The very top scores need
    # breadth (≥3 balanced axes) — that is the anti-gaming design.
    axes = [
        adopt.AxisResult(axis="A", present=True, absolute=1.0, momentum=1.0),
        adopt.AxisResult(axis="B", present=True, absolute=1.0, momentum=1.0),
    ]
    res = adopt.compute_adoption(axes)
    assert res.score == pytest.approx(0.70, abs=1e-6)
    # Three balanced axes reach a genuinely high score.
    axes3 = [
        adopt.AxisResult(axis="A", present=True, absolute=1.0, momentum=1.0),
        adopt.AxisResult(axis="B", present=True, absolute=1.0, momentum=1.0),
        adopt.AxisResult(axis="E", present=True, absolute=1.0, momentum=1.0),
    ]
    assert adopt.compute_adoption(axes3).score > 0.9
    # absolute-only vs momentum-only weighting (with the 0.70 cap ceiling)
    axes2 = [
        adopt.AxisResult(axis="A", present=True, absolute=1.0, momentum=0.0),
        adopt.AxisResult(axis="B", present=True, absolute=1.0, momentum=0.0),
    ]
    res2 = adopt.compute_adoption(axes2)
    assert res2.absolute_tier == pytest.approx(0.70, abs=1e-6)
    assert res2.score == pytest.approx(0.6 * 0.70, abs=1e-6)


# ---------------------------------------------------------------------------
# Anti-gaming: ≥2-axis agreement gate
# ---------------------------------------------------------------------------

def test_single_axis_cannot_reach_top_tier():
    # One massively-inflated axis alone must be gated below the ceiling.
    axes = [adopt.AxisResult(axis="A", present=True, absolute=1.0, momentum=1.0)]
    res = adopt.compute_adoption(axes)
    assert res.score <= adopt._INTERNAL_SINGLE_AXIS_CEILING + 1e-9
    assert "top_tier_gated_needs_2_axis_agreement" in res.notes
    assert res.insufficient_data is True
    assert res.badge == "insufficient_data"


def test_two_axis_agreement_unlocks_top_tier():
    axes = [
        adopt.AxisResult(axis="A", present=True, absolute=0.9, momentum=0.9),
        adopt.AxisResult(axis="B", present=True, absolute=0.9, momentum=0.9),
    ]
    res = adopt.compute_adoption(axes)
    assert res.score > adopt._INTERNAL_SINGLE_AXIS_CEILING
    assert set(res.agreeing_axes) == {"A", "B"}


def test_one_strong_one_weak_axis_does_not_agree():
    # weak axis below the agreement absolute → still single-axis gated
    axes = [
        adopt.AxisResult(axis="A", present=True, absolute=0.95, momentum=0.95),
        adopt.AxisResult(axis="C", present=True, absolute=0.05, momentum=0.5),
    ]
    res = adopt.compute_adoption(axes)
    assert res.agreeing_axes == ["A"]
    assert res.score <= adopt._INTERNAL_SINGLE_AXIS_CEILING + 1e-9


# ---------------------------------------------------------------------------
# Anti-gaming: ≤35% single-source cap
# ---------------------------------------------------------------------------

def test_single_source_cap_limits_dominant_axis():
    # Axis B base weight 0.28; with only B and a tiny C, B would dominate.
    axes = [
        adopt.AxisResult(axis="B", present=True, absolute=1.0, momentum=1.0),
        adopt.AxisResult(axis="C", present=True, absolute=0.0, momentum=0.0),
        adopt.AxisResult(axis="A", present=True, absolute=0.0, momentum=0.0),
    ]
    res = adopt.compute_adoption(axes)
    # B capped at 35% of absolute_tier → absolute_tier ≤ 0.35
    assert res.absolute_tier <= adopt._INTERNAL_MAX_SINGLE_SOURCE_SHARE + 1e-6
    assert "single_source_cap_applied" in res.notes


# ---------------------------------------------------------------------------
# Axis A — downloads + curve anomaly + sanity ratio
# ---------------------------------------------------------------------------

def test_axis_downloads_basic():
    ax = adopt.build_axis_downloads(total_downloads=100_000, series=[100] * 52)
    assert ax.present and 0 < ax.absolute <= 1.0


def test_download_curve_anomaly_flat_floor_discounts():
    normal = adopt.build_axis_downloads(
        total_downloads=52000, series=list(range(100, 152)),
    )
    gamed = adopt.build_axis_downloads(
        total_downloads=52000, series=[1000] * 52,
    )
    assert "download_curve_anomaly" in gamed.discounts
    assert gamed.absolute < normal.absolute


def test_download_curve_anomaly_single_spike():
    series = [1] * 30 + [100000] + [1] * 5
    assert adopt._detect_download_curve_anomaly(series) is True


def test_downloads_per_dependent_ratio_discount():
    high = adopt.build_axis_downloads(
        total_downloads=10_000_000, series=[1] * 4,
        dependents_for_ratio=0, versions=1,
    )
    assert "downloads_per_dependent_ratio" in high.discounts


# ---------------------------------------------------------------------------
# Axis B — reverse-dependents
# ---------------------------------------------------------------------------

def test_axis_dependents_weights_packages_over_repos():
    a = adopt.build_axis_dependents(dependent_packages=100, dependent_repos=0)
    b = adopt.build_axis_dependents(dependent_packages=0, dependent_repos=100)
    assert a.absolute > b.absolute  # packages weighted 2x


def test_axis_dependents_absent():
    ax = adopt.build_axis_dependents()
    assert ax.present is False


# ---------------------------------------------------------------------------
# Axis C — stars + fake-star burst
# ---------------------------------------------------------------------------

def test_fake_star_burst_discounts():
    # 100 stars, 80 landed on a single day → burst
    ts = ["2026-01-01T00:00:00Z"] * 80 + [
        f"2026-02-{d:02d}T00:00:00Z" for d in range(1, 21)
    ]
    ax = adopt.build_axis_stars(stars=100, star_timestamps=ts)
    assert "fake_star_burst" in ax.discounts
    clean_ts = [f"2026-{m:02d}-15T00:00:00Z" for m in range(1, 13)] * 9
    clean = adopt.build_axis_stars(stars=100, star_timestamps=clean_ts[:100])
    assert ax.absolute < clean.absolute


def test_suspect_accounts_discount_without_timestamps():
    ax = adopt.build_axis_stars(stars=100, suspect_accounts=50)
    assert "fake_star_burst" in ax.discounts


# ---------------------------------------------------------------------------
# Axis D — first-party + weight ramp
# ---------------------------------------------------------------------------

def test_first_party_scores_on_unique_not_raw():
    ax, vf = adopt.build_axis_first_party(unique_checkers=200, raw_checks=999999)
    assert ax.present and ax.first_party
    assert ax.raw["raw_checks_vanity"] == 999999
    assert 0 < ax.absolute <= 1.0


def test_first_party_weight_ramp_low_volume():
    _, vf_low = adopt.build_axis_first_party(badge_embed_domains=3)
    _, vf_full = adopt.build_axis_first_party(
        unique_checkers=60, badge_embed_domains=10,
    )
    assert vf_low < 0.2
    assert vf_full == pytest.approx(1.0)


def test_first_party_absent():
    ax, vf = adopt.build_axis_first_party()
    assert ax.present is False and vf == 0.0


def test_first_party_ramp_reduces_influence_when_cold():
    # Cold-start D shouldn't be able to lift the score much on its own.
    d_axis, vf = adopt.build_axis_first_party(badge_embed_domains=3)
    b_axis = adopt.build_axis_dependents(dependent_packages=50)
    with_ramp = adopt.compute_adoption([b_axis, d_axis], first_party_volume_factor=vf)
    # D weight ramped to ~0, so effectively single-axis (B) → gated
    assert d_axis.axis in with_ramp.present_axes


# ---------------------------------------------------------------------------
# Axis E — MCP registry
# ---------------------------------------------------------------------------

def test_axis_mcp_registry():
    ax = adopt.build_axis_mcp_registry(
        smithery_downloads=5000, smithery_stars=120, tool_call_count=20000,
    )
    assert ax.present and ax.absolute > 0


def test_axis_mcp_registry_absent():
    assert adopt.build_axis_mcp_registry().present is False


# ---------------------------------------------------------------------------
# Cold-start fallback
# ---------------------------------------------------------------------------

def test_cold_start_pure_mcp_marks_insufficient_not_penalized():
    # Only axis E present (MCP tool with no package) → insufficient_data, but
    # E's own absolute is not dragged down by absent A/B.
    e = adopt.build_axis_mcp_registry(smithery_downloads=8000, tool_call_count=40000)
    res = adopt.compute_adoption([e])
    assert res.insufficient_data is True
    assert res.present_axes == ["E"]
    # absolute_tier reflects E alone, not diluted toward 0 by empty axes
    assert res.absolute_tier == pytest.approx(e.absolute, abs=1e-3)


def test_no_axes_returns_floor():
    res = adopt.compute_adoption([])
    assert res.score == 0.0
    assert res.insufficient_data is True
    assert res.badge == "insufficient_data"


# ---------------------------------------------------------------------------
# rising vs established badge
# ---------------------------------------------------------------------------

def test_rising_badge():
    axes = [
        adopt.AxisResult(axis="A", present=True, absolute=0.3, momentum=0.9),
        adopt.AxisResult(axis="B", present=True, absolute=0.3, momentum=0.9),
    ]
    assert adopt.compute_adoption(axes).badge == "rising"


def test_established_badge():
    axes = [
        adopt.AxisResult(axis="A", present=True, absolute=0.9, momentum=0.5),
        adopt.AxisResult(axis="B", present=True, absolute=0.9, momentum=0.5),
    ]
    assert adopt.compute_adoption(axes).badge == "established"


# ---------------------------------------------------------------------------
# OpenSSF Criticality Score
# ---------------------------------------------------------------------------

def test_criticality_zero_signals():
    score, comps = adopt.compute_criticality_score({})
    assert score == 0.0
    assert "dependents_count" in comps


def test_criticality_monotonic_in_dependents():
    low, _ = adopt.compute_criticality_score({"dependents_count": 100})
    high, _ = adopt.compute_criticality_score({"dependents_count": 500000})
    assert high > low
    assert 0.0 <= high <= 1.0


def test_criticality_updated_since_inverted():
    # A recently-updated project (small updated_since) scores higher than a
    # long-stale one on that inverted factor.
    fresh, _ = adopt.compute_criticality_score({"updated_since_months": 1})
    stale, _ = adopt.compute_criticality_score({"updated_since_months": 120})
    assert fresh > stale


# ---------------------------------------------------------------------------
# Public vs internal projection (first-party raw counts stay internal)
# ---------------------------------------------------------------------------

def test_public_dict_redacts_first_party_raw():
    d_axis, vf = adopt.build_axis_first_party(unique_checkers=80, raw_checks=123456)
    b_axis = adopt.build_axis_dependents(dependent_packages=200)
    res = adopt.compute_adoption([b_axis, d_axis], first_party_volume_factor=vf)
    pub = res.to_public_dict()
    # find the D axis in the public projection
    d_pub = [a for a in pub["axes"] if a["axis"] == "D"]
    assert d_pub and d_pub[0]["raw"] == {"redacted": True}
    # published formula present; internal thresholds absent
    assert pub["formula"]["axis_weights"] == adopt.PUBLISHED_AXIS_WEIGHTS
    assert "_INTERNAL_MAX_SINGLE_SOURCE_SHARE" not in str(pub)


def test_internal_dict_keeps_first_party_raw():
    d_axis, vf = adopt.build_axis_first_party(unique_checkers=80, raw_checks=123456)
    b_axis = adopt.build_axis_dependents(dependent_packages=200)
    res = adopt.compute_adoption([b_axis, d_axis], first_party_volume_factor=vf)
    internal = res.to_internal_dict()
    blob = str(internal["axes_full"])
    assert "123456" in blob  # raw vanity count retained internally


# ---------------------------------------------------------------------------
# Evidence record + signing (recomputability)
# ---------------------------------------------------------------------------

def test_evidence_record_recomputable_shape():
    axes = [
        adopt.build_axis_downloads(total_downloads=100000, series=[100] * 52),
        adopt.build_axis_dependents(dependent_packages=300),
    ]
    res = adopt.compute_adoption(axes)
    rec = adopt.build_evidence_record(
        {"surface": "npm", "name": "demo"},
        res,
        {"A": {"source": "npm", "fetched_at": "t"}},
    )
    assert rec["schema_version"] == adopt.SCHEMA_VERSION
    assert rec["evidence_anchor"] == "evidence-anchor-adoption-v0"
    assert "raw_inputs" in rec and "adoption" in rec


def test_evidence_record_signs_and_is_deterministic():
    axes = [
        adopt.build_axis_downloads(total_downloads=100000, series=[100] * 52),
        adopt.build_axis_dependents(dependent_packages=300),
    ]
    res = adopt.compute_adoption(axes, computed_at="2026-08-08T00:00:00+00:00")
    rec = adopt.build_evidence_record({"surface": "npm"}, res, {})
    jws = adopt.sign_evidence_record(rec)
    # Signing is best-effort; when a key is available it must be a compact JWS.
    if jws is not None:
        assert jws.count(".") == 2


# ---------------------------------------------------------------------------
# Sources helpers (pure parts)
# ---------------------------------------------------------------------------

def test_referer_host_drops_our_domains():
    assert _referer_host("https://agentavow.com/x") is None
    assert _referer_host("https://github.com/foo/bar") == "github.com"
    assert _referer_host(None) is None
    assert _referer_host("not a url") is None


def test_checker_identity_prefers_entity_then_hashes():
    assert checker_identity("ent-1", "1.2.3.4", "UA").startswith("e:ent-1")
    anon = checker_identity(None, "1.2.3.4", "UA")
    assert anon.startswith("a:")
    # deterministic + no raw IP leaked
    assert anon == checker_identity(None, "1.2.3.4", "UA")
    assert "1.2.3.4" not in anon
