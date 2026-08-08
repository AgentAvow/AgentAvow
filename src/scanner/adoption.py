"""Adoption / engagement metric v1 — a score DISTINCT from the trust grade.

Adoption answers "**do real, independent parties rely on this?**"; trust answers
"**is it safe?**".  They must never collapse.  A widely-adopted tool can be a
critical trust risk (bigger blast radius, not higher trust); a pristine unknown
can be A-grade trust with near-zero adoption.  This module computes a separate
0.0-1.0 adoption score (and an A+..F-style tier + "rising"/"established" badge)
that the UI presents alongside — never merged into — the trust letter.

Design (see docs/internal/scoring-roadmap-2026-08.md §3):

    adoption = 0.6 * absolute_tier + 0.4 * momentum

- ``absolute_tier`` is log-normalized (reuses ``_log_normalize``) so whales
  don't saturate the scale.
- ``momentum`` comes from trend slopes / WoW / MoM growth so a small-but-surging
  tool ranks and a decaying incumbent is visibly decaying.

Five INDEPENDENT axes — independence is the whole anti-gaming design (a gamed
tool spikes on one axis; a genuinely adopted one lights up several):

    (A) Registry downloads + trend       (npm/PyPI/crates/Docker)
    (B) Reverse-dependents               (hardest to game)
    (C) Social stars + velocity          (+ fake-star-burst detection)
    (D) First-party (ours, unfakeable)   (unique checkers, badge-embed domains,
                                          verify-pulls, in-graph connections)
    (E) MCP / agent-registry usage       (Smithery / PulseMCP / Glama)

Anti-gaming: ≥2-axis agreement for top tiers, ≤35% cap on any single source,
downloads/(dependents+versions) sanity discount, download-curve anomaly
detection, fake-star discount, first-party weight-ramp with our own volume, and
a cold-start fallback that leans on E/D/C and marks "insufficient data" rather
than penalizing empty registry axes.

**Publication policy (per Kenne):** the *formula and axis weights are published*
(``PUBLISHED_AXIS_WEIGHTS``, ``compute_adoption``); the *anti-gaming thresholds
are internal* (``_INTERNAL_*`` constants below); and the *first-party raw counts
are internal* — ``AdoptionResult.to_public_dict()`` redacts axis-D raw inputs and
exposes only its sealed normalized contribution.

Every function here is pure and deterministic given its inputs (the Redis /
network I/O lives in ``adoption_sources.py``), so the adoption number is
offline-recomputable exactly like the trust grade.  Fail-open everywhere: a
missing axis contributes nothing and is never scored as a zero.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.external_reputation import _log_normalize

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "adoption-v1"

# ---------------------------------------------------------------------------
# PUBLISHED — formula + axis weights (safe to expose; part of the methodology)
# ---------------------------------------------------------------------------

# adoption = ABSOLUTE_WEIGHT * absolute_tier + MOMENTUM_WEIGHT * momentum
ABSOLUTE_WEIGHT = 0.6
MOMENTUM_WEIGHT = 0.4

# Base per-axis weights (renormalized over the axes actually present).  Axis B
# (reverse-dependents) carries the most weight because it is the hardest to game
# — it requires *other real packages* to depend on you.
PUBLISHED_AXIS_WEIGHTS = {
    "A": 0.22,  # registry downloads + trend
    "B": 0.28,  # reverse-dependents
    "C": 0.15,  # social stars + velocity
    "D": 0.15,  # first-party (ours) — effective weight ramps with our volume
    "E": 0.20,  # MCP / agent-registry usage
}

AXIS_LABELS = {
    "A": "registry_downloads",
    "B": "reverse_dependents",
    "C": "social_stars",
    "D": "first_party",
    "E": "mcp_registry",
}

# ---------------------------------------------------------------------------
# INTERNAL — anti-gaming thresholds (do NOT publish; kept out of public records)
# ---------------------------------------------------------------------------

# No single axis may contribute more than this share of absolute_tier.
_INTERNAL_MAX_SINGLE_SOURCE_SHARE = 0.35
# Reaching the top tiers requires ≥ this many independent axes in agreement.
_INTERNAL_MIN_AXES_FOR_TOP_TIER = 2
# A single-axis (or below-agreement) adoption score is capped here.
_INTERNAL_SINGLE_AXIS_CEILING = 0.55
# An axis "agrees" (counts toward the agreement gate) at/above this absolute.
_INTERNAL_AGREEMENT_ABSOLUTE = 0.30
# downloads / (dependents + repos + versions) above this ⇒ suspicious inflation.
_INTERNAL_DL_PER_DEP_SUSPICIOUS = 40000.0
_INTERNAL_DL_PER_DEP_MAX_DISCOUNT = 0.5  # up to 50% off axis-A absolute
# Fake-star burst: share of stars arriving in anomalous bursts ⇒ discount C.
_INTERNAL_FAKE_STAR_MAX_DISCOUNT = 0.6
# Download-curve anomaly (flat floor / step / release-less spike) discount.
_INTERNAL_CURVE_ANOMALY_DISCOUNT = 0.35
# First-party weight-ramp: axis D reaches full published weight only once we
# have observed this much first-party volume (unique checkers + badge domains +
# verify pulls).  Below it, D's weight scales linearly so a cold-start tool is
# not scored on 3 badge embeds.
_INTERNAL_FIRST_PARTY_FULL_VOLUME = 50.0
# "rising" badge: momentum exceeds absolute by at least this margin.
_INTERNAL_RISING_MARGIN = 0.15
# Minimum present axes below which we flag "insufficient data".
_INTERNAL_MIN_AXES_FOR_CONFIDENCE = 2


# ---------------------------------------------------------------------------
# Per-axis result
# ---------------------------------------------------------------------------

@dataclass
class AxisResult:
    """One independent adoption axis.

    ``absolute`` and ``momentum`` are 0.0-1.0.  ``present`` is False when we
    have no data for the axis (cold-start) — a missing axis contributes nothing
    and is *not* scored as a zero.  ``first_party`` axes may redact their raw
    inputs from public records.
    """

    axis: str
    present: bool = False
    absolute: float = 0.0
    momentum: float = 0.0
    discounts: list = field(default_factory=list)
    first_party: bool = False
    # Raw inputs snapshot for recomputability. For first-party axes this is kept
    # internal (redacted by to_public_dict()).
    raw: dict = field(default_factory=dict)

    def to_dict(self, *, redact_first_party: bool = False) -> dict:
        d = {
            "axis": self.axis,
            "label": AXIS_LABELS.get(self.axis, self.axis),
            "present": self.present,
            "absolute": round(self.absolute, 4),
            "momentum": round(self.momentum, 4),
            "discounts": list(self.discounts),
        }
        if self.first_party and redact_first_party:
            d["raw"] = {"redacted": True}
        else:
            d["raw"] = self.raw
        return d


# ---------------------------------------------------------------------------
# Axis builders — pure functions over already-fetched raw data
# ---------------------------------------------------------------------------

def _slope_to_momentum(series: list) -> float:
    """Map a chronological count series to a 0.0-1.0 momentum via WoW growth.

    Uses the ratio of the most-recent window to the prior window (bounded).
    ``1.0`` = strong sustained growth, ``0.5`` = flat, ``<0.5`` = decaying.
    """
    vals = [float(v) for v in series if v is not None]
    if len(vals) < 4:
        return 0.5  # not enough trend data → neutral
    half = len(vals) // 2
    prior = sum(vals[:half])
    recent = sum(vals[half:])
    if prior <= 0:
        return 1.0 if recent > 0 else 0.5
    ratio = recent / prior
    # ratio 1.0 → 0.5 (flat); ratio 2.0 → ~0.85; ratio 0.5 → ~0.2
    return max(0.0, min(1.0, 0.5 + math.log(ratio) / (2 * math.log(3))))


def _detect_download_curve_anomaly(series: list) -> bool:
    """Flag obviously-gamed download curves: constant floors or single spikes.

    - Constant floor: many identical non-zero values (bot drip).
    - Release-less spike: one point >> the rest with a flat baseline.
    """
    vals = [float(v) for v in series if v is not None]
    if len(vals) < 6:
        return False
    nonzero = [v for v in vals if v > 0]
    if len(nonzero) >= 6:
        # constant floor: the most common value covers the bulk of the series
        most = max(set(nonzero), key=nonzero.count)
        if most > 0 and nonzero.count(most) / len(nonzero) >= 0.7:
            return True
    mx = max(vals)
    baseline = sorted(vals)[len(vals) // 2]  # median
    if mx > 0 and baseline >= 0 and mx >= 20 * (baseline + 1):
        return True
    return False


def build_axis_downloads(
    *,
    total_downloads: int | None = None,
    series: list | None = None,
    dependents_for_ratio: int = 0,
    versions: int = 0,
    cap: float = 5_000_000.0,
) -> AxisResult:
    """(A) Registry downloads + trend.

    ``series`` is a chronological list of per-period download counts (e.g. npm
    ``downloads/range`` daily points) used for momentum + curve-anomaly.
    """
    if total_downloads is None and not series:
        return AxisResult(axis="A", present=False)

    if total_downloads is None:
        total_downloads = int(sum(v for v in (series or []) if v))

    absolute = _log_normalize(total_downloads, cap)
    momentum = _slope_to_momentum(series or [])
    discounts: list = []

    # downloads / (dependents + versions) sanity ratio — extreme ratios
    # (huge downloads, ~0 dependents) discount the download component.
    denom = max(1, dependents_for_ratio + max(0, versions))
    ratio = total_downloads / denom
    if dependents_for_ratio >= 0 and ratio > _INTERNAL_DL_PER_DEP_SUSPICIOUS:
        over = min(ratio / _INTERNAL_DL_PER_DEP_SUSPICIOUS, 4.0)
        factor = 1.0 - min(
            _INTERNAL_DL_PER_DEP_MAX_DISCOUNT, 0.15 * over,
        )
        absolute *= factor
        discounts.append("downloads_per_dependent_ratio")

    if _detect_download_curve_anomaly(series or []):
        absolute *= (1.0 - _INTERNAL_CURVE_ANOMALY_DISCOUNT)
        momentum = min(momentum, 0.5)
        discounts.append("download_curve_anomaly")

    return AxisResult(
        axis="A",
        present=True,
        absolute=absolute,
        momentum=momentum,
        discounts=discounts,
        raw={
            "total_downloads": total_downloads,
            "series_len": len(series or []),
            "dependents_for_ratio": dependents_for_ratio,
            "versions": versions,
        },
    )


def build_axis_dependents(
    *,
    dependent_packages: int | None = None,
    dependent_repos: int | None = None,
    dependents_prev: int | None = None,
    cap: float = 40_000.0,
) -> AxisResult:
    """(B) Reverse-dependents — the hardest axis to game.

    ecosyste.ms ``dependent_packages_count`` / ``dependent_repos_count``,
    deps.dev dependents, GitHub "Used by N".
    """
    if dependent_packages is None and dependent_repos is None:
        return AxisResult(axis="B", present=False)

    pkgs = int(dependent_packages or 0)
    repos = int(dependent_repos or 0)
    # Weight package-dependents (published deps) above repo-dependents.
    weighted = pkgs * 2 + repos
    absolute = _log_normalize(weighted, cap)

    momentum = 0.5
    if dependents_prev is not None and dependents_prev >= 0:
        cur = pkgs + repos
        if dependents_prev == 0:
            momentum = 1.0 if cur > 0 else 0.5
        else:
            momentum = _slope_to_momentum(
                [dependents_prev, dependents_prev, cur, cur]
            )

    return AxisResult(
        axis="B",
        present=True,
        absolute=absolute,
        momentum=momentum,
        raw={
            "dependent_packages": pkgs,
            "dependent_repos": repos,
            "dependents_prev": dependents_prev,
        },
    )


def _fake_star_discount(
    total_stars: int,
    star_timestamps: list | None,
    suspect_accounts: int = 0,
) -> tuple:
    """Return (discount_factor, burst_share) for fake-star detection.

    Detects days where an anomalous share of stars land at once (bought-star
    bursts) and accounts flagged suspicious (new / low-follower samples).
    """
    if not star_timestamps or total_stars <= 0:
        base = 0.0
        if suspect_accounts > 0 and total_stars > 0:
            base = min(
                _INTERNAL_FAKE_STAR_MAX_DISCOUNT,
                suspect_accounts / total_stars,
            )
        return 1.0 - base, base

    # bucket by day
    buckets: dict = {}
    for ts in star_timestamps:
        try:
            day = str(ts)[:10]
        except Exception:
            continue
        buckets[day] = buckets.get(day, 0) + 1
    if not buckets:
        return 1.0, 0.0
    n = sum(buckets.values())
    biggest = max(buckets.values())
    # A single day holding >40% of sampled stars is a burst signal.
    burst_share = 0.0
    if biggest / n > 0.4 and n >= 10:
        burst_share = biggest / n
    if suspect_accounts > 0:
        burst_share = max(burst_share, min(1.0, suspect_accounts / n))
    discount = min(_INTERNAL_FAKE_STAR_MAX_DISCOUNT, burst_share)
    return 1.0 - discount, burst_share


def build_axis_stars(
    *,
    stars: int | None = None,
    stars_prev: int | None = None,
    star_timestamps: list | None = None,
    suspect_accounts: int = 0,
    forks: int = 0,
    cap: float = 20_000.0,
) -> AxisResult:
    """(C) Social stars + velocity + fake-star-burst detection."""
    if stars is None:
        return AxisResult(axis="C", present=False)

    stars = int(stars)
    absolute = _log_normalize(stars + forks, cap)
    factor, burst_share = _fake_star_discount(
        stars, star_timestamps, suspect_accounts,
    )
    discounts: list = []
    if factor < 1.0:
        absolute *= factor
        discounts.append("fake_star_burst")

    momentum = 0.5
    if stars_prev is not None and stars_prev >= 0:
        if stars_prev == 0:
            momentum = 1.0 if stars > 0 else 0.5
        else:
            momentum = _slope_to_momentum([stars_prev, stars_prev, stars, stars])
    # A burst also caps velocity credit.
    if burst_share > 0:
        momentum = min(momentum, 0.6)

    return AxisResult(
        axis="C",
        present=True,
        absolute=absolute,
        momentum=momentum,
        discounts=discounts,
        raw={
            "stars": stars,
            "stars_prev": stars_prev,
            "forks": forks,
            "star_sample": len(star_timestamps or []),
            "suspect_accounts": suspect_accounts,
            "burst_share": round(burst_share, 4),
        },
    )


def build_axis_first_party(
    *,
    unique_checkers: int = 0,
    badge_embed_domains: int = 0,
    verify_pulls: int = 0,
    graph_connections: int = 0,
    returning_watcher_ratio: float = 0.0,
    raw_checks: int = 0,
    cap: float = 500.0,
) -> tuple:
    """(D) First-party (ours, unfakeable) — returns (AxisResult, volume_factor).

    Scored on the UNIQUE estimate (HyperLogLog / set keyed by authed identity,
    fallback hashed IP+UA), NOT the inflatable raw ``checks`` INCR.  ``raw_checks``
    is retained as a vanity number only.

    The second return value is the weight-ramp factor (0.0-1.0): axis D reaches
    its full published weight only once we have observed enough first-party
    volume, so a cold-start tool isn't scored on 3 badge embeds.
    """
    volume = unique_checkers + badge_embed_domains + verify_pulls + graph_connections
    if volume <= 0 and returning_watcher_ratio <= 0:
        return AxisResult(axis="D", present=False, first_party=True), 0.0

    # Composite first-party absolute — verify-pulls + graph-connections are the
    # deepest proof of downstream reliance, weighted highest.
    checker_s = _log_normalize(unique_checkers, cap)
    domain_s = _log_normalize(badge_embed_domains, 60)
    verify_s = _log_normalize(verify_pulls, 100)
    graph_s = _log_normalize(graph_connections, 100)
    absolute = min(
        1.0,
        0.30 * checker_s
        + 0.20 * domain_s
        + 0.28 * verify_s
        + 0.22 * graph_s,
    )
    momentum = max(0.0, min(1.0, returning_watcher_ratio))

    volume_factor = min(1.0, volume / _INTERNAL_FIRST_PARTY_FULL_VOLUME)

    return (
        AxisResult(
            axis="D",
            present=True,
            absolute=absolute,
            momentum=momentum if returning_watcher_ratio > 0 else 0.5,
            first_party=True,
            raw={
                "unique_checkers": unique_checkers,
                "badge_embed_domains": badge_embed_domains,
                "verify_pulls": verify_pulls,
                "graph_connections": graph_connections,
                "returning_watcher_ratio": round(returning_watcher_ratio, 4),
                "raw_checks_vanity": raw_checks,
            },
        ),
        volume_factor,
    )


def build_axis_mcp_registry(
    *,
    smithery_downloads: int | None = None,
    smithery_stars: int | None = None,
    pulsemcp_stars: int | None = None,
    tool_call_count: int | None = None,
    marketplace_installs: int | None = None,
    cap: float = 100_000.0,
) -> AxisResult:
    """(E) MCP / agent-registry usage — Smithery / PulseMCP / marketplace.

    Already fetched by ``source_import`` fetchers, currently unused for scoring.
    """
    have = any(
        v is not None
        for v in (
            smithery_downloads,
            smithery_stars,
            pulsemcp_stars,
            tool_call_count,
            marketplace_installs,
        )
    )
    if not have:
        return AxisResult(axis="E", present=False)

    downloads = int(smithery_downloads or 0) + int(marketplace_installs or 0)
    calls = int(tool_call_count or 0)
    stars = max(int(smithery_stars or 0), int(pulsemcp_stars or 0))

    dl_s = _log_normalize(downloads, cap)
    call_s = _log_normalize(calls, cap)
    star_s = _log_normalize(stars, 5_000)
    absolute = min(1.0, 0.45 * dl_s + 0.35 * call_s + 0.20 * star_s)

    return AxisResult(
        axis="E",
        present=True,
        absolute=absolute,
        momentum=0.5,  # registries rarely expose trend; neutral
        raw={
            "smithery_downloads": smithery_downloads,
            "smithery_stars": smithery_stars,
            "pulsemcp_stars": pulsemcp_stars,
            "tool_call_count": tool_call_count,
            "marketplace_installs": marketplace_installs,
        },
    )


# ---------------------------------------------------------------------------
# OpenSSF Criticality Score reimplementation (§3.6) — importance anchor
# ---------------------------------------------------------------------------

# (weight, threshold, inverted) per openssf/criticality_score defaults.
# S = ( Σ αᵢ · min(Sᵢ, Tᵢ)/Tᵢ ) / Σ αᵢ    (inverted params use 1 - fraction)
_CRITICALITY_PARAMS = {
    "created_since_months": (1.0, 120.0, False),
    "updated_since_months": (-1.0, 120.0, True),
    "contributor_count": (2.0, 5000.0, False),
    "org_count": (1.0, 10.0, False),
    "commit_frequency": (1.0, 1000.0, False),
    "recent_releases_count": (0.5, 26.0, False),
    "closed_issues_count": (0.5, 5000.0, False),
    "updated_issues_count": (0.5, 5000.0, False),
    "comment_frequency": (1.0, 15.0, False),
    "dependents_count": (2.0, 500000.0, False),
}


def compute_criticality_score(signals: dict) -> tuple:
    """Reimplement OpenSSF Criticality Score. Returns (score, components).

    Recomputable, multi-factor importance number resistant to single-axis
    gaming.  Missing signals contribute 0 (never penalize absence).
    """
    weight_sum = sum(abs(w) for w, _, _ in _CRITICALITY_PARAMS.values())
    total = 0.0
    components: dict = {}
    for name, (weight, threshold, inverted) in _CRITICALITY_PARAMS.items():
        # Absence contributes nothing (never reward NOR penalize a missing
        # signal — an inverted param like updated_since must not award
        # "freshness" just because we have no data for it).
        if name not in signals or signals.get(name) is None:
            components[name] = 0.0
            continue
        val = float(signals.get(name) or 0)
        frac = min(val, threshold) / threshold if threshold else 0.0
        if inverted:
            frac = 1.0 - frac
        contribution = abs(weight) * frac
        total += contribution
        components[name] = round(frac, 4)
    score = total / weight_sum if weight_sum else 0.0
    return round(max(0.0, min(1.0, score)), 4), components


# ---------------------------------------------------------------------------
# Blend + anti-gaming gate
# ---------------------------------------------------------------------------

@dataclass
class AdoptionResult:
    score: float
    absolute_tier: float
    momentum: float
    tier: str
    badge: str  # "rising" | "established" | "insufficient_data"
    axes: list  # list[AxisResult]
    present_axes: list
    agreeing_axes: list
    criticality_score: float | None
    criticality_components: dict
    insufficient_data: bool
    computed_at: str
    notes: list = field(default_factory=list)

    def to_public_dict(self) -> dict:
        """Public view — publishes the formula & axis breakdown; REDACTS the
        first-party raw counts and never includes internal thresholds."""
        return {
            "schema_version": SCHEMA_VERSION,
            "adoption_score": round(self.score, 4),
            "adoption_score_100": round(self.score * 100),
            "tier": self.tier,
            "badge": self.badge,
            "absolute_tier": round(self.absolute_tier, 4),
            "momentum": round(self.momentum, 4),
            "criticality_score": self.criticality_score,
            "insufficient_data": self.insufficient_data,
            "present_axes": list(self.present_axes),
            "agreeing_axes": list(self.agreeing_axes),
            "axes": [a.to_dict(redact_first_party=True) for a in self.axes if a.present],
            "formula": {
                "adoption": "0.6*absolute_tier + 0.4*momentum",
                "axis_weights": PUBLISHED_AXIS_WEIGHTS,
            },
            "computed_at": self.computed_at,
            "notes": list(self.notes),
        }

    def to_internal_dict(self) -> dict:
        """Full internal view — includes first-party raw counts, for the signed
        (recomputable) evidence record only.  Never surface to the public UI."""
        d = self.to_public_dict()
        d["axes_full"] = [a.to_dict(redact_first_party=False) for a in self.axes]
        d["criticality_components"] = self.criticality_components
        return d


def _adoption_tier(score: float) -> str:
    s = score * 100
    if s >= 90:
        return "A+"
    if s >= 75:
        return "A"
    if s >= 55:
        return "B"
    if s >= 35:
        return "C"
    if s >= 15:
        return "D"
    return "F"


def compute_adoption(
    axes: list,
    *,
    first_party_volume_factor: float = 1.0,
    criticality_signals: dict | None = None,
    computed_at: str | None = None,
) -> AdoptionResult:
    """Blend the 5 axes into a single adoption score with anti-gaming gates.

    ``axes`` is a list of ``AxisResult`` (absent axes are ignored, never zeroed).
    ``first_party_volume_factor`` (0.0-1.0) ramps axis D's weight with our own
    observed volume.
    """
    computed_at = computed_at or datetime.now(timezone.utc).isoformat()
    present = [a for a in axes if a.present]
    notes: list = []

    if not present:
        return AdoptionResult(
            score=0.0, absolute_tier=0.0, momentum=0.0, tier="F",
            badge="insufficient_data", axes=axes, present_axes=[],
            agreeing_axes=[], criticality_score=None,
            criticality_components={}, insufficient_data=True,
            computed_at=computed_at,
            notes=["no adoption axes had data"],
        )

    # Effective per-axis weights: published base, renormalized over present
    # axes, with axis D ramped by our first-party volume.
    eff_weights: dict = {}
    for a in present:
        w = PUBLISHED_AXIS_WEIGHTS.get(a.axis, 0.0)
        if a.axis == "D":
            w *= max(0.0, min(1.0, first_party_volume_factor))
        eff_weights[a.axis] = w

    total_w = sum(eff_weights.values())
    if total_w <= 0:
        # only axis D present but ramped to ~0 → treat as insufficient
        total_w = sum(PUBLISHED_AXIS_WEIGHTS.get(a.axis, 0.0) for a in present)
        eff_weights = {a.axis: PUBLISHED_AXIS_WEIGHTS.get(a.axis, 0.0) for a in present}

    # Normalize + apply the ≤35% single-source cap (INTERNAL threshold).
    # The cap is applied WITHOUT renormalizing — renormalizing would re-inflate
    # the capped axis and defeat the purpose. Dropping the excess mass means a
    # tool that spikes on one source alone can never carry the whole score, and
    # the very top scores require breadth (≥3 balanced axes), by design.
    norm = {k: (v / total_w if total_w else 0.0) for k, v in eff_weights.items()}
    capped = False
    if len(present) > 1:
        for k in list(norm):
            if norm[k] > _INTERNAL_MAX_SINGLE_SOURCE_SHARE:
                norm[k] = _INTERNAL_MAX_SINGLE_SOURCE_SHARE
                capped = True
    if capped:
        notes.append("single_source_cap_applied")

    absolute_tier = sum(norm[a.axis] * a.absolute for a in present)
    momentum = sum(norm[a.axis] * a.momentum for a in present)

    # ≥2-axis agreement gate for top tiers.
    agreeing = [
        a.axis for a in present
        if a.absolute >= _INTERNAL_AGREEMENT_ABSOLUTE
    ]

    score = ABSOLUTE_WEIGHT * absolute_tier + MOMENTUM_WEIGHT * momentum

    if len(agreeing) < _INTERNAL_MIN_AXES_FOR_TOP_TIER:
        if score > _INTERNAL_SINGLE_AXIS_CEILING:
            score = _INTERNAL_SINGLE_AXIS_CEILING
            notes.append("top_tier_gated_needs_2_axis_agreement")

    insufficient = len(present) < _INTERNAL_MIN_AXES_FOR_CONFIDENCE

    # rising vs established
    if insufficient:
        badge = "insufficient_data"
    elif momentum >= absolute_tier + _INTERNAL_RISING_MARGIN:
        badge = "rising"
    else:
        badge = "established"

    crit_score: float | None = None
    crit_components: dict = {}
    if criticality_signals:
        crit_score, crit_components = compute_criticality_score(criticality_signals)

    return AdoptionResult(
        score=round(max(0.0, min(1.0, score)), 4),
        absolute_tier=round(absolute_tier, 4),
        momentum=round(momentum, 4),
        tier=_adoption_tier(score),
        badge=badge,
        axes=axes,
        present_axes=[a.axis for a in present],
        agreeing_axes=agreeing,
        criticality_score=crit_score,
        criticality_components=crit_components,
        insufficient_data=insufficient,
        computed_at=computed_at,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Signed, recomputable adoption evidence record (§3.7)
# ---------------------------------------------------------------------------

def build_evidence_record(
    target: dict,
    result: AdoptionResult,
    raw_inputs: dict,
) -> dict:
    """Assemble the recomputable adoption evidence record.

    Snapshots every raw input (source + fetch timestamp) so the adoption number
    is offline-recomputable exactly like the trust grade.  First-party raw
    counts live in ``adoption.axes_full`` (internal) here; the public projection
    is ``result.to_public_dict()``.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_anchor": "evidence-anchor-adoption-v0",
        "target": target,
        "computed_at": result.computed_at,
        "adoption": result.to_internal_dict(),
        "raw_inputs": raw_inputs,
        "formula": {
            "adoption": "0.6*absolute_tier + 0.4*momentum",
            "absolute_normalization": "log-normalized per axis",
            "axis_weights": PUBLISHED_AXIS_WEIGHTS,
        },
    }


def sign_evidence_record(record: dict) -> str | None:
    """Sign the adoption evidence record into a compact JWS (best-effort).

    Reuses the platform Ed25519 signing path so the adoption number carries the
    same offline-verifiable proof as the trust grade.  Returns None on failure
    (fail-open — an unsigned record is still a valid, recomputable record).
    """
    try:
        from src.signing import canonicalize, create_jws

        return create_jws(canonicalize(record))
    except Exception:
        logger.warning("adoption evidence signing failed", exc_info=True)
        return None
