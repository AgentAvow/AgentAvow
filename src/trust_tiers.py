"""The six trust tiers — ONE source of truth for every surface.

A 0-100 trust score maps to a tier. The API exposes the lowercase ``trust_tier``
value (``verified`` … ``blocked``) together with the recommended execution posture
(requests/min, token budget, confirmation). Every display surface — badges, cards,
OG images, the local CLI, the MCP app view, the GitHub Action comment, the watch
emails, and the docs — shows the same tier word, at the same floor, in the same
colour. The frontend twin is ``getTrustTier`` in
``web/src/components/trust/gradeSystem.ts``; the two tables are byte-identical.

Floors: verified >= 96, trusted >= 81, standard >= 51, minimal >= 31,
restricted >= 11, blocked >= 0. The Claude Code plugin gate
(``plugins/agentavow-trust/scripts/agentavow_pretool_gate.py`` ``TIER_FLOORS``) and
``github-action/scan.sh`` carry the same numbers; ``tests/test_trust_tiers.py``
asserts they agree.

The tier is DETAIL, not the headline (Kenne, 2026-10-07). Every surface leads with one
of three phrases — "Safe to connect" / "Review before you connect" / "Do not connect"
(short labels Safe / Review / Blocked) — chosen by ``src.scanner.verdict.decide`` from
what was found, not from the score's tier. The phrase table is ``DECISIONS`` below; its
TS twin is ``DECISIONS`` in ``gradeSystem.ts``. Certified is a separate axis and rides
beside the phrase ("Safe to connect · Certified").
"""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class TrustTier:
    """One tier of the six-band trust scale."""

    value: str          # API value — lowercase, as `trust_tier` is emitted
    display: str        # display word — capitalised
    floor: int          # minimum 0-100 score for this tier
    color: str          # vivid hex — bars / rings / badges on dark grounds
    color_light: str    # darkened hex — number / word on light grounds
    posture: str        # recommended execution posture, one line
    requests_per_minute: int | None   # None = unlimited
    max_tokens_per_call: int | None   # None = unlimited
    require_user_confirmation: bool


# Highest tier first — the first floor the score clears wins. Hues run green -> red:
# the deeper green is Verified; Trusted / Standard / Minimal / Restricted / Blocked
# keep the green / light-green / amber / orange / red of the previous five-band scale.
# No tier carries a phrase: the headline phrase comes from ``DECISIONS`` (below).
TIERS: tuple[TrustTier, ...] = (
    TrustTier("verified",   "Verified",   96, "#16A34A", "#166534",
              "Connect normally · no limits", None, None, False),
    TrustTier("trusted",    "Trusted",    81, "#22C55E", "#15803D",
              "Auto-approve within budget", 60, 8192, False),
    TrustTier("standard",   "Standard",   51, "#5BBF3A", "#3F7D1F",
              "Standard rate + token limits", 30, 4096, False),
    TrustTier("minimal",    "Minimal",    31, "#F59E0B", "#B45309",
              "Confirm on sensitive calls", 15, 2048, True),
    TrustTier("restricted", "Restricted", 11, "#F97316", "#C2410C",
              "Gated · manual approval", 5, 1024, True),
    TrustTier("blocked",    "Blocked",    0,  "#EF4444", "#B91C1C",
              "Do not connect", 0, 0, True),
)

@dataclass(frozen=True)
class DecisionPhrase:
    """One of the three headline phrases."""

    value: str          # the machine ``decision`` value
    phrase: str         # the headline
    label: str          # the short label (badges, chips)
    color: str          # vivid hex — on dark grounds
    color_light: str    # darkened hex — on light grounds


# THE phrase table — one source for every Python surface. Order: safe, review, block.
DECISIONS: tuple[DecisionPhrase, ...] = (
    DecisionPhrase("safe", "Safe to connect", "Safe", "#22C55E", "#15803D"),
    DecisionPhrase("review", "Review before you connect", "Review", "#F59E0B", "#B45309"),
    DecisionPhrase("do_not_connect", "Do not connect", "Blocked", "#EF4444", "#B91C1C"),
)
DECISION_BY_VALUE: dict[str, DecisionPhrase] = {d.value: d for d in DECISIONS}

SAFE_PHRASE = DECISIONS[0].phrase
REVIEW_PHRASE = DECISIONS[1].phrase
DO_NOT_CONNECT_PHRASE = DECISIONS[2].phrase
CERTIFIED_SUFFIX = " · Certified"

# The legacy tuple shape ``(min_score, tier_name, requests_per_min, max_tokens,
# require_confirmation)`` with -1 for unlimited — what public_scan_router's
# TRUST_TIERS has always been.
TRUST_TIERS: list[tuple[int, str, int, int, bool]] = [
    (
        t.floor, t.value,
        -1 if t.requests_per_minute is None else t.requests_per_minute,
        -1 if t.max_tokens_per_call is None else t.max_tokens_per_call,
        t.require_user_confirmation,
    )
    for t in TIERS
]

# value -> floor, the shape the Claude Code plugin gate and tool_gate use.
TIER_FLOORS: dict[str, int] = {t.value: t.floor for t in TIERS}

TIER_BY_VALUE: dict[str, TrustTier] = {t.value: t for t in TIERS}


def tier_for_score(score: int | float | None) -> TrustTier:
    """The tier a 0-100 score lands in. None / non-numeric / negative -> blocked."""
    try:
        s = int(score or 0)
    except (TypeError, ValueError):
        s = 0
    for t in TIERS:
        if s >= t.floor:
            return t
    return TIERS[-1]


def trust_tier_value(score: int | float | None) -> str:
    """The lowercase API value (``verified`` … ``blocked``)."""
    return tier_for_score(score).value


def trust_word(score: int | float | None) -> str:
    """The capitalised display word (``Verified`` … ``Blocked``)."""
    return tier_for_score(score).display


def trust_color(score: int | float | None, light: bool = False) -> str:
    """The tier hex colour; ``light`` returns the darkened set for light grounds."""
    t = tier_for_score(score)
    return t.color_light if light else t.color


def trust_posture(score: int | float | None) -> str:
    """The one-line recommended execution posture."""
    return tier_for_score(score).posture


def _decision_value(decision: object) -> str:
    """A decision value from a value string, a ``Decision``, a scan dict (decided here)
    or a bare score (decided from the score alone: under 51 reads review)."""
    from src.scanner.verdict import decide
    if isinstance(decision, str) and decision in DECISION_BY_VALUE:
        return decision
    v = getattr(decision, "decision", None)
    if isinstance(v, str) and v in DECISION_BY_VALUE:
        return v
    if isinstance(decision, dict):
        d = decision.get("decision")
        if isinstance(d, str) and d in DECISION_BY_VALUE:
            return d
        return decide(decision).decision
    return decide({"trust_score": decision}).decision


def decision_for(decision: object) -> DecisionPhrase:
    """The phrase row for a decision value / ``Decision`` / scan dict / score."""
    return DECISION_BY_VALUE[_decision_value(decision)]


def verdict_phrase(decision: object) -> str:
    """The headline phrase: "Safe to connect" / "Review before you connect" /
    "Do not connect". Pass the ``decision`` value, a ``Decision``, or the scan dict
    (an API response that already carries ``decision`` is read, not re-decided)."""
    return decision_for(decision).phrase


def decision_label(decision: object) -> str:
    """The short label: Safe / Review / Blocked."""
    return decision_for(decision).label


def decision_color(decision: object, light: bool = False) -> str:
    """The phrase colour (green / amber / red)."""
    d = decision_for(decision)
    return d.color_light if light else d.color


def is_certified(data: dict | None) -> bool:
    """Whether a scan carries the Certified mark (the full conjunctive gate)."""
    c = (data or {}).get("certified") if isinstance(data, dict) else None
    return bool(isinstance(c, dict) and c.get("eligible") is True)


def headline(decision: object, certified: bool = False) -> str:
    """The phrase, with " · Certified" when the tool carries the mark."""
    return verdict_phrase(decision) + (CERTIFIED_SUFFIX if certified else "")


def recommended_limits(score: int | float | None) -> dict:
    """The ``recommended_limits`` block the public scan API emits."""
    t = tier_for_score(score)
    return {
        "requests_per_minute": t.requests_per_minute,
        "max_tokens_per_call": t.max_tokens_per_call,
        "require_user_confirmation": t.require_user_confirmation,
    }


def tiers_js_table() -> str:
    """The tier table as a JS array literal ``[[display, floor, color, posture], …]``
    for inline scripts (the MCP app view) that cannot import this module."""
    return json.dumps([[t.display, t.floor, t.color, t.posture] for t in TIERS],
                      separators=(",", ":"), ensure_ascii=False)
