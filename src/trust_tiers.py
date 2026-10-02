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
