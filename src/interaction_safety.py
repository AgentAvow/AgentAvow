"""Shared per-interaction-type trust thresholds — ONE source of truth for
"is it safe to <delegate / trade / collaborate / follow / …> with this agent?".

The two MCP servers and the A2A protocol layer each carried their own threshold map, and
the stdio MCP ignored the interaction type entirely (flat cutoff) — so the same agent +
interaction could get opposite answers (a score of 55 on a `follow` was "safe" on the
remote MCP but "caution" on the stdio one). This module ends that: every surface reads the
same numbers.

Thresholds are the minimum 0-100 trust score to initiate each interaction type — riskier
interactions require higher trust. Values preserve the previous remote-MCP and A2A maps
exactly (the stdio server is the only surface whose behaviour changes, to match them).
"""
from __future__ import annotations

INTERACTION_THRESHOLDS: dict[str, int] = {
    "discover": 0,               # open — no trust required
    "follow": 10,                # low-risk social signal
    "capability_exchange": 10,   # sharing capabilities is low-risk
    "collaborate": 40,           # lower-risk joint work
    "negotiate": 50,             # moderate
    "trade": 50,                 # general exchange
    "delegate": 60,              # handing over a task needs high trust
    "data_transfer": 70,         # sharing data needs high trust
    "financial": 80,             # money movement needs the highest trust
}
_DEFAULT = 60  # unknown interaction type → treat at delegate level (conservative)


def threshold_for(interaction_type: str) -> int:
    return INTERACTION_THRESHOLDS.get((interaction_type or "").strip().lower(), _DEFAULT)


def interaction_recommendation(score_0_100: int | float | None, interaction_type: str) -> dict:
    """Return {interaction_type, threshold, safe, recommendation} for a 0-100 score."""
    it = (interaction_type or "delegate").strip().lower()
    thr = threshold_for(it)
    try:
        s = int(score_0_100 or 0)
    except (TypeError, ValueError):
        s = 0
    safe = s >= thr
    return {
        "interaction_type": it,
        "threshold": thr,
        "safe": safe,
        "recommendation": "proceed" if safe else "caution",
    }
