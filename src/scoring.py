"""Shared score→letter-grade bands — ONE source of truth.

Every surface that turns a 0-100 trust score into an A+..F letter grade (public scan,
badges, OG cards, trust gateway, catalog, watch/drift emails) must use this, so the same
score always shows the same grade. The bands were hand-duplicated across ~8 surfaces with
no shared constant, and the watch-email copy had drifted to different cutoffs — an 85 read
"A" on the site but "B" in the email that linked to it. This module ends that.

Canonical bands (match web/src/rebrand/lib/gradeSystem.ts):
    A+ >= 96 · A >= 81 · B >= 61 · C >= 41 · D >= 21 · F otherwise.
"""
from __future__ import annotations

_BANDS: tuple[tuple[int, str], ...] = ((96, "A+"), (81, "A"), (61, "B"), (41, "C"), (21, "D"))

# Grade → display colour (hex). Used by surfaces that colour the grade (e.g. watch emails).
GRADE_COLORS: dict[str, str] = {
    "A+": "#22c55e", "A": "#22c55e", "B": "#3b82f6",
    "C": "#eab308", "D": "#f97316", "F": "#ef4444",
}


def grade_from_score(score: int | float | None) -> str:
    """Canonical 0-100 → letter grade. None / negative / non-numeric → 'F'."""
    try:
        s = int(score or 0)
    except (TypeError, ValueError):
        s = 0
    for floor, grade in _BANDS:
        if s >= floor:
            return grade
    return "F"


def grade_color(grade: str) -> str:
    """Display colour for a letter grade."""
    return GRADE_COLORS.get(grade, "#94a3b8")
