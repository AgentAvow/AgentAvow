"""Shared badge styling primitives — one source of truth for the shields-style
trust badges.

Every shields-style renderer (the public-scan `/badge`, the entity `/badges/trust`,
and the legacy `/badges/embed`) imports width, colour, font, and the Certified
gradient from here, so badges that share a README line up and match. The richer
card / OG surfaces are separate objects and keep their system-ui type by design.

The 0-100 tier word and colour come from ``src.trust_tiers`` (the six API tiers:
verified / trusted / standard / minimal / restricted / blocked), byte-identical to
the frontend `getTrustTier` (`web/src/components/trust/gradeSystem.ts`) — do not
fork either.
"""
from __future__ import annotations

from src.trust_tiers import trust_color, trust_word

__all__ = [
    "BADGE_FONT", "BADGE_HEIGHT", "CERT_GRADIENT", "cert_gradient_def",
    "trust_color", "trust_word", "verdana_width",
]

# The earned-tier gradient (the on-site CertifiedMark teal→magenta). Single source
# for every certified badge/card/OG surface.
CERT_GRADIENT = ("#2dd4bf", "#e879f9")

# Shields-style badges standardize on Verdana — the width table below is measured
# for it, so metrics only line up with this face.
BADGE_FONT = "Verdana,Geneva,DejaVu Sans,sans-serif"

BADGE_HEIGHT = 20


# ---------------------------------------------------------------------------
# Verdana 11px char widths (px) — measured from shields.io's width table.
# The one width function every shields-style renderer uses so badges align.
# ---------------------------------------------------------------------------
_VERDANA_WIDTHS: dict[str, float] = {
    " ": 3.58, "!": 3.94, '"': 5.06, "#": 7.78, "$": 6.36, "%": 8.89,
    "&": 7.52, "'": 2.81, "(": 4.33, ")": 4.33, "*": 6.36, "+": 7.78,
    ",": 3.58, "-": 4.33, ".": 3.58, "/": 4.58, "0": 6.36, "1": 6.36,
    "2": 6.36, "3": 6.36, "4": 6.36, "5": 6.36, "6": 6.36, "7": 6.36,
    "8": 6.36, "9": 6.36, ":": 4.33, ";": 4.33, "<": 7.78, "=": 7.78,
    ">": 7.78, "?": 5.56, "@": 10.0, "A": 7.17, "B": 6.89, "C": 6.67,
    "D": 7.72, "E": 6.22, "F": 5.67, "G": 7.72, "H": 7.72, "I": 4.33,
    "J": 4.67, "K": 7.0, "L": 5.83, "M": 8.83, "N": 7.61, "O": 7.78,
    "P": 6.06, "Q": 7.78, "R": 6.89, "S": 6.67, "T": 6.11, "U": 7.39,
    "V": 7.17, "W": 10.17, "X": 6.33, "Y": 6.11, "Z": 6.56,
    "a": 5.94, "b": 6.39, "c": 5.17, "d": 6.39, "e": 5.94, "f": 3.83,
    "g": 6.39, "h": 6.50, "i": 2.94, "j": 3.61, "k": 6.0, "l": 2.94,
    "m": 9.78, "n": 6.50, "o": 6.28, "p": 6.39, "q": 6.39, "r": 4.50,
    "s": 5.0, "t": 4.17, "u": 6.50, "v": 5.72, "w": 8.22, "x": 5.44,
    "y": 5.72, "z": 5.0,
}
_DEFAULT_CHAR_WIDTH = 6.5


def verdana_width(text: str) -> float:
    """Measure text width in px using Verdana 11px metrics."""
    return sum(_VERDANA_WIDTHS.get(ch, _DEFAULT_CHAR_WIDTH) for ch in text)


def cert_gradient_def(gid: str = "agcert") -> str:
    """The ``<linearGradient>`` def for the Certified (teal→magenta) fill."""
    return (
        f'<linearGradient id="{gid}" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0" stop-color="{CERT_GRADIENT[0]}"/>'
        f'<stop offset="1" stop-color="{CERT_GRADIENT[1]}"/>'
        f'</linearGradient>'
    )
