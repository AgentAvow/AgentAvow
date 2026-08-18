"""Live dual-mark card SVG — the always-current, linkable image of a tool's scores.

Renders the condensed AgentAvow card from the mark spec: branded header + coordinate,
the trust segmented power bar (green->red by tier) and the adoption VU needle
(teal->magenta, fills-to-level). Served from a URL so it can never go stale — the
hosted equivalent of the share card, embeddable anywhere an <img> works.
"""
from __future__ import annotations

import math

from src.api.badge_style import trust_color

# ── palette ─────────────────────────────────────────────────────────────────
# One self-contained (dark) card — it carries its own background, so it reads on
# any page ground. No per-viewer theming (a hosted <img> can't see the page theme;
# g1/g2 are the shared CERT_GRADIENT teal→magenta).
_DARK = {
    "bg": "#0a0e18", "panel_line": "#243458", "line_soft": "#1a273f",
    "text": "#eef2fb", "muted": "#93a1c0", "faint": "#63728f",
    "ndl": "#2dd4bf", "g1": "#2dd4bf", "g2": "#e879f9",
}


def _trust_word(score: int) -> str:
    return ("Trusted" if score >= 80 else "Standard" if score >= 60
            else "Caution" if score >= 40 else "Restricted" if score >= 20 else "Blocked")


def _adopt_word(pct: int) -> str:
    return ("Load-bearing" if pct >= 88 else "Widely Relied" if pct >= 65
            else "Established" if pct >= 40 else "Rising" if pct >= 15 else "New")


def _polar(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = deg * math.pi / 180
    return cx + r * math.cos(a), cy + r * math.sin(a)


def _arc(cx: float, cy: float, r: float, a0: float, a1: float) -> str:
    x0, y0 = _polar(cx, cy, r, a0)
    x1, y1 = _polar(cx, cy, r, a1)
    lg = 1 if (a1 - a0) > 180 else 0
    return f"M{x0:.1f} {y0:.1f} A{r} {r} 0 {lg} 1 {x1:.1f} {y1:.1f}"


def render_card_svg(
    *, coordinate: str, score: int | None, adoption_display: str | None,
    adoption_pct: int, adoption_tier: str | None,
) -> str:
    """Compose the condensed dual-mark card SVG (≈360×156). `score` None → 'not scanned'."""
    c = _DARK
    card_w, card_h = 360, 156

    has_score = score is not None
    s = int(score) if has_score else 0
    tcol = trust_color(s) if has_score else c["faint"]
    tword = _trust_word(s) if has_score else "—"

    # ── trust segmented bar (left) ───────────────────────────────────────────
    total, seg_w, seg_h, gap = 10, 12, 5, 2.5  # spec: 12×5px, gap 2.5
    lv = round(s / 10) if has_score else 0
    bar_x = 90
    bottom = 122
    cells = ""
    for i in range(total):
        y = bottom - i * (seg_h + gap) - seg_h
        fill = tcol if i < lv else c["line_soft"]
        cells += f'<rect x="{bar_x - seg_w / 2:.1f}" y="{y:.1f}" width="{seg_w}" height="{seg_h}" rx="1" fill="{fill}"/>'

    # ── adoption VU needle (right) ───────────────────────────────────────────
    has_ad = adoption_display is not None and adoption_pct > 0
    ncx, ncy, nr = 268, 122, 50
    a0, a1 = 180, 360
    ang = a0 + (adoption_pct / 100) * 180
    ndl = c["ndl"]
    ticks = ""
    for i in range(1, 10):
        ta = a0 + 180 * (i / 10)
        x0, y0 = _polar(ncx, ncy, nr - 4, ta)
        x1, y1 = _polar(ncx, ncy, nr - (9 if i == 5 else 7), ta)
        ticks += f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{x1:.1f}" y2="{y1:.1f}" stroke="{c["faint"]}" stroke-width="{1.2 if i == 5 else 0.8}"/>'
    nx, ny = _polar(ncx, ncy, nr - 11, ang)
    fill_arc = (f'<path d="{_arc(ncx, ncy, nr, a0, ang)}" fill="none" stroke="url(#gArc)" stroke-width="6"/>'
                if has_ad and ang > a0 + 1.5 else "")
    rest_arc = f'<path d="{_arc(ncx, ncy, nr, max(ang, a0 + 0.5), a1)}" fill="none" stroke="{c["line_soft"]}" stroke-width="6"/>'
    needle = (f'<line x1="{ncx}" y1="{ncy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{ndl}" stroke-width="2.6" stroke-linecap="round"/>'
              f'<circle cx="{ncx}" cy="{ncy}" r="4.5" fill="{ndl}"/>') if has_ad else \
        f'<circle cx="{ncx}" cy="{ncy}" r="4.5" fill="{c["faint"]}"/>'
    ad_num = adoption_display if has_ad else "New"
    ad_word = (adoption_tier or _adopt_word(adoption_pct)) if has_ad else "no signal yet"

    score_txt = f'{s}' if has_score else "?"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{card_w}" height="{card_h}" viewBox="0 0 {card_w} {card_h}" font-family="system-ui,-apple-system,Segoe UI,sans-serif">
  <defs>
    <linearGradient id="gBrand" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#2dd4bf"/><stop offset="1" stop-color="#e879f9"/></linearGradient>
    <linearGradient id="gArc" gradientUnits="userSpaceOnUse" x1="{ncx - nr}" y1="0" x2="{ncx + nr}" y2="0"><stop stop-color="{c['g1']}"/><stop offset="1" stop-color="{c['g2']}"/></linearGradient>
  </defs>
  <rect x="0.5" y="0.5" width="{card_w - 1}" height="{card_h - 1}" rx="14" fill="{c['bg']}" stroke="{c['panel_line']}"/>
  <!-- header -->
  <g transform="translate(20,15)">
    <circle cx="9" cy="9" r="8" fill="none" stroke="url(#gBrand)" stroke-width="1.6"/>
    <path d="M5.4 9.4l2.6 2.6 5.2-5.6" fill="none" stroke="url(#gBrand)" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="24" y="13" fill="{c['text']}" font-size="13" font-weight="700">AgentAvow</text>
    <circle cx="106" cy="9" r="3" fill="#2dd4bf"/>
  </g>
  <text x="{card_w - 20}" y="28" text-anchor="end" fill="{c['muted']}" font-size="12" font-family="ui-monospace,SF Mono,Menlo,monospace">{coordinate}</text>
  <!-- trust -->
  <text x="{bar_x}" y="44" text-anchor="middle" fill="{c['faint']}" font-size="8.5" font-weight="700" letter-spacing="1.4" font-family="ui-monospace,monospace">TRUST</text>
  {cells}
  <text x="{bar_x}" y="138" text-anchor="middle" fill="{tcol}" font-size="20" font-weight="800">{score_txt}<tspan fill="{c['faint']}" font-size="10" font-family="ui-monospace,monospace"> /100</tspan></text>
  <text x="{bar_x}" y="150" text-anchor="middle" fill="{tcol}" font-size="9.5" font-weight="700">{tword}</text>
  <!-- divider -->
  <line x1="180" y1="46" x2="180" y2="140" stroke="{c['line_soft']}"/>
  <!-- adoption -->
  <text x="{ncx}" y="44" text-anchor="middle" fill="{c['faint']}" font-size="8.5" font-weight="700" letter-spacing="1.4" font-family="ui-monospace,monospace">ADOPTION · REACH</text>
  {fill_arc}{rest_arc}{ticks}{needle}
  <text x="{ncx}" y="138" text-anchor="middle" fill="{c['text'] if has_ad else c['faint']}" font-size="21" font-weight="800">{ad_num}</text>
  <text x="{ncx}" y="150" text-anchor="middle" fill="{c['g2'] if has_ad else c['faint']}" font-size="9.5" font-weight="700">{ad_word}</text>
</svg>'''
