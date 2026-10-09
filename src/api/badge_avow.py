"""The AgentAvow badge design system — one look for the website embed and the README badge.

Two renderers share one vocabulary (the trust card the Claude and ChatGPT apps show,
``src.bridges.mcp_app_view``): the exact AgentAvow logo, the three-phrase answer, the
10-segment **trust bar** (``renderTrust``: tier colour, or the teal→magenta gradient
when Certified) and the semicircle **adoption VU gauge** (``renderAdopt``: a
teal→magenta arc filled to the adoption level, ticks, a teal needle). The gauge's arc
paths are precomputed here with the card's own ``P`` / ``ARC`` maths — no scripts.

* ``card``    — 360×230, the website embed (``widget.js`` / ``card.svg``) and an opt-in
  README image. Brand row, the full phrase, the coordinate, then an instrument panel
  of two matched columns: the trust bar with the score + tier word to its right, and
  the adoption VU gauge with the count + unit + level word to its right, on shared
  baselines. (``card-stacked`` keeps the 360×290 Claude-card stacked layout.)
* ``compact`` — 20px (shields height), the README badge. The logo, the answer, the
  trust bar laid flat with the score, then a small adoption gauge with the count.

Certified renders only on a Safe answer (never "Review · Certified"). GitHub proxies
README images through camo, so the SVG is self-contained: no scripts, no
``foreignObject``, no external fonts or images, no animation. ``theme=auto`` switches
with ``prefers-color-scheme`` inside the image (a ``<style>`` media query, which
``<img>`` SVGs honour); ``light`` / ``dark`` pin it.

Text widths are estimated from the Verdana table, then pinned with ``textLength`` +
``lengthAdjust="spacing"`` so the layout is exact whatever sans the viewer has.
"""
from __future__ import annotations

import math
import re
from html import escape

from src.api.badge_style import CERT_GRADIENT, verdana_width
from src.bridges.mcp_app_view import TRUST_CARD_HTML
from src.trust_tiers import decision_for, tier_for_score

__all__ = ["AVOW_STYLES", "AVOW_THEMES", "LOGO_INNER", "adoption_level",
           "adoption_pct_from_count", "render_avow_badge"]

AVOW_STYLES = ("card", "compact", "card-stacked")
AVOW_THEMES = ("auto", "light", "dark")

# The logo, byte-for-byte from the Claude / ChatGPT trust card (its 40-unit artwork:
# gradient defs + ring + check). Read from the card itself so the two can never drift.
_LOGO_RE = re.compile(r'<svg width="18" height="18" viewBox="0 0 40 40"[^>]*>(.*?)</svg>')
LOGO_INNER: str = _LOGO_RE.search(TRUST_CARD_HTML).group(1)  # type: ignore[union-attr]

_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"
_SANS_RATIO = 0.92  # Helvetica/Segoe run ~8% narrower than Verdana at the same size

# The trust card's palette (mcp_app_view :root tokens).
_PAL = {
    "dark": {"bg": "#0b0f17", "panel": "#0f1522", "fg": "#e6edf3", "muted": "#9aa7b6",
             "track": "#1e2733", "line": "#1e2733"},
    "light": {"bg": "#ffffff", "panel": "#f7f9fc", "fg": "#0b0f17", "muted": "#5b6673",
              "track": "#e5e9ef", "line": "#e1e6ee"},
}
_KEYS = ("bg", "panel", "fg", "muted", "track", "line")
_ICONS = {"safe": "✓", "review": "⚠", "do_not_connect": "⛔"}
_UNSCANNED = "#94A3B8"
_TEAL = CERT_GRADIENT[0]


def adoption_level(pct: int) -> str:
    """The adoption level word — the trust card's ``adoptTier``."""
    return ("Load-bearing" if pct >= 88 else "Widely relied" if pct >= 65
            else "Established" if pct >= 40 else "Rising" if pct >= 15 else "New")


_WIDE = "⛔⚠✓✔★"  # symbol glyphs render ~1.1em, wider than the table's default


def _w(text: str, size: float = 11, bold: bool = False) -> float:
    plain = "".join(ch for ch in text if ch not in _WIDE)
    w = verdana_width(plain) * (size / 11) * _SANS_RATIO
    w = w * 1.07 if bold else w
    return w + sum(1 for ch in text if ch in _WIDE) * size * 1.1


def _compact(n: int | None) -> str:
    if not n:
        return ""
    for div, suf in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if n >= div:
            return f"{n / div:.1f}".rstrip("0").rstrip(".") + suf
    return str(n)


def _rules(p: dict[str, str]) -> str:
    return "".join(f".f-{k}{{fill:{p[k]}}}.s-{k}{{stroke:{p[k]}}}" for k in _KEYS)


class _Paint:
    """Colour references for one theme. Pinned themes inline hex; ``auto`` adds CSS
    classes (dark by default, light under ``prefers-color-scheme: light``)."""

    def __init__(self, theme: str):
        self.auto = theme not in ("light", "dark")
        self.pal = _PAL["dark" if self.auto else theme]

    def fill(self, key: str) -> str:
        return f'fill="{self.pal[key]}"' + (f' class="f-{key}"' if self.auto else "")

    def stroke(self, key: str) -> str:
        return f'stroke="{self.pal[key]}"' + (f' class="s-{key}"' if self.auto else "")

    def css(self) -> str:
        if not self.auto:
            return ""
        return (_rules(_PAL["dark"]) + "@media (prefers-color-scheme:light){"
                + _rules(_PAL["light"]) + "}")


def _text(x: float, y: float, s: str, *, paint: str, size: float = 11, bold: bool = False,
          anchor: str = "start", width: float | None = None, font: str = _FONT,
          spacing: float = 0) -> str:
    """``paint`` is a full fill attribute string (``fill="…"`` [+ class])."""
    tl = f' textLength="{width:.1f}" lengthAdjust="spacing"' if width else ""
    ls = f' letter-spacing="{spacing}"' if spacing else ""
    wt = ' font-weight="700"' if bold else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family="{font}" font-size="{size}"{wt}{ls} '
            f'{paint} text-anchor="{anchor}"{tl}>{escape(s)}</text>')


def _hex(c: str) -> str:
    return f'fill="{c}"'


def _logo(x: float, y: float, size: float) -> str:
    return (f'<svg x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" viewBox="0 0 40 40" '
            f'fill="none">{LOGO_INNER}</svg>')


def _grad(gid: str, x1: float, y1: float, x2: float, y2: float) -> str:
    return (f'<linearGradient id="{gid}" gradientUnits="userSpaceOnUse" x1="{x1:.1f}" '
            f'y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}">'
            f'<stop offset="0" stop-color="{CERT_GRADIENT[0]}"/>'
            f'<stop offset="1" stop-color="{CERT_GRADIENT[1]}"/></linearGradient>')


def _svg(width: float, height: float, body: str, title: str, css: str = "") -> str:
    st = f"<style>{css}</style>" if css else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
            f'viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-label="{escape(title)}">'
            f'<title>{escape(title)}</title>{st}{body}</svg>')


def _lit(v: int | None) -> int:
    return 0 if v is None else max(0, min(10, round(v / 10)))


class _Facts:
    """Everything a badge shows, resolved once so both styles say the same thing."""

    def __init__(self, decision, score, certified, adoption, adoption_unit, adoption_pct,
                 coordinate, light):
        self.scored = score is not None
        self.score = max(0, min(100, int(score))) if self.scored else None
        d = decision_for(decision or self.score) if self.scored else None
        self.cert = bool(certified) and d is not None and d.value == "safe"
        self.phrase = d.phrase if d else "Not scanned yet"
        self.label = d.label if d else "not scanned"
        self.icon = _ICONS[d.value] if d else "·"
        self.color = (d.color_light if light else d.color) if d else _UNSCANNED
        tier = tier_for_score(self.score) if self.scored else None
        self.tier_word = tier.display if tier else "—"
        self.tier_color = tier.color if tier else _UNSCANNED
        self.adoption = int(adoption) if adoption else 0
        self.adoption_pct = max(0, min(100, int(adoption_pct or 0)))
        self.has_adoption = self.adoption > 0 or self.adoption_pct > 0
        self.adoption_text = _compact(self.adoption) if self.adoption else "New"
        self.adoption_unit = (adoption_unit or "").strip()
        self.adoption_word = (adoption_level(self.adoption_pct) if self.has_adoption
                              else "no signal yet")
        self.coordinate = coordinate

    def title(self) -> str:
        who = f"{self.coordinate} — " if self.coordinate else ""
        if not self.scored:
            return f"AgentAvow: {who}not scanned yet"
        cert = " · Certified" if self.cert else ""
        adopt = (f"{self.adoption_text} {self.adoption_unit}".strip()
                 if self.has_adoption else "new")
        return (f"AgentAvow: {who}{self.phrase}{cert} · trust {self.score}/100 "
                f"({self.tier_word}) · adoption {adopt}")



# ---------------------------------------------------------------------------
# the adoption VU gauge — a port of the trust card's renderAdopt / P / ARC
# ---------------------------------------------------------------------------
def _p(cx: float, cy: float, r: float, d: float) -> tuple[float, float]:
    a = d * math.pi / 180
    return cx + r * math.cos(a), cy + r * math.sin(a)


def _arc(cx: float, cy: float, r: float, a0: float, a1: float) -> str:
    s, e = _p(cx, cy, r, a0), _p(cx, cy, r, a1)
    lg = 1 if (a1 - a0) > 180 else 0
    return (f"M{s[0]:.1f} {s[1]:.1f} A{r:g} {r:g} 0 {lg} 1 {e[0]:.1f} {e[1]:.1f}")


def adoption_pct_from_count(count: int | None) -> int:
    """The card's ``adoptionPct``: log10(count+1)/9*100, capped at 100 (JS rounding)."""
    c = int(count or 0)
    return min(100, math.floor(math.log10(c + 1) / 9 * 100 + 0.5)) if c > 0 else 0


def _gauge(p: _Paint, pct: int, has: bool, *, gid: str, cx: float = 100, cy: float = 88,
           r: float = 74, arc_w: float = 8, needle_w: float = 3.4, hub: float = 5.5,
           ticks: bool = True, tick_out: float = 6, needle_in: float = 16,
           track_cap: bool = False) -> str:
    """The gauge's inner drawing (in its own coordinate space). Defaults are the card's
    ``viewBox="0 0 200 94"`` geometry; the heavier card dial and the compact badge
    pass their own. ``tick_out`` is how far inside the arc's centre line the ticks
    start (they clear the stroke); ``needle_in`` how far short of it the needle stops."""
    a0, a1 = 180.0, 360.0
    ang = a0 + pct / 100 * 180
    track = (f'<path d="{_arc(cx, cy, r, max(ang, a0 + 0.5), a1)}" fill="none" '
             f'{p.stroke("track")} stroke-width="{arc_w:g}"'
             + (' stroke-linecap="round"' if track_cap else "") + "/>")
    fill = ""
    if has and ang > a0 + 1.5:
        fill = (f'<path d="{_arc(cx, cy, r, a0, ang)}" fill="none" stroke="url(#{gid})" '
                f'stroke-width="{arc_w:g}" stroke-linecap="round"/>')
    # The card draws the fill then the track; with a heavy round-capped track the track
    # goes first so its cap never covers the end of the fill.
    out = [track, fill] if track_cap else [fill, track]
    if ticks:
        for i in range(9):
            mid = i + 1 == 5
            ta = a0 + 180 * ((i + 1) / 10)
            x0, y0 = _p(cx, cy, r - tick_out, ta)
            x1, y1 = _p(cx, cy, r - tick_out - (8 if mid else 4), ta)
            out.append(f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{x1:.1f}" y2="{y1:.1f}" '
                       f'{p.stroke("muted")} stroke-width="{1.6 if mid else 1}" '
                       f'opacity="0.4"/>')
    if has:
        nx, ny = _p(cx, cy, r - needle_in, ang)
        out.append(f'<line x1="{cx:g}" y1="{cy:g}" x2="{nx:.1f}" y2="{ny:.1f}" '
                   f'stroke="{_TEAL}" stroke-width="{needle_w:g}" stroke-linecap="round"/>')
        out.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{hub:g}" fill="{_TEAL}"/>')
    else:
        out.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{hub:g}" {p.fill("muted")} '
                   f'opacity="0.3"/>')
    return "".join(out)


def _gauge_grad(gid: str, x1: float, x2: float) -> str:
    return _grad(gid, x1, 0, x2, 0)


# ---------------------------------------------------------------------------
# card-stacked — the round-3 card (Claude-card columns stacked and centred). Kept
# reachable as ``style=card-stacked``; ``card`` (below) is the default.
# ---------------------------------------------------------------------------
def _card_stacked(f: _Facts, p: _Paint, brand: str) -> str:
    w, h = 360, 290
    out: list[str] = [
        f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="14" {p.fill("bg")}/>',
        f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="14" fill="none" '
        f'{p.stroke("line")}/>',
        f'<rect x="14" y="0" width="{w - 28}" height="3" rx="1.5" '
        f'fill="{"url(#gH)" if f.cert else f.color}"/>',
        _logo(18, 15, 18),
    ]
    bu = brand.upper()
    out.append(_text(43, 28.5, bu, paint=p.fill("muted"), size=10.5, bold=True,
                     width=_w(bu, 10.5, True) + len(bu) * 1.5, spacing=1.5))
    if f.cert:
        cw = _w("✓ CERTIFIED", 10.5, True) + 20
        cx = w - 18 - cw
        out.append(f'<rect x="{cx:.1f}" y="13" width="{cw:.1f}" height="20" rx="10" '
                   f'fill="url(#gP)"/>')
        out.append(_text(cx + cw / 2, 27, "✓ CERTIFIED", paint=_hex("#04201c"), size=10.5,
                         bold=True, anchor="middle", width=_w("✓ CERTIFIED", 10.5, True)))
    lead = f"{f.icon} {f.phrase}"
    out.append(_text(18, 58, lead, paint=_hex(f.color), size=16, bold=True,
                     width=min(_w(lead, 16, True), w - 36)))
    coord = f.coordinate if len(f.coordinate) <= 44 else f.coordinate[:43] + "…"
    if coord:
        out.append(_text(18, 78, coord, paint=p.fill("fg"), size=12, font=_MONO,
                         width=min(_w(coord, 12), w - 36)))
    # instrument panel (the card's .inst): trust bar | adoption gauge, side by side
    py, ph = 90, 166
    out.append(f'<rect x="14" y="{py}" width="{w - 28}" height="{ph}" rx="14" '
               f'{p.fill("panel")}/>')
    out.append(f'<rect x="14" y="{py}" width="{w - 28}" height="{ph}" rx="14" fill="none" '
               f'{p.stroke("line")}/>')
    out.append(f'<rect x="{w / 2:.1f}" y="{py + 12}" width="1" height="{ph - 24}" '
               f'{p.fill("line")}/>')
    tcx, acx = w / 4 + 7, 3 * w / 4 - 7
    for cx_, cap in ((tcx, "TRUST"), (acx, "ADOPTION")):
        out.append(_text(cx_, py + 22, cap, paint=p.fill("muted"), size=9.5, bold=True,
                         anchor="middle", width=_w(cap, 9.5, True) + len(cap) * 1.2,
                         spacing=1.2))
    # trust — renderTrust: 10 segments 15×6, gap 2.5, filled bottom-up
    seg_w, seg_h, gap = 15, 6, 2.5
    top = py + 31
    bottom = top + 10 * seg_h + 9 * gap
    lit = 10 if f.cert else _lit(f.score)
    tone = "url(#gT)" if f.cert else f.tier_color
    for i in range(10):
        y = bottom - i * (seg_h + gap) - seg_h
        fill = f'fill="{tone}"' if (f.scored and i < lit) else p.fill("track")
        out.append(f'<rect x="{tcx - seg_w / 2:.1f}" y="{y:.1f}" width="{seg_w}" '
                   f'height="{seg_h}" rx="1" {fill}/>')
    num_y = bottom + 30
    if f.scored:
        num_col = _TEAL if f.cert else f.tier_color
        out.append(f'<text x="{tcx:.1f}" y="{num_y:.1f}" font-family="{_FONT}" '
                   f'font-size="23" font-weight="800" fill="{num_col}" text-anchor="middle">'
                   f'{f.score}<tspan font-family="{_MONO}" font-size="10" font-weight="400" '
                   f'{p.fill("muted")} dx="2">/100</tspan></text>')
        word = "CERTIFIED" if f.cert else f.tier_word
        wpaint = 'fill="url(#gN)"' if f.cert else _hex(f.tier_color)
        out.append(_text(tcx, num_y + 16, word, paint=wpaint, size=10.5, bold=True,
                         anchor="middle", width=_w(word, 10.5, True)))
    else:
        out.append(_text(tcx, num_y, "—", paint=p.fill("muted"), size=23, bold=True,
                         anchor="middle"))
        out.append(_text(tcx, num_y + 16, "not scanned", paint=p.fill("muted"), size=10.5,
                         bold=True, anchor="middle"))
    # adoption — renderAdopt: the VU gauge (svg width 122, viewBox 0 0 200 94)
    gw = 122
    gh = gw * 94 / 200
    gx, gy = acx - gw / 2, top + 6
    out.append(f'<svg x="{gx:.1f}" y="{gy:.1f}" width="{gw}" height="{gh:.1f}" '
               f'viewBox="0 0 200 94" overflow="visible">'
               + _gauge(p, f.adoption_pct, f.has_adoption, gid="agrad") + "</svg>")
    anum_y = gy + gh + 30
    if f.has_adoption:
        unit = (f'<tspan font-family="{_MONO}" font-size="10" font-weight="400" '
                f'{p.fill("muted")} dx="2">{escape(f.adoption_unit)}</tspan>'
                if f.adoption_unit else "")
        out.append(f'<text x="{acx:.1f}" y="{anum_y:.1f}" font-family="{_FONT}" '
                   f'font-size="23" font-weight="800" {p.fill("fg")} text-anchor="middle">'
                   f'{escape(f.adoption_text)}{unit}</text>')
        out.append(_text(acx, anum_y + 16, f.adoption_word, paint='fill="url(#gW)"',
                         size=10.5, bold=True, anchor="middle",
                         width=_w(f.adoption_word, 10.5, True)))
    else:
        out.append(_text(acx, anum_y, "New", paint=p.fill("muted"), size=23, bold=True,
                         anchor="middle"))
        out.append(_text(acx, anum_y + 16, "no signal yet", paint=p.fill("muted"),
                         size=10.5, bold=True, anchor="middle"))
    foot = "signed ✔ Ed25519 · verify offline" if f.scored else "scan it free at agentavow.com"
    out.append(_text(18, h - 14, foot, paint=p.fill("muted"), size=10.5, width=_w(foot, 10.5)))
    if f.scored:
        out.append(_text(w - 18, h - 14, "agentavow.com", paint=p.fill("muted"), size=10.5,
                         anchor="end", width=_w("agentavow.com", 10.5)))
    ww = _w(f.adoption_word, 10.5, True)
    tw = _w("CERTIFIED", 10.5, True)
    defs = (_grad("gH", 14, 0, w - 14, 0) + _grad("gP", w - 140, 0, w - 18, 0)
            + _grad("gT", 0, bottom, 0, top) + _gauge_grad("agrad", 26, 174)
            + _grad("gN", tcx - tw / 2, 0, tcx + tw / 2, 0)
            + _grad("gW", acx - ww / 2, 0, acx + ww / 2, 0))
    return _svg(w, h, f"<defs>{defs}</defs>" + "".join(out), f.title(), p.css())


def _card_head(f: _Facts, p: _Paint, brand: str, w: int, h: int) -> list[str]:
    """Frame, accent rule, logo + brand, Certified pill, the answer and the coordinate."""
    out: list[str] = [
        f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="14" {p.fill("bg")}/>',
        f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="14" fill="none" '
        f'{p.stroke("line")}/>',
        f'<rect x="14" y="0" width="{w - 28}" height="3" rx="1.5" '
        f'fill="{"url(#gH)" if f.cert else f.color}"/>',
        _logo(18, 15, 18),
    ]
    bu = brand.upper()
    out.append(_text(43, 28.5, bu, paint=p.fill("muted"), size=10.5, bold=True,
                     width=_w(bu, 10.5, True) + len(bu) * 1.5, spacing=1.5))
    if f.cert:
        cw = _w("✓ CERTIFIED", 10.5, True) + 20
        cx = w - 18 - cw
        out.append(f'<rect x="{cx:.1f}" y="13" width="{cw:.1f}" height="20" rx="10" '
                   f'fill="url(#gP)"/>')
        out.append(_text(cx + cw / 2, 27, "✓ CERTIFIED", paint=_hex("#04201c"), size=10.5,
                         bold=True, anchor="middle", width=_w("✓ CERTIFIED", 10.5, True)))
    lead = f"{f.icon} {f.phrase}"
    out.append(_text(18, 58, lead, paint=_hex(f.color), size=16, bold=True,
                     width=min(_w(lead, 16, True), w - 36)))
    coord = f.coordinate if len(f.coordinate) <= 44 else f.coordinate[:43] + "…"
    if coord:
        out.append(_text(18, 78, coord, paint=p.fill("fg"), size=12, font=_MONO,
                         width=min(_w(coord, 12), w - 36)))
    return out


# ---------------------------------------------------------------------------
# card — the website embed (default). Trust: the segmented bar with the score and
# tier word to its right. Adoption: the Claude-card dial laid out the same way, the
# count + unit and the level word to its right. One shared set of baselines.
# Trust is the primary signal: its column is at least as wide as adoption's and its
# numeral is the largest on the card; the adoption count and word sit a step down.
# ---------------------------------------------------------------------------
CARD_W, CARD_H = 360, 230
_PANEL_Y, _PANEL_H = 90, 108
_NUM_Y, _WORD_Y, _CAP_Y = 64, 84, 25  # offsets from the panel top, shared by both columns


def _card(f: _Facts, p: _Paint, brand: str) -> str:
    w, h = CARD_W, CARD_H
    out = _card_head(f, p, brand, w, h)
    py, ph = _PANEL_Y, _PANEL_H
    split = 180  # two equal columns (14-180 | 180-346): trust never gets the narrow one
    out.append(f'<rect x="14" y="{py}" width="{w - 28}" height="{ph}" rx="12" '
               f'{p.fill("panel")}/>')
    out.append(f'<rect x="14" y="{py}" width="{w - 28}" height="{ph}" rx="12" fill="none" '
               f'{p.stroke("line")}/>')
    out.append(f'<rect x="{split}" y="{py + 14}" width="1" height="{ph - 28}" '
               f'{p.fill("line")}/>')
    # trust — 10 segments 15×5.5, gap 2.4, filled bottom-up; text block to the right
    seg_w, seg_h, gap = 15, 5.5, 2.4
    bar_h = 10 * seg_h + 9 * gap
    bar_x = 36.0
    bar_bottom = py + (ph + bar_h) / 2
    tx = bar_x + seg_w + 16
    lit = 10 if f.cert else _lit(f.score)
    tone = "url(#gT)" if f.cert else f.tier_color
    for i in range(10):
        y = bar_bottom - i * (seg_h + gap) - seg_h
        fill = f'fill="{tone}"' if (f.scored and i < lit) else p.fill("track")
        out.append(f'<rect x="{bar_x:.1f}" y="{y:.1f}" width="{seg_w}" height="{seg_h}" '
                   f'rx="1" {fill}/>')
    # adoption — the dial (viewBox 0 0 200 94) at 60px, hub on the panel's mid-line
    gw = 60.0
    gh = gw * 94 / 200
    gx = split + 12
    gy = py + ph / 2 + 10 - gh * 88 / 94
    out.append(f'<svg x="{gx:.1f}" y="{gy:.1f}" width="{gw:g}" height="{gh:.1f}" '
               f'viewBox="0 0 200 94" overflow="visible">'
               + _gauge(p, f.adoption_pct, f.has_adoption, gid="agrad", r=72, arc_w=16,
                        needle_w=6.5, hub=9.5, tick_out=13, needle_in=22, track_cap=True)
               + "</svg>")
    ax = gx + gw + 9
    avail = w - 14 - 6 - ax
    for x_, cap in ((tx, "TRUST"), (ax, "ADOPTION")):
        out.append(_text(x_, py + _CAP_Y, cap, paint=p.fill("muted"), size=9, bold=True,
                         width=_w(cap, 9, True) + len(cap) * 1.3, spacing=1.3))
    # trust text
    if f.scored:
        num = str(f.score)
        nw = _w(num, 32, True)
        npaint = 'fill="url(#gN)"' if f.cert else _hex(f.tier_color)
        out.append(_text(tx, py + _NUM_Y, num, paint=npaint, size=32, bold=True, width=nw))
        out.append(_text(tx + nw + 2, py + _NUM_Y, "/100", paint=p.fill("muted"), size=10,
                         font=_MONO))
        word = "CERTIFIED" if f.cert else f.tier_word
        out.append(_text(tx, py + _WORD_Y, word, paint=npaint, size=11.5, bold=True,
                         width=_w(word, 11.5, True)))
    else:
        out.append(_text(tx, py + _NUM_Y, "—", paint=p.fill("muted"), size=30, bold=True))
        out.append(_text(tx, py + _WORD_Y, "not scanned", paint=p.fill("muted"), size=11.5,
                         bold=True))
    # adoption text — count (+ unit when it fits), level word under it
    if f.has_adoption:
        an = f.adoption_text
        # A step below the trust numeral: 21px (18px if it must), muted a touch. The
        # full unit, then the short one (downloads -> dl); the unit drops only when
        # nothing fits (it stays in the accessible title).
        size, unit = 21, ""
        units = [u for u in (f.adoption_unit, f.adoption_unit.replace("downloads", "dl"))
                 if u] or [""]
        for sz in (21, 18):
            fit = next((u for u in units
                        if _w(an, sz, True) + (3 + _w(u, 9) * 0.95 if u else 0) <= avail),
                       None)
            if fit is not None:
                size, unit = sz, fit
                break
        else:
            size = 21 if _w(an, 21, True) <= avail else 18
        anw = _w(an, size, True)
        out.append(_text(ax, py + _NUM_Y, an, paint=p.fill("fg") + ' fill-opacity=".82"',
                         size=size, bold=True, width=anw))
        if unit:
            out.append(_text(ax + anw + 3, py + _NUM_Y, unit, paint=p.fill("muted"),
                             size=9, font=_MONO))
        out.append(_text(ax, py + _WORD_Y, f.adoption_word,
                         paint='fill="url(#gW)" fill-opacity=".9"', size=10, bold=True,
                         width=_w(f.adoption_word, 10, True)))
        ww = _w(f.adoption_word, 10, True)
    else:
        out.append(_text(ax, py + _NUM_Y, "New", paint=p.fill("muted"), size=21, bold=True))
        out.append(_text(ax, py + _WORD_Y, "no signal yet", paint=p.fill("muted"), size=10,
                         bold=True))
        ww = 80.0
    foot = "signed ✔ Ed25519 · verify offline" if f.scored else "scan it free at agentavow.com"
    out.append(_text(18, h - 14, foot, paint=p.fill("muted"), size=10.5, width=_w(foot, 10.5)))
    if f.scored:
        out.append(_text(w - 18, h - 14, "agentavow.com", paint=p.fill("muted"), size=10.5,
                         anchor="end", width=_w("agentavow.com", 10.5)))
    tw = _w("CERTIFIED", 11.5, True)
    defs = (_grad("gH", 14, 0, w - 14, 0) + _grad("gP", w - 140, 0, w - 18, 0)
            + _grad("gT", 0, bar_bottom, 0, bar_bottom - bar_h)
            + _gauge_grad("agrad", 26, 174)
            + _grad("gN", tx, 0, tx + max(tw, 60), 0) + _grad("gW", ax, 0, ax + ww, 0))
    return _svg(w, h, f"<defs>{defs}</defs>" + "".join(out), f.title(), p.css())


# ---------------------------------------------------------------------------
# compact — the README badge (20px)
# ---------------------------------------------------------------------------
def _compact_badge(f: _Facts, p: _Paint, brand: str) -> str:
    h = 20
    out: list[str] = [_logo(5, 3, 14)]
    x = 24.0
    bu = brand.upper()
    bw = _w(bu, 9, True) + len(bu) * 0.9
    out.append(_text(x, 13.5, bu, paint=p.fill("muted"), size=9, bold=True, width=bw,
                     spacing=0.9))
    x += bw + 7
    dividers = [x]
    x += 7
    grads: list[tuple[str, float, float]] = []
    if not f.scored:
        lw = _w("not scanned", 11, True)
        out.append(_text(x, 14, "not scanned", paint=p.fill("muted"), size=11, bold=True,
                         width=lw))
        x += lw + 8
    else:
        label = f"{f.icon} {f.label}"
        lw = _w(label, 11, True)
        out.append(_text(x, 14, label, paint=_hex(f.color), size=11, bold=True, width=lw))
        x += lw + 6
        if f.cert:
            cw = _w("CERTIFIED", 8.5, True) + 9 * 0.6
            out.append(_text(x, 13.5, "CERTIFIED", paint='fill="url(#cC)"', size=8.5,
                             bold=True, width=cw, spacing=0.6))
            grads.append(("cC", x, x + cw))
            x += cw + 6
        else:
            x += 2
        dividers.append(x)
        x += 7
        # trust — the bar laid flat
        lit = 10 if f.cert else _lit(f.score)
        tone = "url(#cT)" if f.cert else f.tier_color
        for i in range(10):
            fill = f'fill="{tone}"' if i < lit else p.fill("track")
            out.append(f'<rect x="{x + i * 4.3:.1f}" y="6" width="3.1" height="8" rx=".8" '
                       f'{fill}/>')
        if f.cert:
            grads.append(("cT", x, x + 43))
        x += 43 + 4
        num = str(f.score)
        nw = _w(num, 11, True)
        out.append(_text(x, 14.2, num, paint=p.fill("fg"), size=11, bold=True, width=nw))
        x += nw + 8
        dividers.append(x)
        x += 7
        # adoption — a small needle gauge (the card's gauge, scaled down) + the count
        gx = x
        # The small badges keep the thinner arc (Kenne, 2026-10-08); only the card's
        # dial is heavy.
        out.append(_gauge(p, f.adoption_pct, f.has_adoption, gid="cA", cx=gx + 9, cy=14.5,
                          r=8, arc_w=2.4, needle_w=1.4, hub=1.7, ticks=False,
                          needle_in=16 * 8 / 74))
        grads.append(("cA", gx + 1, gx + 17))
        x += 18 + 5
        at = f.adoption_text
        aw = _w(at, 11, True)
        out.append(_text(x, 14.2, at, paint=p.fill("fg" if f.has_adoption else "muted"),
                         size=11, bold=True, width=aw))
        x += aw + 6
    total = x + 2
    stroke = 'stroke="url(#cB)"' if f.cert else f'stroke="{f.color}" stroke-opacity=".55"'
    frame = (f'<rect x=".5" y=".5" width="{total - 1:.1f}" height="{h - 1}" rx="4.5" '
             f'{p.fill("bg")}/>'
             f'<rect x=".5" y=".5" width="{total - 1:.1f}" height="{h - 1}" rx="4.5" '
             f'fill="none" {stroke}/>')
    divs = "".join(f'<rect x="{dx - 3.5:.1f}" y="5" width="1" height="10" {p.fill("line")}/>'
                   for dx in dividers)
    defs = "".join(_grad(g, a, 0, b, 0) for g, a, b in grads) + _grad("cB", 0, 0, total, 0)
    return _svg(total, h, f"<defs>{defs}</defs>" + frame + divs + "".join(out), f.title(),
                p.css())


def render_avow_badge(
    *, style: str, decision: str | None, score: int | None, certified: bool = False,
    brand: str = "AgentAvow", theme: str = "auto", coordinate: str = "",
    adoption: int | None = None, adoption_unit: str | None = None,
    adoption_pct: int | None = None,
) -> str:
    """Render one AgentAvow badge as SVG text.

    ``certified`` only takes effect on a Safe answer with a score. ``adoption`` is the
    headline count; ``adoption_pct`` is the 0-100 adoption score that sets the gauge
    (``score_0_100``; the card's ``adoptionPct`` log scale of the count when missing).
    """
    if style not in AVOW_STYLES:
        raise ValueError(f"unknown badge style {style!r}")
    if theme not in AVOW_THEMES:
        theme = "auto"
    if adoption_pct is None:
        adoption_pct = adoption_pct_from_count(adoption)
    f = _Facts(decision, score, certified, adoption, adoption_unit, adoption_pct,
               coordinate, light=(theme == "light"))
    p = _Paint(theme)
    if style == "card":
        return _card(f, p, brand)
    if style == "card-stacked":
        return _card_stacked(f, p, brand)
    return _compact_badge(f, p, brand)
