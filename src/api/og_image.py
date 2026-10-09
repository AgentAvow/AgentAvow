"""Dynamic social-preview (Open Graph) card renderer.

Renders a 1200×630 PNG for a score page in the AgentAvow badge design (option C,
``src/api/badge_avow.py``): the logo, the three-phrase headline ("Safe to connect" /
"Review before you connect" / "Do not connect", in its colour) with the Certified pill
when the tool carries the mark, the tool's name and one-line description, then an
instrument panel — the 10-segment trust bar with the score and tier word to its right,
and (when adoption is known) the adoption dial with the count and level to its right.
Twitter/Facebook need raster, which SVG can't provide, so this is drawn with Pillow.

Pillow's ``load_default(size=)`` gives a scalable default face, so no font file is
bundled. Fail-open: the caller falls back to the static brand image on any error.
"""
from __future__ import annotations

import io
import math

_W, _H = 1200, 630
_BG = (11, 15, 23)          # #0b0f17 — the trust card's ground
_PANEL = (15, 21, 34)       # #0f1522
_LINE = (30, 39, 51)        # #1e2733 — track + hairlines
_FG = (230, 237, 243)       # #e6edf3
_MUTED = (154, 167, 182)    # #9aa7b6
_TEAL = (45, 212, 191)      # #2dd4bf
_MAGENTA = (232, 121, 249)  # #e879f9
_INK = (4, 32, 28)          # #04201c — text on the gradient pill


def _hex_rgb(hexv: str) -> tuple[int, int, int]:
    h = hexv.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _mix(t: float) -> tuple[int, int, int]:
    """The teal→magenta brand gradient at ``t`` (0..1)."""
    t = max(0.0, min(1.0, t))
    return (round(_TEAL[0] + (_MAGENTA[0] - _TEAL[0]) * t),
            round(_TEAL[1] + (_MAGENTA[1] - _TEAL[1]) * t),
            round(_TEAL[2] + (_MAGENTA[2] - _TEAL[2]) * t))


def _font(size: int):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # very old Pillow — unsized bitmap fallback
        return ImageFont.load_default()


def _clip(draw, s: str, font, max_w: int) -> str:
    """Ellipsize a single line that's wider than ``max_w`` (URLs, long names)."""
    if draw.textlength(s, font=font) <= max_w:
        return s
    while s and draw.textlength(s + "…", font=font) > max_w:
        s = s[:-1]
    return s + "…"


def _wrap(draw, text: str, font, max_w: int, max_lines: int) -> list[str]:
    words = (text or "").split()
    lines: list[str] = []
    cur = ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if draw.textlength(trial, font=font) <= max_w:
            cur = trial
        elif cur:
            lines.append(cur)
            cur = w
        else:
            lines.append(_clip(draw, w, font, max_w))
            cur = ""
        if len(lines) >= max_lines:
            cur = ""
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and draw.textlength(text, font=font) > max_w * max_lines:
        lines[-1] = _clip(draw, lines[-1] + "…", font, max_w)
    return [_clip(draw, ln, font, max_w) for ln in lines] or [""]


def _spaced(d, xy, text: str, font, fill, spacing: float) -> float:
    """Draw letter-spaced caps (caplabels); returns the end x."""
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + spacing
    return x


def _gradient_text(img, xy, text: str, font) -> None:
    """Text filled with the teal→magenta gradient across its own width."""
    from PIL import Image, ImageDraw
    d = ImageDraw.Draw(img)
    w = int(d.textlength(text, font=font)) + 4
    h = d.textbbox((0, 0), text, font=font)[3] + 4
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).text((0, 0), text, font=font, fill=255)
    grad = Image.new("RGB", (w, h))
    gd = ImageDraw.Draw(grad)
    for x in range(w):
        gd.line([(x, 0), (x, h)], fill=_mix(x / max(w - 1, 1)))
    img.paste(grad, (int(xy[0]), int(xy[1])), mask)


def _logo(d, x: float, y: float, size: float, color=_TEAL) -> None:
    """The AgentAvow ring + check (the trust card's 40-unit artwork)."""
    k = size / 40
    d.ellipse([x + (20 - 16.3) * k, y + (20 - 16.3) * k, x + (20 + 16.3) * k,
               y + (20 + 16.3) * k], outline=color, width=max(2, round(3.4 * k)))
    pts = [(x + 12 * k, y + 21 * k), (x + 18 * k, y + 27 * k), (x + 30 * k, y + 14 * k)]
    d.line(pts, fill=color, width=max(2, round(4.2 * k)), joint="curve")
    for px, py in (pts[0], pts[2]):
        r = 2.1 * k
        d.ellipse([px - r, py - r, px + r, py + r], fill=color)


def _dial(d, cx: float, cy: float, r: float, pct: int, has: bool, scale: float) -> None:
    """The adoption VU dial (the badge card's heavy arc), drawn in small steps so the
    filled arc carries the teal→magenta gradient. Angles as in the card: 180°→360°."""
    w = 16 * scale
    a0, a1 = 180.0, 360.0
    ang = a0 + pct / 100 * 180

    def pt(rr: float, deg: float) -> tuple[float, float]:
        a = math.radians(deg)
        return cx + rr * math.cos(a), cy + rr * math.sin(a)

    def cap(deg: float, fill) -> None:
        px, py = pt(r, deg)
        d.ellipse([px - w / 2, py - w / 2, px + w / 2, py + w / 2], fill=fill)

    box = [cx - r - w / 2, cy - r - w / 2, cx + r + w / 2, cy + r + w / 2]
    d.arc(box, start=max(ang, a0 + 0.5), end=a1, fill=_LINE, width=round(w))
    cap(a1, _LINE)
    if has and ang > a0 + 1.5:
        steps = max(2, int((ang - a0) / 2))
        for i in range(steps):
            s = a0 + (ang - a0) * i / steps
            e = a0 + (ang - a0) * (i + 1) / steps + 0.6
            d.arc(box, start=s, end=min(e, ang), fill=_mix((s - a0) / 180), width=round(w))
        cap(a0, _mix(0))
        cap(ang, _mix((ang - a0) / 180))
    else:
        cap(a0, _LINE)
    for i in range(9):
        ta = a0 + 180 * ((i + 1) / 10)
        mid = i + 1 == 5
        x0, y0 = pt(r - 13 * scale, ta)
        x1, y1 = pt(r - (13 + (8 if mid else 4)) * scale, ta)
        d.line([(x0, y0), (x1, y1)], fill=(80, 92, 108), width=2 if mid else 1)
    hub = 9.5 * scale
    if has:
        nx, ny = pt(r - 22 * scale, ang)
        d.line([(cx, cy), (nx, ny)], fill=_TEAL, width=round(6.5 * scale))
        d.ellipse([nx - 3.2 * scale, ny - 3.2 * scale, nx + 3.2 * scale, ny + 3.2 * scale],
                  fill=_TEAL)
        d.ellipse([cx - hub, cy - hub, cx + hub, cy + hub], fill=_TEAL)
    else:
        d.ellipse([cx - hub, cy - hub, cx + hub, cy + hub], fill=(55, 64, 78))


def _compact(n: int) -> str:
    for div, suf in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if n >= div:
            return f"{n / div:.1f}".rstrip("0").rstrip(".") + suf
    return str(n)


def _adoption_level(pct: int) -> str:
    return ("Load-bearing" if pct >= 88 else "Widely relied" if pct >= 65
            else "Established" if pct >= 40 else "Rising" if pct >= 15 else "New")


def render_og_png(
    *, title: str, grade: str, score: int | None, subtitle: str = "",
    decision: str | None = None, certified: bool = False,
    adoption: int | None = None, adoption_unit: str | None = None,
    adoption_pct: int | None = None, adoption_known: bool = False,
) -> bytes:
    """Compose the OG card PNG bytes. Raises on a hard Pillow failure (caller falls back).

    ``decision`` (safe | review | do_not_connect) sets the headline + accent; when it is
    absent a scored card decides from the score alone (``src.trust_tiers.decision_for``).
    ``certified`` must be the Certified MARK (``certified_mark``), not raw eligibility;
    it only ever shows beside Safe to connect. The adoption column shows when
    ``adoption_known`` (no count reads "New · no signal yet").
    """
    from PIL import Image, ImageDraw

    from src.trust_tiers import DECISION_BY_VALUE, decision_for, tier_for_score

    _ = grade  # legacy param — the card shows the 0-100 number, not a letter
    scored = score is not None
    s = max(0, min(100, int(score))) if scored else 0
    if scored:
        dp = DECISION_BY_VALUE.get(decision or "") or decision_for(s)
        accent, phrase, safe = _hex_rgb(dp.color), dp.phrase, dp.value == "safe"
        tier = tier_for_score(s)
        tcol, tword = _hex_rgb(tier.color), tier.display
    else:
        accent, phrase, safe = _MUTED, "Not scanned yet", False
        tcol, tword = _MUTED, "not scanned"
    cert = bool(certified) and scored and safe

    img = Image.new("RGB", (_W, _H), _BG)
    d = ImageDraw.Draw(img)

    # Accent rule (the gradient when Certified).
    if cert:
        for x in range(_W):
            d.line([(x, 0), (x, 8)], fill=_mix(x / (_W - 1)))
    else:
        d.rectangle([0, 0, _W, 8], fill=accent)

    # Brand row + the Certified pill.
    _logo(d, 64, 44, 46)
    _spaced(d, (126, 54), "AGENTAVOW", _font(26), _MUTED, 5)
    if cert:
        pf = _font(26)
        label = "CERTIFIED"
        pw = int(d.textlength(label, font=pf) + 76)
        px0, py0 = _W - 64 - pw, 44
        pill = Image.new("RGB", (pw, 46))
        pd = ImageDraw.Draw(pill)
        for x in range(pw):
            pd.line([(x, 0), (x, 46)], fill=_mix(x / pw))
        mask = Image.new("L", (pw, 46), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, pw - 1, 45], radius=23, fill=255)
        img.paste(pill, (px0, py0), mask)
        _logo(d, px0 + 14, py0 + 7, 32, color=_INK)
        d.text((px0 + 54, py0 + 9), label, font=pf, fill=_INK)

    # The answer, the name, the description.
    hf = _font(60)
    d.text((64, 118), _clip(d, phrase, hf, _W - 128), font=hf, fill=accent)
    tf = _font(40 if len(title or "") <= 40 else 32)
    d.text((64, 196), _clip(d, title or "", tf, _W - 128), font=tf, fill=_FG)
    if subtitle:
        sf = _font(27)
        d.text((64, 250), _wrap(d, subtitle, sf, _W - 128, 1)[0], font=sf, fill=_MUTED)

    # Instrument panel: trust | adoption, each meter with its text to the right, on
    # shared caplabel / number / word baselines; trust's numeral is the largest.
    p0, p1 = (56, 306), (_W - 56, 556)
    d.rounded_rectangle([*p0, *p1], radius=24, fill=_PANEL, outline=_LINE, width=2)
    split = _W // 2
    if adoption_known:
        d.line([(split, p0[1] + 30), (split, p1[1] - 30)], fill=_LINE, width=2)
    cap_y, num_y, word_y = p0[1] + 40, p0[1] + 78, p0[1] + 190

    seg_w, seg_h, gap = 34, 13, 6
    bar_h = 10 * seg_h + 9 * gap
    bx = 120
    bottom = (p0[1] + p1[1]) // 2 + bar_h // 2
    lit = 10 if cert else (round(s / 10) if scored else 0)
    for i in range(10):
        y = bottom - i * (seg_h + gap) - seg_h
        if i < lit and cert:
            for x in range(seg_w):
                d.line([(bx + x, y), (bx + x, y + seg_h)], fill=_mix(x / seg_w))
        else:
            d.rounded_rectangle([bx, y, bx + seg_w, y + seg_h], radius=2,
                                fill=tcol if i < lit else _LINE)
    tx = bx + seg_w + 40
    _spaced(d, (tx, cap_y), "TRUST", _font(24), _MUTED, 4)
    nf = _font(104)
    num = str(s) if scored else "—"
    if cert:
        _gradient_text(img, (tx, num_y), num, nf)
    else:
        d.text((tx, num_y), num, font=nf, fill=tcol if scored else _MUTED)
    if scored:
        d.text((tx + d.textlength(num, font=nf) + 10, num_y + 62), "/100", font=_font(30),
               fill=_MUTED)
    wf = _font(34)
    if cert:
        _gradient_text(img, (tx, word_y), "CERTIFIED", wf)
    else:
        d.text((tx, word_y), tword, font=wf, fill=tcol if scored else _MUTED)

    if adoption_known:
        c = int(adoption or 0)
        pct = max(0, min(100, int(adoption_pct or 0)))
        if not pct and c:
            pct = min(100, math.floor(math.log10(c + 1) / 9 * 100 + 0.5))
        has = c > 0 or pct > 0
        scale = 1.15
        r = 72 * scale
        dcx = split + 48 + r + 8
        dcy = (p0[1] + p1[1]) / 2 + 30
        _dial(d, dcx, dcy, r, pct, has, scale)
        ax = dcx + r + 40
        _spaced(d, (ax, cap_y), "ADOPTION", _font(24), _MUTED, 4)
        cf = _font(72)
        dim = (round(_FG[0] * .85 + _PANEL[0] * .15), round(_FG[1] * .85 + _PANEL[1] * .15),
               round(_FG[2] * .85 + _PANEL[2] * .15))
        avail = p1[0] - 30 - ax
        if has:
            ct = _compact(c) if c else "—"
            d.text((ax, num_y + 25), ct, font=cf, fill=dim)
            unit = (adoption_unit or "").strip()
            cw = d.textlength(ct, font=cf)
            uf = _font(26)
            for u in (unit, unit.replace("downloads", "dl")):
                if u and cw + 10 + d.textlength(u, font=uf) <= avail:
                    d.text((ax + cw + 10, num_y + 66), u, font=uf, fill=_MUTED)
                    break
            _gradient_text(img, (ax, word_y + 4), _adoption_level(pct), _font(30))
        else:
            d.text((ax, num_y + 25), "New", font=cf, fill=_MUTED)
            d.text((ax, word_y + 4), "no signal yet", font=_font(30), fill=_MUTED)

    d.text((64, 580), "Signed with Ed25519 · verify it offline at agentavow.com",
           font=_font(24), fill=_MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
