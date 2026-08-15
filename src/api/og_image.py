"""Dynamic social-preview (Open Graph) card renderer.

Renders a 1200×630 PNG for a score page — the graded tool's name, its signed grade,
score, and a one-line description — so a shared AgentAvow link unfurls into a rich
card on every platform (Twitter/Facebook need raster, which SVG can't provide).

Pillow's ``load_default(size=)`` gives a scalable default face, so no font file is
bundled. Fail-open: the caller falls back to the static brand image on any error.
"""
from __future__ import annotations

import io

_W, _H = 1200, 630
_BG = (11, 15, 20)          # near-black brand ground
_FG = (233, 238, 245)       # near-white text
_MUTED = (148, 163, 184)    # slate-400
_TEAL = (34, 211, 238)

# 0-100 Trust tier → accent RGB + word (green->red at 80/60/40/20, dual-mark).
def _score_tier(score: int | None) -> tuple[tuple[int, int, int], str]:
    if score is None:
        return _MUTED, ""
    if score >= 80:
        return (34, 197, 94), "Trusted"      # #22C55E
    if score >= 60:
        return (91, 191, 58), "Standard"     # #5BBF3A
    if score >= 40:
        return (245, 158, 11), "Caution"     # #F59E0B
    if score >= 20:
        return (249, 115, 22), "Restricted"  # #F97316
    return (239, 68, 68), "Blocked"          # #EF4444


def _font(size: int):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # very old Pillow — unsized bitmap fallback
        return ImageFont.load_default()


def _clip(draw, s: str, font, max_w: int) -> str:
    """Ellipsize a single token/line that's wider than ``max_w`` (URLs, long names —
    they have no spaces to wrap on, so they'd otherwise overflow the card)."""
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
            # A single word wider than the line (a URL/long name) — hard-clip it so it
            # never bleeds off the card.
            lines.append(_clip(draw, w, font, max_w))
            cur = ""
        if len(lines) >= max_lines:
            cur = ""
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    # If we ran out of lines with text remaining, ellipsize the final line.
    if len(lines) == max_lines and draw.textlength(text, font=font) > max_w * max_lines:
        lines[-1] = _clip(draw, lines[-1] + "…", font, max_w)
    return [_clip(draw, ln, font, max_w) for ln in lines] or [""]


def render_og_png(
    *, title: str, grade: str, score: int | None, subtitle: str = "",
) -> bytes:
    """Compose the OG card PNG bytes. Raises on a hard Pillow failure (caller falls back)."""
    from PIL import Image, ImageDraw

    _ = grade  # legacy param — the card now shows the 0-100 number, not a letter
    accent, tier_word = _score_tier(score)
    img = Image.new("RGB", (_W, _H), _BG)
    d = ImageDraw.Draw(img)

    # Top accent stripe.
    d.rectangle([0, 0, _W, 10], fill=accent)

    # Trust tile (left) — a rounded square in the tier colour with the 0-100 number.
    tile = (80, 150, 380, 450)
    cx = (tile[0] + tile[2]) / 2
    d.rounded_rectangle(tile, radius=28, fill=accent)
    num = str(score) if score is not None else "?"
    gf = _font(140 if len(num) <= 2 else 108)
    gw = d.textlength(num, font=gf)
    d.text((cx - gw / 2, 195), num, font=gf, fill=_BG)
    label = tier_word or "/100"
    sf = _font(34)
    sw = d.textlength(label, font=sf)
    d.text((cx - sw / 2, 372), label, font=sf, fill=_BG)

    # Right column — eyebrow, title, subtitle. Shrink the title face for long names/URLs
    # so more fits before we have to clip.
    x = 430
    d.text((x, 150), "SAFETY SCORE", font=_font(28), fill=_TEAL)
    _tl = len(title or "")
    tf = _font(66 if _tl <= 22 else 52 if _tl <= 34 else 42)
    ty = 200
    for line in _wrap(d, title, tf, _W - x - 70, 2):
        d.text((x, ty), line, font=tf, fill=_FG)
        ty += 82
    if subtitle:
        ty += 14
        for line in _wrap(d, subtitle, _font(34), _W - x - 70, 2):
            d.text((x, ty), line, font=_font(34), fill=_MUTED)
            ty += 46

    # Footer — brand + the promise.
    d.text((80, 545), "AgentAvow", font=_font(38), fill=_FG)
    d.text((80, 590), "A signed safety score you can verify offline",
           font=_font(26), fill=_MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
