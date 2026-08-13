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

# Grade → accent RGB (matches the frontend grade system).
_GRADE_RGB = {
    "A+": (16, 185, 129), "A": (34, 197, 94), "B": (34, 211, 238),
    "C": (245, 158, 11), "D": (249, 115, 22), "F": (239, 68, 68),
}


def _font(size: int):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # very old Pillow — unsized bitmap fallback
        return ImageFont.load_default()


def _wrap(draw, text: str, font, max_w: int, max_lines: int) -> list[str]:
    words = (text or "").split()
    lines: list[str] = []
    cur = ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if draw.textlength(trial, font=font) <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
        if len(lines) == max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if lines and draw.textlength(text, font=font) > max_w and len(lines) == max_lines:
        # ellipsize the last line if we truncated
        last = lines[-1]
        while last and draw.textlength(last + "…", font=font) > max_w:
            last = last[:-1]
        lines[-1] = last + "…"
    return lines or [""]


def render_og_png(
    *, title: str, grade: str, score: int | None, subtitle: str = "",
) -> bytes:
    """Compose the OG card PNG bytes. Raises on a hard Pillow failure (caller falls back)."""
    from PIL import Image, ImageDraw

    grade = (grade or "?").upper()
    accent = _GRADE_RGB.get(grade, _MUTED)
    img = Image.new("RGB", (_W, _H), _BG)
    d = ImageDraw.Draw(img)

    # Top accent stripe.
    d.rectangle([0, 0, _W, 10], fill=accent)

    # Grade tile (left) — a rounded square in the grade color with the letter + score.
    tile = (80, 150, 380, 450)
    d.rounded_rectangle(tile, radius=28, fill=accent)
    gf = _font(150 if len(grade) == 1 else 110)
    gw = d.textlength(grade, font=gf)
    d.text(((tile[0] + tile[2]) / 2 - gw / 2, 190), grade, font=gf, fill=_BG)
    if score is not None:
        sf = _font(40)
        st = f"{score}/100"
        sw = d.textlength(st, font=sf)
        d.text(((tile[0] + tile[2]) / 2 - sw / 2, 375), st, font=sf, fill=_BG)

    # Right column — eyebrow, title, subtitle.
    x = 430
    d.text((x, 150), "SAFETY GRADE", font=_font(28), fill=_TEAL)
    tf = _font(66)
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
    d.text((80, 590), "A signed safety grade you can verify offline",
           font=_font(26), fill=_MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
