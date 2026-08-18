from __future__ import annotations

import logging
import math
import re as _re
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.badge_style import BADGE_FONT, trust_color, trust_word, verdana_width
from src.api.rate_limit import rate_limit_reads
from src.database import get_db
from src.models import Entity, FrameworkSecurityScan, TrustScore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trust-badges"])

_CACHE_HEADERS = {
    "Cache-Control": "public, max-age=3600, s-maxage=86400",
    "Access-Control-Allow-Origin": "*",
    "Cross-Origin-Resource-Policy": "cross-origin",
}

_BRAND_TEAL = "#0D9488"

# Text metrics + the 0-100 colour/tier vocabulary now live in badge_style (shared
# across every shields-style renderer). These thin wrappers keep the 0.0-1.0 score
# interface this module's callers use.
_text_width = verdana_width


def _trust_tier_color(score: float) -> str:
    """0-100 Trust mark hex colour. ``score`` is 0.0-1.0."""
    return trust_color(round(score * 100))


def _trust_tier_word(score: float) -> str:
    """0-100 Trust mark tier word. ``score`` is 0.0-1.0."""
    return trust_word(round(score * 100))


def _trust_tier_label(score: float) -> str:
    """Legacy A-F letter map (``score`` 0.0-1.0). NOT shown on any badge — the badges
    show the 0-100 number (dual-mark pivot 2026-08). Retained only for scoring-parity
    tests (test_trust_scoring_v6). Do not use for display."""
    s = score * 100
    if s >= 96:
        return "A+"
    if s >= 81:
        return "A"
    if s >= 61:
        return "B"
    if s >= 41:
        return "C"
    if s >= 21:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# SVG icon paths — tiny shield + checkmark, viewBox 0 0 10 12
# ---------------------------------------------------------------------------

# Small shield outline (10x12) — clean vector, no emoji
_SHIELD_PATH = (
    "M5 0L0 2.2v3.5c0 2.9 2.1 5.6 5 6.3 2.9-.7 5-3.4 5-6.3V2.2L5 0z"
)

# Checkmark (fits inside the shield)
_CHECK_PATH = "M3.5 7.5L2 6l-.7.7L3.5 8.9l5-5L7.8 3.2z"

# X mark (fits inside the shield)
_X_PATH = "M7.5 3.2L6.8 2.5 5 4.3 3.2 2.5l-.7.7L4.3 5 2.5 6.8l.7.7L5 5.7l1.8 1.8.7-.7L5.7 5z"


# ---------------------------------------------------------------------------
# Badge palette — one self-contained style (its own backgrounds), so the badge
# reads on any page ground. No per-viewer theming: a server-rendered <img> can't
# see prefers-color-scheme, and shields-style badges ship one fixed scheme.
# ---------------------------------------------------------------------------

_TC = {
    "label_bg": _BRAND_TEAL,
    "label_text": "#fff",
    "mid_bg": "#555",
    "mid_text": "#fff",
    "value_text": "#fff",
    "shadow_fill": "#010101",
}


# ---------------------------------------------------------------------------
# Compact badge (default) — 20px, shields.io compatible
# [shield AgentGraph | 0.85 verified]
# ---------------------------------------------------------------------------

def _scan_badge_info(scan_status: str | None) -> tuple[str, str]:
    """Return (label, color) for the scan status segment."""
    if scan_status == "clean":
        return "scan \u2713", "#22C55E"  # green check
    if scan_status == "warnings":
        return "scan \u26A0", "#F59E0B"  # amber warning
    if scan_status == "critical":
        return "scan \u2717", "#EF4444"  # red x
    if scan_status == "error":
        return "scan ?", "#6C7086"  # gray
    return "", ""  # no scan = no segment


def _render_compact_svg(
    score: float,
    has_operator: bool,
    is_provisional: bool,
    scan_status: str | None = None,
) -> str:
    tc = _TC
    color = _trust_tier_color(score)
    score_pct = round(score * 100)
    value_label = f"{score_pct}/100"

    # Icon (shield) occupies 14px (10 icon + 4 pad)
    icon_width = 14
    label_text = "AgentAvow Trust"
    label_text_w = _text_width(label_text)
    label_width = math.ceil(icon_width + label_text_w + 10)

    value_text_w = _text_width(value_label)
    value_width = math.ceil(value_text_w + 10)

    # Optional scan status segment
    scan_label, scan_color = _scan_badge_info(scan_status)
    scan_width = 0
    if scan_label:
        scan_text_w = _text_width(scan_label)
        scan_width = math.ceil(scan_text_w + 10)

    total_width = label_width + value_width + scan_width
    label_text_x = icon_width + 3 + label_text_w / 2
    value_text_x = label_width + value_width / 2
    scan_text_x = label_width + value_width + scan_width / 2
    height = 20
    rx = 3
    font = BADGE_FONT

    scan_svg = ""
    if scan_label:
        scan_svg = f"""
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{scan_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{scan_label}</text>
    <text x="{scan_text_x}" y="14">{scan_label}</text>
  </g>"""

    scan_rect = ""
    if scan_width:
        scan_rect = (
            f'<rect x="{label_width + value_width}" '
            f'width="{scan_width}" height="{height}" fill="{scan_color}"/>'
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="AgentAvow Trust: {score_pct}/100">
  <title>AgentAvow Trust: {score_pct}/100 ({_trust_tier_word(score)}){' scan: ' + (scan_status or '') if scan_status else ''}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_width}" height="{height}" rx="{rx}" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="{height}" fill="{tc['label_bg']}"/>
    <rect x="{label_width}" width="{value_width}" height="{height}" fill="{color}"/>
    {scan_rect}
    <rect width="{total_width}" height="{height}" fill="url(#s)"/>
  </g>
  <g transform="translate(4,4)" fill="#fff" fill-opacity=".9">
    <path d="{_SHIELD_PATH}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{label_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{label_text}</text>
    <text x="{label_text_x}" y="14">{label_text}</text>
  </g>
  <g fill="{tc['value_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{value_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{value_label}</text>
    <text x="{value_text_x}" y="14">{value_label}</text>
  </g>{scan_svg}
</svg>"""


# ---------------------------------------------------------------------------
# Detailed badge — 20px, three segments with entity name
# [shield AgentGraph | WelcomeBot | 0.85 check]
# ---------------------------------------------------------------------------

def _render_detailed_svg(
    score: float,
    has_operator: bool,
    is_provisional: bool,
    entity_name: str,
    scan_status: str | None = None,
) -> str:
    tc = _TC
    color = _trust_tier_color(score)
    score_pct = str(round(score * 100))

    if len(entity_name) > 20:
        entity_name = entity_name[:19] + "\u2026"

    # Left: shield icon + "AgentAvow"
    icon_width = 14
    left_label = "AgentAvow"
    left_text_w = _text_width(left_label)
    left_width = math.ceil(icon_width + left_text_w + 10)
    left_text_x = icon_width + 3 + left_text_w / 2

    # Middle: entity name
    mid_text_w = _text_width(entity_name)
    mid_width = math.ceil(mid_text_w + 10)
    mid_text_x = left_width + mid_width / 2

    # Right: score + check/x icon
    right_label = score_pct
    right_text_w = _text_width(right_label)
    # Add space for inline check icon (10px)
    right_width = math.ceil(right_text_w + 22)
    right_text_x = left_width + mid_width + (right_width - 10) / 2
    # Check icon position — after score text
    check_x = left_width + mid_width + right_width - 14

    # Optional scan status segment
    scan_label, scan_color = _scan_badge_info(scan_status)
    scan_width = 0
    if scan_label:
        scan_text_w = _text_width(scan_label)
        scan_width = math.ceil(scan_text_w + 10)

    total_width = left_width + mid_width + right_width + scan_width
    scan_text_x = left_width + mid_width + right_width + scan_width / 2
    height = 20
    rx = 3
    font = BADGE_FONT

    is_verified = has_operator and not is_provisional
    check_icon = _CHECK_PATH if is_verified else _X_PATH
    check_color = "#fff"

    scan_rect = ""
    if scan_width:
        scan_rect = (
            f'<rect x="{left_width + mid_width + right_width}" '
            f'width="{scan_width}" height="{height}" fill="{scan_color}"/>'
        )

    scan_svg = ""
    if scan_label:
        scan_svg = f"""
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{scan_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{scan_label}</text>
    <text x="{scan_text_x}" y="14">{scan_label}</text>
  </g>"""

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="AgentAvow: {entity_name} {score_pct}/100">
  <title>AgentAvow: {entity_name} — {score_pct}/100{' scan: ' + (scan_status or '') if scan_status else ''}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_width}" height="{height}" rx="{rx}" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_width}" height="{height}" fill="{tc['label_bg']}"/>
    <rect x="{left_width}" width="{mid_width}" height="{height}" fill="{tc['mid_bg']}"/>
    <rect x="{left_width + mid_width}" width="{right_width}" height="{height}" fill="{color}"/>
    {scan_rect}
    <rect width="{total_width}" height="{height}" fill="url(#s)"/>
  </g>
  <g transform="translate(4,4)" fill="#fff" fill-opacity=".9">
    <path d="{_SHIELD_PATH}"/>
  </g>
  <g fill="{tc['label_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{left_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{left_label}</text>
    <text x="{left_text_x}" y="14">{left_label}</text>
  </g>
  <g fill="{tc['mid_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{mid_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{entity_name}</text>
    <text x="{mid_text_x}" y="14">{entity_name}</text>
  </g>
  <g fill="{tc['value_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{right_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{right_label}</text>
    <text x="{right_text_x}" y="14">{right_label}</text>
  </g>
  <g transform="translate({check_x},4)" fill="{check_color}">
    <path d="{check_icon}"/>
  </g>{scan_svg}
</svg>"""


# ---------------------------------------------------------------------------
# Minimal badge — 20px, single pill with score only
# [0.85]
# ---------------------------------------------------------------------------

def _render_minimal_svg(
    score: float,
    has_operator: bool,
    is_provisional: bool,
    scan_status: str | None = None,
) -> str:
    color = _trust_tier_color(score)
    score_pct = str(round(score * 100))
    tc = _TC

    text_w = _text_width(score_pct)
    # Shield icon (small, 8px) + score
    icon_size = 10
    pill_width = math.ceil(icon_size + text_w + 14)
    text_x = icon_size + 4 + text_w / 2

    # Optional scan status segment
    scan_label, scan_color = _scan_badge_info(scan_status)
    scan_width = 0
    if scan_label:
        scan_text_w = _text_width(scan_label)
        scan_width = math.ceil(scan_text_w + 10)

    total_width = pill_width + scan_width
    scan_text_x = pill_width + scan_width / 2
    height = 20
    rx = 3
    font = BADGE_FONT

    is_verified = has_operator and not is_provisional
    icon_path = _SHIELD_PATH

    scan_rect = ""
    if scan_width:
        scan_rect = (
            f'<rect x="{pill_width}" '
            f'width="{scan_width}" height="{height}" fill="{scan_color}"/>'
        )

    scan_svg = ""
    if scan_label:
        scan_svg = f"""
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{scan_text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{scan_label}</text>
    <text x="{scan_text_x}" y="14">{scan_label}</text>
  </g>"""

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="Trust: {score_pct}/100">
  <title>AgentAvow Trust: {score_pct}/100{' scan: ' + (scan_status or '') if scan_status else ''}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_width}" height="{height}" rx="{rx}" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{pill_width}" height="{height}" fill="{color}"/>
    {scan_rect}
    <rect width="{total_width}" height="{height}" fill="url(#s)"/>
  </g>
  <g transform="translate(3,4)" fill="#fff" fill-opacity="{'.9' if is_verified else '.5'}">
    <path d="{icon_path}"/>
  </g>
  <g fill="{tc['value_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{text_x}" y="15" fill="{tc['shadow_fill']}" fill-opacity=".3">{score_pct}</text>
    <text x="{text_x}" y="14">{score_pct}</text>
  </g>{scan_svg}
</svg>"""


# ---------------------------------------------------------------------------
# Flat-square badge — 20px, no rounded corners, no gradient
# [shield AgentGraph | 0.85 verified]
# ---------------------------------------------------------------------------

def _render_flat_square_svg(
    score: float,
    has_operator: bool,
    is_provisional: bool,
    scan_status: str | None = None,
) -> str:
    tc = _TC
    color = _trust_tier_color(score)
    score_pct = round(score * 100)
    value_label = f"{score_pct}/100"

    icon_width = 14
    label_text = "AgentAvow Trust"
    label_text_w = _text_width(label_text)
    label_width = math.ceil(icon_width + label_text_w + 10)

    value_text_w = _text_width(value_label)
    value_width = math.ceil(value_text_w + 10)

    # Optional scan status segment
    scan_label, scan_color = _scan_badge_info(scan_status)
    scan_width = 0
    if scan_label:
        scan_text_w = _text_width(scan_label)
        scan_width = math.ceil(scan_text_w + 10)

    total_width = label_width + value_width + scan_width
    label_text_x = icon_width + 3 + label_text_w / 2
    value_text_x = label_width + value_width / 2
    scan_text_x = label_width + value_width + scan_width / 2
    height = 20
    font = BADGE_FONT

    scan_rect = ""
    if scan_width:
        scan_rect = (
            f'<rect x="{label_width + value_width}" '
            f'width="{scan_width}" height="{height}" fill="{scan_color}"/>'
        )

    scan_svg = ""
    if scan_label:
        scan_svg = f"""
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{scan_text_x}" y="14">{scan_label}</text>
  </g>"""

    # Flat-square: no gradient, no rounded corners, no shadow
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="AgentAvow Trust: {score_pct}/100">
  <title>AgentAvow Trust: {score_pct}/100 ({_trust_tier_word(score)}){' scan: ' + (scan_status or '') if scan_status else ''}</title>
  <g>
    <rect width="{label_width}" height="{height}" fill="{tc['label_bg']}"/>
    <rect x="{label_width}" width="{value_width}" height="{height}" fill="{color}"/>
    {scan_rect}
  </g>
  <g transform="translate(4,4)" fill="#fff" fill-opacity=".9">
    <path d="{_SHIELD_PATH}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{label_text_x}" y="14">{label_text}</text>
  </g>
  <g fill="{tc['value_text']}" text-anchor="middle" font-family="{font}" font-size="11">
    <text x="{value_text_x}" y="14">{value_label}</text>
  </g>{scan_svg}
</svg>"""


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _apply_scale(svg: str, scale: float) -> str:
    """Scale an SVG badge by adjusting width/height and adding viewBox."""
    m = _re.search(r'width="([\d.]+)" height="([\d.]+)"', svg)
    if not m:
        return svg
    orig_w, orig_h = float(m.group(1)), float(m.group(2))
    new_w = round(orig_w * scale, 1)
    new_h = round(orig_h * scale, 1)
    # Replace first occurrence (the svg element's dimensions)
    svg = svg.replace(
        f'width="{m.group(1)}" height="{m.group(2)}"',
        f'width="{new_w}" height="{new_h}"'
        f' viewBox="0 0 {m.group(1)} {m.group(2)}"',
        1,
    )
    return svg


def _render_badge_svg(
    score: float,
    has_operator: bool,
    is_provisional: bool = False,
    style: str = "compact",
    entity_name: str = "",
    scan_status: str | None = None,
) -> str:
    """Render an SVG trust badge in the requested style (single self-contained palette)."""
    if style == "detailed":
        return _render_detailed_svg(
            score, has_operator, is_provisional, entity_name,
            scan_status,
        )
    if style == "minimal":
        return _render_minimal_svg(
            score, has_operator, is_provisional, scan_status,
        )
    if style == "flat-square":
        return _render_flat_square_svg(
            score, has_operator, is_provisional, scan_status,
        )
    # compact (default)
    return _render_compact_svg(
        score, has_operator, is_provisional, scan_status,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

_STYLE_OPTIONS = Literal["compact", "detailed", "minimal", "flat-square"]


@router.get(
    "/badges/readme/{entity_id}",
    dependencies=[Depends(rate_limit_reads)],
    responses={
        200: {"content": {"text/plain": {}}, "description": "Badge embed snippet"},
        404: {"description": "Entity not found"},
    },
)
async def get_readme_badge(
    entity_id: uuid.UUID,
    fmt: Literal["markdown", "html", "rst"] = Query(
        "markdown", alias="format",
        description="Snippet format: markdown, html, or rst",
    ),
    style: _STYLE_OPTIONS = Query(
        "compact", description="Badge visual style",
    ),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Return a copy-paste snippet for embedding a trust badge in a README."""
    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    badge_url = f"https://agentgraph.co/api/v1/badges/trust/{entity_id}.svg"
    params: list[str] = []
    if style != "compact":
        params.append(f"style={style}")
    # Always add scale=1.5 for README snippets (bigger badge)
    params.append("scale=1.5")
    badge_url += "?" + "&".join(params)

    profile_url = f"https://agentgraph.co/profile/{entity_id}"
    alt = "AgentAvow Trust Score"

    blurb = (
        '<sub>Verified on <a href="https://agentavow.com">'
        "AgentAvow</a>"
        " \u2014 trust infrastructure for AI agents."
        f' <a href="{profile_url}">View profile</a></sub>'
    )

    if fmt == "html":
        snippet = (
            f'<a href="{profile_url}">'
            f'<img src="{badge_url}" alt="{alt}" />'
            f"</a>"
        )
    elif fmt == "rst":
        snippet = (
            f".. image:: {badge_url}\n"
            f"   :target: {profile_url}\n"
            f"   :alt: {alt}"
        )
    else:
        snippet = (
            f'<a href="{profile_url}">\n'
            f'  <img src="{badge_url}" alt="{alt}" />\n'
            f"</a>\n\n{blurb}"
        )

    return Response(
        content=snippet,
        media_type="text/plain",
        headers=dict(_CACHE_HEADERS),
    )


@router.api_route(
    "/badges/trust/{entity_id}.svg",
    methods=["GET", "HEAD"],
    dependencies=[Depends(rate_limit_reads)],
    responses={
        200: {"content": {"image/svg+xml": {}}, "description": "SVG trust badge"},
        404: {"description": "Entity not found"},
    },
)
async def get_trust_badge_svg(
    entity_id: uuid.UUID,
    request: Request,
    style: _STYLE_OPTIONS = Query(
        "compact", description="Badge visual style",
    ),
    scale: float = Query(
        1.0, ge=1.0, le=3.0,
        description="Scale factor (1.0-3.0) for larger badges",
    ),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Return an embeddable SVG badge showing an entity's trust score and
    verification status. No authentication required — badges are public."""

    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Best-effort engagement counter (Redis, never blocks the render).
    from src.api.metrics_dashboard_router import bump_metric

    await bump_metric("badge_fetch")

    # Best-effort adoption axis-D signal: log the Referer host so we can count
    # distinct badge-embed domains (30d). MUST never break the badge render.
    try:
        from src.scanner.adoption_sources import (
            record_badge_referer,
            record_badge_render,
        )

        await record_badge_referer(str(entity_id), request.headers.get("referer"))
        # Segment README embeds (GitHub camo proxy) + per-repo leaderboard.
        _src = getattr(entity, "source_url", None) or ""
        _repo_label = None
        if "github.com/" in _src:
            _parts = _src.split("github.com/", 1)[1].strip("/").split("/")
            if len(_parts) >= 2 and _parts[0] and _parts[1]:
                _repo_label = f"{_parts[0]}/{_parts[1]}"
        await record_badge_render(_repo_label, request.headers.get("user-agent"))
    except Exception:
        pass

    trust = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    score = trust.score if trust else 0.0
    has_operator = entity.operator_id is not None
    is_provisional = getattr(entity, "is_provisional", False) or False

    # Get latest security scan result
    scan = await db.scalar(
        select(FrameworkSecurityScan)
        .where(FrameworkSecurityScan.entity_id == entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(1)
    )
    scan_status = None
    if scan:
        scan_status = scan.scan_result  # clean, warnings, critical, error

    svg = _render_badge_svg(
        score=score,
        has_operator=has_operator,
        is_provisional=is_provisional,
        style=style,
        entity_name=entity.display_name or str(entity_id),
        scan_status=scan_status,
    )

    # Apply scale by wrapping in viewBox if scale > 1
    if scale > 1.0:
        svg = _apply_scale(svg, scale)

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers=dict(_CACHE_HEADERS),
    )
