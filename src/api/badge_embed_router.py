"""Embeddable trust badge endpoint — shields.io-style SVG for READMEs.

DEPRECATED (2026-08): superseded by the repo-addressable ``/public/scan/{owner}/
{repo}/badge`` (and the entity ``/badges/trust/{id}.svg`` ``detailed`` style). This
entity-id-keyed three-segment badge is kept serving because third parties may embed
it, but it now delegates all colour/width/font to ``badge_style`` so it stays
consistent with the current badges. Prefer the repo-addressable badge for new use.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.badge_style import BADGE_FONT, trust_color, trust_word, verdana_width
from src.api.rate_limit import rate_limit_reads
from src.database import get_db
from src.models import Entity, FrameworkSecurityScan, TrustScore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["badges"])

# --- Constants ---

BADGE_LABEL_COLOR = "#555"
BADGE_FONT_SIZE = 11
BADGE_HEIGHT = 20
BADGE_PADDING = 10


def _render_embed_badge_svg(
    entity_name: str,
    score: float,
    is_verified: bool,
    scan_status: str | None = None,
) -> str:
    """Render a shields.io-style three-segment badge as SVG.

    Format: [AgentAvow | entity_name | score ✓/✗]
    Includes scan status in title if available.
    """
    score_pct = str(round(score * 100))
    status_char = "✓" if is_verified else "✗"  # ✓ / ✗ (was double-escaped → rendered literal text)
    value_text = f"{score_pct} {status_char}"

    label = "AgentAvow"
    label_width = verdana_width(label) + BADGE_PADDING
    name_width = verdana_width(entity_name) + BADGE_PADDING
    value_width = verdana_width(value_text) + BADGE_PADDING
    total_width = label_width + name_width + value_width

    color = trust_color(round(score * 100))

    label_center = label_width / 2
    name_center = label_width + name_width / 2
    value_center = label_width + name_width + value_width / 2

    shadow = 'fill="#010101" fill-opacity=".3"'
    verified_label = "Verified" if is_verified else "Unverified"
    scan_label = f" scan: {scan_status}" if scan_status else ""
    h = BADGE_HEIGHT
    val_x = label_width + name_width

    # Build SVG line by line to stay within line-length limits
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg"'
        f' width="{total_width}" height="{h}"'
        f' role="img"'
        f' aria-label="{entity_name}: Trust {score_pct}">',
        f"  <title>{entity_name} -- Trust Score:"
        f" {score_pct} ({verified_label}){scan_label}</title>",
        '  <linearGradient id="s" x2="0" y2="100%">',
        '    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>',
        '    <stop offset="1" stop-opacity=".1"/>',
        "  </linearGradient>",
        '  <clipPath id="r">',
        f'    <rect width="{total_width}" height="{h}"'
        f' rx="3" fill="#fff"/>',
        "  </clipPath>",
        '  <g clip-path="url(#r)">',
        f'    <rect width="{label_width}" height="{h}"'
        f' fill="{BADGE_LABEL_COLOR}"/>',
        f'    <rect x="{label_width}" width="{name_width}"'
        f' height="{h}" fill="#666"/>',
        f'    <rect x="{val_x}" width="{value_width}"'
        f' height="{h}" fill="{color}"/>',
        f'    <rect width="{total_width}" height="{h}"'
        f' fill="url(#s)"/>',
        "  </g>",
        f'  <g fill="#fff" text-anchor="middle"'
        f' font-family="{BADGE_FONT}"'
        f' font-size="{BADGE_FONT_SIZE}">',
        f'    <text x="{label_center}" y="{h * 0.72}"'
        f" {shadow}>{label}</text>",
        f'    <text x="{label_center}" y="{h * 0.68}">'
        f"{label}</text>",
        f'    <text x="{name_center}" y="{h * 0.72}"'
        f" {shadow}>{entity_name}</text>",
        f'    <text x="{name_center}" y="{h * 0.68}">'
        f"{entity_name}</text>",
        f'    <text x="{value_center}" y="{h * 0.72}"'
        f" {shadow}>{value_text}</text>",
        f'    <text x="{value_center}" y="{h * 0.68}">'
        f"{value_text}</text>",
        "  </g>",
        "</svg>",
    ]
    return "\n".join(lines)


@router.get(
    "/badges/embed/{entity_id}",
    dependencies=[Depends(rate_limit_reads)],
    responses={
        200: {
            "content": {
                "image/svg+xml": {},
                "application/json": {},
            },
            "description": "Embeddable trust badge (SVG or JSON)",
        },
        404: {"description": "Entity not found"},
    },
)
async def get_embeddable_badge(
    entity_id: uuid.UUID,
    format: str = Query("svg", pattern="^(svg|json)$"),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Return an embeddable trust badge for use in READMEs and docs.

    - ``?format=svg`` (default): shields.io-style SVG badge image
    - ``?format=json``: JSON with entity name, score, and verification status

    No authentication required — badges are public.
    """
    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    trust = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    score = trust.score if trust else 0.0
    is_verified = entity.operator_id is not None or entity.email_verified
    entity_name = entity.display_name or "Unknown"

    # Get latest security scan result
    scan = await db.scalar(
        select(FrameworkSecurityScan)
        .where(FrameworkSecurityScan.entity_id == entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(1)
    )
    scan_status = scan.scan_result if scan else None

    # Truncate long names to keep the badge readable
    max_name_len = 20
    if len(entity_name) > max_name_len:
        entity_name = entity_name[:max_name_len - 1] + "\u2026"

    if format == "json":
        color, tier = trust_color(round(score * 100)), trust_word(round(score * 100))
        data = {
            "entity_id": str(entity_id),
            "entity_name": entity_name,
            "trust_score": round(score, 4),
            "trust_tier": tier,
            "is_verified": is_verified,
            "badge_color": color,
            "scan_status": scan_status,
            "schema_version": 1,
        }
        return JSONResponse(
            content=data,
            headers={"Cache-Control": "public, max-age=300"},
        )

    # SVG format (default)
    svg = _render_embed_badge_svg(
        entity_name, score, is_verified, scan_status=scan_status,
    )
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=300"},
    )
