"""Open Graph meta tag endpoints for social crawler previews.

Social platforms (Twitter, Slack, Discord, iMessage, etc.) don't execute
JavaScript, so our React SPA's client-side OG tags are invisible to them.
These endpoints serve minimal HTML with proper OG meta tags when nginx
detects a social crawler user agent on /check/* or /profile/* URLs.

Endpoints:
    GET /og/check/{owner}/{repo}    — OG tags for scan result pages
    GET /og/profile/{entity_id}     — OG tags for profile pages
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/og", tags=["og-meta"])

BASE_URL = "https://agentavow.com"


def _html_escape(text: str) -> str:
    """Escape HTML special characters for safe embedding in meta tags."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _render_og_html(
    title: str,
    description: str,
    image_url: str,
    canonical_url: str,
) -> str:
    """Render minimal HTML page with OG meta tags and a redirect."""
    t = _html_escape(title)
    d = _html_escape(description)
    i = _html_escape(image_url)
    u = _html_escape(canonical_url)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta property="og:title" content="{t}" />
  <meta property="og:description" content="{d}" />
  <meta property="og:image" content="{i}" />
  <meta property="og:url" content="{u}" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="AgentAvow" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="{t}" />
  <meta name="twitter:description" content="{d}" />
  <meta name="twitter:image" content="{i}" />
  <meta http-equiv="refresh" content="0;url={u}" />
  <title>{t}</title>
</head>
<body>Redirecting...</body>
</html>"""


def _grade_from_score(score: int) -> str:
    """Return letter grade from a 0-100 score."""
    if score >= 96:
        return "A+"
    if score >= 81:
        return "A"
    if score >= 61:
        return "B"
    if score >= 41:
        return "C"
    if score >= 21:
        return "D"
    return "F"


def _verdict_text(grade: str) -> str:
    """Return a consumer-friendly safety verdict for a letter grade."""
    if grade in ("A+", "A"):
        return "Safe to Use"
    if grade == "B":
        return "Generally Safe"
    if grade == "C":
        return "Use with Caution"
    if grade == "D":
        return "Significant Risks"
    return "Not Recommended"


# ── Scan OG endpoint ────────────────────────────────────────────────────


@router.get("/check/{owner}/{repo}", response_class=HTMLResponse)
async def og_check(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Serve OG meta tags for /check/:owner/:repo scan result pages.

    Called by nginx when a social crawler user agent hits /check/*.
    Returns minimal HTML with OG tags and a meta-refresh redirect.
    """
    full_name = f"{owner}/{repo}"
    canonical_url = f"{BASE_URL}/check/{owner}/{repo}"
    image_url = f"{BASE_URL}/api/v1/public/scan/{owner}/{repo}/og-image"

    # Try to get cached scan data for rich tags
    from src.api.public_scan_router import _get_cached, _get_entity_trust

    # Check for entity trust (composite score) first
    entity_trust = await _get_entity_trust(full_name, db)

    if (
        entity_trust
        and entity_trust.get("imported")
        and entity_trust.get("composite_score") is not None
    ):
        score = entity_trust["composite_score"]
        grade = entity_trust["grade"]
    else:
        cached = await _get_cached(owner, repo)
        if cached:
            score = cached["trust_score"]
            grade = _grade_from_score(score)
        else:
            # No scan data available — generic tags
            title = f"Is {full_name} Safe? | AgentAvow Security Scan"
            description = (
                f"Check the security posture of {full_name} on AgentAvow. "
                "Free automated security scanning for any GitHub repository."
            )
            return HTMLResponse(
                content=_render_og_html(title, description, image_url, canonical_url),
                status_code=200,
            )

    verdict = _verdict_text(grade)
    title = f"Is {full_name} Safe? Grade: {grade} ({score}/100)"
    description = f"Security scan: {verdict}."

    # Add findings summary if from cache
    if not (
        entity_trust
        and entity_trust.get("imported")
        and entity_trust.get("composite_score") is not None
    ):
        cached = await _get_cached(owner, repo)
        if cached:
            findings = cached.get("findings", {})
            critical = findings.get("critical", 0)
            high = findings.get("high", 0)
            if critical > 0 or high > 0:
                parts = []
                if critical > 0:
                    parts.append(f"{critical} critical")
                if high > 0:
                    parts.append(f"{high} high")
                description += f" Found {', '.join(parts)} issues."
            else:
                description += " No critical findings."

    return HTMLResponse(
        content=_render_og_html(title, description, image_url, canonical_url),
        status_code=200,
    )


# ── Profile OG endpoint ────────────────────────────────────────────────


@router.get("/profile/{entity_id}", response_class=HTMLResponse)
async def og_profile(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Serve OG meta tags for /profile/:entity_id pages.

    Called by nginx when a social crawler user agent hits /profile/*.
    Returns minimal HTML with OG tags and a meta-refresh redirect.
    """
    from src.models import Entity, TrustScore

    canonical_url = f"{BASE_URL}/profile/{entity_id}"
    # Default OG image — could be enhanced with a profile OG image endpoint later
    image_url = f"{BASE_URL}/api/v1/public/scan/{entity_id}/og-image"

    # Parse entity_id as UUID
    try:
        eid = uuid.UUID(entity_id)
    except ValueError:
        # Invalid UUID — return generic tags
        title = "Profile | AgentAvow"
        description = "View this entity's trust profile on AgentAvow."
        return HTMLResponse(
            content=_render_og_html(title, description, image_url, canonical_url),
            status_code=200,
        )

    # Look up entity
    entity = (
        await db.execute(select(Entity).where(Entity.id == eid))
    ).scalar_one_or_none()

    if not entity:
        title = "Profile Not Found | AgentAvow"
        description = "This profile does not exist on AgentAvow."
        return HTMLResponse(
            content=_render_og_html(title, description, image_url, canonical_url),
            status_code=200,
        )

    display_name = entity.display_name or entity.handle or "Unknown"
    entity_type = "Agent" if entity.type == "agent" else "User"

    # Look up trust score
    ts = (
        await db.execute(
            select(TrustScore).where(TrustScore.entity_id == eid)
        )
    ).scalar_one_or_none()

    if ts:
        score100 = round(ts.score * 100)
        grade = _grade_from_score(score100)
        title = f"{display_name} on AgentAvow — Trust Score: {grade} ({score100}/100)"
        description = (
            f"{entity_type} with verified identity on AgentAvow. "
            f"Trust grade: {grade} ({score100}/100)."
        )
    else:
        title = f"{display_name} on AgentAvow"
        description = f"{entity_type} profile on AgentAvow — the trust layer for AI agents."

    # Use badge as OG image if entity has a source_url with GitHub repo
    if entity.source_url and "github.com/" in (entity.source_url or ""):
        # Extract owner/repo from source_url
        parts = entity.source_url.rstrip("/").split("github.com/")
        if len(parts) == 2:
            repo_path = parts[1].split("?")[0].split("#")[0]
            if "/" in repo_path:
                image_url = (
                    f"{BASE_URL}/api/v1/public/scan/{repo_path}/og-image"
                )

    return HTMLResponse(
        content=_render_og_html(title, description, image_url, canonical_url),
        status_code=200,
    )


# ── Package / model / container / MCP / skill OG endpoints ─────────────────
# The newer score surfaces. nginx routes a social crawler on /check/pkg/*,
# /check/mcp, /check/skill/* here; real users still get the SPA.

def _og_image_url(title: str, grade: str, score, subtitle: str) -> str:
    from urllib.parse import urlencode
    q = urlencode({
        "title": title, "grade": grade or "",
        "score": "" if score is None else int(score), "subtitle": (subtitle or "")[:180],
    })
    return f"{BASE_URL}/api/v1/public/scan/og.png?{q}"


def _og_verdict(score: int | None) -> str:
    if score is None:
        return "A signed safety grade — verify it offline."
    if score >= 81:
        return "Safe to use · signed, verifiable offline."
    if score >= 61:
        return "Generally safe · signed, verifiable offline."
    if score >= 41:
        return "Use with caution · signed, verifiable offline."
    return "Significant risks · signed, verifiable offline."


@router.get("/pkg/{surface}/{name:path}", response_class=HTMLResponse)
async def og_package(surface: str, name: str) -> HTMLResponse:
    """OG tags for a package/model/container score page (/check/pkg/:surface/*)."""
    from src.api.public_scan_router import _display_grade, _get_cached

    surface = (surface or "").strip().lower()
    name = (name or "").strip().strip("/")
    full = f"{surface}:{name}"
    canonical_url = f"{BASE_URL}/check/pkg/{surface}/{name}"
    grade, score, subtitle = "", None, ""
    cached = await _get_cached(surface, name)
    if cached:
        score = cached.get("trust_score")
        _elig = (cached.get("certified") or {}).get("eligible")
        grade = cached.get("grade") or _display_grade(score or 0, _elig)
        subtitle = (cached.get("tool_description") or "").strip()
    if not subtitle:
        subtitle = _og_verdict(score)
    title = f"{name} ({surface})"
    description = f"{name} scored {grade or '—'} on AgentAvow — {_og_verdict(score)}"
    image_url = _og_image_url(full, grade, score, subtitle)
    return HTMLResponse(content=_render_og_html(title, description, image_url, canonical_url))


@router.get("/skill/{owner}/{repo}", response_class=HTMLResponse)
async def og_skill(owner: str, repo: str, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    """OG tags for an OpenClaw skill score page (/check/skill/:owner/:repo)."""
    from src.api.public_scan_router import _get_cached

    full_name = f"{owner}/{repo}"
    canonical_url = f"{BASE_URL}/check/skill/{owner}/{repo}"
    grade, score = "", None
    cached = await _get_cached(owner, repo)
    if cached:
        score = cached.get("trust_score")
        grade = cached.get("grade") or _grade_from_score(score or 0)
    subtitle = "OpenClaw agent skill · " + _og_verdict(score)
    title = f"{full_name} — Agent Skill"
    description = f"{full_name} scored {grade or '—'} on AgentAvow — {_og_verdict(score)}"
    image_url = _og_image_url(full_name, grade, score, subtitle)
    return HTMLResponse(content=_render_og_html(title, description, image_url, canonical_url))


@router.get("/mcp", response_class=HTMLResponse)
async def og_mcp(endpoint: str = "") -> HTMLResponse:
    """OG tags for a live MCP server score page (/check/mcp?endpoint=…)."""
    from urllib.parse import quote

    ep = (endpoint or "").strip()
    canonical_url = f"{BASE_URL}/check/mcp?endpoint={quote(ep, safe='')}"
    title = "MCP server — safety grade"
    subtitle = "Live-graded MCP server · " + _og_verdict(None)
    description = f"AgentAvow live-graded this MCP server's served tool surface. {ep}".strip()
    image_url = _og_image_url(ep or "MCP server", "", None, subtitle)
    return HTMLResponse(content=_render_og_html(title, description, image_url, canonical_url))
