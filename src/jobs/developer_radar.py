"""Developer-discovery radar — the personalized, human-gated outreach queue.

Turns raw GitHub discovery into a ranked outreach list: it takes the MCP/agent-tool
prospects `src.recruitment.github_discovery` finds, **scans each with AgentAvow**,
detects whether the README already shows shields, and ranks them into a queue with a
recommended channel + angle. Kenne reviews + sends manually — this NEVER auto-contacts
anyone (bulk/scripted outreach is the top flag trigger).

Pipeline stages live on `RecruitmentProspect.status`:
  discovered → (this job) → queued   (enrichment JSON stashed in `.notes`)
No new table — enrichment rides in `notes`, the pipeline rides in `status`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import RecruitmentProspect

logger = logging.getLogger(__name__)

# The ideal first adopter: active, small-to-mid, high-scoring, already shows shields.
_IDEAL_STARS = (5, 800)
_BADGE_ASK_MIN = 80  # ≥80 → pride+proof badge note; below → value-first / fix, no badge ask
_SHIELDS_RE = re.compile(r"shields\.io|img\.shields\.io|badgen\.net|!\[[^\]]*\]\([^)]*badge", re.I)


async def _detect_shields(owner: str, repo: str, token: str | None) -> bool:
    """Best-effort: does the README already display badges? (zero-friction signal)."""
    try:
        import base64

        import httpx

        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/readme", headers=headers,
            )
            if r.status_code != 200:
                return False
            content = r.json().get("content", "")
            readme = base64.b64decode(content).decode("utf-8", "ignore")
            return bool(_SHIELDS_RE.search(readme))
    except Exception:
        return False


def _rank(score: int | None, stars: int, has_shields: bool, certified: bool,
          critical: int, high: int) -> dict:
    """Compute an outreach priority (0-100) + recommended channel + angle."""
    s = score or 0
    ideal_stars = _IDEAL_STARS[0] <= (stars or 0) <= _IDEAL_STARS[1]

    priority = s
    if has_shields:
        priority += 12       # already displays shields → zero friction to add one more
    if ideal_stars:
        priority += 8        # a personal note actually gets read at this size
    if certified:
        priority += 15
    priority = max(0, min(100, priority))

    if certified:
        channel = "personal note — lead with Certified (pride + proof)"
        angle = "Certified — the earned top tier; strongest possible proof point"
    elif s >= _BADGE_ASK_MIN:
        channel = "personal note — badge ask (pride + proof)"
        angle = f"scored {s}/100 — high; offer the signed README badge"
    elif critical > 0:
        channel = "value-first GitHub issue — cite the CRITICAL (file:line + fix); NO badge ask"
        angle = f"{s}/100 with a critical — help first, never a badge"
    else:
        channel = "value-first note/issue — cite the top finding; NO badge ask"
        angle = f"{s}/100 — offer a concrete fix, mention the badge only if they'd want it"

    return {"priority": priority, "channel": channel, "angle": angle,
            "badge_ask": certified or s >= _BADGE_ASK_MIN, "ideal_stars": ideal_stars}


async def run_developer_radar(
    db: AsyncSession, *, discover: bool = True, limit: int = 25,
) -> dict:
    """One radar cycle: refresh discovery, then scan + rank up to ``limit`` new
    ``discovered`` prospects into the ``queued`` outreach list. Human-gated — it
    never contacts anyone. Returns a summary."""
    from src.github_auth import get_github_token
    from src.scanner.scan import scan_repo

    summary = {"discovered": 0, "scored": 0, "queued": 0, "skipped": 0, "errors": 0}

    if discover:
        try:
            from src.recruitment.github_discovery import run_discovery_cycle
            summary["discovered"] = await run_discovery_cycle(db)
        except Exception:
            logger.exception("developer_radar: discovery cycle failed")

    prospects = (await db.execute(
        select(RecruitmentProspect)
        .where(RecruitmentProspect.platform == "github")
        .where(RecruitmentProspect.status == "discovered")
        .order_by(RecruitmentProspect.stars.desc())
        .limit(limit)
    )).scalars().all()

    token = await get_github_token()
    for p in prospects:
        owner, repo = p.owner_login, (p.repo_name or "")
        if not owner or not repo:
            summary["skipped"] += 1
            continue
        try:
            result = await asyncio.wait_for(
                scan_repo(full_name=f"{owner}/{repo}", token=token), timeout=90,
            )
            if getattr(result, "error", None):
                summary["errors"] += 1
                continue
            score = result.trust_score
            certified = bool((getattr(result, "certified", None) or {}).get("eligible"))
            crit = result.critical_count
            high = result.high_count
            has_shields = await _detect_shields(owner, repo, token)
            rank = _rank(score, p.stars or 0, has_shields, certified, crit, high)

            p.notes = json.dumps({
                "trust_score": score, "certified": certified,
                "critical": crit, "high": high, "has_shields": has_shields,
                "stars": p.stars, "score_url": f"https://agentavow.com/check/{owner}/{repo}",
                **rank,
            })
            p.status = "queued"
            summary["scored"] += 1
            summary["queued"] += 1
        except Exception:
            logger.exception("developer_radar: scan failed for %s/%s", owner, repo)
            summary["errors"] += 1

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        logger.exception("developer_radar: commit failed")

    logger.info("developer_radar cycle: %s", summary)
    return summary
