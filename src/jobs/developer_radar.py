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


async def _fetch_readme(owner: str, repo: str, token: str | None) -> str | None:
    """Best-effort README text — feeds both the shields signal and the LLM draft."""
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
                return None
            return base64.b64decode(r.json().get("content", "")).decode("utf-8", "ignore")
    except Exception:
        return None


async def _llm_draft(owner: str, repo: str, description: str, score: int | None,
                     certified: bool, badge_ask: bool, top_finding: str | None,
                     readme: str | None) -> str | None:
    """An LLM-written, genuinely specific outreach note that reads the maintainer's
    actual README — not a template. Returns None if the LLM is unavailable (caller
    falls back to the deterministic template)."""
    system = (
        "You write a SHORT personal message from Kenne, a founder who is genuinely trying "
        "to solve trust for AI-agent tools and wants to solve it WITH the maintainer, not "
        "sell them anything. This must read like a real human wrote it from the heart in "
        "one sitting — NOT a marketing pitch, NOT a feature list, NOT polished corporate "
        "copy. Voice rules: warm, humble, a little informal; plain everyday words, not "
        "jargon; it's fine if the grammar isn't perfect or a sentence runs on — that reads "
        "human. Reference ONE specific real thing about THEIR tool (from the README) so it's "
        "clearly not a template. Weave in genuine notes like: 'I saw you were working on X "
        "and I really want to solve the trust problem with agent tools', 'I hope this isn't "
        "too forward', 'honestly I'm just trying to build trust for the tools agents "
        "connect to', 'regardless, I'd love your feedback', 'any ideas on how we could "
        "build trust here that I'm not thinking about?', 'help me solve this'. Ask for their "
        "help/ideas, don't pitch. 3-5 short sentences. No emojis. At most ONE link (their "
        "own report). For a HIGH scorer you can mention the free badge exists but softly, as "
        "an aside, never the point. For a LOWER scorer, offer to help with the specific "
        "finding and do NOT mention a badge. End on wanting to solve this together. It should "
        "feel like a person, not a product."
    )
    excerpt = (readme or description or "")[:1600]
    posture = (
        "HIGH scorer — pride+proof, offer the signed badge" if badge_ask
        else "LOWER scorer — value-first, cite the finding, NO badge ask"
    )
    prompt = (
        f"Maintainer's tool: {owner}/{repo}\n"
        f"One-line description: {description or '(none)'}\n"
        f"AgentAvow score: {score}/100"
        f"{' — CERTIFIED, the earned top tier' if certified else ''}\n"
        f"Posture: {posture}\n"
        f"Top finding: {top_finding or 'none notable'}\n"
        f"Their signed report: https://agentavow.com/check/{owner}/{repo}\n\n"
        f"README excerpt:\n{excerpt}\n\nWrite the outreach note only — no preamble."
    )
    try:
        from src.marketing.llm.anthropic_client import generate
        r = await generate(prompt, system=system, max_tokens=420, temperature=0.7)
        text = (r.text or "").strip()
        return text or None
    except Exception:
        logger.debug("radar LLM draft failed for %s/%s", owner, repo, exc_info=True)
        return None


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


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _top_finding(result) -> str | None:
    """The single most-severe finding, phrased for an outreach note."""
    fs = sorted(getattr(result, "findings", []) or [],
                key=lambda x: _SEV_ORDER.get(x.severity, 5))
    if not fs:
        return None
    f = fs[0]
    loc = ""
    if getattr(f, "file_path", None):
        loc = f.file_path + (f":{f.line_number}" if getattr(f, "line_number", None) else "")
    return f"a {f.severity}-severity {f.category} finding" + (f" in {loc}" if loc else "")


def _draft(owner: str, repo: str, score: int | None, certified: bool,
           badge_ask: bool, top_finding: str | None) -> str:
    """A personalized, value-first outreach draft that uses our own tools (the signed
    score, the specific finding, the README badge). Kenne personalizes + sends manually."""
    # Human, from-the-heart fallback (used only if the LLM is down). Deliberately plain
    # and a little informal — asks for help, doesn't pitch. See _llm_draft for the voice.
    url = f"https://agentavow.com/check/{owner}/{repo}"
    if certified or badge_ask:
        return (
            f"Hey — hope this isn't too forward. I came across {repo} and really liked what "
            f"you're building. I'm honestly just trying to figure out how we build trust for "
            f"the tools agents connect to, and yours came out looking really solid ({url}). "
            f"There's a little badge thing if you ever want it, but no pressure at all — "
            f"mostly I'd just love your take: what would actually make you trust a tool "
            f"before you connect it? Trying to solve this and would rather do it with people "
            f"actually building in this space."
        )
    finding = f" (the thing that stood out was {top_finding})" if top_finding else ""
    return (
        f"Hey — I hope this is ok to send. I've been trying to solve the trust problem for "
        f"agent tools and I ran {repo} through what I'm building{finding}. Not trying to "
        f"call anything out — genuinely just want to help if it's useful, here's the full "
        f"thing: {url}. Honestly I'd love your feedback too — any ideas on how we could "
        f"build trust here that I'm not thinking about? Would love to solve this together."
    )


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
            readme = await _fetch_readme(owner, repo, token)
            has_shields = bool(readme and _SHIELDS_RE.search(readme))
            rank = _rank(score, p.stars or 0, has_shields, certified, crit, high)
            top = _top_finding(result)
            # Prefer an LLM-written, repo-specific note; fall back to the template.
            llm = await _llm_draft(
                owner, repo, p.description or "", score, certified,
                rank["badge_ask"], top, readme,
            )
            draft = llm or _draft(owner, repo, score, certified, rank["badge_ask"], top)

            p.notes = json.dumps({
                "trust_score": score, "certified": certified,
                "critical": crit, "high": high, "has_shields": has_shields,
                "stars": p.stars, "score_url": f"https://agentavow.com/check/{owner}/{repo}",
                "top_finding": top, "draft": draft,
                "draft_source": "llm" if llm else "template",
                **rank,
            })
            p.status = "queued"
            summary["scored"] += 1
            summary["queued"] += 1
        except asyncio.TimeoutError:
            # A candidate scan overran the 90s budget — expected under load (e.g. the
            # corpus grind running concurrently, or GitHub rate limits). Not a bug: the
            # radar is human-gated and just skips this candidate. WARN, don't page Sentry.
            logger.warning(
                "developer_radar: scan timed out for %s/%s (skipped)", owner, repo,
            )
            summary["errors"] += 1
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
