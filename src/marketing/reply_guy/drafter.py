"""Generate reply drafts for detected opportunities using LLM."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from src.database import async_session
from src.marketing.content.ai_tells import VOICE_PROMPT_FRAGMENT
from src.marketing.content.ai_tells import check as check_ai_tells
from src.marketing.llm.router import generate as llm_generate
from src.models import ReplyOpportunity

logger = logging.getLogger(__name__)

_AGENTAVOW_CONTEXT = (
    "AgentAvow is a trust verification platform for AI agents. "
    "Its free tool at agentavow.com/check lets anyone check if an AI agent, "
    "MCP server, or skill is safe before installing — like checking a restaurant's "
    "health grade before eating there. Results are cryptographically signed and "
    "independent of any platform. We scanned 231 OpenClaw skills and found 14,350 "
    "security issues (32% scored F). Gen Z increasingly distrusts AI but can't stop "
    "using it — independent verification answers the question they're already asking: "
    "'is this safe?' Also: 7 PyPI packages for trust-gated tool execution across "
    "LangChain, CrewAI, AutoGen, PydanticAI, and MCP."
)

_REPLY_PROMPT = """\
You are a knowledgeable AI engineer who works on agent trust infrastructure. \
Draft a reply to this post:

Post by {author} ({followers} followers):
"{post_content}"

Context about your work: {context}

Guidelines:
- Add genuine technical insight related to the post's topic
- Only mention AgentAvow if directly relevant -- most replies should NOT mention it
- Match the platform's tone ({platform}: {tone_hint})
- Keep it 1-3 sentences, natural and conversational
- Be helpful and insightful, not promotional
- Never use hashtags in replies
- Never start with "Great post!" or similar sycophantic openers

Draft reply (just the reply text, nothing else):
"""

_TONE_HINTS = {
    "bluesky": "concise, developer-friendly, thoughtful",
    "twitter": "punchy, concise, max 280 chars",
}


async def generate_drafts(limit: int = 20) -> dict:
    """Generate drafts for all undrafted opportunities. Returns stats."""
    async with async_session() as db:
        opps = (
            await db.scalars(
                select(ReplyOpportunity)
                .options(selectinload(ReplyOpportunity.target))
                .where(ReplyOpportunity.status == "new")
                .order_by(ReplyOpportunity.urgency_score.desc())
                .limit(limit)
            )
        ).all()

    stats: dict = {"drafted": 0, "errors": 0}
    for opp in opps:
        try:
            await _draft_single(opp)
            stats["drafted"] += 1
        except Exception:
            logger.exception("Failed to draft reply for %s", opp.id)
            stats["errors"] += 1

    logger.info("Reply drafter: %s", stats)
    return stats


async def _draft_single(opp: ReplyOpportunity) -> None:
    """Generate a draft reply for a single opportunity."""
    target = opp.target

    # Never draft against an empty source post — that produced meta-refusals
    # ("the post appears empty, could you share what they wrote…") which then
    # auto-posted. Skip loudly instead of asking the LLM to reply to nothing.
    if not (opp.post_content or "").strip():
        async with async_session() as db:
            opp_db = await db.get(ReplyOpportunity, opp.id)
            if opp_db:
                opp_db.status = "skipped"
                await db.commit()
        logger.info("Skipped reply draft for %s: empty source post", opp.id)
        return

    prompt = _REPLY_PROMPT.format(
        author=target.display_name or target.handle,
        followers=target.follower_count,
        post_content=(opp.post_content or "")[:500],
        context=_AGENTAVOW_CONTEXT,
        platform=opp.platform,
        tone_hint=_TONE_HINTS.get(opp.platform, "conversational"),
    )

    base_system = (
        "You are a technical expert writing a reply on social media. "
        "Output ONLY the reply text. No quotes, no preamble, no explanation."
    )
    # Self-learning: feed in the replies that actually earned engagement.
    try:
        from src.marketing.content.performance import get_reply_learning_context
        async with async_session() as _db:
            base_system = base_system + await get_reply_learning_context(_db, opp.platform)
    except Exception:
        pass
    result = await llm_generate(
        prompt,
        content_type="engagement_reply",
        system=base_system + VOICE_PROMPT_FRAGMENT,
        max_tokens=200,
        temperature=0.7,
    )

    if result.error:
        logger.warning("LLM error drafting reply: %s", result.error)
        return

    # AI-tell linter — retry once with hint if first draft trips it.
    tell_check = check_ai_tells(result.text, platform=opp.platform, strict=True)
    if not tell_check.passed:
        logger.info(
            "Reply draft tripped AI-tell linter for %s (%s); retrying",
            opp.id, tell_check.reasons,
        )
        retry_prompt = (
            f"{prompt}\n\n## Previous draft was rejected by the voice linter\n"
            f"{tell_check.hint()}\n"
            f"Write a new reply that does not have those issues."
        )
        retry = await llm_generate(
            retry_prompt,
            content_type="engagement_reply",
            system=base_system + VOICE_PROMPT_FRAGMENT,
            max_tokens=200,
            temperature=0.7,
        )
        if not retry.error and retry.text:
            second = check_ai_tells(retry.text, platform=opp.platform, strict=True)
            if second.passed:
                result = retry
            else:
                logger.warning(
                    "Reply draft still tripping linter after retry for %s; "
                    "shipping retry anyway",
                    opp.id,
                )
                result = retry

    draft = result.text.strip().strip('"').strip("'")

    # Platform length limits
    max_len = 300 if opp.platform == "bluesky" else 280
    if len(draft) > max_len:
        # Truncate at last sentence boundary
        truncated = draft[:max_len]
        last_period = truncated.rfind(".")
        if last_period > max_len // 2:
            draft = truncated[: last_period + 1]
        else:
            draft = truncated.rsplit(" ", 1)[0] + "..."

    # Content-integrity gate before the draft can ever reach the auto-poster: reject
    # brief-echoes, stage directions, and meta-refusals (single source of truth).
    from src.marketing.content.engine import content_quality_issue

    _issue = content_quality_issue(draft)
    if _issue:
        async with async_session() as db:
            opp_db = await db.get(ReplyOpportunity, opp.id)
            if opp_db:
                opp_db.status = "failed"
                await db.commit()
        logger.warning(
            "Reply draft for %s failed content-quality gate (%s): %r",
            opp.id, _issue, draft[:100],
        )
        return

    async with async_session() as db:
        opp_db = await db.get(ReplyOpportunity, opp.id)
        if opp_db:
            opp_db.draft_content = draft
            opp_db.status = "drafted"
            opp_db.drafted_at = datetime.now(timezone.utc)
            # Recalculate urgency (may have decayed)
            from src.marketing.reply_guy.monitor import _calculate_urgency

            opp_db.urgency_score = _calculate_urgency(
                {
                    "text": opp.post_content,
                    "timestamp": opp.post_timestamp,
                    "likes": opp.engagement_count,
                },
                target,
            )
            await db.commit()
