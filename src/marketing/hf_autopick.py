"""HuggingFace Auto-Pick — automatically select and reply to the best discussion.

Scores discussions from hf_scout by keyword relevance, recency, comment count,
and whether we've already replied.  Generates a draft via the LLM router and
posts it through the HuggingFace adapter.

Called by the orchestrator on HF posting days (Wed/Sat).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.marketing.hf_scout import (
    RELEVANCE_KEYWORDS,
    HFDiscussion,
    scan_hf_discussions,
)

logger = logging.getLogger(__name__)

# Redis set key tracking discussion URLs we've already replied to
_REPLIED_KEY = "ag:mktg:hf:replied_urls"
_REPLIED_TTL = 90 * 86400  # 90 days


async def _get_replied_urls() -> set[str]:
    """Load the set of discussion URLs we've already replied to from Redis."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        members = await r.smembers(_REPLIED_KEY)
        return {m.decode() if isinstance(m, bytes) else m for m in members}
    except Exception:
        logger.debug("Could not load replied URLs from Redis")
        return set()


async def _mark_replied(url: str) -> None:
    """Record that we replied to a discussion."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        await r.sadd(_REPLIED_KEY, url)
        await r.expire(_REPLIED_KEY, _REPLIED_TTL)
    except Exception:
        logger.debug("Could not mark replied URL in Redis")


def _score_discussion(
    disc: HFDiscussion,
    replied_urls: set[str],
    now: datetime | None = None,
) -> float:
    """Score a discussion for auto-pick ranking.

    Weights:
    - Keyword match count: weight 3
    - Recency (prefer last 48hrs): weight 2
    - Comment count sweet spot (3-20): weight 1
    - Already replied: disqualified (returns -1)
    """
    if disc.url in replied_urls:
        return -1.0

    score = 0.0

    # (a) Keyword match count — weight 3
    keyword_score = len(disc.keywords_matched) * 3.0

    # Also check title for additional keyword matches not in content_preview
    title_lower = disc.title.lower()
    extra_kw = [
        kw for kw in RELEVANCE_KEYWORDS
        if kw in title_lower and kw not in disc.keywords_matched
    ]
    keyword_score += len(extra_kw) * 1.5  # Half weight for title-only matches

    score += keyword_score

    # (b) Recency — weight 2
    # Prefer discussions from last 48 hours, decay after that
    if now is None:
        now = datetime.now(timezone.utc)

    try:
        created = datetime.fromisoformat(
            disc.created_at.replace("Z", "+00:00"),
        )
        age_hours = (now - created).total_seconds() / 3600.0
        if age_hours <= 48:
            recency_score = 2.0 * (1.0 - age_hours / 48.0)  # 2.0 → 0.0 over 48hrs
        elif age_hours <= 168:  # Up to 7 days, diminishing returns
            recency_score = 0.5 * (1.0 - (age_hours - 48) / 120.0)
        else:
            recency_score = 0.0
        score += recency_score
    except (ValueError, AttributeError):
        pass  # No recency bonus if we can't parse the date

    # (c) Comment count sweet spot (3-20) — weight 1
    # Active but not overcrowded
    n = disc.num_comments
    if 3 <= n <= 20:
        # Peak at ~10 comments
        if n <= 10:
            comment_score = 1.0 * (n / 10.0)
        else:
            comment_score = 1.0 * (1.0 - (n - 10) / 10.0)
        score += comment_score
    elif n < 3:
        score += 0.2  # Low activity, small bonus
    # > 20: no bonus (too crowded)

    return score


async def pick_best_discussion(
    repos: list[str] | None = None,
) -> HFDiscussion | None:
    """Scan HF discussions and return the single best one to reply to.

    Returns None if no suitable discussions are found.
    """
    discussions = await scan_hf_discussions(repos=repos)
    if not discussions:
        logger.info("No HF discussions found to auto-pick")
        return None

    replied_urls = await _get_replied_urls()
    now = datetime.now(timezone.utc)

    scored: list[tuple[float, HFDiscussion]] = []
    for disc in discussions:
        s = _score_discussion(disc, replied_urls, now=now)
        if s > 0:
            scored.append((s, disc))

    if not scored:
        logger.info("All HF discussions either already replied or scored <= 0")
        return None

    scored.sort(key=lambda x: x[0], reverse=True)
    best_score, best_disc = scored[0]
    logger.info(
        "HF auto-pick: best=%s score=%.2f keywords=%s comments=%d",
        best_disc.url, best_score, best_disc.keywords_matched,
        best_disc.num_comments,
    )
    return best_disc


async def generate_hf_reply(disc: HFDiscussion) -> str | None:
    """Generate a draft reply for a HuggingFace discussion using the LLM.

    Uses the same prompt pattern as the admin generate_hf_draft endpoint.
    Returns the generated text, or None on failure.
    """
    from src.marketing.llm.router import generate as llm_generate

    prompt = (
        f"Write a reply to this HuggingFace discussion on "
        f"the model page `{disc.repo_id}`:\n\n"
        f"**Discussion title:** {disc.title}\n\n"
    )
    if disc.content_preview:
        prompt += f"**Discussion content:** {disc.content_preview}\n\n"

    # Gather news context for topical relevance
    news_snippet = ""
    try:
        from src.marketing.news_signals import gather_news_signals

        signals = await gather_news_signals(limit=3, days=4)  # HF posts 2x/week
        if signals:
            headlines = "\n".join(
                f"- {s['title']} ({s['source']})" for s in signals[:3]
            )
            news_snippet = (
                f"\n\nRecent AI/tech news (reference if relevant):\n"
                f"{headlines}\n"
            )
    except Exception:
        pass  # News signals are optional

    prompt += (
        "## Instructions\n"
        "- You are a developer who works on AI agent trust and "
        "identity infrastructure (AgentAvow).\n"
        "- Respond with genuine technical insight relevant to "
        "the discussion.\n"
        "- If agent trust, verification, or identity is relevant, "
        "mention AgentAvow naturally \u2014 don't force it.\n"
        "- Write 1-3 paragraphs. Be technically precise.\n"
        "- Reference the specific model/repo when relevant.\n"
        "- No marketing speak, no emojis.\n"
        f"{news_snippet}"
    )

    from src.marketing.content.ai_tells import VOICE_PROMPT_FRAGMENT
    from src.marketing.content.ai_tells import check as check_ai_tells

    system = (
        "You are a knowledgeable AI/ML engineer who participates "
        "in HuggingFace model discussions. You have expertise in "
        "agent identity, trust scoring, and multi-agent systems. "
        "Write like a real researcher sharing expertise."
    ) + VOICE_PROMPT_FRAGMENT

    result = await llm_generate(
        prompt,
        content_type="hf_scout_draft",
        system=system,
        max_tokens=512,
        temperature=0.7,
    )

    if result.error:
        logger.warning("HF reply LLM generation failed: %s", result.error)
        return None

    if not result.text or not result.text.strip():
        logger.warning("HF reply LLM returned empty content")
        return None

    # Reject AI-tell-laden drafts; one retry with the specific hint, same as
    # the reply-guy + engine paths. HF is an auto-post platform, so this is the
    # last gate before public posting.
    tell_check = check_ai_tells(result.text, platform="huggingface", strict=True)
    if not tell_check.passed:
        logger.info("HF draft tripped AI-tell check (%s); retrying", tell_check.reasons)
        retry = await llm_generate(
            prompt + f"\n\nYour previous draft read as AI-written. {tell_check.hint()}\n",
            content_type="hf_scout_draft",
            system=system,
            max_tokens=512,
            temperature=0.7,
        )
        if retry.text and retry.text.strip() and not retry.error:
            second = check_ai_tells(retry.text, platform="huggingface", strict=True)
            if second.passed:
                return retry.text.strip()
            logger.warning(
                "HF retry still tripped AI-tell check (%s); using cleaner of the two",
                second.reasons,
            )
            # Fall through to whichever had fewer flagged reasons.
            return (retry if len(second.reasons) < len(tell_check.reasons)
                    else result).text.strip()

    return result.text.strip()


async def post_hf_reply(
    disc: HFDiscussion,
    reply_text: str,
) -> bool:
    """Post the reply to a HuggingFace discussion via the adapter.

    Returns True on success, False on failure.
    """
    from src.marketing.adapters.huggingface import HuggingFaceAdapter

    adapter = HuggingFaceAdapter()
    if not await adapter.is_configured():
        logger.warning("HuggingFace adapter not configured, cannot post reply")
        return False

    result = await adapter.reply(
        parent_id=str(disc.discussion_num),
        content=reply_text,
        metadata={"repo_id": disc.repo_id},
    )

    if result.success:
        await _mark_replied(disc.url)
        logger.info("Posted HF reply to %s", disc.url)
        return True

    logger.warning("HF reply post failed: %s", result.error)
    return False


async def run_hf_autopick_cycle() -> dict:
    """Full auto-pick cycle: scan, pick, generate, post.

    Returns a dict with the result status for logging/monitoring.
    """
    result: dict = {"status": "no_action", "discussion": None, "posted": False}

    disc = await pick_best_discussion()
    if disc is None:
        return result

    result["discussion"] = disc.to_dict()
    result["status"] = "picked"

    reply_text = await generate_hf_reply(disc)
    if reply_text is None:
        result["status"] = "generation_failed"
        return result

    result["status"] = "generated"
    result["reply_preview"] = reply_text[:200]

    posted = await post_hf_reply(disc, reply_text)
    if posted:
        result["status"] = "posted"
        result["posted"] = True
    else:
        result["status"] = "post_failed"

    return result
