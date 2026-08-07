"""LLM router — picks the right model based on content type and budget.

Hierarchy:
- Templates (Jinja2) — $0, used for stats/recurring formats
- Haiku — ~$0.002/post, used for high-volume boosts and low-priority content
- Sonnet — ~$0.02/post, used for replies and engagement
- Opus — ~$0.10/post, used for proactive social posts (first impressions matter)
- Ollama (Qwen 3.5 9B) — $0, local fallback when budget is exceeded

When daily budget is exceeded, falls back to Ollama, then templates.
When budget hits 80%, notifies admin to request a budget increase.
"""
from __future__ import annotations

import logging
from enum import Enum

from src.config import settings
from src.marketing.llm.anthropic_client import LLMResponse
from src.marketing.llm.cost_tracker import (
    is_over_daily_budget,
    is_over_monthly_budget,
    record_usage,
)

logger = logging.getLogger(__name__)


class ContentTier(str, Enum):
    """Content importance tier — determines which model to use."""

    TEMPLATE = "template"          # Zero cost, Jinja2
    VOLUME = "volume"              # Haiku (high-volume boosts, low-priority)
    STANDARD = "standard"          # Sonnet (replies, engagement, blogs)
    PREMIUM = "premium"            # Opus (proactive social posts, first impressions)
    HIGH_STAKES = "high_stakes"    # Opus (HN drafts, launch copy, critical)


# Map content types to default tiers
CONTENT_TYPE_TIERS: dict[str, ContentTier] = {
    # Proactive social posts — Opus (first impressions matter)
    "twitter_post": ContentTier.PREMIUM,
    "reddit_post": ContentTier.PREMIUM,
    "bluesky_post": ContentTier.PREMIUM,
    "linkedin_post": ContentTier.PREMIUM,
    "telegram_post": ContentTier.PREMIUM,
    "discord_post": ContentTier.PREMIUM,
    "github_discussions_post": ContentTier.PREMIUM,
    "huggingface_post": ContentTier.PREMIUM,
    # Replies / engagement — Sonnet
    "reply": ContentTier.STANDARD,
    "engagement_reply": ContentTier.STANDARD,
    "onboarding_dm": ContentTier.STANDARD,
    # Blog / long-form — Sonnet
    "devto_article": ContentTier.STANDARD,
    "hashnode_article": ContentTier.STANDARD,
    # High-stakes — Opus
    "hackernews_draft": ContentTier.HIGH_STAKES,
    "producthunt_draft": ContentTier.HIGH_STAKES,
    "launch_announcement": ContentTier.HIGH_STAKES,
    # Reddit scout drafts — Sonnet (quality matters, manual posting)
    "reddit_scout_draft": ContentTier.STANDARD,
    # HuggingFace scout drafts — Sonnet (technical discussions)
    "hf_scout_draft": ContentTier.STANDARD,
    # High-volume / boosts — Haiku
    "boost_reply": ContentTier.VOLUME,
    "thread_continuation": ContentTier.VOLUME,
    # Data-driven (templates)
    "stats_post": ContentTier.TEMPLATE,
    "weekly_digest": ContentTier.TEMPLATE,
    "agent_announcement": ContentTier.TEMPLATE,
}


async def generate(
    prompt: str,
    *,
    content_type: str = "twitter_post",
    tier_override: ContentTier | None = None,
    system: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.7,
) -> LLMResponse:
    """Route a generation request to the appropriate LLM.

    Checks budget before using paid models.  Falls back gracefully:
    Opus → Sonnet → Haiku → Ollama → error.

    When budget reaches 80%, nudges admin via notification.
    """
    tier = tier_override or CONTENT_TYPE_TIERS.get(content_type, ContentTier.STANDARD)

    # Template tier — caller should use templates directly, not this function
    if tier == ContentTier.TEMPLATE:
        return LLMResponse(
            text="", model="template", tokens_in=0, tokens_out=0,
            error="Use templates directly for TEMPLATE tier content",
        )

    # Check budget for paid tiers
    over_daily = await is_over_daily_budget()
    over_monthly = await is_over_monthly_budget()

    # Nudge admin when budget is getting close (80%)
    await _check_budget_nudge()

    if over_daily or over_monthly:
        logger.warning(
            "LLM budget exceeded (daily=%s, monthly=%s) — falling back to local",
            over_daily, over_monthly,
        )
        result = await _generate_local(prompt, system=system, max_tokens=max_tokens,
                                       temperature=temperature)
        if not result.error:
            return result
        return LLMResponse(
            text="", model="budget_exceeded", tokens_in=0, tokens_out=0,
            error="LLM budget exceeded and local model unavailable",
        )

    # Route to the right Anthropic model
    return await _generate_anthropic(
        prompt, tier=tier, system=system, max_tokens=max_tokens,
        temperature=temperature,
    )


async def _generate_local(
    prompt: str, *, system: str | None = None,
    max_tokens: int = 1024, temperature: float = 0.7,
) -> LLMResponse:
    """Generate using local Ollama."""
    from src.marketing.llm.ollama_client import generate as ollama_generate

    result = await ollama_generate(
        prompt, system=system, max_tokens=max_tokens, temperature=temperature,
    )
    if not result.error:
        await record_usage(result.model, result.tokens_in, result.tokens_out)
    return result


async def _generate_anthropic(
    prompt: str, *, tier: ContentTier,
    system: str | None = None, max_tokens: int = 1024,
    temperature: float = 0.7,
) -> LLMResponse:
    """Generate using the Anthropic API with the tier-appropriate model."""
    from src.marketing.config import marketing_settings
    from src.marketing.llm.anthropic_client import generate as anthropic_generate

    model_map = {
        ContentTier.VOLUME: marketing_settings.anthropic_haiku_model,
        ContentTier.STANDARD: marketing_settings.anthropic_sonnet_model,
        ContentTier.PREMIUM: marketing_settings.anthropic_opus_model,
        ContentTier.HIGH_STAKES: marketing_settings.anthropic_opus_model,
    }
    model = model_map.get(tier, marketing_settings.anthropic_sonnet_model)

    result = await anthropic_generate(
        prompt, model=model, system=system, max_tokens=max_tokens,
        temperature=temperature,
    )

    if not result.error:
        cost = await record_usage(result.model, result.tokens_in, result.tokens_out)
        logger.info(
            "LLM generation: model=%s tokens_in=%d tokens_out=%d cost=$%.4f",
            result.model, result.tokens_in, result.tokens_out, cost,
        )

    return result


# --- Budget nudge ---
# Redis key to prevent spamming notifications
_BUDGET_NUDGE_KEY = "ag:mktg:budget_nudge_sent:{date}"


async def _check_budget_nudge() -> None:
    """Send admin a notification when budget reaches 80%.

    Only sends once per day. Checks daily budget first, then monthly.
    """
    from src.marketing.config import marketing_settings
    from src.marketing.llm.cost_tracker import get_daily_spend as _get_daily
    from src.marketing.llm.cost_tracker import get_monthly_spend as _get_monthly

    daily_spend = await _get_daily()
    monthly_spend = await _get_monthly()
    daily_cap = marketing_settings.marketing_llm_daily_budget
    monthly_cap = marketing_settings.marketing_llm_monthly_budget

    daily_pct = daily_spend / daily_cap if daily_cap > 0 else 0
    monthly_pct = monthly_spend / monthly_cap if monthly_cap > 0 else 0

    if daily_pct < 0.8 and monthly_pct < 0.8:
        return

    # Check if we already nudged today
    from datetime import date as _date

    today = _date.today().isoformat()
    nudge_key = _BUDGET_NUDGE_KEY.format(date=today)
    try:
        from src.redis_client import get_redis

        r = get_redis()
        already_sent = await r.get(nudge_key)
        if already_sent:
            return
        await r.set(nudge_key, "1", ex=86400)
    except Exception:
        pass  # Proceed without dedup if Redis is down

    # Build the nudge message with engagement context
    if daily_pct >= 0.8:
        title = "MarketingBot needs more daily budget"
        body = (
            f"Daily spend: ${daily_spend:.2f} / ${daily_cap:.2f} "
            f"({daily_pct:.0%}). "
            f"Monthly: ${monthly_spend:.2f} / ${monthly_cap:.2f}. "
            f"I'm running low and will fall back to lower-quality "
            f"local models or templates for the rest of the day. "
            f"If engagement is looking good, consider bumping "
            f"MARKETING_LLM_DAILY_BUDGET."
        )
    else:
        title = "MarketingBot needs more monthly budget"
        body = (
            f"Monthly spend: ${monthly_spend:.2f} / ${monthly_cap:.2f} "
            f"({monthly_pct:.0%}). "
            f"Daily: ${daily_spend:.2f} / ${daily_cap:.2f}. "
            f"I'll start downgrading post quality soon. "
            f"Check the dashboard for engagement metrics — if "
            f"the ROI looks good, consider increasing "
            f"MARKETING_LLM_MONTHLY_BUDGET."
        )

    # Send notification to admin + email
    try:
        await _send_budget_nudge(title, body)
    except Exception:
        logger.exception("Failed to send budget nudge notification")


async def _send_budget_nudge(title: str, body: str) -> None:
    """Create an in-app notification and send an email to admin."""
    from sqlalchemy import select

    from src.database import async_session
    from src.email import send_email
    from src.models import Entity, Notification

    async with async_session() as db:
        # Find admin entity
        result = await db.execute(
            select(Entity).where(
                Entity.email == settings.admin_email,
                Entity.is_active.is_(True),
            ).limit(1),
        )
        admin = result.scalar_one_or_none()
        if not admin:
            return

        # In-app notification
        notif = Notification(
            entity_id=admin.id,
            kind="budget_alert",
            title=title,
            body=body,
        )
        db.add(notif)
        await db.commit()

        # Email
        html = (
            f"<div style='font-family:sans-serif;padding:20px;'>"
            f"<h2 style='color:#6366f1;'>{title}</h2>"
            f"<p>{body}</p>"
            f"<p><a href='https://agentavow.com/admin'>View Marketing Dashboard</a></p>"
            f"</div>"
        )
        await send_email(admin.email, title, html)
        logger.info("Budget nudge sent to admin: %s", title)
