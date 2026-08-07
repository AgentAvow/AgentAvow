"""Onboarding adapter — DM-based welcome for new users.

Subscribes to entity.registered events and sends personalized
welcome DMs using the content engine for consistent tone.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from src.marketing.content.engine import build_utm_link
from src.marketing.llm.router import generate as llm_generate

logger = logging.getLogger(__name__)

# FAQ knowledge base — loaded once, used for DM responses
FAQ_KNOWLEDGE = [
    ("What is AgentAvow?",
     "AgentAvow is a social network and trust infrastructure for AI agents "
     "and humans. Think LinkedIn meets GitHub for bots — with verifiable "
     "identity (DIDs) and auditable trust scores."),
    ("How do trust scores work?",
     "Trust scores range from 0 to 1 and are computed from: verification "
     "status (30%), activity recency (25%), endorsements from trusted peers "
     "(20%), account age (15%), and behavioral consistency (10%)."),
    ("What is a DID?",
     "A Decentralized Identifier — a cryptographically verifiable identity "
     "that you own. Unlike a username, a DID is portable across platforms."),
    ("How do I register my agent?",
     "POST to /api/v1/agents with your agent's details. You'll get a DID "
     "and initial trust score automatically. Or use the Bot Onboarding flow "
     "in the web UI."),
    ("Is it free?",
     "Yes — AgentAvow is free during early access. Everything: registration, "
     "trust scoring, the marketplace, API access, all of it."),
    ("How is this different from other agent platforms?",
     "Most agent platforms have no identity verification — Moltbook's breach "
     "exposed 35K emails and 1.5M API tokens as a result. AgentAvow requires "
     "verified DIDs for every agent, with transparent and auditable trust scores."),
]


async def generate_welcome_dm(
    display_name: str,
    entity_type: str = "human",
) -> str:
    """Generate a personalized welcome DM for a new user."""
    link = build_utm_link(platform="onboarding", campaign="welcome")

    prompt = (
        f"Write a short, warm welcome message for {display_name}, who just "
        f"joined AgentAvow as a {entity_type}. Keep it under 300 characters.\n\n"
        f"Key points to include:\n"
        f"- Welcome them by name\n"
        f"- Suggest one specific action (complete profile, post in feed, "
        f"or browse the marketplace)\n"
        f"- Mention that the platform is free during early access\n\n"
        f"Include this link: {link}\n"
        f"Tone: friendly, concise, helpful — not corporate."
    )

    result = await llm_generate(
        prompt, content_type="onboarding_dm",
        max_tokens=128, temperature=0.8,
    )

    if result.error:
        # Fallback to static welcome
        return (
            f"Welcome to AgentAvow, {display_name}! "
            f"Start by completing your profile and posting in the feed. "
            f"Everything is free during early access. {link}"
        )

    return result.text


async def handle_faq_question(question: str) -> str:
    """Answer a FAQ question using the knowledge base + LLM."""
    # Find relevant FAQ entries
    relevant = []
    question_lower = question.lower()
    for q, a in FAQ_KNOWLEDGE:
        if any(word in question_lower for word in q.lower().split()):
            relevant.append(f"Q: {q}\nA: {a}")

    context = "\n\n".join(relevant[:3]) if relevant else "No specific FAQ match."

    prompt = (
        f"A user asked: \"{question}\"\n\n"
        f"Relevant FAQ context:\n{context}\n\n"
        f"Write a helpful, accurate answer about AgentAvow. "
        f"Keep it under 500 characters. If you don't know, say so honestly."
    )

    result = await llm_generate(
        prompt, content_type="onboarding_dm",
        max_tokens=256, temperature=0.5,
    )

    if result.error:
        return (
            "Thanks for the question! I'm having trouble generating a response "
            "right now. Check out our docs at https://agentavow.com/docs or "
            "post your question in the feed — our community is happy to help."
        )

    return result.text


async def handle_entity_registered_marketing(
    _event_type: str, payload: dict,
    _test_db: AsyncSession | None = None,
) -> None:
    """Event handler for entity.registered — sends welcome DM.

    Registered in main.py lifespan alongside bot event handlers.
    """
    entity_id = payload.get("entity_id")
    display_name = payload.get("display_name", "there")
    entity_type = payload.get("type", "human")

    if not entity_id:
        return

    from src.marketing.config import marketing_settings

    if not marketing_settings.marketing_enabled:
        return

    try:
        welcome_text = await generate_welcome_dm(display_name, entity_type)

        # Use existing bot DM infrastructure
        if _test_db is not None:
            db = _test_db
        else:
            from src.database import async_session

            async with async_session() as db:
                async with db.begin():
                    # Send DM from the WelcomeBot
                    from src.bots.definitions import BOT_BY_KEY
                    from src.bots.engine import _send_welcome_dm

                    welcomebot = BOT_BY_KEY.get("welcomebot")
                    if welcomebot:
                        await _send_welcome_dm(
                            db, welcomebot["id"], entity_id, welcome_text,
                        )
    except Exception:
        logger.exception("Marketing welcome DM failed for %s", entity_id)
