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
     "AgentAvow gives any tool, MCP server, or package an AI agent connects to "
     "a signed, verifiable safety score — so you know whether it's safe to connect. "
     "Paste a URL and get a 0-100 trust score backed by scan evidence anyone can "
     "recompute offline."),
    ("How do trust scores work?",
     "Every scan reads the actual source across 12 safety categories — exposed "
     "secrets, unsafe code execution, data handling, network and filesystem access, "
     "prompt-injection surfaces, obfuscation, and dependency health — and produces "
     "a 0-100 trust score plus a signed attestation. Higher is safer; the earned "
     "top tier is Certified."),
    ("What makes the score verifiable?",
     "Every result is signed with Ed25519 (JWS). You can verify any attestation "
     "offline against our public keys — no call back to us required. If a single "
     "byte of the score is altered, verification fails. It's a signature, not just "
     "a badge."),
    ("What is a DID?",
     "A Decentralized Identifier — a cryptographically verifiable identity. "
     "AgentAvow's signer publishes a did:web identity, so anyone can tie an "
     "attestation back to the exact key that produced it."),
    ("How do I check a tool?",
     "Paste a GitHub repo, MCP server, or npm/PyPI package URL at "
     "agentavow.com/check — free, no account, no install. You can also add a "
     "one-line trust badge to your README that renders your live signed score."),
    ("Is it free?",
     "Yes. Checking any tool and browsing the catalog are free and need no "
     "account. An account is only for watching tools for change-alerts, managing "
     "API keys, or claiming repositories you own."),
    ("How is this different from other agent platforms?",
     "A fully identified, fully authorized agent can still connect to a poisoned "
     "tool — whether the tool is safe to connect is the third axis, next to "
     "identity and authorization. AgentAvow grades that and signs the verdict so "
     "anyone can recompute it. It's the safety-grading layer underneath agent "
     "ecosystems, not another directory or marketplace."),
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
        f"- Suggest one specific action (check a tool at agentavow.com/check, "
        f"add a signed trust badge to their README, or browse the trust catalog)\n"
        f"- Mention that checking tools is free and needs no account\n\n"
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
            f"Start by checking a tool at agentavow.com/check — it's free, no "
            f"account needed — and add a signed trust badge to your README. {link}"
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
            "right now. Check out our docs at https://agentavow.com/docs — "
            "we're happy to help."
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
