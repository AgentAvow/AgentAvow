"""Content engine — routes generation to LLM, template, or local model.

The engine is the central content generation hub.  It:
1. Picks a topic (respecting cooldowns)
2. Gets the platform-specific angle and tone
3. Routes to the right generation method (template vs LLM)
4. Runs content through the safety filter
5. Appends UTM links and bot disclosure
6. Deduplicates via SHA-256 content hash
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from src.marketing.config import marketing_settings
from src.marketing.content.ai_tells import VOICE_PROMPT_FRAGMENT
from src.marketing.content.ai_tells import check as check_ai_tells
from src.marketing.content.tone import ToneProfile, get_tone
from src.marketing.content.topics import Topic, get_angle, pick_topic
from src.marketing.llm.cost_tracker import estimate_cost
from src.marketing.llm.router import generate as llm_generate

logger = logging.getLogger(__name__)

BASE_URL = "https://agentavow.com"

# Global knowledge injected into all LLM prompts so the marketing bot
# is aware of recent milestones and the competitive landscape.
_GLOBAL_KNOWLEDGE = (
    "\n\n## Current AgentAvow context (March 2026)\n"
    "- AgentAvow is live at agentavow.com — the trust and identity layer "
    "for AI agents. Early access: free registration, trust scoring, "
    "marketplace, API access.\n"
    "- Competitive landscape: Moltbook (770K agents, zero identity "
    "verification, acquired by Meta — breach exposed 35K emails + 1.5M "
    "API tokens), OpenClaw (512 CVEs, 12% malware in skills marketplace). "
    "These are cautionary tales, not competitors — we're the trust layer.\n"
    "- Our differentiator: verifiable DIDs, transparent trust scores, "
    "auditable trails. Every agent gets a cryptographic identity.\n"
    "- We're actively recruiting agent operators from GitHub, npm, "
    "PyPI, HuggingFace — verified trust badges for READMEs.\n"
    "- World/Tools for Humanity: launched 'proof of human' for agentic "
    "commerce — validates our thesis that agents need identity.\n"
    "- Bluesky: $100M Series B, AT Protocol — decentralised social "
    "aligns with our values.\n"
    "- NVIDIA GTC: $1T AI chip projection. Compute layer (them) + "
    "trust layer (us).\n"
    "- Our Bluesky custom feed 'AI Agent News' is live — curated AI agent "
    "developments at bsky.app/profile/agentavow.bsky.social/feed/ai-agent-news\n"
    "- New: mcp-security-scan — open-source CLI + GitHub Action for "
    "scanning MCP servers. Repo: github.com/AgentAvow/mcp-security-scan "
    "(MIT license). Scans for credential theft, data exfiltration, unsafe "
    "execution, filesystem access, and code obfuscation. Outputs a trust "
    "score 0-100 that integrates with AgentAvow trust badges. Available as "
    "a GitHub Action for CI/CD pipelines. This is a pull-based growth tool — "
    "developers discover AgentAvow through the scanner.\n"
    "- Our brand IS trust — always be transparent that this content "
    "is bot-generated.\n"
)


@dataclass
class GeneratedContent:
    """Result of content generation."""

    text: str
    topic: str
    platform: str
    post_type: str
    llm_model: str | None = None
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0
    llm_cost_usd: float = 0.0
    content_hash: str = ""
    utm_params: dict | None = None
    image_path: str | None = None
    error: str | None = None


def content_hash(text: str) -> str:
    """SHA-256 hash for deduplication."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _generate_with_voice_check(
    prompt: str,
    *,
    system: str,
    content_type: str,
    max_tokens: int,
    temperature: float | None = None,
    platform: str = "generic",
):
    """Generate content with one retry if the AI-tell linter rejects the draft.

    Adds VOICE_PROMPT_FRAGMENT to the system prompt so the model avoids the
    tells in the first place. If the first draft still fails the linter,
    retries once with the linter's regeneration hint appended. If retry
    also fails, returns the better of the two drafts and logs a warning —
    we never block content entirely on a tell, only nudge it.
    """
    augmented_system = system + VOICE_PROMPT_FRAGMENT
    kwargs: dict = {
        "system": augmented_system,
        "content_type": content_type,
        "max_tokens": max_tokens,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature

    result = await llm_generate(prompt, **kwargs)
    if result.error or not result.text:
        return result

    first_check = check_ai_tells(result.text, platform=platform, strict=True)
    if first_check.passed:
        return result

    # Retry with hint
    logger.info(
        "AI-tell linter rejected first draft for %s (reasons=%s); retrying",
        platform, first_check.reasons,
    )
    retry_prompt = (
        f"{prompt}\n\n## Previous draft was rejected by the voice linter\n"
        f"{first_check.hint()}\n"
        f"Write a new draft that does not have those issues."
    )
    retry = await llm_generate(retry_prompt, **kwargs)
    if retry.error or not retry.text:
        return result  # fall back to first draft

    second_check = check_ai_tells(retry.text, platform=platform, strict=True)
    if second_check.passed:
        return retry

    logger.warning(
        "AI-tell linter rejected both drafts for %s (first=%s, retry=%s); "
        "shipping retry anyway",
        platform, first_check.reasons, second_check.reasons,
    )
    # Ship retry — usually closer to passing even if not perfect
    return retry


def build_utm_link(
    path: str = "/",
    platform: str = "twitter",
    campaign: str = "general",
) -> str:
    """Build a URL with UTM parameters for attribution tracking."""
    params = {
        "utm_source": marketing_settings.utm_source,
        "utm_medium": platform,
        "utm_campaign": campaign,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{BASE_URL}{path}?{query}"


# The LLM sometimes labels its own output ("Short post (under 300 chars):",
# "Long-form (1500-2000 words).", "Single post, bot-labelled.", "2-post thread.
# Post 1:") or wraps the whole post in quotes — strip that so it never ships.
_META_PREFIX_RE = re.compile(
    r"^\s*(?:"
    r"short post[^:.\n]*[:.]|long[- ]?form[^:.\n]*[:.]|"
    r"single post[^:.\n]*[:.]|(?:\d+|two|three)[- ]post thread[^:.\n]*[:.]|"
    r"post\s*\d+\s*:|thread\s*:|title\s*:|draft\s*:|"
    r"here'?s?\s+(?:a|the)\s+\w+[^:\n]*:"
    r")\s*",
    re.IGNORECASE,
)


def _strip_meta_prefix(text: str) -> str:
    """Remove leading format-labels / wrapping quotes the LLM sometimes adds to
    its own output, so they never get posted as the content."""
    t = (text or "").strip()
    for _ in range(3):  # labels can stack, e.g. "2-post thread. Post 1:"
        m = _META_PREFIX_RE.match(t)
        if not m:
            break
        t = t[m.end():].strip()
    # Unwrap if the entire post is wrapped in matching quotes.
    if len(t) >= 2 and t[0] in "\"'‘“" and t[-1] in "\"'’”":
        t = t[1:-1].strip()
    return t


# Unfilled template placeholders: a bare "%" (NOT "12%"), {var}, <var>, XX, ___.
_PLACEHOLDER_RE = re.compile(
    r"(?:^|\s)%(?:\s|$)"      # bare percent sign, e.g. "...: % with unsafe exec"
    r"|\{[a-z0-9_]{2,}\}"     # {variable}
    r"|<[a-z0-9_]{2,}>"       # <variable>
    r"|\bXX+\b"               # XX / XXX numeric placeholder
    r"|_{3,}",                # ___ blank
    re.IGNORECASE,
)
# Brief-echo: the content DESCRIBES the post instead of being it. Must start with
# a post-type noun (modulo a/an/the) followed by a meta verb within ~50 chars.
_BRIEF_ECHO_RE = re.compile(
    r"^\s*(?:a |an |the )?"
    r"(?:tweet|post|thread|reply|skeet|toot|article|blog\s*post|linkedin\s*post)\b"
    r"[^.\n]{0,50}?\b"
    r"(?:sharing|share|about|that|which|covering|highlighting|announcing|"
    r"recapping|summari[sz]ing|describing|explaining|discussing|promoting|linking)\b",
    re.IGNORECASE,
)


def content_quality_issue(text: str) -> str | None:
    """Return a reason string if ``text`` looks like an unfilled brief/template
    rather than finished copy, else None.

    Single source of truth for "is this real content or LLM scaffolding?" —
    called at every boundary that posts or queues content (proactive generation,
    the draft queue, planned campaign posts) so brief-echoes and unfilled
    placeholders can never reach a live post or the review queue again.
    """
    t = (text or "").strip()
    if not t:
        return "empty"
    if _BRIEF_ECHO_RE.match(t):
        return "brief-echo (describes the post instead of being the post)"
    if _PLACEHOLDER_RE.search(t):
        return "unfilled placeholder (bare %, {var}, XX, or ___)"
    return None


async def generate_proactive(
    platform: str,
    recent_topics: list[str] | None = None,
    topic_override: Topic | None = None,
) -> GeneratedContent:
    """Generate a proactive post for a platform.

    Picks a topic, generates content via the LLM router, and
    applies platform-specific tone and formatting.
    """
    topic = topic_override or await pick_topic(
        platform, recent_topics=recent_topics,
        cooldown_hours=marketing_settings.topic_cooldown_hours,
    )
    if not topic:
        return GeneratedContent(
            text="", topic="", platform=platform, post_type="proactive",
            error="No topic available (all on cooldown)",
        )

    tone = get_tone(platform)
    angle = get_angle(topic, platform)
    utm_link = build_utm_link(platform=platform, campaign=topic.key)

    # Gather news signals for topical relevance
    # Lookback = days between posts for this platform (7 / posts_per_week)
    news_context = ""
    try:
        from src.marketing.config import PLATFORM_SCHEDULE
        from src.marketing.news_signals import gather_news_signals

        ppw = PLATFORM_SCHEDULE.get(platform, {}).get("posts_per_week", 3)
        lookback_days = max(2, 7 // ppw)  # e.g. 2x/week → 3 days, 1x/week → 7 days
        signals = await gather_news_signals(limit=5, days=lookback_days)
        if signals:
            lines: list[str] = []
            for s in signals[:5]:
                line = f"- {s['title']} ({s['source']})"
                summary = s.get("summary")
                if summary:
                    line += f": {summary[:120]}"
                lines.append(line)
            headlines = "\n".join(lines)
            news_context = (
                f"\n\nToday's trending AI/tech news "
                f"(reference if relevant):\n{headlines}\n"
            )
    except Exception:
        pass  # News signals are optional

    # Build the prompt
    launch_context = ""
    if marketing_settings.pre_launch:
        launch_context = (
            "\n\nIMPORTANT: AgentAvow is NOT publicly launched yet. "
            "Frame it as 'coming soon' or 'building in public'. "
            "Tease what it will offer, build curiosity. "
            "Do NOT say 'check it out' or 'sign up' — "
            "say things like 'we're building', 'coming soon', "
            "'follow along', 'stay tuned'.\n"
        )

    # Operator recruitment topic gets additional context for the LLM
    recruitment_context = ""
    if topic.key == "operator_recruitment":
        recruitment_context = (
            "\n\n## Key facts about operator recruitment\n"
            "- AgentAvow is in early access — free registration, trust "
            "scoring, marketplace, API access\n"
            "- We're actively recruiting agent operators from GitHub, npm, "
            "PyPI, and HuggingFace\n"
            "- Every registered agent gets: a W3C DID, trust score, public "
            "profile, and embeddable README badge\n"
            "- Trust badges for GitHub READMEs are a key growth mechanic\n"
            "- Onboarding takes ~2 minutes at agentavow.com/bot-onboarding\n"
            "- Competitive context: Moltbook (770K agents, zero identity "
            "verification, 1.5M API tokens leaked), OpenClaw (512 CVEs, "
            "12% malware in skills marketplace)\n"
            "- AgentAvow provides what competitors don't: verifiable identity "
            "(DIDs), trust scoring, auditable evolution trails, and an open "
            "social graph\n"
            "\n## Links to include\n"
            "- Register your agent: https://agentavow.com/bot-onboarding\n"
            "- Discover agents: https://agentavow.com/discover\n"
            "- Learn more: https://agentavow.com\n"
        )

    # Global knowledge is always included so the bot knows about
    # the competitive landscape and transparency stance.
    global_ctx = _GLOBAL_KNOWLEDGE if topic.key != "operator_recruitment" else ""

    if platform in ("devto", "hashnode"):
        prompt = _build_blog_prompt(
            platform=platform,
            angle=angle,
            utm_link=utm_link,
            tone=tone,
            news_context=news_context,
            launch_context=launch_context,
            recruitment_context=recruitment_context,
            global_context=global_ctx,
        )
    elif platform == "github_discussions":
        prompt = _build_github_discussions_prompt(
            angle=angle,
            utm_link=utm_link,
            news_context=news_context,
            launch_context=launch_context,
            recruitment_context=recruitment_context,
            global_context=global_ctx,
        )
    else:
        prompt = (
            f"Write a {platform} post about AgentAvow "
            f"based on this angle:\n\n"
            f"{angle}\n\n"
            f"Include this full link (keep the https://): {utm_link}\n\n"
            f"Maximum length: {tone.max_length} characters.\n"
            f"Platform: {platform}\n"
            f"Output ONLY the post text itself — no labels (never write "
            f"'Short post:', 'Single post', 'Thread:', '2-post thread.', etc.), "
            f"no surrounding quotes, no preamble or meta-commentary about format.\n"
            f"{news_context}"
            f"{launch_context}"
            f"{recruitment_context}"
            f"{global_ctx}"
        )

    # Determine content type for LLM tier routing
    content_type = f"{platform}_post"
    if platform in ("devto", "hashnode"):
        content_type = f"{platform}_article"

    result = await _generate_with_voice_check(
        prompt,
        system=tone.system_prompt,
        content_type=content_type,
        max_tokens=_max_tokens_for_platform(platform),
        platform=platform,
    )

    if result.error:
        return GeneratedContent(
            text="", topic=topic.key, platform=platform, post_type="proactive",
            error=result.error,
        )

    # Strip self-labels ("Short post:", "Long-form:", "2-post thread. Post 1:")
    # the LLM sometimes prepends, then guard against empty output.
    stripped = _strip_meta_prefix(result.text)
    if not stripped:
        return GeneratedContent(
            text="", topic=topic.key, platform=platform, post_type="proactive",
            error="LLM returned empty content",
        )

    # Guard against LLM instruction leakage (meta-instructions in output)
    _leakage_markers = (
        "post in a relevant",
        "post in ",
        "post this to",
        "share in ",
        "share this in",
        "publish this",
        "submit to",
        "create a discussion",
        "title:",
        "body:",
        "ideally ",
        "here's a draft",
        "here is a draft",
        "suggested post",
    )
    # Check first 3 lines, not just the first — leakage can start on line 2
    check_text = "\n".join(
        stripped.split("\n", 3)[:3],
    ).lower()
    if any(marker in check_text for marker in _leakage_markers):
        logger.warning(
            "LLM instruction leakage detected for %s/%s: %s",
            platform, topic.key, check_text[:100],
        )
        return GeneratedContent(
            text="", topic=topic.key, platform=platform, post_type="proactive",
            error="LLM instruction leakage detected — content rejected",
        )

    # Guard against unfilled briefs/placeholders ("Tweet sharing ... %") reaching
    # a live post. Same gate runs in enqueue_draft + planned-post posting.
    _quality = content_quality_issue(stripped)
    if _quality:
        logger.warning(
            "Content quality gate rejected %s/%s: %s | %s",
            platform, topic.key, _quality, stripped[:80],
        )
        return GeneratedContent(
            text="", topic=topic.key, platform=platform, post_type="proactive",
            error=f"Content quality gate: {_quality}",
        )

    # Apply disclosure footer
    text = stripped
    if tone.disclosure:
        text = text + tone.disclosure

    # Truncate if needed
    if len(text) > tone.max_length:
        text = text[: tone.max_length - 1] + "\u2026"

    # Safety check — only for short-form social platforms.
    # Long-form article platforms (devto, hashnode) generate 1500-3000 word technical
    # articles via our own LLM. The UGC content filter was designed for 280-char social
    # posts and has systematic false positives on long-form markdown:
    #   - noise_pattern: all-caps headings like "WHY AI AGENTS NEED TRUST INFRASTRUCTURE"
    #   - prompt_injection: sentences like "In a multi-agent system:" or code blocks
    #     showing OpenAI-style system prompts
    #   - excessive_links: technical articles legitimately reference many URLs
    # These are our own LLM outputs, not user-submitted content, so spam/abuse
    # screening is not the right gate. We still check short-form social posts.
    long_form_platforms = {"devto", "hashnode"}
    if platform not in long_form_platforms:
        from src.content_filter import check_content

        filter_result = check_content(text)
        if not filter_result.is_clean:
            logger.warning(
                "Generated content flagged by safety filter: %s", filter_result.flags,
            )
            return GeneratedContent(
                text="", topic=topic.key, platform=platform, post_type="proactive",
                error=f"Content flagged: {filter_result.flags}",
            )

    h = content_hash(text)

    # Resolve topic card image
    card_path = _resolve_card_image(topic.key)

    return GeneratedContent(
        text=text,
        topic=topic.key,
        platform=platform,
        post_type="proactive",
        llm_model=result.model,
        llm_tokens_in=result.tokens_in,
        llm_tokens_out=result.tokens_out,
        llm_cost_usd=estimate_cost(
            result.model, result.tokens_in, result.tokens_out,
        ),
        content_hash=h,
        utm_params={
            "source": marketing_settings.utm_source,
            "medium": platform,
            "campaign": topic.key,
        },
        image_path=card_path,
    )


async def generate_reactive(
    platform: str,
    mention_content: str,
    mention_author: str,
    context: str = "",
) -> GeneratedContent:
    """Generate a reply to a mention or keyword match.

    Routes through the LLM router, which maps ``reply`` content type to
    the STANDARD tier (Sonnet by default).  Falls back to Ollama when
    the daily budget is exceeded.
    """
    tone = get_tone(platform)
    utm_link = build_utm_link(platform=platform, campaign="reactive")

    prompt = (
        f"Someone on {platform} posted:\n\n"
        f'"{mention_content}"\n\n'
        f"Write a helpful, relevant reply that naturally mentions AgentAvow "
        f"where appropriate. Don't force it — if AgentAvow isn't relevant "
        f"to their question, just be helpful.\n\n"
        f"If relevant, include this link: {utm_link}\n\n"
        f"Maximum length: {min(tone.max_length, 500)} characters."
        f"{_GLOBAL_KNOWLEDGE}"
    )

    result = await _generate_with_voice_check(
        prompt,
        system=tone.system_prompt,
        content_type="reply",
        max_tokens=256,
        temperature=0.8,
        platform=platform,
    )

    if result.error:
        return GeneratedContent(
            text="", topic="reactive", platform=platform, post_type="reactive",
            error=result.error,
        )

    text = result.text
    if tone.disclosure:
        text = text + tone.disclosure

    h = content_hash(text)

    return GeneratedContent(
        text=text,
        topic="reactive",
        platform=platform,
        post_type="reactive",
        llm_model=result.model,
        llm_tokens_in=result.tokens_in,
        llm_tokens_out=result.tokens_out,
        llm_cost_usd=estimate_cost(
            result.model, result.tokens_in, result.tokens_out,
        ),
        content_hash=h,
        utm_params={
            "source": marketing_settings.utm_source,
            "medium": platform,
            "campaign": "reactive",
        },
    )


async def generate_data_driven(
    platform: str,
    template_key: str,
    **template_vars: object,
) -> GeneratedContent:
    """Generate a data-driven post using templates (zero LLM cost)."""
    from src.marketing.content.templates import render

    link = build_utm_link(platform=platform, campaign=template_key)
    template_vars["link"] = link

    text = render(template_key, platform, **template_vars)
    if not text:
        return GeneratedContent(
            text="", topic=template_key, platform=platform,
            post_type="data_driven",
            error=f"No template for {template_key}/{platform}",
        )

    tone = get_tone(platform)
    if tone.disclosure:
        text = text + tone.disclosure

    h = content_hash(text)

    return GeneratedContent(
        text=text,
        topic=template_key,
        platform=platform,
        post_type="data_driven",
        llm_model="template",
        content_hash=h,
        utm_params={
            "source": marketing_settings.utm_source,
            "medium": platform,
            "campaign": template_key,
        },
    )


def _build_github_discussions_prompt(
    *,
    angle: str,
    utm_link: str,
    news_context: str,
    launch_context: str,
    recruitment_context: str = "",
    global_context: str = "",
) -> str:
    """Build a prompt for GitHub Discussions posts on our repo.

    GitHub Discussions need a thoughtful, developer-oriented tone.
    The LLM must output ONLY the discussion body — no meta-instructions.
    """
    return (
        f"Write a GitHub Discussion post for the AgentAvow repository.\n\n"
        f"## Topic / angle\n"
        f"{angle}\n\n"
        f"## Requirements\n"
        f"- Output ONLY the discussion body text in Markdown\n"
        f"- Do NOT include a title line (it is set separately)\n"
        f"- Do NOT include instructions like 'post this to' or 'share in'\n"
        f"- Length: 300-800 words\n"
        f"- Format: Markdown with ## headings, bullet points, code examples\n"
        f"- Tone: developer sharing technical insights, not marketing copy\n"
        f"- Include honest trade-offs and open questions to spark discussion\n"
        f"- End with a question to encourage replies\n"
        f"- Include this link naturally: {utm_link}\n\n"
        f"## About AgentAvow\n"
        f"AgentAvow is trust infrastructure for AI agents: "
        f"verifiable identity (W3C DIDs), trust scoring, "
        f"social graph, and a marketplace. Open source at "
        f"github.com/AgentAvow/AgentAvow.\n"
        f"{news_context}"
        f"{launch_context}"
        f"{recruitment_context}"
        f"{global_context}"
    )


def _build_blog_prompt(
    *,
    platform: str,
    angle: str,
    utm_link: str,
    tone: ToneProfile,
    news_context: str,
    launch_context: str,
    recruitment_context: str = "",
    global_context: str = "",
) -> str:
    """Build a detailed prompt for blog/article platforms (Dev.to, Hashnode).

    Blog posts need much more structure than social media posts — the generic
    "Write a {platform} post" prompt produces thin or empty content because
    the LLM doesn't know what depth is expected.
    """
    return (
        f"Write a technical blog article for {platform} about AgentAvow.\n\n"
        f"## Article topic / angle\n"
        f"{angle}\n\n"
        f"## Requirements\n"
        f"- Length: 1500-3000 words\n"
        f"- Format: Markdown with headers (##), code blocks, and bullet points\n"
        f"- Start with a TL;DR section (2-3 sentences)\n"
        f"- Include at least one code example showing an API call or SDK usage\n"
        f"- Discuss architecture decisions and trade-offs honestly\n"
        f"- End with a conclusion and a link to learn more\n"
        f"- Include this link naturally in the article: {utm_link}\n"
        f"- Do NOT include YAML front matter (no --- block)\n"
        f"- Start directly with the article content (the title is set separately)\n"
        f"- Do NOT prefix with a length/format label — never write 'Long-form "
        f"(1500-2000 words).' or similar; just the article\n\n"
        f"## About AgentAvow\n"
        f"AgentAvow is a trust infrastructure platform for AI agents. "
        f"It provides verifiable identity (W3C DIDs), trust scoring, "
        f"social graph visualization, and a marketplace — creating a unified "
        f"space where AI agents and humans interact as peers. "
        f"Key features: on-chain DIDs, auditable agent evolution trails, "
        f"trust-scored social graph, MCP bridge for tool discovery.\n"
        f"{news_context}"
        f"{launch_context}"
        f"{recruitment_context}"
        f"{global_context}"
    )


def _max_tokens_for_platform(platform: str) -> int:
    """Return appropriate max_tokens for the platform's content length."""
    if platform in ("devto", "hashnode"):
        return 4096
    if platform in ("reddit", "linkedin", "github_discussions"):
        return 1024
    return 256


# Topic → card image mapping.  Falls back to "features" card.
_CARD_DIR = Path(__file__).resolve().parent.parent / "assets"

# Map topic keys to card filenames
_TOPIC_CARD_MAP: dict[str, str] = {
    "security": "card-security.png",
    "security_scanner": "card-security.png",
    "tutorials": "card-tutorials.png",
    "ecosystem": "card-ecosystem.png",
    "features": "card-features.png",
    "community": "card-community.png",
    "operator_recruitment": "card-features.png",
}


def _resolve_card_image(topic: str) -> str | None:
    """Find the card image for a topic, or None if missing."""
    filename = _TOPIC_CARD_MAP.get(topic)
    if not filename:
        filename = "card-features.png"  # fallback
    path = _CARD_DIR / filename
    if path.exists():
        return str(path)
    return None
