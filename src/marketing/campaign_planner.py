"""Weekly campaign planning system.

Generates structured campaign plans using Opus, saves them as
MarketingCampaign records, and supports approve/reject workflows.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.email import send_email
from src.marketing.config import PLATFORM_SCHEDULE, marketing_settings
from src.marketing.models import MarketingCampaign, MarketingPost
from src.marketing.news_signals import gather_news_signals

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are the campaign strategist for AgentAvow — the tool-safety layer \
for AI agents.

AgentAvow's positioning: it gives any tool, MCP server, package, or \
skill an AI agent connects to a signed, verifiable safety grade you can \
recompute offline — the "is this tool safe to connect?" third axis that \
sits next to identity and authorization.  Point it at a GitHub repo, MCP \
server, npm/PyPI package, or OpenClaw skill and it returns an A+ to F \
grade with per-finding detail and a cryptographic attestation (Ed25519 \
JWS) anyone can verify against the public JWKS.  The sharp line: a fully \
identified, fully authorized agent can still connect to a poisoned tool. \
That's the gap we close.  We are NOT a social network, a marketplace, or \
an agent framework — we operate underneath them as the safety-grading \
layer any gateway or agent framework can act on.

## Current focus (2026): tool-safety adoption
AgentAvow is live at agentavow.com/check.  Key growth mechanic: free \
signed safety grades and README badges for MCP servers, packages, and \
skills.  We're reaching out to MCP server authors, AI agent repos, \
npm/PyPI maintainers, and OpenClaw skill authors — anyone shipping a \
tool an agent connects to.  A scan is free and anonymous: point it at a \
repo and get back a letter grade, per-finding detail pointing at the \
exact line, and a JWS attestation.  Check any tool: agentavow.com/check.

## Current landscape (2026)
- OpenClaw: 190K+ GitHub stars but 512 CVEs and ~12% malware in its \
  skills marketplace (CVE-2026-25253, CVSS 8.8).  We scanned 231 OpenClaw \
  skills and found 14,350 security issues, 32% graded F.  This is exactly \
  the poisoned-tool gap AgentAvow grades.
- Moltbook: 770K agents, zero verification, a breach that exposed 35K \
  emails + 1.5M API tokens.  Identity alone saved no one — the tools were \
  unsafe.
- The framing that matters: World/Tools for Humanity ships "proof of \
  human" and every framework ships authorization, yet a fully identified, \
  fully authorized agent still connects to whatever tool it is pointed at. \
  Whether the tool is safe to connect is the unsolved axis.

## New: mcp-security-scan — open-source security scanner for MCP servers
We launched mcp-security-scan (github.com/AgentAvow/mcp-security-scan). \
It's an open-source CLI + GitHub Action (MIT licensed) that scans MCP servers \
for credential theft, data exfiltration, unsafe execution, filesystem access, \
and code obfuscation. Outputs a trust score 0-100 that integrates with \
AgentAvow trust badges. Key growth mechanic: developers discover AgentAvow \
through the scanner — pull-based, not push-based.

## CRITICAL: Bot content transparency
Given industry scandals like Moltbook's fake posts, transparency is paramount. \
ALL AgentAvow marketing content must be clearly identifiable as \
bot-generated. Never try to pass bot content as human-written. \
This is both ethical and strategic — our brand IS trust.

Your job is to produce a JSON campaign plan for the coming week.  \
The plan must respect platform norms:
- Reddit: 9:1 value-to-promotion ratio.  Lead with genuine insight.
- Hacker News: human-only; never auto-post.  Pure value, no product \
  pitching.
- Twitter/Bluesky: concise, opinionated takes.
- Dev.to / Hashnode: long-form technical deep-dives.
- LinkedIn: professional tone, thought leadership.
- Discord / Telegram: community engagement.

Respond ONLY with a JSON object (no markdown fences) matching this \
schema exactly:

{
  "strategy_summary": "<2-3 sentences>",
  "posts": [
    {
      "platform": "<string>",
      "topic": "<string>",
      "angle": "<specific hook>",
      "content_brief": "<what to write>",
      "day": "<monday|tuesday|...>",
      "value_type": "<pure_value|soft_mention|product_feature>",
      "why": "<why this will resonate>"
    }
  ],
  "news_hooks": [
    {"title": "<string>", "angle": "<string>"}
  ],
  "avoid_this_week": ["<string>"],
  "budget_estimate_usd": <float>
}
"""


async def _last_week_performance(
    db: AsyncSession,
) -> list[dict]:
    """Summarise marketing post performance from the past 7 days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    result = await db.execute(
        select(MarketingPost).where(
            MarketingPost.posted_at >= cutoff,
            MarketingPost.status == "posted",
        ).order_by(MarketingPost.posted_at.desc()),
    )
    rows = result.scalars().all()
    summary: list[dict] = []
    for row in rows:
        summary.append({
            "platform": row.platform,
            "topic": row.topic,
            "post_type": row.post_type,
            "engagement": row.metrics_json or {},
            "posted_at": (
                row.posted_at.isoformat() if row.posted_at else ""
            ),
        })
    return summary


def _parse_json_response(raw: str) -> dict | None:
    """Extract and parse JSON from an LLM response.

    Handles markdown code fences, preamble text, and minor
    truncation at the end.
    """
    import re

    text = raw.strip()

    # Try to extract JSON from code fences first
    fence_match = re.search(
        r"```(?:json)?\s*\n(.*?)```",
        text,
        re.DOTALL,
    )
    if fence_match:
        text = fence_match.group(1).strip()
    else:
        # Try to find the outermost { ... }
        start = text.find("{")
        if start >= 0:
            text = text[start:]

    # Try parsing as-is
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # If truncated, try closing open braces/brackets
    for suffix in ["}", "]}", "\"]}", "\"]}"]:
        try:
            return json.loads(text + suffix)
        except json.JSONDecodeError:
            continue

    return None


async def _configured_platforms() -> list[str]:
    """Return platforms eligible for content generation.

    A platform is eligible if its adapter is API-configured (needed to *auto-post*) OR
    it's a scheduled **human_review/manual** platform (``auto_post: False`` with
    ``posts_per_week > 0``). The latter — e.g. LinkedIn — is posted by hand, so it must
    get a draft generated WITHOUT a posting-API token. Gating those on ``is_configured()``
    silently drops them from the plan (the LinkedIn-drafts bug).
    """
    from src.marketing.orchestrator import _get_adapters, _is_manual_review_platform

    adapters = _get_adapters()
    eligible: list[str] = []
    for name, adapter in adapters.items():
        if _is_manual_review_platform(name) or await adapter.is_configured():
            eligible.append(name)
    return eligible


async def generate_weekly_plan(
    db: AsyncSession,
) -> dict:
    """Generate a weekly campaign plan via Opus.

    Returns the parsed plan dict and saves a MarketingCampaign
    record with status='proposed'.
    """
    from src.marketing.llm.anthropic_client import (
        generate as anthropic_generate,
    )

    perf = await _last_week_performance(db)
    signals = await gather_news_signals(limit=15, days=7)
    platforms = await _configured_platforms()

    today = date.today()
    today_weekday = today.weekday()  # 0=Mon
    # If generated early in the week (Mon-Wed), plan rest of this week + full next week.
    # If generated later (Thu-Sun), plan remaining days + full next week.
    # Always start from tomorrow so the first post fires the very next day.
    tomorrow = today + timedelta(days=1)
    remaining_this_week = 6 - today_weekday  # days left including today
    end_of_plan = today + timedelta(days=remaining_this_week + 7)
    week_label = tomorrow.isoformat()

    day_names = []
    for i in range(1, (end_of_plan - today).days + 1):
        d = today + timedelta(days=i)
        day_names.append(d.strftime("%A").lower())

    # Build per-platform schedule constraints for the LLM
    schedule_lines: list[str] = []
    for plat, cfg in PLATFORM_SCHEDULE.items():
        if plat in platforms:
            mode = "auto-post" if cfg.get("auto_post") else "human-review"
            schedule_lines.append(
                f"- **{plat}**: {cfg['posts_per_week']}x/week on "
                f"{', '.join(cfg['days'])} ({mode})"
            )

    schedule_block = "\n".join(schedule_lines) if schedule_lines else "No schedule constraints."

    user_prompt = (
        f"Plan starting: {week_label} "
        f"(today is {today.strftime('%A')})\n"
        f"Available days: {', '.join(day_names)}\n\n"
        f"## Configured platforms\n{json.dumps(platforms)}\n\n"
        f"## Platform posting schedule (MUST follow these days exactly)\n"
        f"{schedule_block}\n\n"
        f"IMPORTANT: Only schedule posts on the allowed days listed "
        f"above for each platform.  Do not exceed the posts_per_week "
        f"limit for any platform.\n\n"
        f"## Last week performance\n"
        f"{json.dumps(perf[:20], indent=2)}\n\n"
        f"## Trending news signals\n"
        f"{json.dumps(signals[:15], indent=2)}\n\n"
        "Generate a campaign plan with 5-7 specific post ideas.  "
        "For each post, explain WHY it will resonate.  "
        "Emphasise anti-ban strategy: Reddit needs 9:1, "
        "HN is human-only.  "
        "Budget estimate should reflect Anthropic API costs "
        "for content generation only.\n\n"
        "## Platform priority (we have ZERO followers on owned channels)\n"
        "1. **Reddit** (highest priority — 2 posts/week): "
        "topic-based reach, millions of subscribers see good posts "
        "regardless of our follower count.\n"
        "2. **Dev.to** (1 post/week): SEO value, ranks in Google, "
        "compounds over time.\n"
        "3. **Bluesky / Twitter** (3 posts/week each): "
        "credibility and presence only — zero reach until we "
        "build followers.\n"
        "4. **LinkedIn** (1 founder-voice draft/week, Wednesday → human review): "
        "first-person post for Kenne's personal profile; professional credibility.\n"
        "5. **Discord** (if configured): community engagement "
        "in existing servers.\n"
        "Allocate posts according to the platform schedule above. "
        "Do NOT over-index on Bluesky/Twitter."
    )

    resp = await anthropic_generate(
        prompt=user_prompt,
        model=marketing_settings.anthropic_opus_model,
        system=_SYSTEM_PROMPT,
        max_tokens=8192,
        temperature=0.6,
    )

    if resp.error:
        logger.error("Opus campaign plan failed: %s", resp.error)
        return {"error": resp.error}

    plan = _parse_json_response(resp.text)
    if plan is None:
        logger.error(
            "Failed to parse Opus plan JSON: %s", resp.text[:500],
        )
        return {"error": "json_parse_failure", "raw": resp.text[:1000]}

    plan["week_of"] = week_label

    # Override LLM's budget estimate with real pricing calculation.
    # Most posts use Haiku (~$0.002/post). Blogs use Sonnet (~$0.05/post).
    # The plan generation itself used Opus (~$0.15).
    n_posts = len(plan.get("posts", []))
    blog_platforms = {"devto", "hashnode"}
    n_blogs = sum(
        1 for p in plan.get("posts", [])
        if p.get("platform") in blog_platforms
    )
    n_social = n_posts - n_blogs
    # Haiku social: ~500 in + 200 out tokens → ~$0.0004/post
    # Sonnet blog: ~1000 in + 4000 out tokens → ~$0.063/post
    # Opus plan generation: ~2000 in + 4000 out → ~$0.33
    estimated = 0.33 + (n_social * 0.002) + (n_blogs * 0.07)
    plan["budget_estimate_usd"] = round(estimated, 2)

    # Persist as campaign record
    campaign = MarketingCampaign(
        id=uuid.uuid4(),
        name=f"Weekly plan — {week_label}",
        topic="weekly_campaign",
        platforms=[
            p.get("platform", "")
            for p in plan.get("posts", [])
        ],
        status="proposed",
        schedule_config=plan,
        start_date=tomorrow,
        end_date=end_of_plan,
    )
    db.add(campaign)
    await db.flush()

    plan["campaign_id"] = str(campaign.id)
    return plan


async def approve_campaign_plan(
    db: AsyncSession,
    campaign_id: uuid.UUID,
    approved_post_indices: list[int] | None = None,
) -> dict:
    """Approve a proposed campaign, creating planned posts.

    If *approved_post_indices* is ``None``, all posts in the
    plan are approved.  Otherwise only the specified indices.
    """
    result = await db.execute(
        select(MarketingCampaign).where(
            MarketingCampaign.id == campaign_id,
            MarketingCampaign.status == "proposed",
        ),
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        return {"error": "campaign_not_found_or_not_proposed"}

    plan = campaign.schedule_config or {}
    posts_spec = plan.get("posts", [])

    if approved_post_indices is not None:
        posts_spec = [
            posts_spec[i]
            for i in approved_post_indices
            if 0 <= i < len(posts_spec)
        ]

    created: list[dict] = []
    for spec in posts_spec:
        post = MarketingPost(
            id=uuid.uuid4(),
            campaign_id=campaign.id,
            platform=spec.get("platform", "unknown"),
            content=spec.get("content_brief", ""),
            content_hash="planned",
            post_type="proactive",
            topic=spec.get("topic", "")[:200],
            status="planned",
        )
        db.add(post)
        created.append({
            "id": str(post.id),
            "platform": spec.get("platform"),
            "topic": spec.get("topic"),
            "day": spec.get("day"),
        })

    campaign.status = "active"
    await db.flush()

    return {
        "campaign_id": str(campaign.id),
        "status": "active",
        "approved_posts": created,
    }


async def reject_campaign_plan(
    db: AsyncSession,
    campaign_id: uuid.UUID,
    feedback: str,
) -> dict:
    """Reject a proposed campaign, storing feedback."""
    result = await db.execute(
        select(MarketingCampaign).where(
            MarketingCampaign.id == campaign_id,
            MarketingCampaign.status == "proposed",
        ),
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        return {"error": "campaign_not_found_or_not_proposed"}

    config = dict(campaign.schedule_config or {})
    config["rejection_feedback"] = feedback
    campaign.schedule_config = config
    campaign.status = "rejected"
    await db.flush()

    return {
        "campaign_id": str(campaign.id),
        "status": "rejected",
        "feedback": feedback,
    }


async def _comment_worthy_html(db: AsyncSession, plan: dict) -> str:
    """Build the 'worth your personal comment this week' digest for the proposal email.

    The high-ROI engagement lever: Kenne commenting personally (esp. on LinkedIn) beats
    another scheduled post. Sources = the week's news hooks (founder-take fodder) + the top
    posts the reply-guy already flagged (real people in our space, often also on LinkedIn).
    """
    from sqlalchemy import select as _select

    from src.models import ReplyOpportunity, ReplyTarget

    items: list[str] = []
    for hook in plan.get("news_hooks", [])[:4]:
        title = hook.get("title", "")
        if title:
            items.append(
                f"<li>📰 <b>{title}</b> &mdash; your take: {hook.get('angle', '')}</li>"
            )
    try:
        rows = await db.execute(
            _select(ReplyOpportunity, ReplyTarget.handle)
            .join(
                ReplyTarget,
                ReplyOpportunity.target_id == ReplyTarget.id,
                isouter=True,
            )
            .where(ReplyOpportunity.status.in_(["new", "drafted"]))
            .order_by(ReplyOpportunity.urgency_score.desc().nullslast())
            .limit(3),
        )
        for opp, handle in rows.all():
            snip = (opp.post_content or "").strip().replace("\n", " ")[:90]
            who = f"[{opp.platform}] {handle or ''}".strip()
            items.append(f"<li>💬 <b>{who}</b>: “{snip}…”</li>")
    except Exception:  # noqa: BLE001 - digest is best-effort
        pass

    if not items:
        return ""
    return (
        "<h3>💬 Comment-worthy this week (engage personally)</h3>"
        "<p>Your <b>personal</b> voice on these beats another scheduled post &mdash; post a "
        "take on LinkedIn or comment in-thread. (Reply-guy handles routine X/Bluesky replies; "
        "these are the higher-touch ones worth <em>you</em>.)</p>"
        f"<ul>{''.join(items)}</ul>"
    )


async def send_campaign_proposal_email(
    db: AsyncSession,
    plan: dict,
    campaign_id: uuid.UUID,
) -> bool:
    """Email the admin a formatted campaign proposal."""
    week = plan.get("week_of", "unknown")
    subject = (
        f"MarketingBot: Proposed campaign for week of {week}"
    )

    posts_html = ""
    for i, post in enumerate(plan.get("posts", [])):
        posts_html += (
            f"<tr>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{i + 1}</td>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{post.get('platform', '')}</td>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{post.get('topic', '')}</td>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{post.get('angle', '')}</td>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{post.get('day', '')}</td>"
            f"<td style='padding:6px;border:1px solid #444'>"
            f"{post.get('value_type', '')}</td>"
            f"</tr>"
        )

    comment_html = await _comment_worthy_html(db, plan)

    avoid_items = ", ".join(plan.get("avoid_this_week", []))
    budget = plan.get("budget_estimate_usd", 0)

    html = (
        f"<h2>Campaign Proposal: Week of {week}</h2>"
        f"<p><b>Strategy:</b> "
        f"{plan.get('strategy_summary', '')}</p>"
        f"<h3>Planned Posts</h3>"
        f"<table style='border-collapse:collapse;width:100%'>"
        f"<tr style='background:#222;color:#fff'>"
        f"<th style='padding:6px;border:1px solid #444'>#</th>"
        f"<th style='padding:6px;border:1px solid #444'>"
        f"Platform</th>"
        f"<th style='padding:6px;border:1px solid #444'>"
        f"Topic</th>"
        f"<th style='padding:6px;border:1px solid #444'>"
        f"Angle</th>"
        f"<th style='padding:6px;border:1px solid #444'>"
        f"Day</th>"
        f"<th style='padding:6px;border:1px solid #444'>"
        f"Type</th>"
        f"</tr>{posts_html}</table>"
        f"{comment_html}"
        f"<h3>Avoid This Week</h3><p>{avoid_items}</p>"
        f"<h3>Budget Estimate</h3>"
        f"<p>${budget:.2f} USD</p>"
        f"<p><em>Campaign ID: {campaign_id}</em></p>"
        f"<p>Reply to approve or reject this plan.</p>"
    )

    return await send_email(
        to=marketing_settings.marketing_notify_email,
        subject=subject,
        html_body=html,
    )


async def get_campaign_detail(
    db: AsyncSession,
    campaign_id: uuid.UUID,
) -> dict | None:
    """Fetch a campaign with its posts."""
    result = await db.execute(
        select(MarketingCampaign)
        .options(selectinload(MarketingCampaign.posts))
        .where(MarketingCampaign.id == campaign_id),
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        return None

    return {
        "id": str(campaign.id),
        "name": campaign.name,
        "topic": campaign.topic,
        "platforms": campaign.platforms or [],
        "status": campaign.status,
        "schedule_config": campaign.schedule_config,
        "start_date": (
            campaign.start_date.isoformat()
            if campaign.start_date
            else None
        ),
        "end_date": (
            campaign.end_date.isoformat()
            if campaign.end_date
            else None
        ),
        "created_at": campaign.created_at.isoformat(),
        "posts": [
            {
                "id": str(p.id),
                "platform": p.platform,
                "topic": p.topic,
                "status": p.status,
                "content": p.content,
                "posted_at": (
                    p.posted_at.isoformat()
                    if p.posted_at
                    else None
                ),
            }
            for p in (campaign.posts or [])
        ],
    }


async def get_proposed_campaigns(
    db: AsyncSession,
) -> list[dict]:
    """List all campaigns with status='proposed'."""
    result = await db.execute(
        select(MarketingCampaign)
        .where(MarketingCampaign.status == "proposed")
        .order_by(MarketingCampaign.created_at.desc()),
    )
    campaigns = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "name": c.name,
            "topic": c.topic,
            "platforms": c.platforms or [],
            "status": c.status,
            "start_date": (
                c.start_date.isoformat()
                if c.start_date
                else None
            ),
            "created_at": c.created_at.isoformat(),
        }
        for c in campaigns
    ]


async def get_planned_posts_for_today(
    db: AsyncSession,
) -> list[MarketingPost]:
    """Fetch planned posts from active campaigns for today."""
    today_name = date.today().strftime("%A").lower()
    result = await db.execute(
        select(MarketingPost)
        .join(MarketingCampaign)
        .options(selectinload(MarketingPost.campaign))
        .where(
            MarketingPost.status == "planned",
            MarketingCampaign.status == "active",
        )
        .order_by(MarketingPost.created_at.asc()),
    )
    posts = list(result.scalars().all())

    # Filter by day-of-week from the campaign schedule
    matched: list[MarketingPost] = []
    for post in posts:
        campaign_cfg = {}
        if post.campaign:
            campaign_cfg = post.campaign.schedule_config or {}
        plan_posts = campaign_cfg.get("posts", [])
        for spec in plan_posts:
            if (
                spec.get("platform") == post.platform
                and spec.get("topic") == post.topic
                and spec.get("day", "").lower() == today_name
            ):
                matched.append(post)
                break
    return matched
