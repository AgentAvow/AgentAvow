"""Admin marketing dashboard and draft management API."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, get_db, require_admin
from src.models import AnalyticsEvent, Entity

router = APIRouter(prefix="/admin/marketing", tags=["admin"])


# --- Response models ---

class MarketingDashboardResponse(BaseModel):
    platform_stats: list[dict]
    topic_stats: list[dict]
    type_stats: list[dict]
    engagement: dict
    cost: dict
    recent_posts: list[dict]
    pending_drafts: int
    campaigns: list[dict]


class DraftResponse(BaseModel):
    id: uuid.UUID
    platform: str
    content: str
    topic: str | None
    post_type: str
    status: str
    llm_model: str | None
    created_at: str
    image_url: str | None = None
    destination: str | None = None
    parent_external_id: str | None = None
    scheduled_day: str | None = None
    thread_url: str | None = None
    thread_title: str | None = None
    # Per-platform playbook context (HN talking points/checklist/pre-scanned repos,
    # LinkedIn featured links, etc.) — surfaced in the admin UI to guide manual posting.
    playbook: dict | None = None

    model_config = {"from_attributes": True}


def _draft_playbook(post: object) -> dict | None:
    """Extract the platform-specific playbook block from utm_params, if any."""
    utm = getattr(post, "utm_params", None) or {}
    return (utm.get("platform_playbook") or {}).get(getattr(post, "platform", ""))


class DraftActionRequest(BaseModel):
    action: str = Field(..., pattern="^(approve|reject|edit_approve|edit|mark_posted)$")
    content: str | None = None  # Required for edit_approve
    reason: str | None = None   # Optional for reject
    posted_url: str | None = None  # Optional URL where it was manually posted


class CreateDraftRequest(BaseModel):
    """Admin-authored draft (hand-written, not LLM-generated) — e.g. LinkedIn / HN."""
    platform: str = Field(..., description="reddit, linkedin, hackernews, etc.")
    content: str = Field(..., min_length=1)
    topic: str | None = None
    post_type: str = "admin_manual"
    # Per-platform playbook: HN talking_points/checklist/pre_scanned/title_options,
    # LinkedIn featured_links/hashtags, etc. Stored under utm_params.platform_playbook.
    playbook: dict | None = None
    utm_params: dict | None = None


class WeeklyDigestResponse(BaseModel):
    week_start: str
    week_end: str
    platforms: list[dict]
    total_posts: int
    cost_breakdown: list[dict]
    total_cost_usd: float
    top_posts: list[dict]


class PlatformConversion(BaseModel):
    platform: str
    clicks: int
    signups: int
    cost_usd: float
    cost_per_signup: float | None


class ConversionResponse(BaseModel):
    platforms: list[PlatformConversion]
    total_clicks: int
    total_signups: int
    total_cost_usd: float


class ActivityItem(BaseModel):
    id: uuid.UUID
    platform: str
    content_preview: str
    status: str
    post_type: str
    topic: str | None
    external_id: str | None
    external_url: str | None = None
    posted_at: str | None
    created_at: str
    metrics: dict | None

    model_config = {"from_attributes": True}


class BotActivityResponse(BaseModel):
    posted: list[ActivityItem]
    pending_review: list[ActivityItem]
    failed: list[ActivityItem]
    total: int


class RedditThreadResponse(BaseModel):
    title: str
    url: str
    permalink: str
    subreddit: str
    score: int
    num_comments: int
    created_utc: float
    selftext_preview: str
    author: str
    keywords_matched: list[str]
    ranking_score: int | None = None


class RedditDraftRequest(BaseModel):
    thread_url: str = Field(..., description="Full Reddit thread URL")
    context: str | None = Field(
        None,
        description="Optional extra context for the LLM to consider",
    )


class RedditDraftResponse(BaseModel):
    thread_url: str
    thread_title: str
    draft_content: str
    llm_model: str | None
    llm_cost_usd: float
    promo_eligible: bool = False
    reddit_post_number: int = 0


class HFDiscussionResponse(BaseModel):
    title: str
    url: str
    repo_id: str
    discussion_num: int
    author: str
    num_comments: int
    status: str
    created_at: str
    content_preview: str
    keywords_matched: list[str]


class HFDraftRequest(BaseModel):
    repo_id: str = Field(..., description="HF repo ID (e.g. meta-llama/Llama-3.3-70B)")
    discussion_num: int = Field(..., description="Discussion number")
    discussion_title: str = Field(..., description="Discussion title for context")
    context: str | None = Field(None, description="Extra context for the LLM")


class HFDraftResponse(BaseModel):
    repo_id: str
    discussion_title: str
    draft_content: str
    llm_model: str | None
    llm_cost_usd: float


# --- Endpoints ---

@router.get("/dashboard", response_model=MarketingDashboardResponse)
async def get_marketing_dashboard(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> MarketingDashboardResponse:
    """Get marketing dashboard data — posts, engagement, costs, campaigns."""
    require_admin(current_entity)
    from src.marketing.dashboard import get_dashboard_data

    data = await get_dashboard_data(db)
    return MarketingDashboardResponse(**data)


@router.get("/drafts", response_model=list[DraftResponse])
async def get_pending_drafts(
    platform: str | None = None,
    status_filter: str | None = Query(
        None, alias="status",
        description="Comma-separated statuses (default: human_review,draft)",
    ),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> list[DraftResponse]:
    """Get drafts awaiting human review or in draft status."""
    require_admin(current_entity)
    from src.marketing.draft_queue import get_pending_drafts as _get_drafts

    statuses: list[str] | None = None
    if status_filter:
        statuses = [s.strip() for s in status_filter.split(",") if s.strip()]

    drafts = await _get_drafts(db, platform=platform, statuses=statuses)
    return [
        DraftResponse(
            id=d.id,
            platform=d.platform,
            content=d.content,
            topic=d.topic,
            post_type=d.post_type,
            status=d.status,
            llm_model=d.llm_model,
            created_at=d.created_at.isoformat(),
            image_url=_topic_image_url(d.topic, d.platform),
            parent_external_id=d.parent_external_id,
            scheduled_day=_get_scheduled_day(d),
            thread_url=(d.utm_params or {}).get("thread_url"),
            thread_title=(d.utm_params or {}).get("thread_title"),
            playbook=_draft_playbook(d),
        )
        for d in drafts
    ]


@router.post("/drafts/create", response_model=DraftResponse)
async def create_manual_draft(
    req: CreateDraftRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> DraftResponse:
    """Create a hand-written draft directly into the human-review queue.

    For platforms where content is authored by a human (LinkedIn, HN) rather than
    LLM-generated. Optional `playbook` carries per-platform posting guidance that
    the admin UI renders alongside the draft.
    """
    require_admin(current_entity)
    from src.marketing.draft_queue import enqueue_draft

    utm: dict = dict(req.utm_params or {})
    if req.playbook:
        utm["platform_playbook"] = {req.platform: req.playbook}

    post = await enqueue_draft(
        db,
        platform=req.platform,
        content=req.content,
        topic=req.topic or "manual",
        post_type=req.post_type,
        utm_params=utm or None,
    )
    await db.commit()
    await db.refresh(post)
    return DraftResponse(
        id=post.id,
        platform=post.platform,
        content=post.content,
        topic=post.topic,
        post_type=post.post_type,
        status=post.status,
        llm_model=post.llm_model,
        created_at=post.created_at.isoformat(),
        image_url=_topic_image_url(post.topic, post.platform),
        parent_external_id=post.parent_external_id,
        thread_url=(post.utm_params or {}).get("thread_url"),
        thread_title=(post.utm_params or {}).get("thread_title"),
        playbook=_draft_playbook(post),
    )


@router.post("/drafts/{post_id}", response_model=DraftResponse)
async def action_draft(
    post_id: uuid.UUID,
    req: DraftActionRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> DraftResponse:
    """Approve, reject, or edit+approve a draft."""
    require_admin(current_entity)
    from src.marketing.draft_queue import (
        approve_draft,
        edit_and_approve,
        reject_draft,
    )

    post = None
    if req.action == "approve":
        post = await approve_draft(db, post_id)
    elif req.action == "reject":
        post = await reject_draft(db, post_id, reason=req.reason or "")
    elif req.action == "edit_approve":
        if not req.content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="content required for edit_approve",
            )
        post = await edit_and_approve(db, post_id, req.content)
    elif req.action == "edit":
        # Plain content edit (no status change) — for scheduled/planned campaign posts.
        if not req.content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="content required for edit",
            )
        from src.marketing.draft_queue import edit_content
        post = await edit_content(db, post_id, req.content)
    elif req.action == "mark_posted":
        from src.marketing.draft_queue import mark_manually_posted

        post = await mark_manually_posted(
            db, post_id, posted_url=req.posted_url,
        )

    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Draft not found or not in human_review status",
        )

    await db.commit()

    # If approved/edited, immediately post — but ONLY for auto-post platforms.
    _logger = logging.getLogger(__name__)
    from src.marketing.orchestrator import _is_auto_post

    if req.action in ("approve", "edit_approve") and _is_auto_post(post.platform):
        try:
            from src.marketing.orchestrator import _get_adapters

            await db.refresh(post)
            adapters = _get_adapters()
            adapter = adapters.get(post.platform)
            if adapter and await adapter.is_configured():
                result = await adapter.post(post.content)
                if result.success:
                    post.status = "posted"
                    post.external_id = result.external_id
                    post.posted_at = datetime.now(timezone.utc)
                    if result.url:
                        post.utm_params = {
                            **(post.utm_params or {}),
                            "external_url": result.url,
                        }
                    _logger.info(
                        "Posted %s to %s: %s",
                        post.id, post.platform, result.external_id,
                    )
                else:
                    post.error_message = result.error
                    _logger.warning(
                        "Failed to post %s to %s: %s",
                        post.id, post.platform, result.error,
                    )
                    from src.marketing.draft_notify import notify_post_failure

                    await notify_post_failure(
                        post.platform, post.content[:200], result.error or "Unknown error",
                    )
            else:
                _logger.warning(
                    "Adapter not available for %s", post.platform,
                )
        except Exception as exc:
            post.error_message = str(exc)
            _logger.exception("Error posting %s", post.id)
            from src.marketing.draft_notify import notify_post_failure

            await notify_post_failure(
                post.platform, post.content[:200], str(exc),
            )
        await db.commit()
    elif req.action in ("approve", "edit_approve"):
        # Manual-post platform (LinkedIn/HN/Reddit/...): keep the (possibly edited)
        # draft in human_review so the human finalizes it via "Manually Posted".
        # Never auto-post or queue it for the poster cycle (avoids "Adapter not
        # configured" failure spam).
        post.status = "human_review"
        await db.commit()

    await db.refresh(post)
    return DraftResponse(
        id=post.id,
        platform=post.platform,
        content=post.content,
        topic=post.topic,
        post_type=post.post_type,
        status=post.status,
        llm_model=post.llm_model,
        created_at=post.created_at.isoformat(),
        image_url=_topic_image_url(post.topic, post.platform),
        parent_external_id=post.parent_external_id,
        thread_url=(post.utm_params or {}).get("thread_url"),
        thread_title=(post.utm_params or {}).get("thread_title"),
        playbook=_draft_playbook(post),
    )


# Topic → card image mapping
_TOPIC_CARDS: dict[str, str] = {
    "security": "/cards/card-security.svg",
    "tutorials": "/cards/card-tutorials.svg",
    "ecosystem": "/cards/card-ecosystem.svg",
    "features": "/cards/card-features.svg",
    "community": "/cards/card-community.svg",
    "moltbook_import": "/cards/card-moltbook-import.svg",
}
_DEFAULT_CARD = "/cards/card-features.svg"


def _topic_image_url(topic: str | None, platform: str) -> str | None:
    """Return a web-accessible card image URL for a draft's topic."""
    if topic and topic in _TOPIC_CARDS:
        return _TOPIC_CARDS[topic]
    return _DEFAULT_CARD


def _get_scheduled_day(post: object) -> str | None:
    """Extract the scheduled day from a planned post's campaign config."""
    campaign = getattr(post, "campaign", None)
    if not campaign:
        return None
    cfg = campaign.schedule_config or {}
    for spec in cfg.get("posts", []):
        if (
            spec.get("platform") == post.platform
            and spec.get("topic") == post.topic
        ):
            day = spec.get("day", "")
            return day.capitalize() if day else None
    return None


@router.get("/digest", response_model=WeeklyDigestResponse)
async def get_weekly_digest(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> WeeklyDigestResponse:
    """Get current weekly marketing digest data."""
    require_admin(current_entity)
    from src.marketing.digest import generate_weekly_digest

    data = await generate_weekly_digest(db)
    return WeeklyDigestResponse(**data)


@router.post("/digest/send")
async def send_digest_email(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually send the weekly digest email to admin."""
    require_admin(current_entity)
    from src.marketing.digest import send_weekly_digest_email

    sent = await send_weekly_digest_email(db)
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send digest email",
        )
    return {"status": "sent", "to": current_entity.email}


@router.post("/trigger", response_model=None)
async def trigger_marketing_tick(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually trigger a marketing tick (for testing)."""
    require_admin(current_entity)
    from src.marketing.orchestrator import run_marketing_tick

    results = await run_marketing_tick(db)
    await db.commit()
    return results


class MilestoneTriggerRequest(BaseModel):
    topic: str = Field(
        "operator_recruitment",
        description="Topic key to generate drafts for (default: operator_recruitment)",
    )
    platforms: list[str] | None = Field(
        None,
        description=(
            "Platforms to target. Omit or null for all configured platforms."
        ),
    )


@router.post("/trigger/milestone")
async def trigger_milestone_drafts(
    req: MilestoneTriggerRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Generate drafts for a milestone event across all platforms.

    All drafts go to human_review status — nothing is auto-posted.
    Default topic is ``operator_recruitment``.
    """
    require_admin(current_entity)
    from src.marketing.orchestrator import generate_milestone_drafts

    results = await generate_milestone_drafts(
        db, topic_key=req.topic, platforms=req.platforms,
    )
    await db.commit()

    # Notify admin about new drafts
    new_drafts = results.get("drafts", [])
    if new_drafts:
        try:
            from src.marketing.draft_notify import notify_pending_drafts

            await notify_pending_drafts(new_drafts)
        except Exception:
            pass  # notification is best-effort

    return results


@router.post("/trigger/{platform}", response_model=None)
async def trigger_platform_tick(
    platform: str,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually trigger a marketing post for a specific platform.

    Returns the generated draft content so the admin can preview it
    before approving.
    """
    require_admin(current_entity)
    from src.marketing.orchestrator import generate_and_post_for_platform

    result = await generate_and_post_for_platform(db, platform)
    await db.commit()

    # If a draft was created, fetch it so we can return the content
    if result.get("status") == "draft_created" and result.get("draft_id"):
        from src.marketing.models import MarketingPost

        draft_q = await db.execute(
            select(MarketingPost).where(
                MarketingPost.id == result["draft_id"],
            ),
        )
        draft = draft_q.scalar_one_or_none()
        if draft:
            result["draft"] = {
                "id": str(draft.id),
                "platform": draft.platform,
                "content": draft.content,
                "topic": draft.topic,
                "post_type": draft.post_type,
                "status": draft.status,
                "llm_model": draft.llm_model,
                "created_at": draft.created_at.isoformat(),
            }

    return result


@router.post("/recap")
async def trigger_recap_post(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually trigger a marketing recap post to the AgentGraph feed."""
    require_admin(current_entity)
    from src.marketing.recap import trigger_recap

    result = await trigger_recap(db)
    await db.commit()
    return result


async def _build_comment_worthy(db: AsyncSession) -> dict:
    """Gather the comment-worthy digest (news events + top reply-guy posts) and enrich each
    item with a one-line angle + a paste-ready, founder-voice draft via one LLM pass."""
    from src.marketing.config import marketing_settings
    from src.marketing.news_signals import gather_news_signals
    from src.models import ReplyOpportunity, ReplyTarget

    news: list[dict] = []
    try:
        for a in (await gather_news_signals(limit=6, days=7)) or []:
            news.append({
                "title": a.get("title", ""), "source": a.get("source", ""),
                "url": a.get("url", ""), "summary": (a.get("summary") or "")[:240],
                "angle": "", "draft": "",
            })
    except Exception:  # noqa: BLE001 - best-effort
        pass

    posts: list[dict] = []
    try:
        rows = await db.execute(
            select(ReplyOpportunity, ReplyTarget.handle)
            .join(ReplyTarget, ReplyOpportunity.target_id == ReplyTarget.id, isouter=True)
            .where(ReplyOpportunity.status.in_(["new", "drafted"]))
            .order_by(ReplyOpportunity.urgency_score.desc().nullslast())
            .limit(5),
        )
        for opp, handle in rows.all():
            posts.append({
                "platform": opp.platform, "handle": handle or "",
                "snippet": (opp.post_content or "").strip().replace("\n", " ")[:140],
                "url": opp.post_uri or "", "angle": "", "draft": "",
            })
    except Exception:  # noqa: BLE001
        pass

    # One LLM pass: angle + paste-ready founder-voice draft per item.
    llm_items = (
        [{"idx": f"n{i}", "kind": "news", "text": f"{n['title']} — {n['summary']}"}
         for i, n in enumerate(news)]
        + [{"idx": f"p{i}", "kind": "post", "text": f"[{p['platform']}] {p['handle']}: {p['snippet']}"}
           for i, p in enumerate(posts)]
    )
    if llm_items:
        try:
            import json as _json

            from src.marketing.campaign_planner import _parse_json_response
            from src.marketing.llm.anthropic_client import generate as anthropic_generate

            prompt = (
                "You draft LinkedIn/social engagement for Kenne Ives, founder of AgentGraph "
                "(the trust + security layer for AI agents). For EACH item below return an "
                "\"angle\" (one line: why it's worth Kenne's personal take) and a \"draft\" "
                "(paste-ready, FIRST-PERSON founder voice, 2-4 sentences, specific, no hashtag "
                "spam, no AI-tells; kind=news -> a short LinkedIn take post, kind=post -> a reply "
                "to that post). Return ONLY JSON: "
                "{\"items\":[{\"idx\":\"\",\"angle\":\"\",\"draft\":\"\"}]}.\n\n"
                + _json.dumps(llm_items)
            )
            resp = await anthropic_generate(
                prompt=prompt, model=marketing_settings.anthropic_sonnet_model,
                max_tokens=2500, temperature=0.6,
            )
            if not resp.error:
                by_idx = {it.get("idx"): it for it in (_parse_json_response(resp.text) or {}).get("items", [])}
                for i, n in enumerate(news):
                    it = by_idx.get(f"n{i}", {})
                    n["angle"], n["draft"] = it.get("angle", ""), it.get("draft", "")
                for i, p in enumerate(posts):
                    it = by_idx.get(f"p{i}", {})
                    p["angle"], p["draft"] = it.get("angle", ""), it.get("draft", "")
        except Exception:  # noqa: BLE001 - enrichment best-effort; links/snippets still useful
            pass

    return {"news": news, "posts": posts}


@router.get("/comment-worthy")
async def get_comment_worthy(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Comment-worthy digest for the admin Engage panel — news events + top reply-guy posts,
    each with an angle + a paste-ready founder-voice draft. Cached daily (one LLM pass/day).
    NOTE: no LinkedIn post-search API, so this surfaces events + tracked-account activity to
    engage with, not LinkedIn posts directly.
    """
    require_admin(current_entity)
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from src import cache

    key = f"ag:mktg:comment_worthy:{_dt.now(_tz.utc).date().isoformat()}"
    try:
        cached = await cache.get(key)
        if cached:
            return cached
    except Exception:  # noqa: BLE001
        pass
    data = await _build_comment_worthy(db)
    try:
        await cache.set(key, data, ttl=26 * 3600)
    except Exception:  # noqa: BLE001
        pass
    return data


@router.get("/activity", response_model=BotActivityResponse)
async def get_bot_activity(
    limit: int = Query(50, ge=1, le=200),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> BotActivityResponse:
    """Get recent marketing bot activity grouped by status."""
    require_admin(current_entity)
    from src.marketing.models import MarketingPost

    q = (
        select(MarketingPost)
        .order_by(MarketingPost.created_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()

    posted: list[ActivityItem] = []
    pending_review: list[ActivityItem] = []
    failed: list[ActivityItem] = []

    for row in rows:
        item = ActivityItem(
            id=row.id,
            platform=row.platform,
            content_preview=row.content[:200] if row.content else "",
            status=row.status,
            post_type=row.post_type,
            topic=row.topic,
            external_id=row.external_id,
            external_url=(row.utm_params or {}).get("external_url"),
            posted_at=row.posted_at.isoformat() if row.posted_at else None,
            created_at=row.created_at.isoformat(),
            metrics=row.metrics_json,
        )
        if row.status == "posted":
            posted.append(item)
        elif row.status == "human_review":
            pending_review.append(item)
        elif row.status == "failed":
            failed.append(item)
        # Other statuses (draft, rejected) go nowhere special — still counted

    return BotActivityResponse(
        posted=posted,
        pending_review=pending_review,
        failed=failed,
        total=len(rows),
    )


@router.post("/slop-proposals/ingest")
async def slop_proposals_ingest(
    body: dict,
    request: Request,
) -> dict:
    """Ingest candidate AI-slop phrases from an external tool (e.g. the news-digest bot)
    into the approval queue. Auth via the ``X-Proposal-Secret`` header matching
    ``SLOP_PROPOSAL_SECRET``. Body: ``{"phrases": [{"phrase": str, "reason": str}, ...]}``
    or ``{"phrases": ["phrase", ...]}``. Nothing is applied until an admin approves it."""
    from src.config import settings
    secret = (settings.slop_proposal_secret or "").strip()
    if not secret or request.headers.get("x-proposal-secret", "") != secret:
        raise HTTPException(status_code=403, detail="Forbidden")
    from src.marketing.content.slop_learning import propose
    items = (body or {}).get("phrases") or []
    added = 0
    for it in items[:50]:
        phrase = it if isinstance(it, str) else (it or {}).get("phrase", "")
        reason = (it or {}).get("reason", "news-digest lesson") if isinstance(it, dict) \
            else "news-digest lesson"
        if await propose(phrase, reason):
            added += 1
    return {"added": added, "received": len(items)}


@router.post("/check-slop")
async def check_slop(
    body: dict,
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Run the no-slop detector on arbitrary copy (for the 'Check my copy' button on
    hand-written drafts). Returns pass/fail + reasons + a fix hint."""
    require_admin(current_entity)
    from src.marketing.content.ai_tells import check as check_ai_tells
    content = (body or {}).get("content", "") or ""
    platform = (body or {}).get("platform", "linkedin") or "linkedin"
    r = check_ai_tells(content, platform=platform, strict=True)
    return {"passed": r.passed, "severity": r.severity, "reasons": r.reasons,
            "hint": r.hint()}


@router.get("/slop-proposals")
async def slop_proposals(
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Candidate slop phrases (from edit-learning + LLM proposals) awaiting approval."""
    require_admin(current_entity)
    from src.marketing.content.slop_learning import list_proposals
    return {"proposals": await list_proposals()}


@router.post("/slop-proposals/action")
async def slop_proposals_action(
    body: dict,
    current_entity: Entity = Depends(get_current_entity),
) -> dict:
    """Approve (→ dynamic blocklist) or reject a candidate slop phrase."""
    require_admin(current_entity)
    from src.marketing.content.slop_learning import act
    phrase = (body or {}).get("phrase", "")
    action = (body or {}).get("action", "")
    if action not in ("approve", "reject") or not phrase:
        raise HTTPException(400, "phrase + action(approve|reject) required")
    ok = await act(phrase, action)
    return {"ok": ok}


@router.get("/eval")
async def marketing_eval(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Marketing eval snapshot: engagement trend, no-slop pass rate, reply engagement,
    and any active alerts — the 'is the learning loop working?' view."""
    require_admin(current_entity)
    from src.marketing.content.eval import get_marketing_eval
    return await get_marketing_eval(db)


@router.get("/health")
async def marketing_health(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Check health of all configured platform adapters."""
    require_admin(current_entity)
    from src.marketing.adapters.bluesky import BlueskyAdapter
    from src.marketing.adapters.devto import DevtoAdapter
    from src.marketing.adapters.discord_bot import DiscordAdapter
    from src.marketing.adapters.github_discussions import GitHubDiscussionsAdapter
    from src.marketing.adapters.hackernews import HackerNewsAdapter
    from src.marketing.adapters.hashnode import HashnodeAdapter
    from src.marketing.adapters.huggingface import HuggingFaceAdapter
    from src.marketing.adapters.linkedin import LinkedInAdapter
    from src.marketing.adapters.reddit import RedditAdapter
    from src.marketing.adapters.telegram_bot import TelegramAdapter
    from src.marketing.adapters.twitter import TwitterAdapter
    from src.marketing.config import marketing_settings
    from src.marketing.llm.cost_tracker import (
        get_daily_spend,
        get_monthly_spend,
    )
    from src.marketing.llm.ollama_client import is_available as ollama_available

    adapters = {
        "twitter": TwitterAdapter(),
        "reddit": RedditAdapter(),
        "bluesky": BlueskyAdapter(),
        "discord": DiscordAdapter(),
        "linkedin": LinkedInAdapter(),
        "telegram": TelegramAdapter(),
        "devto": DevtoAdapter(),
        "hashnode": HashnodeAdapter(),
        "github_discussions": GitHubDiscussionsAdapter(),
        "huggingface": HuggingFaceAdapter(),
        "hackernews": HackerNewsAdapter(),
    }

    health: dict = {
        "marketing_enabled": marketing_settings.marketing_enabled,
        "ollama_available": await ollama_available(),
        "anthropic_configured": bool(marketing_settings.anthropic_api_key),
        "daily_spend_usd": round(await get_daily_spend(), 4),
        "monthly_spend_usd": round(await get_monthly_spend(), 4),
        "adapters": {},
    }

    for name, adapter in adapters.items():
        configured = await adapter.is_configured()
        health["adapters"][name] = {
            "configured": configured,
            "healthy": (
                await adapter.health_check() if configured else False
            ),
        }

    # Recent failure counts
    from src.marketing.alerts import get_failure_summary

    failures = await get_failure_summary(db, hours=24)
    health["failures_24h"] = {
        "failed": failures["total_failed"],
        "permanently_failed": failures[
            "total_permanently_failed"
        ],
        "by_platform": failures["by_platform"],
    }

    return health


@router.get(
    "/conversions",
    response_model=ConversionResponse,
)
async def get_marketing_conversions(
    days: int = Query(30, ge=1, le=365),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> ConversionResponse:
    """UTM attribution: clicks and signups per marketing platform."""
    require_admin(current_entity)

    from datetime import timedelta

    from src.marketing.models import MarketingPost

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # 1. Clicks: analytics events where referrer has utm_source
    click_q = (
        select(
            func.substring(
                AnalyticsEvent.referrer,
                r"utm_source=([^&]+)",
            ).label("src"),
            func.count().label("cnt"),
        )
        .where(
            AnalyticsEvent.created_at >= cutoff,
            AnalyticsEvent.referrer.ilike(
                "%utm_source=agentgraph_bot%"
            ),
        )
        .group_by("src")
    )
    click_rows = (await db.execute(click_q)).all()
    clicks_by_src: dict[str, int] = {}
    for row in click_rows:
        src = row[0] or "unknown"
        # utm_source format: agentgraph_bot_<platform>
        platform = src.replace("agentgraph_bot_", "")
        clicks_by_src[platform] = (
            clicks_by_src.get(platform, 0) + row[1]
        )

    # 2. Signups: register_complete events with utm referrer
    signup_q = (
        select(
            func.substring(
                AnalyticsEvent.referrer,
                r"utm_source=([^&]+)",
            ).label("src"),
            func.count().label("cnt"),
        )
        .where(
            AnalyticsEvent.created_at >= cutoff,
            AnalyticsEvent.event_type == "register_complete",
            AnalyticsEvent.referrer.ilike(
                "%utm_source=agentgraph_bot%"
            ),
        )
        .group_by("src")
    )
    signup_rows = (await db.execute(signup_q)).all()
    signups_by_src: dict[str, int] = {}
    for row in signup_rows:
        src = row[0] or "unknown"
        platform = src.replace("agentgraph_bot_", "")
        signups_by_src[platform] = (
            signups_by_src.get(platform, 0) + row[1]
        )

    # 3. Cost per platform from marketing_posts
    cost_q = (
        select(
            MarketingPost.platform,
            func.coalesce(
                func.sum(MarketingPost.llm_cost_usd), 0.0,
            ).label("total_cost"),
        )
        .where(MarketingPost.created_at >= cutoff)
        .group_by(MarketingPost.platform)
    )
    cost_rows = (await db.execute(cost_q)).all()
    cost_by_platform: dict[str, float] = {
        row[0]: float(row[1]) for row in cost_rows
    }

    # Merge all platforms
    all_platforms = sorted(
        set(clicks_by_src)
        | set(signups_by_src)
        | set(cost_by_platform)
    )

    platforms: list[PlatformConversion] = []
    total_clicks = 0
    total_signups = 0
    total_cost = 0.0

    for p in all_platforms:
        c = clicks_by_src.get(p, 0)
        s = signups_by_src.get(p, 0)
        cost = round(cost_by_platform.get(p, 0.0), 4)
        cps = round(cost / s, 4) if s > 0 else None
        platforms.append(PlatformConversion(
            platform=p,
            clicks=c,
            signups=s,
            cost_usd=cost,
            cost_per_signup=cps,
        ))
        total_clicks += c
        total_signups += s
        total_cost += cost

    return ConversionResponse(
        platforms=platforms,
        total_clicks=total_clicks,
        total_signups=total_signups,
        total_cost_usd=round(total_cost, 4),
    )


# --- Reddit: digest_history.json fallback ---

# Candidate paths for digest_history.json
_DIGEST_PATHS = [
    Path("/app/digest_history.json"),  # Docker container
    Path(__file__).resolve().parent.parent.parent / "digest_history.json",  # Local dev
]


def _reddit_from_digest_history() -> list[RedditThreadResponse]:
    """Extract Reddit articles from the news-digest history file.

    The news-digest bot on the Windows server scrapes Reddit RSS
    and SCPs digest_history.json to EC2. This is the last-resort
    fallback when both live Reddit API and Redis cache are empty.
    """
    import json

    path = None
    for p in _DIGEST_PATHS:
        if p.exists():
            path = p
            break
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return []

    results: list[RedditThreadResponse] = []
    for info in data.get("sent_articles", {}).values():
        source = info.get("source", "")
        if not source.startswith("Reddit"):
            continue
        link = info.get("link", "")
        # Extract subreddit from source name like "Reddit r/artificial"
        sub = source.replace("Reddit r/", "").replace("Reddit ", "")
        results.append(
            RedditThreadResponse(
                title=info.get("title", ""),
                url=link,
                permalink=link.replace("https://www.reddit.com", ""),
                subreddit=sub,
                score=0,
                num_comments=0,
                created_utc=0.0,
                selftext_preview=info.get("summary", "")[:300],
                author="",
                keywords_matched=[],
            ),
        )
    return results[:20]


# --- Reddit Scout endpoints ---


def _rank_thread(thread: RedditThreadResponse) -> int:
    """Score a thread for actionability.

    Scoring:
    - keywords_matched count * 3
    - score > 50 → +2
    - num_comments 3-30 (sweet spot) → +2, else +1
    - Recency: last 24h → +3, last 48h → +2, last week → +1
    """
    import time

    ranking = len(thread.keywords_matched) * 3

    if thread.score > 50:
        ranking += 2

    if 3 <= thread.num_comments <= 30:
        ranking += 2
    elif thread.num_comments > 0:
        ranking += 1

    now = time.time()
    age_hours = (now - thread.created_utc) / 3600 if thread.created_utc else 999
    if age_hours <= 24:
        ranking += 3
    elif age_hours <= 48:
        ranking += 2
    elif age_hours <= 168:  # 7 days
        ranking += 1

    return ranking


@router.get(
    "/reddit/threads",
    response_model=list[RedditThreadResponse],
)
async def get_reddit_threads(
    sort: str = Query("hot", description="Sort: hot, new, top, rising"),
    min_score: int = Query(0, ge=0),
    top_n: int = Query(10, ge=1, le=50, description="Return top N ranked threads"),
    current_entity: Entity = Depends(get_current_entity),
) -> list[RedditThreadResponse]:
    """Scan Reddit for relevant threads, ranked by actionability.

    Falls back to Redis cache, then to digest_history.json (synced
    from the news-digest bot on Windows server via SCP).
    Returns only the top N most actionable threads.
    """
    require_admin(current_entity)
    from src.marketing.reddit_scout import get_cached_threads, scan_subreddits

    threads = await scan_subreddits(sort=sort, min_score=min_score)
    if not threads:
        threads = await get_cached_threads()

    results: list[RedditThreadResponse] = []
    if threads:
        results = [
            RedditThreadResponse(
                title=t.title,
                url=t.url,
                permalink=t.permalink,
                subreddit=t.subreddit,
                score=t.score,
                num_comments=t.num_comments,
                created_utc=t.created_utc,
                selftext_preview=t.selftext_preview,
                author=t.author,
                keywords_matched=t.keywords_matched,
            )
            for t in threads
        ]
    else:
        # Final fallback: extract Reddit articles from digest_history.json
        results = _reddit_from_digest_history()

    # Score and rank threads
    for r in results:
        r.ranking_score = _rank_thread(r)
    results.sort(key=lambda x: x.ranking_score or 0, reverse=True)

    return results[:top_n]


@router.post(
    "/reddit/generate-draft",
    response_model=RedditDraftResponse,
)
async def generate_reddit_draft(
    req: RedditDraftRequest,
    current_entity: Entity = Depends(get_current_entity),
) -> RedditDraftResponse:
    """Generate a draft reply for a specific Reddit thread."""
    require_admin(current_entity)
    from src.marketing.reddit_scout import fetch_thread_detail

    detail = await fetch_thread_detail(req.thread_url)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not fetch thread. Check the URL.",
        )

    thread_title = detail["title"]
    thread_body = detail.get("selftext", "")[:1000]
    subreddit = detail.get("subreddit", "")
    top_comments_text = ""
    for c in detail.get("top_comments", [])[:3]:
        top_comments_text += (
            f"\n- u/{c['author']} ({c['score']} pts): "
            f"{c['body'][:200]}"
        )

    # --- Reddit 10% self-promotion rule ---
    # Track post count in Redis. Only every 10th post may mention AgentGraph.
    from src.redis_client import get_redis

    reddit_count_key = "ag:reddit:post_count"
    redis = await get_redis()
    post_number = 1
    promo_eligible = False
    if redis:
        post_number = await redis.incr(reddit_count_key)
        promo_eligible = post_number % 10 == 0
    # --- end 10% rule ---

    extra_context = ""
    if req.context:
        extra_context = (
            f"\n\nAdditional context from the admin:\n{req.context}\n"
        )

    prompt = (
        f"You are writing a Reddit comment for r/{subreddit}.\n\n"
        f"Thread title: {thread_title}\n"
        f"Thread body: {thread_body}\n"
    )
    if top_comments_text:
        prompt += f"\nTop comments:{top_comments_text}\n"
    prompt += extra_context

    if promo_eligible:
        prompt += (
            "\n\nWrite a helpful, insightful reply that adds genuine "
            "value to the discussion. Rules:\n"
            "- Be helpful FIRST. Share knowledge or perspectives.\n"
            "- Where relevant, link to specific GitHub repos, tools, "
            "or libraries that help answer the question. Redditors "
            "appreciate concrete resources.\n"
            "- This thread is a good fit to naturally mention "
            "AgentGraph (agentgraph.co) if it's relevant to the "
            "topic. Work it in organically as something you use or "
            "built — NOT as an ad. Pair it with other useful "
            "recommendations so it doesn't stand alone.\n"
            "- Do NOT be promotional. No 'check out' or 'sign up'.\n"
            "- Match the subreddit's tone and culture.\n"
            "- Keep it concise — 2-4 paragraphs max.\n"
            "- No emojis, no hashtags, no marketing speak.\n"
            "- Sound like a knowledgeable developer, not a brand.\n"
        )
    else:
        prompt += (
            "\n\nWrite a helpful, insightful reply that adds genuine "
            "value to the discussion. Rules:\n"
            "- Be genuinely helpful. Share knowledge, perspectives, "
            "or experience.\n"
            "- Do NOT mention AgentGraph, agentgraph.co, or any "
            "product/project you work on. This is a pure community "
            "contribution.\n"
            "- Where relevant, link to specific GitHub repos, tools, "
            "or libraries that help answer the question or add to "
            "the discussion. Redditors appreciate concrete resources "
            "over vague advice. Use real, well-known repos — do NOT "
            "invent URLs.\n"
            "- Match the subreddit's tone and culture.\n"
            "- Keep it concise — 2-4 paragraphs max.\n"
            "- No emojis, no hashtags, no marketing speak.\n"
            "- Sound like a knowledgeable developer sharing expertise.\n"
        )

    from src.marketing.llm.router import generate as llm_generate

    system = (
        "You are a knowledgeable developer and AI researcher who "
        "genuinely participates in Reddit discussions. You are NOT "
        "a marketing bot. Write like a real person sharing expertise."
    )

    result = await llm_generate(
        prompt,
        content_type="reddit_scout_draft",
        system=system,
        max_tokens=512,
        temperature=0.7,
    )

    if result.error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"LLM generation failed: {result.error}",
        )

    from src.marketing.llm.cost_tracker import estimate_cost

    cost = estimate_cost(
        result.model, result.tokens_in, result.tokens_out,
    )

    return RedditDraftResponse(
        thread_url=req.thread_url,
        thread_title=thread_title,
        draft_content=result.text,
        llm_model=result.model,
        llm_cost_usd=round(cost, 6),
        promo_eligible=promo_eligible,
        reddit_post_number=post_number,
    )


# --- HuggingFace Scout endpoints ---


@router.get(
    "/huggingface/discussions",
    response_model=list[HFDiscussionResponse],
)
async def get_hf_discussions(
    refresh: bool = Query(False, description="Force refresh (bypass cache)"),
    current_entity: Entity = Depends(get_current_entity),
) -> list[HFDiscussionResponse]:
    """Scan HuggingFace for relevant model discussions to engage with.

    Results are cached in Redis for 2 hours to avoid rate limiting.
    Pass ?refresh=true to force a fresh scan.
    """
    require_admin(current_entity)

    import json as _json

    _cache_key = "ag:mktg:hf_discussions_cache"
    _cache_ttl = 7200  # 2 hours

    # Try cache first (unless refresh requested)
    if not refresh:
        try:
            from src.redis_client import get_redis

            _r = get_redis()
            cached = await _r.get(_cache_key)
            if cached:
                data = _json.loads(cached)
                return [HFDiscussionResponse(**d) for d in data]
        except Exception:
            pass  # Cache miss or Redis down — fetch live

    from src.marketing.hf_scout import scan_hf_discussions

    discussions = await scan_hf_discussions()
    result = [
        HFDiscussionResponse(
            title=d.title,
            url=d.url,
            repo_id=d.repo_id,
            discussion_num=d.discussion_num,
            author=d.author,
            num_comments=d.num_comments,
            status=d.status,
            created_at=d.created_at,
            content_preview=d.content_preview,
            keywords_matched=d.keywords_matched,
        )
        for d in discussions
    ]

    # Cache results
    try:
        from src.redis_client import get_redis

        _r = get_redis()
        await _r.set(
            _cache_key,
            _json.dumps([r.model_dump() for r in result]),
            ex=_cache_ttl,
        )
    except Exception:
        pass

    return result


@router.post(
    "/huggingface/generate-draft",
    response_model=HFDraftResponse,
)
async def generate_hf_draft(
    req: HFDraftRequest,
    current_entity: Entity = Depends(get_current_entity),
) -> HFDraftResponse:
    """Generate a draft reply for a HuggingFace discussion."""
    require_admin(current_entity)

    prompt = (
        f"Write a reply to this HuggingFace discussion on "
        f"the model page `{req.repo_id}`:\n\n"
        f"**Discussion title:** {req.discussion_title}\n\n"
    )
    if req.context:
        prompt += f"**Additional context:** {req.context}\n\n"

    prompt += (
        "## Instructions\n"
        "- You are a developer who works on AI agent trust and "
        "identity infrastructure (AgentGraph).\n"
        "- Respond with genuine technical insight relevant to "
        "the discussion.\n"
        "- If agent trust, verification, or identity is relevant, "
        "mention AgentGraph naturally — don't force it.\n"
        "- Write 1-3 paragraphs. Be technically precise.\n"
        "- Reference the specific model/repo when relevant.\n"
        "- No marketing speak, no emojis.\n"
    )

    from src.marketing.llm.router import generate as llm_generate

    system = (
        "You are a knowledgeable AI/ML engineer who participates "
        "in HuggingFace model discussions. You have expertise in "
        "agent identity, trust scoring, and multi-agent systems. "
        "Write like a real researcher sharing expertise."
    )

    result = await llm_generate(
        prompt,
        content_type="hf_scout_draft",
        system=system,
        max_tokens=512,
        temperature=0.7,
    )

    if result.error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"LLM generation failed: {result.error}",
        )

    from src.marketing.llm.cost_tracker import estimate_cost

    cost = estimate_cost(
        result.model, result.tokens_in, result.tokens_out,
    )

    return HFDraftResponse(
        repo_id=req.repo_id,
        discussion_title=req.discussion_title,
        draft_content=result.text,
        llm_model=result.model,
        llm_cost_usd=round(cost, 6),
    )


class ClearFailedResponse(BaseModel):
    deleted: int
    platforms: dict[str, int]


@router.delete(
    "/posts/failed",
    response_model=ClearFailedResponse,
)
async def clear_failed_posts(
    platform: str | None = Query(None, description="Filter by platform"),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> ClearFailedResponse:
    """Delete all failed and permanently_failed marketing posts.

    Optionally filter by platform name.
    """
    require_admin(current_entity)

    from sqlalchemy import delete as sa_delete

    from src.marketing.models import MarketingPost

    where_clauses = [
        MarketingPost.status.in_(["failed", "permanently_failed"]),
    ]
    if platform:
        where_clauses.append(MarketingPost.platform == platform)

    # Count by platform first
    count_q = select(
        MarketingPost.platform,
        func.count().label("cnt"),
    ).where(*where_clauses).group_by(MarketingPost.platform)
    count_result = await db.execute(count_q)
    platform_counts: dict[str, int] = {
        row[0]: row[1] for row in count_result.all()
    }

    total = sum(platform_counts.values())

    if total > 0:
        del_q = sa_delete(MarketingPost).where(*where_clauses)
        await db.execute(del_q)
        await db.flush()

    return ClearFailedResponse(
        deleted=total,
        platforms=platform_counts,
    )
