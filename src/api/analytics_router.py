from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_analytics, rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import AnalyticsEvent, Entity, InteractionEvent

router = APIRouter(prefix="/analytics", tags=["analytics"])

ALLOWED_EVENT_TYPES = {
    "guest_page_view",
    "guest_cta_click",
    "register_start",
    "register_complete",
    "first_action",
    "login_start",
    "login_complete",
    "ios_waitlist",
    "newsletter_signup",
}

FUNNEL_ORDER = [
    "guest_page_view",
    "guest_cta_click",
    "register_start",
    "register_complete",
    "first_action",
]


# --- Schemas ---


class NewsletterSignupRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    source: str = Field(..., max_length=64)


class TrackEventRequest(BaseModel):
    event_type: str = Field(..., max_length=50)
    session_id: str = Field(..., max_length=64)
    page: str = Field(..., max_length=200)
    intent: str | None = Field(None, max_length=50)
    referrer: str | None = Field(None, max_length=500)
    metadata: dict | None = None


class FunnelStep(BaseModel):
    event_type: str
    count: int
    conversion_rate: float | None = None  # % of previous step


class ConversionSummary(BaseModel):
    period_days: int
    funnel: list[FunnelStep]
    top_pages: list[dict]
    top_intents: list[dict]
    total_events: int


class DailyConversion(BaseModel):
    period_days: int
    daily: list[dict]


class UtmFunnelStep(BaseModel):
    event_type: str
    count: int


class UtmSourceData(BaseModel):
    source: str
    medium: str | None = None
    events: list[UtmFunnelStep]
    total: int


class AttributionSummary(BaseModel):
    period_days: int
    sources: list[UtmSourceData]
    total_attributed: int
    total_unattributed: int


# --- Public endpoint ---


@router.post(
    "/event",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_analytics)],
)
async def track_event(
    body: TrackEventRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Record a conversion funnel event. No auth required."""
    if body.event_type not in ALLOWED_EVENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid event_type. Must be one of: {', '.join(sorted(ALLOWED_EVENT_TYPES))}",
        )

    event = AnalyticsEvent(
        event_type=body.event_type,
        session_id=body.session_id,
        page=body.page,
        intent=body.intent,
        referrer=body.referrer,
        extra_metadata=body.metadata or {},
        ip_address=request.client.host if request.client else None,
    )
    db.add(event)
    await db.flush()
    return {"status": "ok"}


@router.post(
    "/newsletter-signup",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_writes)],
)
async def newsletter_signup(
    body: NewsletterSignupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Capture a quarterly-newsletter signup. No auth required.

    Stores email + source in analytics_events.extra_metadata until a proper
    newsletter_signups table lands (see task #69 follow-up).
    """
    event = AnalyticsEvent(
        event_type="newsletter_signup",
        session_id=f"newsletter-{body.source}",
        page=f"/{body.source}",
        intent="subscribe",
        referrer=request.headers.get("referer"),
        extra_metadata={"email": body.email, "source": body.source},
        ip_address=request.client.host if request.client else None,
    )
    db.add(event)
    await db.flush()
    return {"status": "ok"}


# --- Admin endpoints ---


@router.get(
    "/conversion",
    response_model=ConversionSummary,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_conversion_funnel(
    days: int = Query(30, ge=1, le=90),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Conversion funnel summary. Admin only."""
    require_admin(current_entity)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Count per event_type
    type_counts_result = await db.execute(
        select(
            AnalyticsEvent.event_type,
            func.count().label("count"),
        )
        .where(AnalyticsEvent.created_at >= cutoff)
        .group_by(AnalyticsEvent.event_type)
    )
    type_counts = {row[0]: row[1] for row in type_counts_result.all()}

    # Build funnel with conversion rates
    funnel: list[FunnelStep] = []
    prev_count: int | None = None
    for event_type in FUNNEL_ORDER:
        count = type_counts.get(event_type, 0)
        rate = None
        if prev_count is not None and prev_count > 0:
            rate = round((count / prev_count) * 100, 1)
        funnel.append(FunnelStep(
            event_type=event_type,
            count=count,
            conversion_rate=rate,
        ))
        prev_count = count

    # Top pages
    top_pages_result = await db.execute(
        select(
            AnalyticsEvent.page,
            func.count().label("count"),
        )
        .where(AnalyticsEvent.created_at >= cutoff)
        .group_by(AnalyticsEvent.page)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_pages = [{"page": row[0], "count": row[1]} for row in top_pages_result.all()]

    # Top intents
    top_intents_result = await db.execute(
        select(
            AnalyticsEvent.intent,
            func.count().label("count"),
        )
        .where(
            AnalyticsEvent.created_at >= cutoff,
            AnalyticsEvent.intent.isnot(None),
        )
        .group_by(AnalyticsEvent.intent)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_intents = [{"intent": row[0], "count": row[1]} for row in top_intents_result.all()]

    total = sum(type_counts.values())

    return ConversionSummary(
        period_days=days,
        funnel=funnel,
        top_pages=top_pages,
        top_intents=top_intents,
        total_events=total,
    )


@router.get(
    "/conversion/daily",
    response_model=DailyConversion,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_daily_conversion(
    days: int = Query(30, ge=1, le=90),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Daily event breakdown. Admin only."""
    require_admin(current_entity)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    _day = literal_column("'day'")
    day_col = func.date_trunc(_day, AnalyticsEvent.created_at)

    result = await db.execute(
        select(
            day_col.label("day"),
            AnalyticsEvent.event_type,
            func.count().label("count"),
        )
        .where(AnalyticsEvent.created_at >= cutoff)
        .group_by(day_col, AnalyticsEvent.event_type)
        .order_by(day_col)
    )

    # Group by date
    daily_map: dict[str, dict[str, int]] = {}
    for row in result.all():
        date_str = row[0].isoformat()[:10]
        if date_str not in daily_map:
            daily_map[date_str] = {}
        daily_map[date_str][row[1]] = row[2]

    daily = [
        {"date": date, **counts}
        for date, counts in sorted(daily_map.items())
    ]

    return DailyConversion(period_days=days, daily=daily)


@router.get(
    "/attribution",
    response_model=AttributionSummary,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_attribution(
    days: int = Query(30, ge=1, le=90),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Marketing attribution funnel grouped by UTM source. Admin only."""
    require_admin(current_entity)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Query events that have utm_source in their metadata JSONB
    _source = AnalyticsEvent.extra_metadata["utm_source"].as_string().label("source")
    _medium = AnalyticsEvent.extra_metadata["utm_medium"].as_string().label("medium")
    utm_result = await db.execute(
        select(
            _source,
            _medium,
            AnalyticsEvent.event_type,
            func.count().label("count"),
        )
        .where(
            AnalyticsEvent.created_at >= cutoff,
            AnalyticsEvent.extra_metadata["utm_source"] != literal_column("'null'"),
            AnalyticsEvent.extra_metadata.has_key("utm_source"),
        )
        .group_by(
            _source,
            _medium,
            AnalyticsEvent.event_type,
        )
        .order_by(func.count().desc())
    )

    # Group by source+medium
    source_map: dict[tuple[str, str | None], dict[str, int]] = {}
    total_attributed = 0
    for row in utm_result.all():
        source = row[0]
        medium = row[1] if row[1] != "null" else None
        event_type = row[2]
        count = row[3]
        key = (source, medium)
        if key not in source_map:
            source_map[key] = {}
        source_map[key][event_type] = count
        total_attributed += count

    # Count total unattributed events
    total_all = await db.scalar(
        select(func.count()).select_from(AnalyticsEvent).where(
            AnalyticsEvent.created_at >= cutoff,
        )
    ) or 0
    total_unattributed = total_all - total_attributed

    # Build response
    sources: list[UtmSourceData] = []
    for (source, medium), events_map in sorted(
        source_map.items(), key=lambda x: sum(x[1].values()), reverse=True
    ):
        def funnel_sort_key(item: tuple[str, int]) -> int:
            et = item[0]
            return FUNNEL_ORDER.index(et) if et in FUNNEL_ORDER else 99

        steps = [
            UtmFunnelStep(event_type=et, count=c)
            for et, c in sorted(events_map.items(), key=funnel_sort_key)
        ]
        sources.append(UtmSourceData(
            source=source,
            medium=medium,
            events=steps,
            total=sum(events_map.values()),
        ))

    return AttributionSummary(
        period_days=days,
        sources=sources,
        total_attributed=total_attributed,
        total_unattributed=total_unattributed,
    )


# --- Interaction Analytics ---


class InteractionStats(BaseModel):
    total_interactions: int = 0
    allowed_count: int = 0
    denied_count: int = 0
    cross_framework_count: int = 0
    cross_framework_pct: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    framework_pairs: list[dict] = Field(default_factory=list)
    period_days: int = 30


@router.get(
    "/interactions",
    response_model=InteractionStats,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_interaction_stats(
    days: int = Query(30, ge=1, le=365),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> InteractionStats:
    """Get A2A interaction analytics for assumption validation.

    Returns:
    - Total interactions, allowed/denied split
    - Cross-framework interaction rate (target: >15% within 90 days)
    - Interaction type breakdown
    - Framework pair frequency
    """
    require_admin(current_entity)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Filter to A2A interactions (prefixed with "a2a.")
    a2a_filter = InteractionEvent.interaction_type.like("a2a.%")

    # Total A2A interactions
    total = await db.scalar(
        select(func.count()).select_from(InteractionEvent).where(
            InteractionEvent.created_at >= cutoff, a2a_filter,
        )
    ) or 0

    # Allowed (context->>'allowed' = 'true')
    allowed = await db.scalar(
        select(func.count()).select_from(InteractionEvent).where(
            InteractionEvent.created_at >= cutoff,
            a2a_filter,
            InteractionEvent.context["allowed"].as_boolean().is_(True),
        )
    ) or 0

    # Cross-framework
    cross_fw = await db.scalar(
        select(func.count()).select_from(InteractionEvent).where(
            InteractionEvent.created_at >= cutoff,
            a2a_filter,
            InteractionEvent.context["is_cross_framework"].as_boolean().is_(True),
        )
    ) or 0

    # By interaction type
    type_result = await db.execute(
        select(
            InteractionEvent.interaction_type,
            func.count(),
        )
        .where(InteractionEvent.created_at >= cutoff, a2a_filter)
        .group_by(InteractionEvent.interaction_type)
    )
    by_type = {row[0]: row[1] for row in type_result.fetchall()}

    # Framework pairs from JSONB context (top 20)
    pair_result = await db.execute(
        select(
            InteractionEvent.context["initiator_framework"].as_string(),
            InteractionEvent.context["target_framework"].as_string(),
            func.count(),
        )
        .where(
            InteractionEvent.created_at >= cutoff,
            a2a_filter,
            InteractionEvent.context["initiator_framework"] != literal_column("'null'"),
            InteractionEvent.context["target_framework"] != literal_column("'null'"),
        )
        .group_by(
            InteractionEvent.context["initiator_framework"].as_string(),
            InteractionEvent.context["target_framework"].as_string(),
        )
        .order_by(func.count().desc())
        .limit(20)
    )
    framework_pairs = [
        {
            "initiator": row[0],
            "target": row[1],
            "count": row[2],
        }
        for row in pair_result.fetchall()
    ]

    return InteractionStats(
        total_interactions=total,
        allowed_count=allowed,
        denied_count=total - allowed,
        cross_framework_count=cross_fw,
        cross_framework_pct=(cross_fw / total * 100) if total > 0 else 0.0,
        by_type=by_type,
        framework_pairs=framework_pairs,
        period_days=days,
    )


class SocialFeatureStats(BaseModel):
    total_social_events: int = 0
    unique_entities: int = 0
    agent_social_pct: float = 0.0
    by_feature: dict[str, int] = Field(default_factory=dict)
    agent_vs_human: dict[str, int] = Field(default_factory=dict)
    period_days: int = 30


@router.get(
    "/social-features",
    response_model=SocialFeatureStats,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_social_feature_stats(
    days: int = Query(30, ge=1, le=365),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> SocialFeatureStats:
    """Get social feature usage analytics for assumption validation.

    Validates Assumption #4: Do agents use social features or only API
    interactions? Returns breakdown by feature type and entity type.
    """
    require_admin(current_entity)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Total social events (non-A2A interaction types)
    total = await db.scalar(
        select(func.count()).select_from(InteractionEvent).where(
            InteractionEvent.created_at >= cutoff,
            ~InteractionEvent.interaction_type.like("a2a.%"),
        )
    ) or 0

    # Unique entities using social features
    unique = await db.scalar(
        select(func.count(InteractionEvent.entity_a_id.distinct())).where(
            InteractionEvent.created_at >= cutoff,
            ~InteractionEvent.interaction_type.like("a2a.%"),
        )
    ) or 0

    # By feature type
    type_result = await db.execute(
        select(
            InteractionEvent.interaction_type,
            func.count(),
        )
        .where(
            InteractionEvent.created_at >= cutoff,
            ~InteractionEvent.interaction_type.like("a2a.%"),
        )
        .group_by(InteractionEvent.interaction_type)
        .order_by(func.count().desc())
    )
    by_feature = {row[0]: row[1] for row in type_result.fetchall()}

    # Agent vs human breakdown (join with entities)
    type_counts = await db.execute(
        select(
            Entity.type,
            func.count(InteractionEvent.id),
        )
        .join(Entity, Entity.id == InteractionEvent.entity_a_id)
        .where(
            InteractionEvent.created_at >= cutoff,
            ~InteractionEvent.interaction_type.like("a2a.%"),
        )
        .group_by(Entity.type)
    )
    agent_vs_human = {
        str(row[0].value): row[1] for row in type_counts.fetchall()
    }

    # Calculate agent social percentage
    agent_count = agent_vs_human.get("agent", 0)
    agent_pct = (agent_count / total * 100) if total > 0 else 0.0

    return SocialFeatureStats(
        total_social_events=total,
        unique_entities=unique,
        agent_social_pct=agent_pct,
        by_feature=by_feature,
        agent_vs_human=agent_vs_human,
        period_days=days,
    )
