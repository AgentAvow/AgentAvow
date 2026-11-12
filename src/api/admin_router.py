from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deactivation import cascade_deactivate
from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.audit import log_action
from src.database import get_db
from src.models import (
    AnalyticsEvent,
    AnomalyAlert,
    APIKey,
    AuditLog,
    BehavioralBaseline,
    Bookmark,
    CapabilityEndorsement,
    DIDDocument,
    DIDStatus,
    EmailVerification,
    Entity,
    EntityRelationship,
    EntityType,
    EvolutionRecord,
    FrameworkSecurityScan,
    IssueReport,
    Listing,
    ModerationFlag,
    ModerationStatus,
    Notification,
    PopulationAlert,
    Post,
    RelationshipType,
    Review,
    Submolt,
    Transaction,
    TransactionStatus,
    TrustScore,
    Vote,
    WebhookSubscription,
)
from src.utils import like_pattern

router = APIRouter(prefix="/admin", tags=["admin"])


class FrameworkDistributionEntry(BaseModel):
    framework: str
    count: int


class SecurityScanStats(BaseModel):
    total_scanned: int = 0
    clean: int = 0
    warnings: int = 0
    critical: int = 0
    errors: int = 0
    last_scan_at: str | None = None


class PlatformStats(BaseModel):
    total_entities: int
    total_humans: int
    total_agents: int
    moltbook_imported: int = 0
    total_posts: int
    total_votes: int
    total_follows: int
    total_submolts: int
    total_listings: int
    total_reviews: int
    total_endorsements: int
    total_bookmarks: int
    total_evolution_records: int
    pending_moderation_flags: int
    active_webhooks: int
    total_transactions: int
    total_revenue_cents: int
    active_entities_30d: int
    population_alerts_unresolved: int = 0
    framework_distribution: list[FrameworkDistributionEntry] = []
    security_scans: SecurityScanStats = SecurityScanStats()


class EntityListItem(BaseModel):
    id: uuid.UUID
    type: str
    display_name: str
    email: str | None
    did_web: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class EntityListResponse(BaseModel):
    entities: list[EntityListItem]
    total: int


class UnverifiedEntityItem(BaseModel):
    id: uuid.UUID
    email: str | None
    display_name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class UnverifiedEntitiesResponse(BaseModel):
    entities: list[UnverifiedEntityItem]
    total: int


class EmailStatsResponse(BaseModel):
    unverified_count: int
    registered_last_24h: int
    verified_last_24h: int


@router.get(
    "/stats", response_model=PlatformStats,
    dependencies=[Depends(rate_limit_reads)],
)
async def platform_stats(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get platform-wide statistics. Admin only.

    Counts only active entities. Deactivated Moltbook profiles (synthetic
    data removed March 2026) are excluded from totals but reported
    separately in ``moltbook_imported``.
    """
    require_admin(current_entity)

    from src import cache

    cached = await cache.get("admin:stats")
    if cached is not None:
        return cached

    _active = Entity.is_active.is_(True)
    total_entities = await db.scalar(
        select(func.count()).select_from(Entity).where(_active)
    ) or 0
    total_humans = await db.scalar(
        select(func.count()).select_from(Entity).where(
            _active, Entity.type == EntityType.HUMAN,
        )
    ) or 0
    total_agents = await db.scalar(
        select(func.count()).select_from(Entity).where(
            _active, Entity.type == EntityType.AGENT,
        )
    ) or 0
    moltbook_imported = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.source_type == "moltbook",
        )
    ) or 0
    total_posts = await db.scalar(
        select(func.count()).select_from(Post)
    ) or 0
    total_votes = await db.scalar(
        select(func.count()).select_from(Vote)
    ) or 0
    total_follows = await db.scalar(
        select(func.count()).select_from(EntityRelationship)
    ) or 0
    total_submolts = await db.scalar(
        select(func.count()).select_from(Submolt)
    ) or 0
    total_listings = await db.scalar(
        select(func.count()).select_from(Listing)
    ) or 0
    total_reviews = await db.scalar(
        select(func.count()).select_from(Review)
    ) or 0
    total_endorsements = await db.scalar(
        select(func.count()).select_from(CapabilityEndorsement)
    ) or 0
    total_bookmarks = await db.scalar(
        select(func.count()).select_from(Bookmark)
    ) or 0
    total_evolution = await db.scalar(
        select(func.count()).select_from(EvolutionRecord)
    ) or 0
    pending_flags = await db.scalar(
        select(func.count()).select_from(ModerationFlag).where(
            ModerationFlag.status == ModerationStatus.PENDING
        )
    ) or 0
    active_webhooks = await db.scalar(
        select(func.count()).select_from(WebhookSubscription).where(
            WebhookSubscription.is_active.is_(True)
        )
    ) or 0

    total_transactions = await db.scalar(
        select(func.count()).select_from(Transaction)
    ) or 0
    total_revenue = await db.scalar(
        select(func.coalesce(func.sum(Transaction.amount_cents), 0)).where(
            Transaction.status == TransactionStatus.COMPLETED,
        )
    ) or 0

    from datetime import timedelta
    from datetime import timezone as _tz

    cutoff_30d = datetime.now(_tz.utc) - timedelta(days=30)
    active_30d = await db.scalar(
        select(func.count(func.distinct(Post.author_entity_id))).where(
            Post.created_at >= cutoff_30d,
        )
    ) or 0

    # Framework distribution: count of entities per framework_source
    # (excluding Moltbook bulk imports)
    fw_label = func.coalesce(
        Entity.framework_source, "unknown",
    ).label("fw")
    fw_result = await db.execute(
        select(fw_label, func.count().label("cnt"))
        .where(Entity.is_active.is_(True))
        .group_by(fw_label)
        .order_by(func.count().desc())
    )
    framework_distribution = [
        FrameworkDistributionEntry(framework=fw, count=cnt)
        for fw, cnt in fw_result.all()
    ]

    pop_alerts_unresolved = await db.scalar(
        select(func.count()).select_from(PopulationAlert).where(
            PopulationAlert.is_resolved.is_(False),
        )
    ) or 0

    # Security scan stats
    _scan_counts = await db.execute(
        select(
            FrameworkSecurityScan.scan_result,
            func.count().label("cnt"),
        )
        .group_by(FrameworkSecurityScan.scan_result)
    )
    _scan_map = {row[0]: row[1] for row in _scan_counts.all()}
    _last_scan = await db.scalar(
        select(func.max(FrameworkSecurityScan.scanned_at))
    )
    security_scans = SecurityScanStats(
        total_scanned=sum(_scan_map.values()),
        clean=_scan_map.get("clean", 0),
        warnings=_scan_map.get("warnings", 0),
        critical=_scan_map.get("critical", 0),
        errors=_scan_map.get("error", 0),
        last_scan_at=_last_scan.isoformat() if _last_scan else None,
    )

    result = PlatformStats(
        total_entities=total_entities,
        total_humans=total_humans,
        total_agents=total_agents,
        moltbook_imported=moltbook_imported,
        total_posts=total_posts,
        total_votes=total_votes,
        total_follows=total_follows,
        total_submolts=total_submolts,
        total_listings=total_listings,
        total_reviews=total_reviews,
        total_endorsements=total_endorsements,
        total_bookmarks=total_bookmarks,
        total_evolution_records=total_evolution,
        pending_moderation_flags=pending_flags,
        active_webhooks=active_webhooks,
        total_transactions=total_transactions,
        total_revenue_cents=total_revenue,
        active_entities_30d=active_30d,
        population_alerts_unresolved=pop_alerts_unresolved,
        framework_distribution=framework_distribution,
        security_scans=security_scans,
    )
    await cache.set("admin:stats", result.model_dump(mode="json"), ttl=cache.TTL_SHORT)
    return result


@router.get(
    "/entities", response_model=EntityListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_entities(
    type: str | None = Query(None, pattern="^(human|agent)$"),
    q: str | None = Query(None, max_length=200),
    active_only: bool = Query(True),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List all entities. Admin only. Use q to search by name or email."""
    require_admin(current_entity)

    from sqlalchemy import or_

    query = select(Entity).order_by(Entity.created_at.desc())
    count_query = select(func.count()).select_from(Entity)

    if type == "human":
        query = query.where(Entity.type == EntityType.HUMAN)
        count_query = count_query.where(Entity.type == EntityType.HUMAN)
    elif type == "agent":
        query = query.where(Entity.type == EntityType.AGENT)
        count_query = count_query.where(Entity.type == EntityType.AGENT)

    if q:
        pattern = like_pattern(q)
        search_filter = or_(
            Entity.display_name.ilike(pattern),
            Entity.email.ilike(pattern),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    if active_only:
        query = query.where(Entity.is_active.is_(True))
        count_query = count_query.where(Entity.is_active.is_(True))

    total = await db.scalar(count_query) or 0
    result = await db.execute(query.offset(offset).limit(limit))
    entities = result.scalars().all()

    return EntityListResponse(
        entities=[
            EntityListItem(
                id=e.id,
                type=e.type.value,
                display_name=e.display_name,
                email=e.email,
                did_web=e.did_web,
                is_active=e.is_active,
                is_admin=e.is_admin,
                created_at=e.created_at,
            )
            for e in entities
        ],
        total=total,
    )


@router.patch(
    "/entities/{entity_id}/deactivate",
    dependencies=[Depends(rate_limit_writes)],
)
async def deactivate_entity(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate an entity. Admin only."""
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.id == current_entity.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    entity.is_active = False
    await db.flush()

    cascade = await cascade_deactivate(
        db, entity_id, performed_by=current_entity.id,
    )

    return {
        "message": f"Entity {entity.display_name} deactivated",
        "cascade": cascade,
    }


@router.patch(
    "/entities/{entity_id}/reactivate",
    dependencies=[Depends(rate_limit_writes)],
)
async def reactivate_entity(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Reactivate an entity. Admin only."""
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    entity.is_active = True
    await db.flush()
    return {"message": f"Entity {entity.display_name} reactivated"}


@router.post(
    "/entities/{entity_id}/verify-email",
    dependencies=[Depends(rate_limit_writes)],
)
async def admin_verify_email(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Force-verify an entity's email. Admin only (for support cases)."""
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    if entity.email_verified:
        return {"message": f"Entity {entity.display_name} is already email-verified"}

    entity.email_verified = True
    await log_action(
        db,
        action="admin.entity.verify_email",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
    )
    await db.flush()
    return {"message": f"Entity {entity.display_name} email verified"}


@router.patch(
    "/entities/{entity_id}/promote",
    dependencies=[Depends(rate_limit_writes)],
)
async def promote_to_admin(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Promote an entity to admin. Admin only."""
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.is_admin:
        raise HTTPException(status_code=409, detail="Already an admin")

    entity.is_admin = True
    await db.flush()
    return {"message": f"Entity {entity.display_name} promoted to admin"}


@router.patch(
    "/entities/{entity_id}/demote",
    dependencies=[Depends(rate_limit_writes)],
)
async def demote_admin(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Remove admin status from an entity. Admin only."""
    require_admin(current_entity)

    if entity_id == current_entity.id:
        raise HTTPException(
            status_code=400, detail="Cannot demote yourself",
        )

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if not entity.is_admin:
        raise HTTPException(status_code=409, detail="Not an admin")

    entity.is_admin = False
    await db.flush()
    return {"message": f"Entity {entity.display_name} demoted from admin"}


@router.post("/trust/recompute", dependencies=[Depends(rate_limit_writes)])
async def recompute_trust_scores(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Recompute trust scores for all active entities. Admin only."""
    require_admin(current_entity)

    from src.trust.score import batch_recompute

    count = await batch_recompute(db)
    return {"message": f"Recomputed trust scores for {count} entities"}


@router.post("/trust/recompute-all", dependencies=[Depends(rate_limit_writes)])
async def recompute_all_trust_scores(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger batch trust recompute with attestation decay and activity weighting.

    This enhanced recompute applies:
    - Attestation decay: >90 days = 50% weight, >180 days = 25% weight
    - Activity recency: last 30 days = 100%, 30-90 days = 50%, >90 days = 25%

    Returns a summary with entities_processed, scores_changed, avg_score,
    and duration_seconds.

    Admin only.
    """
    require_admin(current_entity)

    from src.jobs.trust_recompute import run_trust_recompute

    summary = await run_trust_recompute(db)
    return summary


class TrustDistributionBucket(BaseModel):
    range: str
    count: int


class TrustEntityTypeAvg(BaseModel):
    entity_type: str
    avg_score: float
    count: int


class TrustStatsResponse(BaseModel):
    distribution: list[TrustDistributionBucket]
    avg_by_type: list[TrustEntityTypeAvg]
    total_with_scores: int


@router.get(
    "/trust/stats",
    response_model=TrustStatsResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def trust_distribution_stats(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trust score distribution stats. Admin only.

    Returns:
    - distribution: count by score range (0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0)
    - avg_by_type: average score per entity type (human vs agent)
    - total_with_scores: total entities that have trust scores
    """
    require_admin(current_entity)

    from src.models import EntityType, TrustScore

    # Distribution buckets
    buckets = [
        ("0.0-0.2", 0.0, 0.2),
        ("0.2-0.4", 0.2, 0.4),
        ("0.4-0.6", 0.4, 0.6),
        ("0.6-0.8", 0.6, 0.8),
        ("0.8-1.0", 0.8, 1.01),  # include 1.0
    ]

    # Only count trust scores for active entities
    _active_trust = (
        select(TrustScore.score, TrustScore.id, TrustScore.entity_id)
        .join(Entity, TrustScore.entity_id == Entity.id)
        .where(Entity.is_active.is_(True))
        .subquery()
    )

    distribution = []
    for label, lo, hi in buckets:
        count = await db.scalar(
            select(func.count()).select_from(_active_trust).where(
                _active_trust.c.score >= lo,
                _active_trust.c.score < hi,
            )
        ) or 0
        distribution.append(TrustDistributionBucket(range=label, count=count))

    # Average by entity type (active entities only)
    avg_by_type = []
    for etype in [EntityType.HUMAN, EntityType.AGENT]:
        row = await db.execute(
            select(
                func.avg(TrustScore.score),
                func.count(TrustScore.id),
            )
            .join(Entity, TrustScore.entity_id == Entity.id)
            .where(Entity.type == etype, Entity.is_active.is_(True))
        )
        avg_val, cnt = row.one()
        avg_by_type.append(TrustEntityTypeAvg(
            entity_type=etype.value,
            avg_score=round(float(avg_val), 4) if avg_val else 0.0,
            count=cnt or 0,
        ))

    total_with_scores = await db.scalar(
        select(func.count()).select_from(_active_trust)
    ) or 0

    return TrustStatsResponse(
        distribution=distribution,
        avg_by_type=avg_by_type,
        total_with_scores=total_with_scores,
    )


@router.get("/rate-limits", dependencies=[Depends(rate_limit_reads)])
async def get_rate_limit_status(
    current_entity: Entity = Depends(get_current_entity),
):
    """Get current rate limiter state. Admin only."""
    require_admin(current_entity)

    import time as _time

    from src.api.rate_limit import _limiter

    now = _time.time()
    active_keys: list[dict] = []

    # Try Redis first for accurate cross-worker data
    try:
        from src.redis_client import get_redis

        r = get_redis()
        keys = []
        async for rk in r.scan_iter(match="rl:*", count=100):
            keys.append(rk)
            if len(keys) >= 200:
                break
        for rk in keys:
            await r.zremrangebyscore(rk, 0, now - 60)
            count = await r.zcard(rk)
            if count > 0:
                oldest = await r.zrange(rk, 0, 0, withscores=True)
                age = round(now - oldest[0][1], 1) if oldest else 0
                active_keys.append({
                    "key": rk.replace("rl:", "", 1) if isinstance(rk, str) else rk,
                    "requests_last_60s": count,
                    "oldest_request_age_s": age,
                })
    except Exception:
        # Fallback to in-memory data
        for key, timestamps in _limiter._fallback.items():
            recent = [t for t in timestamps if now - t < 60]
            if recent:
                active_keys.append({
                    "key": key,
                    "requests_last_60s": len(recent),
                    "oldest_request_age_s": round(now - min(recent), 1),
                })

    active_keys.sort(
        key=lambda x: x["requests_last_60s"], reverse=True,
    )

    return {
        "total_tracked_keys": len(active_keys),
        "active_keys": active_keys[:50],
    }


@router.get("/growth", dependencies=[Depends(rate_limit_reads)])
async def get_growth_metrics(
    days: int = Query(7, ge=1, le=90),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get daily growth metrics for the past N days. Admin only."""
    require_admin(current_entity)

    from datetime import timedelta, timezone

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    _day = literal_column("'day'")

    # Daily signups
    signup_day = func.date_trunc(_day, Entity.created_at)
    signup_result = await db.execute(
        select(signup_day.label("day"), func.count().label("count"))
        .where(Entity.created_at >= cutoff)
        .group_by(signup_day)
        .order_by(signup_day)
    )
    signups = [
        {"date": row[0].isoformat()[:10], "count": row[1]}
        for row in signup_result.all()
    ]

    # Daily posts
    post_day = func.date_trunc(_day, Post.created_at)
    post_result = await db.execute(
        select(post_day.label("day"), func.count().label("count"))
        .where(Post.created_at >= cutoff)
        .group_by(post_day)
        .order_by(post_day)
    )
    posts = [
        {"date": row[0].isoformat()[:10], "count": row[1]}
        for row in post_result.all()
    ]

    # Daily notifications (engagement proxy)
    notif_day = func.date_trunc(_day, Notification.created_at)
    notif_result = await db.execute(
        select(notif_day.label("day"), func.count().label("count"))
        .where(Notification.created_at >= cutoff)
        .group_by(notif_day)
        .order_by(notif_day)
    )
    notifications = [
        {"date": row[0].isoformat()[:10], "count": row[1]}
        for row in notif_result.all()
    ]

    return {
        "period_days": days,
        "signups_per_day": signups,
        "posts_per_day": posts,
        "notifications_per_day": notifications,
    }


@router.get("/top-entities", dependencies=[Depends(rate_limit_reads)])
async def get_top_entities(
    metric: str = Query(
        "trust", pattern="^(trust|posts|followers)$"
    ),
    limit: int = Query(10, ge=1, le=50),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get top entities by various metrics. Admin only."""
    require_admin(current_entity)

    from src.models import RelationshipType, TrustScore

    if metric == "trust":
        result = await db.execute(
            select(Entity, TrustScore.score)
            .join(TrustScore, TrustScore.entity_id == Entity.id)
            .where(Entity.is_active.is_(True))
            .order_by(TrustScore.score.desc())
            .limit(limit)
        )
        return {
            "metric": "trust",
            "entities": [
                {
                    "id": str(e.id),
                    "display_name": e.display_name,
                    "type": e.type.value,
                    "score": s,
                }
                for e, s in result.all()
            ],
        }

    elif metric == "posts":
        result = await db.execute(
            select(
                Entity,
                func.count(Post.id).label("cnt"),
            )
            .join(Post, Post.author_entity_id == Entity.id)
            .where(Entity.is_active.is_(True))
            .group_by(Entity.id)
            .order_by(func.count(Post.id).desc())
            .limit(limit)
        )
        return {
            "metric": "posts",
            "entities": [
                {
                    "id": str(e.id),
                    "display_name": e.display_name,
                    "type": e.type.value,
                    "count": cnt,
                }
                for e, cnt in result.all()
            ],
        }

    else:  # followers
        result = await db.execute(
            select(
                Entity,
                func.count(EntityRelationship.id).label("cnt"),
            )
            .join(
                EntityRelationship,
                EntityRelationship.target_entity_id == Entity.id,
            )
            .where(
                Entity.is_active.is_(True),
                EntityRelationship.type == RelationshipType.FOLLOW,
            )
            .group_by(Entity.id)
            .order_by(func.count(EntityRelationship.id).desc())
            .limit(limit)
        )
        return {
            "metric": "followers",
            "entities": [
                {
                    "id": str(e.id),
                    "display_name": e.display_name,
                    "type": e.type.value,
                    "count": cnt,
                }
                for e, cnt in result.all()
            ],
        }


@router.patch(
    "/listings/{listing_id}/feature",
    dependencies=[Depends(rate_limit_writes)],
)
async def toggle_featured_listing(
    listing_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Toggle featured status on a listing. Admin only."""
    require_admin(current_entity)

    listing = await db.get(Listing, listing_id)
    if listing is None:
        raise HTTPException(status_code=404, detail="Listing not found")

    listing.is_featured = not (listing.is_featured or False)
    await log_action(
        db,
        action="admin.listing.feature_toggle",
        entity_id=current_entity.id,
        resource_type="listing",
        resource_id=listing.id,
        details={"is_featured": listing.is_featured},
    )
    await db.flush()
    return {
        "message": f"Listing {'featured' if listing.is_featured else 'unfeatured'}",
        "is_featured": listing.is_featured,
    }


@router.patch(
    "/entities/{entity_id}/suspend",
    dependencies=[Depends(rate_limit_writes)],
)
async def suspend_entity(
    entity_id: uuid.UUID,
    days: int = Query(..., ge=1, le=365),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Temporarily suspend an entity for N days. Admin only."""
    from datetime import timedelta, timezone

    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.id == current_entity.id:
        raise HTTPException(status_code=400, detail="Cannot suspend yourself")

    until = datetime.now(timezone.utc) + timedelta(days=days)
    entity.is_active = False
    entity.suspended_until = until
    await log_action(
        db,
        action="admin.entity.suspend",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity.id,
        details={"days": days, "until": until.isoformat()},
    )
    await db.flush()

    cascade = await cascade_deactivate(
        db, entity.id, performed_by=current_entity.id,
    )

    return {
        "message": f"Entity suspended until {until.isoformat()[:10]}",
        "suspended_until": until.isoformat(),
        "cascade": cascade,
    }


@router.post("/cleanup/token-blacklist", dependencies=[Depends(rate_limit_writes)])
async def cleanup_token_blacklist(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Remove expired entries from the token blacklist. Admin only."""
    require_admin(current_entity)

    from src.api.auth_service import cleanup_expired_blacklist

    removed = await cleanup_expired_blacklist(db)
    return {"message": f"Removed {removed} expired blacklist entries", "removed": removed}


@router.patch(
    "/posts/{post_id}/hide",
    dependencies=[Depends(rate_limit_writes)],
)
async def admin_hide_post(
    post_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Hide a post (soft delete). Admin only."""
    require_admin(current_entity)

    post = await db.get(Post, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.is_hidden:
        return {"message": "Post is already hidden"}

    post.is_hidden = True
    await log_action(
        db,
        action="admin.post.hide",
        entity_id=current_entity.id,
        resource_type="post",
        resource_id=post.id,
    )
    await db.flush()
    return {"message": "Post hidden"}


@router.get("/audit-logs", dependencies=[Depends(rate_limit_reads)])
async def query_audit_logs(
    action: str | None = Query(None, description="Filter by action prefix"),
    entity_id: uuid.UUID | None = Query(None),
    resource_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Query audit logs with filters. Admin only."""
    require_admin(current_entity)

    base = select(AuditLog)
    count_base = select(func.count()).select_from(AuditLog)

    if action:
        base = base.where(AuditLog.action.startswith(action))
        count_base = count_base.where(AuditLog.action.startswith(action))
    if entity_id:
        base = base.where(AuditLog.entity_id == entity_id)
        count_base = count_base.where(AuditLog.entity_id == entity_id)
    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)
        count_base = count_base.where(AuditLog.resource_type == resource_type)

    total = await db.scalar(count_base) or 0

    result = await db.execute(
        base.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": str(log.id),
                "entity_id": str(log.entity_id) if log.entity_id else None,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "details": log.details or {},
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# --- Email Verification Management ---


@router.get(
    "/email-verifications",
    response_model=UnverifiedEntitiesResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_unverified_entities(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List active entities with unverified emails. Admin only.

    Returns paginated list of entities where email_verified=False and is_active=True.
    Useful for identifying users who may need a verification email resend.
    """
    require_admin(current_entity)

    base_filter = (
        Entity.email_verified.is_(False),
        Entity.is_active.is_(True),
    )

    total = await db.scalar(
        select(func.count()).select_from(Entity).where(*base_filter)
    ) or 0

    result = await db.execute(
        select(Entity)
        .where(*base_filter)
        .order_by(Entity.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    entities = result.scalars().all()

    return UnverifiedEntitiesResponse(
        entities=[
            UnverifiedEntityItem(
                id=e.id,
                email=e.email,
                display_name=e.display_name,
                created_at=e.created_at,
            )
            for e in entities
        ],
        total=total,
    )


@router.post(
    "/email-verifications/{entity_id}/resend",
    dependencies=[Depends(rate_limit_writes)],
)
async def resend_verification_email(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Resend verification email to an entity. Admin only.

    Creates a new verification token (invalidating any previous ones)
    and sends a verification email to the entity's address.
    """
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    if not entity.is_active:
        raise HTTPException(status_code=400, detail="Entity is deactivated")
    if entity.email_verified:
        raise HTTPException(status_code=409, detail="Entity email is already verified")
    if not entity.email:
        raise HTTPException(status_code=400, detail="Entity has no email address")

    from src.api.auth_service import create_verification_token
    from src.email import send_verification_email

    token = await create_verification_token(db, entity.id)
    sent = await send_verification_email(entity.email, token)

    await log_action(
        db,
        action="admin.email_verification.resend",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity.id,
        details={"email_sent": sent},
    )
    await db.flush()

    if not sent:
        raise HTTPException(
            status_code=502,
            detail="Verification token created but email delivery failed",
        )

    return {"message": f"Verification email resent to {entity.email}"}


@router.get(
    "/email-stats",
    response_model=EmailStatsResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def email_verification_stats(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Quick email verification health overview. Admin only.

    Returns:
    - unverified_count: active entities with email_verified=False
    - registered_last_24h: entities created in the last 24 hours
    - verified_last_24h: entities that verified their email in the last 24 hours
    """
    require_admin(current_entity)

    from datetime import timedelta
    from datetime import timezone as _tz

    now = datetime.now(_tz.utc)
    cutoff_24h = now - timedelta(hours=24)

    unverified_count = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.email_verified.is_(False),
            Entity.is_active.is_(True),
        )
    ) or 0

    registered_last_24h = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.created_at >= cutoff_24h,
        )
    ) or 0

    # Entities verified in last 24h: look for used verification tokens consumed recently
    verified_last_24h = await db.scalar(
        select(func.count(func.distinct(EmailVerification.entity_id)))
        .where(
            EmailVerification.is_used.is_(True),
            EmailVerification.created_at >= cutoff_24h,
        )
    ) or 0

    return EmailStatsResponse(
        unverified_count=unverified_count,
        registered_last_24h=registered_last_24h,
        verified_last_24h=verified_last_24h,
    )


# ---------------------------------------------------------------------------
# TestFlight Waitlist
# ---------------------------------------------------------------------------


class WaitlistEntry(BaseModel):
    email: str
    submitted_at: str
    page: str
    session_id: str


class WaitlistResponse(BaseModel):
    entries: list[WaitlistEntry]
    total: int


@router.get(
    "/waitlist",
    response_model=WaitlistResponse,
)
async def get_waitlist(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List all iOS TestFlight waitlist signups."""
    require_admin(current_entity)
    result = await db.execute(
        select(AnalyticsEvent)
        .where(AnalyticsEvent.event_type == "ios_waitlist")
        .order_by(AnalyticsEvent.created_at.desc())
    )
    events = result.scalars().all()

    entries = []
    for ev in events:
        meta = ev.extra_metadata or {}
        email = meta.get("email", "")
        if email:
            entries.append(
                WaitlistEntry(
                    email=email,
                    submitted_at=ev.created_at.isoformat() if ev.created_at else "",
                    page=ev.page or "",
                    session_id=ev.session_id or "",
                )
            )

    return WaitlistResponse(entries=entries, total=len(entries))


# ---------------------------------------------------------------------------
# Collusion Detection
# ---------------------------------------------------------------------------


class CollusionAlertResponse(BaseModel):
    id: uuid.UUID
    entity_id: uuid.UUID
    alert_type: str
    severity: str
    z_score: float
    details: dict | None = None
    is_resolved: bool
    resolved_by: uuid.UUID | None = None
    resolved_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class CollusionAlertsListResponse(BaseModel):
    alerts: list[CollusionAlertResponse]
    total: int


class CollusionScanResponse(BaseModel):
    total_alerts: int
    mutual_attestation: int
    attestation_cluster: int
    voting_ring: int


@router.get(
    "/collusion/alerts",
    response_model=CollusionAlertsListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_collusion_alerts(
    alert_type: str | None = Query(None),
    severity: str | None = Query(None),
    is_resolved: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get collusion alerts with optional filtering. Admin only."""
    require_admin(current_entity)

    from src.safety.collusion import COLLUSION_ALERT_TYPES

    base = select(AnomalyAlert).where(
        AnomalyAlert.alert_type.in_(COLLUSION_ALERT_TYPES)
    )
    count_base = select(func.count()).select_from(AnomalyAlert).where(
        AnomalyAlert.alert_type.in_(COLLUSION_ALERT_TYPES)
    )

    if alert_type is not None:
        base = base.where(AnomalyAlert.alert_type == alert_type)
        count_base = count_base.where(AnomalyAlert.alert_type == alert_type)

    if severity is not None:
        base = base.where(AnomalyAlert.severity == severity)
        count_base = count_base.where(AnomalyAlert.severity == severity)

    if is_resolved is not None:
        base = base.where(AnomalyAlert.is_resolved.is_(is_resolved))
        count_base = count_base.where(AnomalyAlert.is_resolved.is_(is_resolved))

    total = await db.scalar(count_base) or 0

    result = await db.execute(
        base.order_by(AnomalyAlert.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    alerts = result.scalars().all()

    return CollusionAlertsListResponse(
        alerts=[CollusionAlertResponse.model_validate(a) for a in alerts],
        total=total,
    )


@router.post(
    "/collusion/scan",
    response_model=CollusionScanResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def trigger_collusion_scan(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a collusion detection scan. Admin only."""
    require_admin(current_entity)

    from src.jobs.collusion_scan import run_collusion_scan

    summary = await run_collusion_scan(db, auto_flag=True)
    await db.commit()
    return CollusionScanResponse(**summary)


# ---------------------------------------------------------------------------
# Population Composition Monitoring
# ---------------------------------------------------------------------------


class PopulationCompositionResponse(BaseModel):
    total_entities: int
    total_humans: int
    total_agents: int
    human_agent_ratio: float
    framework_distribution: list[FrameworkDistributionEntry]
    top_operators: list[dict]


class PopulationAlertResponse(BaseModel):
    id: uuid.UUID
    alert_type: str
    severity: str
    details: dict | None = None
    is_resolved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class PopulationAlertsListResponse(BaseModel):
    alerts: list[PopulationAlertResponse]
    total: int


class PopulationScanResponse(BaseModel):
    total_alerts: int
    framework_monoculture: int
    operator_flood: int
    registration_spike: int
    sybil_cluster: int


@router.get(
    "/population/composition",
    response_model=PopulationCompositionResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_population_composition(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get current population composition: framework distribution,
    human/agent ratio, and top operators by agent count. Admin only."""
    require_admin(current_entity)

    total_entities = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.is_active.is_(True),
        )
    ) or 0

    total_humans = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.type == EntityType.HUMAN,
            Entity.is_active.is_(True),
        )
    ) or 0

    total_agents = await db.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.type == EntityType.AGENT,
            Entity.is_active.is_(True),
        )
    ) or 0

    human_agent_ratio = (
        round(total_humans / total_agents, 4) if total_agents > 0 else 0.0
    )

    # Framework distribution (active agents only)
    fw_label = func.coalesce(Entity.framework_source, "unknown").label("fw")
    fw_result = await db.execute(
        select(fw_label, func.count().label("cnt"))
        .where(
            Entity.type == EntityType.AGENT,
            Entity.is_active.is_(True),
        )
        .group_by(fw_label)
        .order_by(func.count().desc())
    )
    framework_distribution = [
        FrameworkDistributionEntry(framework=fw, count=cnt)
        for fw, cnt in fw_result.all()
    ]

    # Top operators by agent count
    op_result = await db.execute(
        select(
            Entity.operator_id,
            func.count().label("cnt"),
        )
        .where(
            Entity.type == EntityType.AGENT,
            Entity.is_active.is_(True),
            Entity.operator_id.isnot(None),
        )
        .group_by(Entity.operator_id)
        .order_by(func.count().desc())
        .limit(20)
    )
    op_rows = op_result.all()

    # Fetch operator display names
    if op_rows:
        op_ids = [row[0] for row in op_rows]
        name_result = await db.execute(
            select(Entity.id, Entity.display_name).where(Entity.id.in_(op_ids))
        )
        name_map = {eid: name for eid, name in name_result.all()}
    else:
        name_map = {}

    top_operators = [
        {
            "operator_id": str(op_id),
            "display_name": name_map.get(op_id, "unknown"),
            "agent_count": cnt,
        }
        for op_id, cnt in op_rows
    ]

    return PopulationCompositionResponse(
        total_entities=total_entities,
        total_humans=total_humans,
        total_agents=total_agents,
        human_agent_ratio=human_agent_ratio,
        framework_distribution=framework_distribution,
        top_operators=top_operators,
    )


@router.get(
    "/population/alerts",
    response_model=PopulationAlertsListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_population_alerts(
    alert_type: str | None = Query(None),
    severity: str | None = Query(None),
    is_resolved: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get population alerts with optional filtering. Admin only."""
    require_admin(current_entity)

    base = select(PopulationAlert)
    count_base = select(func.count()).select_from(PopulationAlert)

    if alert_type is not None:
        base = base.where(PopulationAlert.alert_type == alert_type)
        count_base = count_base.where(PopulationAlert.alert_type == alert_type)

    if severity is not None:
        base = base.where(PopulationAlert.severity == severity)
        count_base = count_base.where(PopulationAlert.severity == severity)

    if is_resolved is not None:
        base = base.where(PopulationAlert.is_resolved.is_(is_resolved))
        count_base = count_base.where(PopulationAlert.is_resolved.is_(is_resolved))

    total = await db.scalar(count_base) or 0

    result = await db.execute(
        base.order_by(PopulationAlert.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    alerts = result.scalars().all()

    return PopulationAlertsListResponse(
        alerts=[PopulationAlertResponse.model_validate(a) for a in alerts],
        total=total,
    )


@router.post(
    "/population/scan",
    response_model=PopulationScanResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def trigger_population_scan(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a population composition scan. Admin only."""
    require_admin(current_entity)

    from src.jobs.population_scan import run_population_scan

    summary = await run_population_scan(db)
    await db.commit()
    return PopulationScanResponse(**summary)


# ---------------------------------------------------------------------------
# Behavioral Baselines
# ---------------------------------------------------------------------------


class BehavioralBaselineResponse(BaseModel):
    id: uuid.UUID
    entity_id: uuid.UUID
    period_start: str
    period_end: str
    metrics: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class BehavioralBaselineListResponse(BaseModel):
    baselines: list[BehavioralBaselineResponse]
    total: int


class WeeklyBaselinesSummary(BaseModel):
    entities_processed: int
    baselines_created: int
    pruned: int
    period_start: str
    period_end: str
    duration_seconds: float


@router.get(
    "/baselines/{entity_id}",
    response_model=BehavioralBaselineListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_entity_baselines(
    entity_id: uuid.UUID,
    limit: int = Query(12, ge=1, le=52),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get behavioral baseline history for an entity (up to 12 weeks).

    Returns the list of BehavioralBaseline records for the entity,
    ordered by period_start descending.  Admin only.
    """
    require_admin(current_entity)

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    count_query = (
        select(func.count())
        .select_from(BehavioralBaseline)
        .where(BehavioralBaseline.entity_id == entity_id)
    )
    total = await db.scalar(count_query) or 0

    result = await db.execute(
        select(BehavioralBaseline)
        .where(BehavioralBaseline.entity_id == entity_id)
        .order_by(BehavioralBaseline.period_start.desc())
        .offset(offset)
        .limit(limit)
    )
    baselines = result.scalars().all()

    return BehavioralBaselineListResponse(
        baselines=[
            BehavioralBaselineResponse(
                id=b.id,
                entity_id=b.entity_id,
                period_start=b.period_start.isoformat(),
                period_end=b.period_end.isoformat(),
                metrics=b.metrics or {},
                created_at=b.created_at,
            )
            for b in baselines
        ],
        total=total,
    )


@router.post(
    "/baselines/compute",
    response_model=WeeklyBaselinesSummary,
    dependencies=[Depends(rate_limit_writes)],
)
async def trigger_weekly_baselines(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger weekly behavioral baseline computation. Admin only.

    Computes baselines for all active entities for the last 7 days and
    prunes baselines older than 12 weeks.
    """
    require_admin(current_entity)

    from src.jobs.behavioral_baseline import run_weekly_baselines

    summary = await run_weekly_baselines(db)
    await db.commit()
    return WeeklyBaselinesSummary(**summary)


# ---------------------------------------------------------------------------
# Issue Tracking (Bug Reports / Feature Requests)
# ---------------------------------------------------------------------------


class IssueResponse(BaseModel):
    id: uuid.UUID
    post_id: uuid.UUID
    bot_reply_id: uuid.UUID | None
    reporter_entity_id: uuid.UUID
    bot_entity_id: uuid.UUID
    issue_type: str
    status: str
    title: str
    resolution_note: str | None
    resolved_by: uuid.UUID | None
    resolved_at: datetime | None
    resolution_reply_id: uuid.UUID | None
    created_at: datetime
    reporter_name: str | None = None
    bot_name: str | None = None
    post_content: str | None = None


class IssueListResponse(BaseModel):
    issues: list[IssueResponse]
    total: int


class ResolveIssueRequest(BaseModel):
    status: str  # "resolved", "closed", "wontfix"
    resolution_note: str | None = None


@router.get(
    "/issues",
    response_model=IssueListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_issues(
    status: str | None = Query(None),
    issue_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List all issue reports with optional filters. Admin only."""
    require_admin(current_entity)

    base = select(IssueReport)
    count_base = select(func.count()).select_from(IssueReport)

    if status:
        base = base.where(IssueReport.status == status)
        count_base = count_base.where(IssueReport.status == status)
    if issue_type:
        base = base.where(IssueReport.issue_type == issue_type)
        count_base = count_base.where(IssueReport.issue_type == issue_type)

    total = await db.scalar(count_base) or 0

    result = await db.execute(
        base.order_by(IssueReport.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    issues = result.scalars().all()

    # Gather related data
    entity_ids = set()
    post_ids = set()
    for iss in issues:
        entity_ids.add(iss.reporter_entity_id)
        entity_ids.add(iss.bot_entity_id)
        post_ids.add(iss.post_id)

    name_map: dict[uuid.UUID, str] = {}
    if entity_ids:
        name_result = await db.execute(
            select(Entity.id, Entity.display_name).where(Entity.id.in_(entity_ids))
        )
        name_map = {eid: name for eid, name in name_result.all()}

    content_map: dict[uuid.UUID, str] = {}
    if post_ids:
        post_result = await db.execute(
            select(Post.id, Post.content).where(Post.id.in_(post_ids))
        )
        content_map = {pid: content for pid, content in post_result.all()}

    return IssueListResponse(
        issues=[
            IssueResponse(
                id=iss.id,
                post_id=iss.post_id,
                bot_reply_id=iss.bot_reply_id,
                reporter_entity_id=iss.reporter_entity_id,
                bot_entity_id=iss.bot_entity_id,
                issue_type=iss.issue_type,
                status=iss.status,
                title=iss.title,
                resolution_note=iss.resolution_note,
                resolved_by=iss.resolved_by,
                resolved_at=iss.resolved_at,
                resolution_reply_id=iss.resolution_reply_id,
                created_at=iss.created_at,
                reporter_name=name_map.get(iss.reporter_entity_id),
                bot_name=name_map.get(iss.bot_entity_id),
                post_content=(content_map.get(iss.post_id) or "")[:200],
            )
            for iss in issues
        ],
        total=total,
    )


@router.patch(
    "/issues/{issue_id}/resolve",
    dependencies=[Depends(rate_limit_writes)],
)
async def resolve_issue(
    issue_id: uuid.UUID,
    body: ResolveIssueRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Resolve an issue report. Bot posts a follow-up reply. Admin only."""
    require_admin(current_entity)

    if body.status not in ("resolved", "closed", "wontfix"):
        raise HTTPException(
            status_code=400,
            detail="status must be 'resolved', 'closed', or 'wontfix'",
        )

    issue = await db.get(IssueReport, issue_id)
    if issue is None:
        raise HTTPException(status_code=404, detail="Issue not found")

    if issue.status in ("resolved", "closed", "wontfix"):
        raise HTTPException(status_code=409, detail="Issue is already resolved")

    issue.status = body.status
    issue.resolution_note = body.resolution_note
    issue.resolved_by = current_entity.id
    issue.resolved_at = datetime.now(
        __import__("datetime").timezone.utc
    )
    await db.flush()

    # Bot posts a follow-up reply to the original post
    status_label = {
        "resolved": "resolved",
        "closed": "closed",
        "wontfix": "won't fix",
    }
    reply_content = (
        f"**Update:** This {issue.issue_type} report has been marked as "
        f"**{status_label[body.status]}**."
    )
    if body.resolution_note:
        reply_content += f"\n\n{body.resolution_note}"
    reply_content += "\n\nThank you for your report!"

    from src.bots.engine import _post_as_bot

    reply = await _post_as_bot(
        db,
        issue.bot_entity_id,
        reply_content,
        flair="discussion",
        parent_post_id=issue.post_id,
    )
    if reply:
        issue.resolution_reply_id = reply.id
        await db.flush()

    # Notify the original reporter
    from src.api.notification_router import create_notification

    await create_notification(
        db,
        entity_id=issue.reporter_entity_id,
        kind="issue_resolution",
        title=f"Your {issue.issue_type} report was {status_label[body.status]}",
        body=body.resolution_note or f"Your {issue.issue_type} report has been addressed.",
        reference_id=str(issue.post_id),
    )

    await log_action(
        db,
        action="admin.issue.resolve",
        entity_id=current_entity.id,
        resource_type="issue_report",
        resource_id=issue.id,
        details={"status": body.status, "resolution_note": body.resolution_note},
    )

    return {
        "message": f"Issue {status_label[body.status]}",
        "issue_id": str(issue.id),
        "resolution_reply_id": str(reply.id) if reply else None,
    }


# ---------------------------------------------------------------------------
# Bot ownership claims — admin review queue
# ---------------------------------------------------------------------------


class ClaimItem(BaseModel):
    agent_id: str
    agent_name: str
    claimer_id: str
    claimer_name: str
    claimed_at: str
    reason: str
    status: str  # "unclaimed", "approved", "rejected"
    source_url: str | None = None
    source_type: str | None = None


class ClaimListResponse(BaseModel):
    claims: list[ClaimItem]
    total: int


class ClaimDecisionRequest(BaseModel):
    note: str = ""


@router.get(
    "/claims",
    response_model=ClaimListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_claims(
    status_filter: str = Query(
        "all",
        pattern="^(unclaimed|approved|rejected|all)$",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List bot ownership claims and unclaimed bots. Admin only.

    Statuses:
    - unclaimed: provisional bots with no operator (need someone to claim)
    - approved: bots that have been claimed (operator assigned)
    - rejected: claims that were rejected by admin
    - all: everything
    """
    require_admin(current_entity)

    _base_where = [
        Entity.type == EntityType.AGENT,
        Entity.is_active.is_(True),
    ]

    if status_filter == "unclaimed":
        # Provisional bots with no operator — these need claiming
        _base_where.append(Entity.is_provisional.is_(True))
        _base_where.append(Entity.operator_id.is_(None))
    elif status_filter == "approved":
        _has_claim = Entity.onboarding_data["ownership_claim"].isnot(None)
        _base_where.append(_has_claim)
        _base_where.append(
            Entity.onboarding_data["ownership_claim"]["status"].astext
            == "approved",
        )
    elif status_filter == "rejected":
        _has_claim = Entity.onboarding_data["ownership_claim"].isnot(None)
        _base_where.append(_has_claim)
        _base_where.append(
            Entity.onboarding_data["ownership_claim"]["status"].astext
            == "rejected",
        )
    # "all" = no extra filter

    stmt = (
        select(Entity)
        .where(*_base_where)
        .order_by(Entity.updated_at.desc())
    )

    count_stmt = (
        select(func.count())
        .select_from(Entity)
        .where(*_base_where)
    )

    total = await db.scalar(count_stmt) or 0
    result = await db.execute(stmt.offset(offset).limit(limit))
    agents = result.scalars().all()

    claims: list[ClaimItem] = []
    for agent in agents:
        claim = (agent.onboarding_data or {}).get("ownership_claim", {})
        # Determine status from data
        if claim and claim.get("status"):
            status = claim["status"]
            claimer_id = claim.get("claimed_by", "")
            claimer_name = claim.get("claimer_name", "Unknown")
            claimed_at = claim.get("claimed_at", "")
            reason = claim.get("reason", "")
        elif agent.operator_id:
            status = "approved"
            claimer_id = str(agent.operator_id)
            claimer_name = ""
            claimed_at = ""
            reason = "Operator assigned at creation"
        else:
            status = "unclaimed"
            claimer_id = ""
            claimer_name = ""
            claimed_at = ""
            reason = ""
        claims.append(ClaimItem(
            agent_id=str(agent.id),
            agent_name=agent.display_name,
            claimer_id=claimer_id,
            claimer_name=claimer_name,
            claimed_at=claimed_at,
            reason=reason,
            status=status,
            source_url=agent.source_url,
            source_type=agent.source_type,
        ))

    return ClaimListResponse(claims=claims, total=total)


@router.post(
    "/claims/{agent_id}/approve",
    dependencies=[Depends(rate_limit_writes)],
)
async def approve_claim(
    agent_id: uuid.UUID,
    body: ClaimDecisionRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Approve a bot ownership claim. Links bot to claimer, elevates trust. Admin only."""
    require_admin(current_entity)

    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    onboarding = agent.onboarding_data or {}
    claim = onboarding.get("ownership_claim")
    if not claim or claim.get("status") != "pending":
        raise HTTPException(400, "No pending claim for this agent")

    claimer_id = uuid.UUID(claim["claimed_by"])
    claimer = await db.get(Entity, claimer_id)
    if claimer is None or not claimer.is_active:
        raise HTTPException(400, "Claiming user no longer exists or is inactive")

    from datetime import timezone as tz

    # Update claim status
    claim["status"] = "approved"
    claim["reviewed_by"] = str(current_entity.id)
    claim["reviewed_at"] = datetime.now(tz.utc).isoformat()
    claim["review_note"] = body.note
    onboarding["ownership_claim"] = claim
    agent.onboarding_data = {**onboarding}

    # Link bot to claimer
    agent.operator_id = claimer_id
    agent.is_provisional = False
    agent.claim_token = None
    agent.provisional_expires_at = None

    # Upgrade API key scopes
    key_result = await db.execute(
        select(APIKey).where(
            APIKey.entity_id == agent.id,
            APIKey.is_active.is_(True),
        )
    )
    for key in key_result.scalars().all():
        key.scopes = ["agent:read", "agent:write", "webhooks:manage"]

    # Upgrade DID from PROVISIONAL to FULL
    did_doc = await db.scalar(
        select(DIDDocument).where(DIDDocument.entity_id == agent.id)
    )
    if did_doc and did_doc.did_status == DIDStatus.PROVISIONAL:
        did_doc.did_status = DIDStatus.FULL
        did_doc.promoted_at = datetime.now(tz.utc)
        did_doc.promoted_by = current_entity.id
        did_doc.promotion_reason = "ownership_claim_approved"

    # Create operator-agent relationship
    existing_rel = await db.execute(
        select(EntityRelationship).where(
            EntityRelationship.source_entity_id == claimer_id,
            EntityRelationship.target_entity_id == agent.id,
            EntityRelationship.type == RelationshipType.OPERATOR_AGENT,
        )
    )
    if existing_rel.scalar_one_or_none() is None:
        rel = EntityRelationship(
            id=uuid.uuid4(),
            source_entity_id=claimer_id,
            target_entity_id=agent.id,
            type=RelationshipType.OPERATOR_AGENT,
        )
        db.add(rel)

    # Boost trust score — operator-linked = 0.7 verification component
    trust = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == agent.id)
    )
    if trust:
        components = trust.components or {}
        components["verification"] = 0.7
        trust.components = {**components}
        # Recompute overall score as weighted average
        weights = {
            "activity": 0.2,
            "endorsements": 0.15,
            "verification": 0.25,
            "consistency": 0.2,
            "community": 0.2,
        }
        total_weight = sum(weights.get(k, 0.1) for k in components)
        if total_weight > 0:
            trust.score = round(
                sum(components.get(k, 0) * weights.get(k, 0.1) for k in components) / total_weight,
                4,
            )
    else:
        # Create trust score with verification component
        trust = TrustScore(
            id=uuid.uuid4(),
            entity_id=agent.id,
            score=0.175,  # 0.7 * 0.25 weight
            components={"verification": 0.7},
        )
        db.add(trust)

    # Notify claimer
    notif = Notification(
        id=uuid.uuid4(),
        entity_id=claimer_id,
        kind="claim_approved",
        title="Bot ownership claim approved",
        body=f"Your claim on {agent.display_name} has been approved. "
        "You are now the verified owner.",
        reference_id=str(agent.id),
    )
    db.add(notif)

    await log_action(
        db,
        action="admin.claim.approve",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "claimer_id": str(claimer_id),
            "note": body.note,
        },
    )
    await db.flush()

    return {
        "message": "Claim approved. Bot linked to owner with verified status.",
        "agent_id": str(agent.id),
        "owner_id": str(claimer_id),
    }


@router.post(
    "/claims/{agent_id}/reject",
    dependencies=[Depends(rate_limit_writes)],
)
async def reject_claim(
    agent_id: uuid.UUID,
    body: ClaimDecisionRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Reject a bot ownership claim. Admin only."""
    require_admin(current_entity)

    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    onboarding = agent.onboarding_data or {}
    claim = onboarding.get("ownership_claim")
    if not claim or claim.get("status") != "pending":
        raise HTTPException(400, "No pending claim for this agent")

    claimer_id = uuid.UUID(claim["claimed_by"])

    from datetime import timezone as tz

    claim["status"] = "rejected"
    claim["reviewed_by"] = str(current_entity.id)
    claim["reviewed_at"] = datetime.now(tz.utc).isoformat()
    claim["review_note"] = body.note
    onboarding["ownership_claim"] = claim
    agent.onboarding_data = {**onboarding}

    # Notify claimer
    notif = Notification(
        id=uuid.uuid4(),
        entity_id=claimer_id,
        kind="claim_rejected",
        title="Bot ownership claim rejected",
        body=(
            f"Your claim on {agent.display_name} was not approved."
            + (f" Reason: {body.note}" if body.note else "")
        ),
        reference_id=str(agent.id),
    )
    db.add(notif)

    await log_action(
        db,
        action="admin.claim.reject",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "claimer_id": str(claimer_id),
            "note": body.note,
        },
    )
    await db.flush()

    return {
        "message": "Claim rejected.",
        "agent_id": str(agent.id),
    }


# ---------------------------------------------------------------------------
# Admin security scan endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/security-scan/trigger/{agent_id}",
    dependencies=[Depends(rate_limit_writes)],
)
async def admin_trigger_scan(
    agent_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a security scan for a specific agent. Admin only."""
    require_admin(current_entity)

    agent = await db.get(Entity, agent_id)
    if agent is None or not agent.is_active:
        raise HTTPException(404, "Agent not found")

    from src.scanner.service import _extract_github_repo, run_security_scan

    repo = _extract_github_repo(agent.source_url)
    if not repo:
        raise HTTPException(400, "Agent has no GitHub source URL")

    scan = await run_security_scan(db, agent_id, force=True)
    await db.commit()

    return {
        "message": f"Scan triggered for {agent.display_name}",
        "agent_id": str(agent_id),
        "scan_result": scan.scan_result if scan else "no_result",
    }


@router.post(
    "/security-scan/batch",
    dependencies=[Depends(rate_limit_writes)],
)
async def admin_batch_scan(
    limit: int = Query(20, ge=1, le=100),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger batch re-scan of agents not scanned recently. Admin only."""
    require_admin(current_entity)

    from src.scanner.service import rescan_all_agents

    scanned = await rescan_all_agents(db, limit=limit)
    return {"message": f"Batch scan complete: {scanned} agents scanned", "scanned": scanned}


@router.get(
    "/security-scan/recent",
    dependencies=[Depends(rate_limit_reads)],
)
async def admin_recent_scans(
    limit: int = Query(20, ge=1, le=100),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """List recent security scans with entity info. Admin only."""
    require_admin(current_entity)

    stmt = (
        select(
            FrameworkSecurityScan.id,
            FrameworkSecurityScan.entity_id,
            FrameworkSecurityScan.scan_result,
            FrameworkSecurityScan.scanned_at,
            FrameworkSecurityScan.vulnerabilities,
            Entity.display_name,
            Entity.source_url,
        )
        .join(Entity, Entity.id == FrameworkSecurityScan.entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(limit)
    )
    rows = await db.execute(stmt)
    scans = []
    for row in rows.all():
        vulns = row.vulnerabilities or {}
        scans.append({
            "id": str(row.id),
            "entity_id": str(row.entity_id),
            "entity_name": row.display_name,
            "source_url": row.source_url,
            "scan_result": row.scan_result,
            "trust_score": vulns.get("trust_score", 0),
            "total_findings": vulns.get("total_findings", 0),
            "critical_count": vulns.get("critical_count", 0),
            "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
        })
    return {"scans": scans}


@router.get("/access", dependencies=[Depends(rate_limit_reads)])
async def list_admin_access_accounts(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Every account with admin or read-only viewer access: display name, email
    (unmasked), role (Admin / Viewer), active flag and created date. Full admins only:
    a viewer gets 403 (this lists people's emails)."""
    require_admin(current_entity)
    from src.admin_access import list_admin_access

    return {"accounts": await list_admin_access(db)}
