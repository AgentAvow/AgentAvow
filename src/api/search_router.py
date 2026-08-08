from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import bindparam, case, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src import cache
from src.api.rate_limit import rate_limit_reads
from src.cache import TTL_SHORT
from src.database import get_db
from src.models import (
    CommunityScan,
    Entity,
    EntityType,
    Listing,
    Post,
    PrivacyTier,
    Submolt,
    TrustScore,
)
from src.utils import escape_like, like_pattern

router = APIRouter(prefix="/search", tags=["search"])


class SearchEntityResult(BaseModel):
    id: uuid.UUID
    type: str
    display_name: str
    did_web: str = ""
    bio_markdown: str = ""
    avatar_url: str | None = None
    trust_score: float | None = None
    trust_components: dict | None = None
    framework_source: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SearchPostResult(BaseModel):
    id: uuid.UUID
    content: str
    author_display_name: str
    author_id: uuid.UUID
    vote_count: int
    created_at: datetime


class SearchSubmoltResult(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    description: str
    member_count: int
    created_at: datetime


class SearchToolResult(BaseModel):
    owner: str
    repo: str
    full_name: str
    trust_score: int | None = None
    grade: str
    last_scanned_at: datetime


class SearchResponse(BaseModel):
    entities: list[SearchEntityResult]
    posts: list[SearchPostResult]
    submolts: list[SearchSubmoltResult] = []
    tools: list[SearchToolResult] = []
    entity_count: int
    post_count: int
    submolt_count: int = 0
    tool_count: int = 0


def _make_tsquery(q: str) -> str:
    """Convert user query to PostgreSQL tsquery-safe string.

    Splits on whitespace, escapes each token, joins with '&'.
    Returns a safe string for use as a bind parameter with to_tsquery().
    """
    tokens = q.strip().split()
    if not tokens:
        return ""
    # Strip non-alphanumeric chars (except hyphens/underscores) to prevent
    # tsquery syntax injection, then add prefix matching
    import re
    safe = [re.sub(r"[^\w\-]", "", t) + ":*" for t in tokens if t.strip()]
    safe = [t for t in safe if t != ":*"]  # drop empty tokens
    if not safe:
        return ""
    return " & ".join(safe)


@router.get(
    "", response_model=SearchResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def search(
    q: str = Query(..., min_length=1, max_length=200),
    type: str | None = Query(None, pattern="^(human|agent|post|all)$"),
    framework: str | None = Query(
        None, max_length=50,
        description="Filter entities by framework_source (e.g. openclaw, langchain, mcp, native)",
    ),
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Search entities, posts, and submolts.

    Uses PostgreSQL full-text search with ts_rank for relevance
    ordering, falling back to ILIKE for short queries.
    Results are cached in Redis for TTL_SHORT (30s).
    """
    cache_key = f"search:{q}:{type}:{framework}:{limit}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    search_type = type or "all"
    tsquery_str = _make_tsquery(q)
    use_fts = len(q.strip()) >= 2 and tsquery_str

    entities: list[SearchEntityResult] = []
    posts: list[SearchPostResult] = []
    submolts: list[SearchSubmoltResult] = []
    tools: list[SearchToolResult] = []

    # Search entities
    if search_type in ("all", "human", "agent"):
        entity_query = (
            select(Entity, TrustScore.score, TrustScore.components)
            .outerjoin(TrustScore, TrustScore.entity_id == Entity.id)
            .where(
                Entity.is_active.is_(True),
                Entity.privacy_tier == PrivacyTier.PUBLIC,
            )
        )

        # Entities use ILIKE for display_name (handles compound names)
        # combined with FTS for bio text when available
        pattern = like_pattern(q)
        if use_fts:
            ts_col = func.to_tsvector(
                text("'english'"),
                func.coalesce(Entity.bio_markdown, text("''")),
            )
            tsq = func.to_tsquery(text("'english'"), bindparam("tsq_entity", tsquery_str))
            entity_query = entity_query.where(
                or_(
                    Entity.display_name.ilike(pattern),
                    ts_col.op("@@")(tsq),
                    Entity.did_web.ilike(pattern),
                ),
            )
            rank = func.ts_rank(ts_col, tsq)
            entity_query = entity_query.order_by(
                rank.desc(),
                TrustScore.score.desc().nullslast(),
            )
        else:
            entity_query = entity_query.where(
                or_(
                    Entity.display_name.ilike(pattern),
                    Entity.bio_markdown.ilike(pattern),
                    Entity.did_web.ilike(pattern),
                ),
            )
            entity_query = entity_query.order_by(
                TrustScore.score.desc().nullslast(),
                Entity.created_at.desc(),
            )

        if search_type == "human":
            entity_query = entity_query.where(
                Entity.type == EntityType.HUMAN,
            )
        elif search_type == "agent":
            entity_query = entity_query.where(
                Entity.type == EntityType.AGENT,
            )

        if framework:
            entity_query = entity_query.where(
                Entity.framework_source == framework.lower(),
            )

        entity_query = entity_query.limit(limit)
        result = await db.execute(entity_query)
        for entity, score, components in result.all():
            entities.append(SearchEntityResult(
                id=entity.id,
                type=entity.type.value,
                display_name=entity.display_name,
                did_web=entity.did_web,
                bio_markdown=entity.bio_markdown,
                avatar_url=entity.avatar_url,
                trust_score=score,
                trust_components=components,
                framework_source=entity.framework_source,
                created_at=entity.created_at,
            ))

    # Search posts
    if search_type in ("all", "post"):
        post_query = (
            select(Post, Entity.display_name, Entity.id)
            .join(Entity, Post.author_entity_id == Entity.id)
            .where(
                Post.is_hidden.is_(False),
                Entity.is_active.is_(True),
                Entity.privacy_tier == PrivacyTier.PUBLIC,
            )
        )

        if use_fts:
            post_ts = func.to_tsvector(
                text("'english'"), Post.content,
            )
            post_tsq = func.to_tsquery(
                text("'english'"), bindparam("tsq_post", tsquery_str),
            )
            post_query = post_query.where(post_ts.op("@@")(post_tsq))
            post_rank = func.ts_rank(post_ts, post_tsq)
            post_query = post_query.order_by(
                post_rank.desc(),
                Post.vote_count.desc(),
            )
        else:
            pattern = like_pattern(q)
            post_query = post_query.where(Post.content.ilike(pattern))
            post_query = post_query.order_by(
                Post.vote_count.desc(), Post.created_at.desc(),
            )

        post_query = post_query.limit(limit)
        result = await db.execute(post_query)
        for post, author_name, author_id in result.all():
            posts.append(SearchPostResult(
                id=post.id,
                content=post.content,
                author_display_name=author_name,
                author_id=author_id,
                vote_count=post.vote_count,
                created_at=post.created_at,
            ))

    # Search submolts
    if search_type == "all":
        submolt_query = select(Submolt).where(
            Submolt.is_active.is_(True),
        )

        if use_fts:
            sm_ts = func.to_tsvector(
                text("'english'"),
                func.coalesce(Submolt.display_name, text("''"))
                + text("' '")
                + func.coalesce(Submolt.description, text("''")),
            )
            sm_tsq = func.to_tsquery(
                text("'english'"), bindparam("tsq_submolt", tsquery_str),
            )
            submolt_query = submolt_query.where(sm_ts.op("@@")(sm_tsq))
        else:
            pattern = like_pattern(q)
            submolt_query = submolt_query.where(
                or_(
                    Submolt.display_name.ilike(pattern),
                    Submolt.name.ilike(pattern),
                    Submolt.description.ilike(pattern),
                ),
            )

        submolt_query = submolt_query.order_by(
            Submolt.member_count.desc(),
            Submolt.created_at.desc(),
        ).limit(limit)

        result = await db.execute(submolt_query)
        for s in result.scalars().all():
            submolts.append(SearchSubmoltResult(
                id=s.id,
                name=s.name,
                display_name=s.display_name,
                description=s.description or "",
                member_count=s.member_count or 0,
                created_at=s.created_at,
            ))

    # Search community scans (tools a user publicly scanned — persisted in
    # CommunityScan). This is a real gap otherwise: a repo someone scanned via
    # /public/scan never surfaces in global search. CommunityScan has no
    # tsvector column, so match owner/repo/full_name with an ILIKE prefix;
    # relevance = exact repo/full_name match first, then most-recently scanned.
    if search_type == "all":
        from src.api.public_scan_router import _grade_from_score

        prefix = escape_like(q.strip()) + "%"
        q_lower = q.strip().lower()
        relevance = case(
            (func.lower(CommunityScan.repo) == q_lower, 0),
            (func.lower(CommunityScan.full_name) == q_lower, 0),
            (func.lower(CommunityScan.owner) == q_lower, 0),
            else_=1,
        )
        tool_query = (
            select(CommunityScan)
            .where(
                or_(
                    CommunityScan.owner.ilike(prefix),
                    CommunityScan.repo.ilike(prefix),
                    CommunityScan.full_name.ilike(prefix),
                ),
            )
            .order_by(relevance.asc(), CommunityScan.last_scanned_at.desc())
            .limit(10)
        )
        result = await db.execute(tool_query)
        for c in result.scalars().all():
            tools.append(SearchToolResult(
                owner=c.owner,
                repo=c.repo,
                full_name=c.full_name,
                trust_score=c.trust_score,
                grade=_grade_from_score(c.trust_score or 0),
                last_scanned_at=c.last_scanned_at,
            ))

    result = SearchResponse(
        entities=entities,
        posts=posts,
        submolts=submolts,
        tools=tools,
        entity_count=len(entities),
        post_count=len(posts),
        submolt_count=len(submolts),
        tool_count=len(tools),
    )
    await cache.set(cache_key, result.model_dump(mode="json"), ttl=TTL_SHORT)
    return result


@router.get(
    "/entities", response_model=list[SearchEntityResult],
    dependencies=[Depends(rate_limit_reads)],
)
async def search_entities(
    q: str = Query(..., min_length=1, max_length=200),
    type: str | None = Query(None, pattern="^(human|agent)$"),
    framework: str | None = Query(
        None, max_length=50,
        description="Filter entities by framework_source (e.g. openclaw, langchain, mcp, native)",
    ),
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Search only entities using full-text search."""
    tsquery_str = _make_tsquery(q)
    use_fts = len(q.strip()) >= 2 and tsquery_str

    query = (
        select(Entity, TrustScore.score, TrustScore.components)
        .outerjoin(TrustScore, TrustScore.entity_id == Entity.id)
        .where(
            Entity.is_active.is_(True),
            Entity.privacy_tier == PrivacyTier.PUBLIC,
        )
    )

    pattern = like_pattern(q)
    if use_fts:
        ts_col = func.to_tsvector(
            text("'english'"),
            func.coalesce(Entity.bio_markdown, text("''")),
        )
        tsq = func.to_tsquery(text("'english'"), bindparam("tsq_lb", tsquery_str))
        query = query.where(
            or_(
                Entity.display_name.ilike(pattern),
                ts_col.op("@@")(tsq),
            ),
        )
        rank = func.ts_rank(ts_col, tsq)
        query = query.order_by(
            rank.desc(), TrustScore.score.desc().nullslast(),
        )
    else:
        query = query.where(
            or_(
                Entity.display_name.ilike(pattern),
                Entity.bio_markdown.ilike(pattern),
            ),
        )
        query = query.order_by(
            TrustScore.score.desc().nullslast(),
            Entity.created_at.desc(),
        )

    if type == "human":
        query = query.where(Entity.type == EntityType.HUMAN)
    elif type == "agent":
        query = query.where(Entity.type == EntityType.AGENT)

    if framework:
        query = query.where(Entity.framework_source == framework.lower())

    query = query.limit(limit)
    result = await db.execute(query)
    return [
        SearchEntityResult(
            id=entity.id,
            type=entity.type.value,
            display_name=entity.display_name,
            did_web=entity.did_web,
            bio_markdown=entity.bio_markdown,
            avatar_url=entity.avatar_url,
            trust_score=score,
            trust_components=components,
            framework_source=entity.framework_source,
            created_at=entity.created_at,
        )
        for entity, score, components in result.all()
    ]


class LeaderboardEntry(BaseModel):
    id: uuid.UUID
    type: str
    display_name: str
    avatar_url: str | None = None
    trust_score: float | None = None
    post_count: int = 0
    follower_count: int = 0
    framework_source: str | None = None
    framework_diversity_score: int = 0

    model_config = {"from_attributes": True}


@router.get(
    "/leaderboard", response_model=list[LeaderboardEntry],
    dependencies=[Depends(rate_limit_reads)],
)
async def leaderboard(
    metric: str = Query(
        "trust", pattern="^(trust|posts|followers|framework_diversity)$"
    ),
    entity_type: str | None = Query(
        None, pattern="^(human|agent)$"
    ),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Public leaderboard of top entities by trust, posts, followers, or framework diversity.

    The ``framework_diversity`` metric ranks entities by the number of distinct
    ``framework_source`` values among their interaction partners (followers +
    following).  This rewards entities that bridge multiple agent frameworks.
    """
    from src.models import EntityRelationship, RelationshipType

    # Cap offset to avoid deep scans on large tables
    if offset > 200:
        offset = 200

    # Cache leaderboard results (short TTL — changes frequently)
    cache_key = f"search_leaderboard:{metric}:{entity_type}:{limit}:{offset}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    if metric == "framework_diversity":
        # Count distinct framework_source values among an entity's
        # followers and following (interaction partners).
        partner_frameworks = (
            select(
                EntityRelationship.source_entity_id.label("entity_id"),
                Entity.framework_source,
            )
            .join(Entity, EntityRelationship.target_entity_id == Entity.id)
            .where(
                EntityRelationship.type == RelationshipType.FOLLOW,
                Entity.is_active.is_(True),
                Entity.framework_source.isnot(None),
            )
        )
        # Also include entities this person follows (outgoing relationships)
        following_frameworks = (
            select(
                EntityRelationship.target_entity_id.label("entity_id"),
                Entity.framework_source,
            )
            .join(Entity, EntityRelationship.source_entity_id == Entity.id)
            .where(
                EntityRelationship.type == RelationshipType.FOLLOW,
                Entity.is_active.is_(True),
                Entity.framework_source.isnot(None),
            )
        )
        from sqlalchemy import union_all
        combined = union_all(partner_frameworks, following_frameworks).subquery()
        diversity_sub = (
            select(
                combined.c.entity_id,
                func.count(func.distinct(combined.c.framework_source)).label("diversity"),
            )
            .group_by(combined.c.entity_id)
            .subquery()
        )

        query = (
            select(
                Entity,
                TrustScore.score,
                func.coalesce(diversity_sub.c.diversity, 0).label("diversity_score"),
            )
            .outerjoin(TrustScore, TrustScore.entity_id == Entity.id)
            .outerjoin(diversity_sub, diversity_sub.c.entity_id == Entity.id)
            .where(
                Entity.is_active.is_(True),
                Entity.privacy_tier == PrivacyTier.PUBLIC,
            )
            .group_by(Entity.id, TrustScore.score, diversity_sub.c.diversity)
            .order_by(
                func.coalesce(diversity_sub.c.diversity, 0).desc(),
                TrustScore.score.desc().nullslast(),
            )
        )

        if entity_type == "human":
            query = query.where(Entity.type == EntityType.HUMAN)
        elif entity_type == "agent":
            query = query.where(Entity.type == EntityType.AGENT)

        query = query.offset(offset).limit(limit)
        result = await db.execute(query)

        entries = []
        for row in result.all():
            entity = row[0]
            score = row[1]
            div = row[2] if len(row) > 2 else 0
            entries.append(LeaderboardEntry(
                id=entity.id,
                type=entity.type.value,
                display_name=entity.display_name,
                avatar_url=entity.avatar_url,
                trust_score=round(float(score), 4) if score is not None else None,
                framework_source=entity.framework_source,
                framework_diversity_score=div,
            ))
        await cache.set(cache_key, [e.model_dump(mode="json") for e in entries], ttl=TTL_SHORT)
        return entries

    query = (
        select(
            Entity,
            TrustScore.score,
            func.count(func.distinct(Post.id)).label("post_count"),
        )
        .outerjoin(TrustScore, TrustScore.entity_id == Entity.id)
        .outerjoin(Post, (Post.author_entity_id == Entity.id) & Post.is_hidden.is_(False))
        .where(
            Entity.is_active.is_(True),
            Entity.privacy_tier == PrivacyTier.PUBLIC,
        )
        .group_by(Entity.id, TrustScore.score)
    )

    if entity_type == "human":
        query = query.where(Entity.type == EntityType.HUMAN)
    elif entity_type == "agent":
        query = query.where(Entity.type == EntityType.AGENT)

    if metric == "trust":
        query = query.order_by(TrustScore.score.desc().nullslast())
    elif metric == "posts":
        query = query.order_by(func.count(func.distinct(Post.id)).desc())
    elif metric == "followers":
        # Sub-query for follower count
        follower_sub = (
            select(
                EntityRelationship.target_entity_id,
                func.count().label("fc"),
            )
            .where(EntityRelationship.type == RelationshipType.FOLLOW)
            .group_by(EntityRelationship.target_entity_id)
            .subquery()
        )
        query = (
            select(
                Entity,
                TrustScore.score,
                func.count(func.distinct(Post.id)).label("post_count"),
                func.coalesce(follower_sub.c.fc, 0).label("follower_count"),
            )
            .outerjoin(TrustScore, TrustScore.entity_id == Entity.id)
            .outerjoin(Post, (Post.author_entity_id == Entity.id) & Post.is_hidden.is_(False))
            .outerjoin(follower_sub, follower_sub.c.target_entity_id == Entity.id)
            .where(
                Entity.is_active.is_(True),
                Entity.privacy_tier == PrivacyTier.PUBLIC,
            )
            .group_by(Entity.id, TrustScore.score, follower_sub.c.fc)
            .order_by(func.coalesce(follower_sub.c.fc, 0).desc())
        )
        if entity_type == "human":
            query = query.where(Entity.type == EntityType.HUMAN)
        elif entity_type == "agent":
            query = query.where(Entity.type == EntityType.AGENT)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)

    entries = []
    for row in result.all():
        entity = row[0]
        score = row[1]
        pc = row[2] if len(row) > 2 else 0
        fc = row[3] if len(row) > 3 else 0
        entries.append(LeaderboardEntry(
            id=entity.id,
            type=entity.type.value,
            display_name=entity.display_name,
            avatar_url=entity.avatar_url,
            trust_score=round(float(score), 4) if score is not None else None,
            post_count=pc,
            follower_count=fc,
            framework_source=entity.framework_source,
        ))

    await cache.set(cache_key, [e.model_dump(mode="json") for e in entries], ttl=TTL_SHORT)
    return entries


class SearchListingResult(BaseModel):
    id: uuid.UUID
    title: str
    description: str
    category: str
    pricing_model: str
    price_cents: int
    seller_name: str
    seller_id: uuid.UUID
    view_count: int
    created_at: datetime


@router.get(
    "/listings",
    response_model=list[SearchListingResult],
    dependencies=[Depends(rate_limit_reads)],
)
async def search_listings(
    q: str = Query(..., min_length=1, max_length=200),
    category: str | None = Query(None),
    pricing: str | None = Query(
        None, pattern="^(free|one_time|subscription)$",
    ),
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Search marketplace listings by title and description."""
    query = (
        select(Listing, Entity.display_name, Entity.id)
        .join(Entity, Listing.entity_id == Entity.id)
        .where(Listing.is_active.is_(True))
    )

    if category:
        query = query.where(Listing.category == category)
    if pricing:
        query = query.where(Listing.pricing_model == pricing)

    pattern = like_pattern(q)
    query = query.where(
        or_(
            Listing.title.ilike(pattern),
            Listing.description.ilike(pattern),
        ),
    )
    query = query.order_by(
        Listing.view_count.desc(), Listing.created_at.desc(),
    )

    query = query.limit(limit)
    result = await db.execute(query)

    return [
        SearchListingResult(
            id=listing.id,
            title=listing.title,
            description=listing.description,
            category=listing.category,
            pricing_model=listing.pricing_model,
            price_cents=listing.price_cents or 0,
            seller_name=seller_name,
            seller_id=seller_id,
            view_count=listing.view_count or 0,
            created_at=listing.created_at,
        )
        for listing, seller_name, seller_id in result.all()
    ]


@router.get(
    "/submolts",
    response_model=list[SearchSubmoltResult],
    dependencies=[Depends(rate_limit_reads)],
)
async def search_submolts(
    q: str = Query(..., min_length=1, max_length=200),
    tag: str | None = Query(None),
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Search submolts with optional tag filter."""
    from sqlalchemy import type_coerce
    from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB

    tsquery_str = _make_tsquery(q)
    use_fts = len(q.strip()) >= 2 and tsquery_str

    query = select(Submolt).where(Submolt.is_active.is_(True))

    if tag:
        query = query.where(
            Submolt.tags.op("@>")(type_coerce([tag], PG_JSONB))
        )

    if use_fts:
        sm_ts = func.to_tsvector(
            text("'english'"),
            func.coalesce(Submolt.display_name, text("''"))
            + text("' '")
            + func.coalesce(Submolt.description, text("''")),
        )
        sm_tsq = func.to_tsquery(
            text("'english'"), bindparam("tsq_sm_browse", tsquery_str),
        )
        query = query.where(sm_ts.op("@@")(sm_tsq))
    else:
        pattern = like_pattern(q)
        query = query.where(
            or_(
                Submolt.display_name.ilike(pattern),
                Submolt.name.ilike(pattern),
                Submolt.description.ilike(pattern),
            ),
        )

    query = query.order_by(
        Submolt.member_count.desc(), Submolt.created_at.desc(),
    ).limit(limit)

    result = await db.execute(query)
    return [
        SearchSubmoltResult(
            id=s.id,
            name=s.name,
            display_name=s.display_name,
            description=s.description or "",
            member_count=s.member_count or 0,
            created_at=s.created_at,
        )
        for s in result.scalars().all()
    ]
