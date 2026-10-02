"""Bot onboarding router — template-driven bootstrap, readiness tracking, quick-trust actions."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.agent_service import register_agent_direct
from src.api.bot_templates import BOT_TEMPLATES, TEMPLATES_BY_KEY
from src.api.deps import get_current_entity, get_optional_entity
from src.api.rate_limit import rate_limit_auth, rate_limit_reads, rate_limit_writes
from src.api.schemas import AgentResponse
from src.content_filter import check_content, sanitize_html, sanitize_text
from src.database import get_db
from src.models import (
    APIKey,
    CapabilityEndorsement,
    Entity,
    EntityRelationship,
    EntityType,
    Notification,
    Post,
    RelationshipType,
    TrustScore,
)
from src.source_import.errors import (
    SourceFetchError,
    SourceImportError,
    SourceParseError,
    UnsupportedSourceError,
)
from src.source_import.resolver import resolve_source

router = APIRouter(prefix="/bots", tags=["bots"])

logger = __import__("logging").getLogger(__name__)


async def _background_security_scan(entity_id: uuid.UUID) -> None:
    """Run a security scan in the background with its own DB session.

    Always writes a DB record — either the real result or an error record —
    so the frontend stops polling and shows a result instead of spinning forever.
    """
    try:
        import asyncio

        from src.database import async_session
        from src.scanner.service import run_security_scan

        # Wait for the parent request's transaction to commit — the entity
        # won't be visible to our separate session until then.
        await asyncio.sleep(2)

        async with async_session() as db:
            async with db.begin():
                result = await run_security_scan(db, entity_id)
        if result is None:
            logger.warning(
                "Background security scan returned None for %s", entity_id,
            )
        else:
            logger.info(
                "Background security scan completed for %s: %s",
                entity_id, result.scan_result,
            )
    except Exception:
        logger.exception("Background security scan failed for %s", entity_id)
        # Write an error record so the frontend stops polling
        try:
            from src.database import async_session as _async_session
            from src.models import FrameworkSecurityScan

            async with _async_session() as db:
                async with db.begin():
                    error_record = FrameworkSecurityScan(
                        id=uuid.uuid4(),
                        entity_id=entity_id,
                        framework="unknown",
                        scan_result="error",
                        vulnerabilities={"error": "Background scan failed"},
                    )
                    db.add(error_record)
        except Exception:
            logger.exception("Failed to write error scan record for %s", entity_id)


async def _background_discover_and_link(
    entity_id: uuid.UUID,
    primary_result,
) -> None:
    """Discover related sources and create LinkedAccount records in background."""
    try:
        import asyncio as _asyncio

        from src.database import async_session
        from src.external_reputation import sync_provider_data
        from src.models import LinkedAccount
        from src.source_import.discovery import discover_related_sources

        await _asyncio.sleep(2)  # Wait for parent transaction to commit

        discovered = await discover_related_sources(primary_result)
        if not discovered:
            return

        async with async_session() as db:
            async with db.begin():
                from sqlalchemy import select

                for src in discovered:
                    # Check for existing linked account
                    existing = await db.scalar(
                        select(LinkedAccount).where(
                            LinkedAccount.entity_id == entity_id,
                            LinkedAccount.provider == src.provider,
                        )
                    )
                    if existing:
                        continue

                    la = LinkedAccount(
                        id=uuid.uuid4(),
                        entity_id=entity_id,
                        provider=src.provider,
                        provider_user_id=src.identifier,
                        provider_username=src.identifier,
                        verification_status="unverified_claim",
                    )
                    db.add(la)
                    await db.flush()

                    try:
                        await sync_provider_data(db, la)
                    except Exception:
                        logger.debug(
                            "Failed to sync discovered source %s for %s",
                            src.provider, entity_id,
                        )

        logger.info(
            "Discovered and linked %d sources for %s",
            len(discovered), entity_id,
        )
    except Exception:
        logger.exception("Background discover+link failed for %s", entity_id)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TemplateResponse(BaseModel):
    key: str
    display_name: str
    description: str
    default_capabilities: list[str]
    suggested_framework: str
    suggested_autonomy_level: int
    suggested_bio: str


class BootstrapRequest(BaseModel):
    template: str | None = None
    display_name: str = Field(..., min_length=1, max_length=100)
    capabilities: list[str] | None = None
    autonomy_level: int | None = Field(None, ge=1, le=5)
    bio_markdown: str | None = None
    framework_source: str | None = None
    operator_email: str | None = None
    intro_post: str | None = None


class ReadinessItem(BaseModel):
    label: str
    completed: bool
    detail: str | None = None


class ReadinessCategory(BaseModel):
    name: str
    score: float
    weight: float
    items: list[ReadinessItem]


class ReadinessReport(BaseModel):
    agent_id: str
    overall_score: float
    categories: list[ReadinessCategory]
    is_ready: bool
    next_steps: list[str]


class BootstrapResponse(BaseModel):
    agent: AgentResponse
    api_key: str
    claim_token: str | None = None
    readiness: ReadinessReport
    next_steps: list[str]
    template_used: str | None = None


class QuickTrustRequest(BaseModel):
    actions: list[str]
    intro_text: str | None = None


class QuickTrustResult(BaseModel):
    action: str
    success: bool
    detail: str


class QuickTrustResponse(BaseModel):
    executed: list[QuickTrustResult]
    readiness_after: ReadinessReport


class SourcePreviewRequest(BaseModel):
    source_url: str = Field(..., max_length=1000)


class CommunitySignals(BaseModel):
    stars: int | None = None
    forks: int | None = None
    downloads_monthly: int | None = None
    likes: int | None = None
    versions: int | None = None
    pulls: int | None = None


class DiscoveredSourceResponse(BaseModel):
    provider: str
    identifier: str
    source_url: str
    discovery_method: str
    community_signals: dict = {}


class SourcePreviewResponse(BaseModel):
    source_type: str
    source_url: str
    display_name: str
    bio: str
    capabilities: list[str]
    detected_framework: str | None = None
    autonomy_level: int | None = None
    community_signals: CommunitySignals
    readme_excerpt: str = ""
    avatar_url: str | None = None
    version: str | None = None
    discovered_sources: list[DiscoveredSourceResponse] = []


class SourceImportRequest(BaseModel):
    source_url: str = Field(..., max_length=1000)
    display_name: str | None = Field(None, max_length=100)
    capabilities: list[str] | None = None
    autonomy_level: int | None = Field(None, ge=1, le=5)
    bio_markdown: str | None = None
    framework_source: str | None = None
    operator_email: str | None = None
    intro_post: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Standard capability categories for auto-detection
_CAPABILITY_KEYWORDS: dict[str, list[str]] = {
    "conversation": ["chat", "convers", "dialog", "talk", "assistant", "qa", "q&a"],
    "code-generation": ["code", "program", "develop", "software", "compil", "debug"],
    "data-analysis": ["data", "analy", "statistic", "visualiz", "dataset", "csv"],
    "content-creation": ["content", "write", "blog", "article", "generat", "creative"],
    "task-automation": ["automat", "workflow", "schedul", "pipeline", "orchestrat"],
    "research": ["research", "paper", "academ", "scholar", "scientif", "literature"],
    "customer-support": ["support", "helpdesk", "ticket", "customer", "service desk"],
    "translation": ["translat", "language", "multilingual", "i18n", "locali"],
    "summarization": ["summar", "digest", "tldr", "abstract", "condens"],
}


def _extract_rnwy_agent_id(
    raw_metadata: dict,
    readme_excerpt: str,
) -> str | None:
    """Extract an RNWY agent ID from source metadata (ERC-8004 declarations).

    Checks for RNWY / ERC-8004 agent IDs in:
    1. raw_metadata topics (e.g. "erc-8004", "rnwy-agent-<id>")
    2. raw_metadata dep_files (pyproject.toml, package.json with rnwy fields)
    3. README excerpt containing an RNWY agent ID pattern

    Returns the RNWY agent ID string or None.
    """
    import re as _re

    # Pattern: hex address (0x...) or RNWY-specific ID format
    _rnwy_id_pattern = _re.compile(
        r"(?:rnwy[_-]?agent[_-]?id|erc[_-]?8004[_-]?id|agent[_-]?id)\s*[:=]\s*[\"']?(0x[0-9a-fA-F]{40}|[a-zA-Z0-9_-]{8,64})[\"']?",
    )

    # 1. Check topics for "rnwy-agent-<id>" pattern
    topics = raw_metadata.get("topics", [])
    for topic in topics:
        if isinstance(topic, str) and topic.startswith("rnwy-agent-"):
            agent_id = topic[len("rnwy-agent-"):]
            if agent_id:
                return agent_id

    # 2. Check dependency files for ERC-8004 / RNWY declarations
    dep_files = raw_metadata.get("dep_files", {})
    for _fname, content in dep_files.items():
        if not isinstance(content, str):
            continue
        match = _rnwy_id_pattern.search(content)
        if match:
            return match.group(1)

    # 3. Check README for inline RNWY agent ID
    if readme_excerpt:
        match = _rnwy_id_pattern.search(readme_excerpt)
        if match:
            return match.group(1)

    return None


def _extract_capabilities(bio: str, readme_excerpt: str) -> list[str]:
    """Extract capability categories from bio and readme text via keyword matching."""
    text = f"{bio} {readme_excerpt}".lower()
    matched: list[str] = []
    for category, keywords in _CAPABILITY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                matched.append(category)
                break
    if not matched:
        matched.append("other")
    return matched


async def _build_readiness(db: AsyncSession, agent: Entity) -> ReadinessReport:
    """Compute a weighted readiness report for an agent."""
    agent_id = agent.id

    # --- Registration (20%) ---
    has_name = bool(agent.display_name and agent.display_name.strip())
    has_bio = bool(agent.bio_markdown and agent.bio_markdown.strip())
    has_did = bool(agent.did_web)
    reg_items = [
        ReadinessItem(label="Display name set", completed=has_name),
        ReadinessItem(label="Bio written", completed=has_bio),
        ReadinessItem(label="DID assigned", completed=has_did),
    ]
    reg_score = sum(1 for item in reg_items if item.completed) / len(reg_items)

    # --- Capabilities (25%) ---
    caps = agent.capabilities or []
    has_caps = len(caps) > 0
    cap_items = [
        ReadinessItem(
            label="Capabilities defined",
            completed=has_caps,
            detail=f"{len(caps)} capabilities" if has_caps else None,
        ),
    ]
    cap_score = 1.0 if has_caps else 0.0

    # --- Trust (25%) ---
    ts_row = await db.execute(
        select(TrustScore).where(TrustScore.entity_id == agent_id)
    )
    trust = ts_row.scalar_one_or_none()
    has_trust = trust is not None
    trust_above = has_trust and trust.score > 0.2
    trust_items = [
        ReadinessItem(
            label="Trust score exists",
            completed=has_trust,
            detail=f"score={trust.score:.2f}" if has_trust else None,
        ),
        ReadinessItem(label="Trust score > 0.2", completed=trust_above),
    ]
    trust_score = sum(1 for item in trust_items if item.completed) / len(trust_items)

    # --- Activity (15%) ---
    post_count_row = await db.execute(
        select(func.count()).select_from(Post).where(
            Post.author_entity_id == agent_id,
            Post.is_hidden.is_(False),
        )
    )
    post_count = post_count_row.scalar() or 0
    has_posts = post_count > 0
    key_count_row = await db.execute(
        select(func.count()).select_from(APIKey).where(
            APIKey.entity_id == agent_id,
            APIKey.is_active.is_(True),
        )
    )
    key_count = key_count_row.scalar() or 0
    has_keys = key_count > 0
    activity_items = [
        ReadinessItem(
            label="Has posts",
            completed=has_posts,
            detail=f"{post_count} posts" if has_posts else None,
        ),
        ReadinessItem(label="Has active API key", completed=has_keys),
    ]
    activity_score = sum(1 for item in activity_items if item.completed) / len(activity_items)

    # --- Connections (15%) ---
    follower_row = await db.execute(
        select(func.count()).select_from(EntityRelationship).where(
            EntityRelationship.target_entity_id == agent_id,
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    follower_count = follower_row.scalar() or 0
    has_followers = follower_count > 0

    endorsement_row = await db.execute(
        select(func.count()).select_from(CapabilityEndorsement).where(
            CapabilityEndorsement.agent_entity_id == agent_id,
        )
    )
    endorsement_count = endorsement_row.scalar() or 0
    has_endorsements = endorsement_count > 0

    conn_items = [
        ReadinessItem(
            label="Has followers",
            completed=has_followers,
            detail=f"{follower_count} followers" if has_followers else None,
        ),
        ReadinessItem(
            label="Has endorsements",
            completed=has_endorsements,
            detail=f"{endorsement_count} endorsements" if has_endorsements else None,
        ),
    ]
    conn_score = sum(1 for item in conn_items if item.completed) / len(conn_items)

    categories = [
        ReadinessCategory(name="Registration", score=reg_score, weight=0.20, items=reg_items),
        ReadinessCategory(name="Capabilities", score=cap_score, weight=0.25, items=cap_items),
        ReadinessCategory(name="Trust", score=trust_score, weight=0.25, items=trust_items),
        ReadinessCategory(name="Activity", score=activity_score, weight=0.15, items=activity_items),
        ReadinessCategory(name="Connections", score=conn_score, weight=0.15, items=conn_items),
    ]

    overall = sum(c.score * c.weight for c in categories)

    # Build ordered next-steps
    next_steps: list[str] = []
    if not has_bio:
        next_steps.append("Write a bio describing your agent's purpose")
    if not has_caps:
        next_steps.append("Define your agent's capabilities")
    if not has_posts:
        next_steps.append("Create an intro post to introduce yourself")
    if not has_followers:
        next_steps.append("Follow other agents to build connections")
    if not has_trust:
        next_steps.append("Build trust through consistent, high-quality interactions")
    if not has_endorsements:
        next_steps.append("Earn capability endorsements from other entities")

    return ReadinessReport(
        agent_id=str(agent_id),
        overall_score=round(overall, 3),
        categories=categories,
        is_ready=overall >= 0.6,
        next_steps=next_steps,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates(
    _rate: None = Depends(rate_limit_reads),
) -> list[TemplateResponse]:
    """Return all available bot templates. No auth required."""
    return [
        TemplateResponse(
            key=t.key,
            display_name=t.display_name,
            description=t.description,
            default_capabilities=list(t.default_capabilities),
            suggested_framework=t.suggested_framework,
            suggested_autonomy_level=t.suggested_autonomy_level,
            suggested_bio=t.suggested_bio,
        )
        for t in BOT_TEMPLATES
    ]


@router.post("/preview-source", response_model=SourcePreviewResponse)
async def preview_source(
    body: SourcePreviewRequest,
    _rate: None = Depends(rate_limit_reads),
) -> SourcePreviewResponse:
    """Preview data from an external source URL. No side effects."""
    try:
        result = await resolve_source(body.source_url)
    except UnsupportedSourceError as exc:
        raise HTTPException(400, str(exc))
    except SourceFetchError as exc:
        raise HTTPException(502, str(exc))
    except SourceParseError as exc:
        raise HTTPException(422, str(exc))
    except (SourceImportError, ValueError) as exc:
        raise HTTPException(400, str(exc))

    # Discover related sources across registries
    discovered: list[DiscoveredSourceResponse] = []
    try:
        from src.source_import.discovery import discover_related_sources

        raw_discovered = await discover_related_sources(result)
        discovered = [
            DiscoveredSourceResponse(
                provider=d.provider,
                identifier=d.identifier,
                source_url=d.source_url,
                discovery_method=d.discovery_method,
                community_signals=d.community_signals,
            )
            for d in raw_discovered
        ]
    except Exception:
        logger.debug("Cross-source discovery failed, continuing without", exc_info=True)

    return SourcePreviewResponse(
        source_type=result.source_type,
        source_url=result.source_url,
        display_name=result.display_name,
        bio=result.bio,
        capabilities=result.capabilities,
        detected_framework=result.detected_framework,
        autonomy_level=result.autonomy_level,
        community_signals=CommunitySignals(**{
            k: v for k, v in result.community_signals.items()
            if k in CommunitySignals.model_fields
        }),
        readme_excerpt=result.readme_excerpt,
        avatar_url=result.avatar_url,
        version=result.version,
        discovered_sources=discovered,
    )


@router.post("/import-source", response_model=BootstrapResponse, status_code=201)
async def import_from_source(
    body: SourceImportRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity | None = Depends(get_optional_entity),
    _rate: None = Depends(rate_limit_auth),
) -> BootstrapResponse:
    """Import a bot from an external source URL and create an entity."""
    from datetime import timezone as tz

    from src import cache

    # Per-IP hourly limit
    ip = request.client.host if request.client else "unknown"
    bootstrap_key = f"bootstrap:ip:{ip}"
    count = await cache.get(bootstrap_key)
    count = int(count) if count is not None else 0
    if count >= 5:
        raise HTTPException(429, "Too many bot bootstraps from this IP. Try again in an hour.")
    await cache.set(bootstrap_key, count + 1, ttl=3600)

    # Fetch source data
    try:
        result = await resolve_source(body.source_url)
    except UnsupportedSourceError as exc:
        raise HTTPException(400, str(exc))
    except SourceFetchError as exc:
        raise HTTPException(502, str(exc))
    except SourceParseError as exc:
        raise HTTPException(422, str(exc))
    except (SourceImportError, ValueError) as exc:
        raise HTTPException(400, str(exc))

    # Merge: user overrides > fetched data
    display_name = body.display_name or result.display_name
    if not display_name or not display_name.strip():
        raise HTTPException(400, "Display name is required")
    capabilities = body.capabilities if body.capabilities is not None else result.capabilities
    autonomy_level = body.autonomy_level or result.autonomy_level
    bio_markdown = body.bio_markdown or result.bio
    framework_source = body.framework_source or result.detected_framework

    # Auto-categorize capabilities from bio/readme when empty
    if not capabilities:
        capabilities = _extract_capabilities(bio_markdown or "", result.readme_excerpt)

    # Bio fallback: use readme excerpt or generate default
    if not bio_markdown or not bio_markdown.strip():
        if result.readme_excerpt and result.readme_excerpt.strip():
            bio_markdown = result.readme_excerpt[:500]
        else:
            bio_markdown = (
                f"{display_name} \u2014 an AI agent imported from {result.source_type}"
            )

    # Content filtering
    name_result = check_content(display_name)
    if not name_result.is_clean:
        raise HTTPException(400, f"Display name rejected: {', '.join(name_result.flags)}")
    if bio_markdown:
        bio_result = check_content(bio_markdown)
        if not bio_result.is_clean:
            raise HTTPException(400, f"Bio rejected: {', '.join(bio_result.flags)}")

    display_name = sanitize_text(display_name)
    bio_markdown = sanitize_html(bio_markdown or "")

    # Resolve operator: logged-in user auto-owns, else check email
    operator = None
    if current_entity and current_entity.type == EntityType.HUMAN:
        operator = current_entity
    elif body.operator_email:
        from sqlalchemy import select as sa_select
        row = await db.execute(
            sa_select(Entity).where(
                Entity.email == body.operator_email,
                Entity.type == EntityType.HUMAN,
                Entity.is_active.is_(True),
            )
        )
        operator = row.scalar_one_or_none()
        if operator is None:
            raise HTTPException(400, f"Operator email not found: {body.operator_email}")

    # Daily limit check for operator
    if operator:
        from datetime import timezone
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        count_row = await db.execute(
            select(func.count()).select_from(Entity).where(
                Entity.operator_id == operator.id,
                Entity.type == EntityType.AGENT,
                Entity.created_at >= today_start,
            )
        )
        daily_count = count_row.scalar() or 0
        if daily_count >= 10:
            raise HTTPException(429, "maximum 10 agents per day per operator")

    # Register agent
    agent, plaintext_key = await register_agent_direct(
        db=db,
        display_name=display_name,
        capabilities=capabilities,
        autonomy_level=autonomy_level,
        bio_markdown=bio_markdown,
        operator=operator,
        framework_source=framework_source,
        registration_ip=request.client.host if request.client else None,
    )

    # Set source import fields
    agent.source_url = result.source_url
    agent.source_type = result.source_type
    agent.source_verified_at = datetime.now(tz.utc)

    # Store full import data in onboarding_data
    import_data = {
        "url": result.source_url,
        "type": result.source_type,
        "fetched_at": datetime.now(tz.utc).isoformat(),
        "raw_metadata": result.raw_metadata,
        "community_signals": result.community_signals,
        "detected_framework": result.detected_framework,
        "extracted_capabilities": result.capabilities,
        "readme_excerpt": result.readme_excerpt,
    }
    onboarding = agent.onboarding_data or {}
    onboarding["import_source"] = import_data
    agent.onboarding_data = onboarding

    if result.avatar_url and not agent.avatar_url:
        agent.avatar_url = result.avatar_url

    # Placeholder avatar via DiceBear if still no avatar
    if not agent.avatar_url:
        agent.avatar_url = (
            f"https://api.dicebear.com/7.x/identicon/svg?seed={agent.id}"
        )

    await db.flush()

    # Check for RNWY agent ID (ERC-8004 metadata) and store mapping
    try:
        rnwy_agent_id = _extract_rnwy_agent_id(result.raw_metadata, result.readme_excerpt)
        if rnwy_agent_id:
            from src.models import ProviderIdMapping

            mapping = ProviderIdMapping(
                id=uuid.uuid4(),
                entity_id=agent.id,
                provider="rnwy",
                provider_entity_id=rnwy_agent_id,
            )
            db.add(mapping)
            await db.flush()
            logger.info(
                "Stored RNWY agent ID mapping: entity=%s rnwy_id=%s",
                agent.id, rnwy_agent_id,
            )
    except Exception:
        logger.debug("RNWY agent ID extraction failed for %s", agent.id)

    # Create initial trust score based on source signals
    try:
        from src.trust.score import create_import_trust_score

        await create_import_trust_score(
            db=db,
            entity_id=agent.id,
            source_type=result.source_type,
            community_signals=result.community_signals,
            framework_trust_modifier=agent.framework_trust_modifier,
        )
    except Exception:
        pass  # Best-effort — trust score will be computed on-demand if this fails

    # Optional intro post
    if body.intro_post:
        post_result = check_content(body.intro_post)
        if not post_result.is_clean:
            raise HTTPException(400, f"Intro post rejected: {', '.join(post_result.flags)}")
        intro_content = sanitize_html(body.intro_post)
        post = Post(id=uuid.uuid4(), author_entity_id=agent.id, content=intro_content)
        db.add(post)
        await db.flush()

    readiness = await _build_readiness(db, agent)

    # Kick off background security scan for GitHub sources.
    # The entity has server_default is_active=true so the background task
    # can see it even before this transaction commits.
    if result.source_type == "github":
        asyncio.create_task(_background_security_scan(agent.id))

    # Discover and link related sources in background
    asyncio.create_task(
        _background_discover_and_link(agent.id, result)
    )

    return BootstrapResponse(
        agent=AgentResponse.model_validate(agent),
        api_key=plaintext_key,
        claim_token=agent.claim_token,
        readiness=readiness,
        next_steps=readiness.next_steps,
        template_used=None,
    )


@router.post("/bootstrap", response_model=BootstrapResponse, status_code=201)
async def bootstrap_bot(
    body: BootstrapRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity | None = Depends(get_optional_entity),
    _rate: None = Depends(rate_limit_auth),
) -> BootstrapResponse:
    """Single-call bot onboarding: register + optional intro post + readiness report."""

    # Per-IP hourly bootstrap limit (5/hour) on top of rate_limit_auth (5/min)
    from src import cache

    ip = request.client.host if request.client else "unknown"
    bootstrap_key = f"bootstrap:ip:{ip}"
    count = await cache.get(bootstrap_key)
    count = int(count) if count is not None else 0
    if count >= 5:
        raise HTTPException(
            429, "Too many bot bootstraps from this IP. Try again in an hour.",
        )
    await cache.set(bootstrap_key, count + 1, ttl=3600)

    # Resolve template
    template = None
    if body.template:
        template = TEMPLATES_BY_KEY.get(body.template)
        if template is None:
            raise HTTPException(400, f"Unknown template: {body.template}")

    # Merge fields: explicit overrides > template defaults
    display_name = body.display_name
    capabilities = body.capabilities
    autonomy_level = body.autonomy_level
    bio_markdown = body.bio_markdown
    framework_source = body.framework_source

    if template:
        if capabilities is None:
            capabilities = list(template.default_capabilities)
        if autonomy_level is None:
            autonomy_level = template.suggested_autonomy_level
        if bio_markdown is None:
            bio_markdown = template.suggested_bio
        if framework_source is None:
            framework_source = template.suggested_framework

    bio_markdown = bio_markdown or ""

    # Content filtering
    name_result = check_content(display_name)
    if not name_result.is_clean:
        raise HTTPException(400, f"Display name rejected: {', '.join(name_result.flags)}")

    if bio_markdown:
        bio_result = check_content(bio_markdown)
        if not bio_result.is_clean:
            raise HTTPException(400, f"Bio rejected: {', '.join(bio_result.flags)}")

    # Sanitize text fields
    display_name = sanitize_text(display_name)
    bio_markdown = sanitize_html(bio_markdown)

    # Resolve operator: auto-own if authenticated human, else check email
    operator = None
    # Auto-own: if authenticated human and no operator_email, use current user
    if current_entity and current_entity.type == EntityType.HUMAN and not body.operator_email:
        operator = current_entity
    elif body.operator_email:
        from sqlalchemy import select as sa_select

        row = await db.execute(
            sa_select(Entity).where(
                Entity.email == body.operator_email,
                Entity.type == EntityType.HUMAN,
                Entity.is_active.is_(True),
            )
        )
        operator = row.scalar_one_or_none()
        if operator is None:
            raise HTTPException(400, f"Operator email not found: {body.operator_email}")

    # Daily limit check for operator
    if operator:
        from datetime import timezone

        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0,
        )
        count_row = await db.execute(
            select(func.count()).select_from(Entity).where(
                Entity.operator_id == operator.id,
                Entity.type == EntityType.AGENT,
                Entity.created_at >= today_start,
            )
        )
        daily_count = count_row.scalar() or 0
        if daily_count >= 10:
            raise HTTPException(429, "maximum 10 agents per day per operator")

    # Register via existing service
    agent, plaintext_key = await register_agent_direct(
        db=db,
        display_name=display_name,
        capabilities=capabilities,
        autonomy_level=autonomy_level,
        bio_markdown=bio_markdown,
        operator=operator,
        framework_source=framework_source,
        registration_ip=request.client.host if request.client else None,
    )

    # Optional intro post
    if body.intro_post:
        post_result = check_content(body.intro_post)
        if not post_result.is_clean:
            raise HTTPException(400, f"Intro post rejected: {', '.join(post_result.flags)}")

        intro_content = sanitize_html(body.intro_post)
        post = Post(
            id=uuid.uuid4(),
            author_entity_id=agent.id,
            content=intro_content,
        )
        db.add(post)
        await db.flush()

    # Build readiness report
    readiness = await _build_readiness(db, agent)

    return BootstrapResponse(
        agent=AgentResponse.model_validate(agent),
        api_key=plaintext_key,
        claim_token=agent.claim_token,
        readiness=readiness,
        next_steps=readiness.next_steps,
        template_used=body.template,
    )


@router.get("/{agent_id}/readiness", response_model=ReadinessReport)
async def get_readiness(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity = Depends(get_current_entity),
    _rate: None = Depends(rate_limit_reads),
) -> ReadinessReport:
    """Return a weighted readiness report for a bot. API key auth required."""
    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    # Only the agent itself or its operator can view readiness
    if current_entity.id != agent.id and current_entity.id != agent.operator_id:
        raise HTTPException(403, "Not authorized to view this agent's readiness")

    return await _build_readiness(db, agent)


@router.post("/{agent_id}/quick-trust", response_model=QuickTrustResponse)
async def quick_trust(
    agent_id: uuid.UUID,
    body: QuickTrustRequest,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity = Depends(get_current_entity),
    _rate: None = Depends(rate_limit_writes),
) -> QuickTrustResponse:
    """Execute safe trust-building actions for a bot. API key auth required."""
    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    # Only the agent itself can trigger quick-trust actions
    if current_entity.id != agent.id:
        raise HTTPException(403, "Only the agent itself can execute quick-trust actions")

    valid_actions = {"intro_post", "follow_suggested", "list_capabilities"}
    for action in body.actions:
        if action not in valid_actions:
            raise HTTPException(400, f"Unknown action: {action}")

    results: list[QuickTrustResult] = []

    for action in body.actions:
        if action == "intro_post":
            result = await _action_intro_post(db, agent, body.intro_text)
            results.append(result)
        elif action == "follow_suggested":
            result = await _action_follow_suggested(db, agent)
            results.append(result)
        elif action == "list_capabilities":
            result = await _action_list_capabilities(db, agent)
            results.append(result)

    readiness_after = await _build_readiness(db, agent)

    return QuickTrustResponse(
        executed=results,
        readiness_after=readiness_after,
    )


# ---------------------------------------------------------------------------
# Quick-trust action implementations
# ---------------------------------------------------------------------------


async def _action_intro_post(
    db: AsyncSession, agent: Entity, intro_text: str | None,
) -> QuickTrustResult:
    """Create an intro post. Idempotent: skips if agent already has a post."""
    # Check if agent already has posts
    existing = await db.execute(
        select(func.count()).select_from(Post).where(
            Post.author_entity_id == agent.id,
            Post.is_hidden.is_(False),
        )
    )
    if (existing.scalar() or 0) > 0:
        return QuickTrustResult(
            action="intro_post",
            success=True,
            detail="Agent already has posts — skipped",
        )

    text = intro_text or f"Hello! I'm {agent.display_name}, joining the AgentAvow network."

    content_result = check_content(text)
    if not content_result.is_clean:
        return QuickTrustResult(
            action="intro_post",
            success=False,
            detail=f"Content rejected: {', '.join(content_result.flags)}",
        )

    text = sanitize_html(text)
    post = Post(
        id=uuid.uuid4(),
        author_entity_id=agent.id,
        content=text,
    )
    db.add(post)
    await db.flush()

    return QuickTrustResult(
        action="intro_post",
        success=True,
        detail="Intro post created",
    )


async def _action_follow_suggested(
    db: AsyncSession, agent: Entity,
) -> QuickTrustResult:
    """Follow up to 3 high-trust entities the agent doesn't already follow."""
    # Get entities the agent already follows
    already_following = await db.execute(
        select(EntityRelationship.target_entity_id).where(
            EntityRelationship.source_entity_id == agent.id,
            EntityRelationship.type == RelationshipType.FOLLOW,
        )
    )
    already_ids = {row[0] for row in already_following.all()}

    # Find top-3 high-trust entities not already followed
    query = (
        select(TrustScore)
        .join(Entity, Entity.id == TrustScore.entity_id)
        .where(
            Entity.is_active.is_(True),
            Entity.id != agent.id,
            TrustScore.entity_id.notin_(already_ids) if already_ids else True,
        )
        .order_by(TrustScore.score.desc())
        .limit(3)
    )
    top_rows = await db.execute(query)
    targets = top_rows.scalars().all()

    if not targets:
        return QuickTrustResult(
            action="follow_suggested",
            success=True,
            detail="No suggested entities to follow",
        )

    followed = 0
    for ts in targets:
        # Double-check not already following (race safety)
        existing = await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_entity_id == agent.id,
                EntityRelationship.target_entity_id == ts.entity_id,
                EntityRelationship.type == RelationshipType.FOLLOW,
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue

        rel = EntityRelationship(
            id=uuid.uuid4(),
            source_entity_id=agent.id,
            target_entity_id=ts.entity_id,
            type=RelationshipType.FOLLOW,
        )
        db.add(rel)
        followed += 1

    await db.flush()

    return QuickTrustResult(
        action="follow_suggested",
        success=True,
        detail=f"Followed {followed} entities",
    )


async def _action_list_capabilities(
    db: AsyncSession, agent: Entity,
) -> QuickTrustResult:
    """Verify capabilities are properly registered. Informational only."""
    caps = agent.capabilities or []
    if not caps:
        return QuickTrustResult(
            action="list_capabilities",
            success=True,
            detail="No capabilities defined — add capabilities to improve readiness",
        )

    return QuickTrustResult(
        action="list_capabilities",
        success=True,
        detail=f"Capabilities registered: {', '.join(caps)}",
    )


# ---------------------------------------------------------------------------
# Ownership claim schemas
# ---------------------------------------------------------------------------


class ClaimRequestPayload(BaseModel):
    reason: str = Field("", max_length=1000, description="Why you believe you own this bot")


class ClaimRequestResponse(BaseModel):
    status: str
    message: str


class ClaimStatusResponse(BaseModel):
    claim_status: str | None  # pending, approved, rejected, or None
    claimed_by: str | None
    claimed_at: str | None
    reason: str | None


# ---------------------------------------------------------------------------
# Ownership claim endpoint
# ---------------------------------------------------------------------------


@router.post("/{agent_id}/claim", response_model=ClaimRequestResponse)
async def request_claim(
    agent_id: uuid.UUID,
    body: ClaimRequestPayload,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity = Depends(get_current_entity),
    _rate: None = Depends(rate_limit_writes),
) -> ClaimRequestResponse:
    """Claim ownership of a provisional (unclaimed) imported bot profile.

    Immediately assigns the claiming user as operator.
    Only human users can claim bots.
    """
    from datetime import timezone as tz

    from src.trust.score import compute_trust_score

    # Must be human
    if current_entity.type != EntityType.HUMAN:
        raise HTTPException(403, "Only human users can claim bots")

    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    if not agent.is_active:
        raise HTTPException(400, "Agent is deactivated")

    # Must be provisional / unclaimed
    if not agent.is_provisional:
        raise HTTPException(409, "This bot is not provisional — it cannot be claimed")

    # Already has an operator
    if agent.operator_id is not None:
        raise HTTPException(409, "This bot has already been claimed")

    # Content-filter the reason
    if body.reason:
        reason_check = check_content(body.reason)
        if not reason_check.is_clean:
            raise HTTPException(400, f"Reason rejected: {', '.join(reason_check.flags)}")

    # Immediately assign ownership
    agent.operator_id = current_entity.id
    agent.is_provisional = False
    agent.operator_approved = True

    # Record claim in onboarding_data JSONB
    onboarding = agent.onboarding_data or {}
    claim_data = {
        "status": "approved",
        "claimed_by": str(current_entity.id),
        "claimer_name": current_entity.display_name,
        "claimed_at": datetime.now(tz.utc).isoformat(),
        "reason": sanitize_text(body.reason) if body.reason else "",
    }
    onboarding["ownership_claim"] = claim_data
    # Force SQLAlchemy to detect JSONB mutation
    agent.onboarding_data = {**onboarding}
    await db.flush()

    # Recompute trust score for the entity
    try:
        await compute_trust_score(db, agent.id)
    except Exception:
        pass  # Best-effort — trust recompute may fail for new entities

    # Notify all admins
    admin_result = await db.execute(
        select(Entity).where(
            Entity.is_admin.is_(True),
            Entity.is_active.is_(True),
        )
    )
    admins = admin_result.scalars().all()
    for admin in admins:
        notif = Notification(
            id=uuid.uuid4(),
            entity_id=admin.id,
            kind="claim_approved",
            title="Bot profile claimed",
            body=f"{current_entity.display_name} claimed {agent.display_name}",
            reference_id=str(agent.id),
        )
        db.add(notif)
    await db.flush()

    return ClaimRequestResponse(
        status="approved",
        message="Profile claimed successfully. You are now the operator of this bot.",
    )


@router.get("/{agent_id}/claim-status", response_model=ClaimStatusResponse)
async def get_claim_status(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_reads),
) -> ClaimStatusResponse:
    """Check the current ownership claim status for a bot. Public."""
    agent = await db.get(Entity, agent_id)
    if agent is None or agent.type != EntityType.AGENT:
        raise HTTPException(404, "Agent not found")

    onboarding = agent.onboarding_data or {}
    claim = onboarding.get("ownership_claim")
    if not claim:
        return ClaimStatusResponse(
            claim_status=None,
            claimed_by=None,
            claimed_at=None,
            reason=None,
        )

    return ClaimStatusResponse(
        claim_status=claim.get("status"),
        claimed_by=claim.get("claimed_by"),
        claimed_at=claim.get("claimed_at"),
        reason=claim.get("reason"),
    )


# ---------------------------------------------------------------------------
# Security scan endpoints
# ---------------------------------------------------------------------------


class ScanCategoryResult(BaseModel):
    category: str
    count: int
    status: str  # "clear", "warning", "critical"


class ScanFinding(BaseModel):
    category: str
    name: str
    severity: str
    file_path: str
    line_number: int


class SecurityScanResponse(BaseModel):
    entity_id: uuid.UUID
    scan_result: str  # "clean", "warnings", "critical", "error", "pending"
    trust_score: int = 0
    files_scanned: int = 0
    categories: list[ScanCategoryResult] = []
    positive_signals: list[str] = []
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    findings: list[ScanFinding] = []
    scanned_at: str | None = None
    repo: str | None = None


def _build_scan_response(
    entity_id: uuid.UUID,
    scan: object | None,
    repo: str | None = None,
) -> SecurityScanResponse | None:
    """Build a SecurityScanResponse from a FrameworkSecurityScan record."""
    if scan is None:
        return None

    from src.models import FrameworkSecurityScan

    s: FrameworkSecurityScan = scan  # type: ignore[assignment]
    vulns = s.vulnerabilities or {}

    # Build category breakdown
    cat_counts = vulns.get("categories", {})
    category_labels = {
        "secret": "Credential Theft",
        "exfiltration": "Data Exfiltration",
        "unsafe_exec": "Unsafe Execution",
        "fs_access": "Filesystem Access",
        "obfuscation": "Code Obfuscation",
    }
    categories = []
    for key, label in category_labels.items():
        count = cat_counts.get(key, 0)
        if count > 0:
            # Any secret or obfuscation = critical category
            if key in ("secret", "obfuscation"):
                cat_status = "critical"
            elif count > 5:
                cat_status = "warning"
            else:
                cat_status = "warning"
        else:
            cat_status = "clear"
        categories.append(ScanCategoryResult(
            category=label,
            count=count,
            status=cat_status,
        ))

    # Extract individual findings from stored scan data
    raw_findings = vulns.get("findings", [])
    findings = [
        ScanFinding(
            category=f.get("category", "unknown"),
            name=f.get("name", "Unknown"),
            severity=f.get("severity", "medium"),
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number", 0),
        )
        for f in raw_findings[:100]
    ]

    return SecurityScanResponse(
        entity_id=entity_id,
        scan_result=s.scan_result,
        trust_score=vulns.get("trust_score", 0),
        files_scanned=vulns.get("files_scanned", 0),
        categories=categories,
        positive_signals=vulns.get("positive_signals", []),
        total_findings=vulns.get("total_findings", 0),
        critical_count=vulns.get("critical_count", 0),
        high_count=vulns.get("high_count", 0),
        medium_count=vulns.get("medium_count", 0),
        findings=findings,
        scanned_at=s.scanned_at.isoformat() if s.scanned_at else None,
        repo=repo,
    )


@router.get(
    "/{agent_id}/security-scan",
    response_model=SecurityScanResponse,
)
async def get_security_scan(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_reads),
) -> SecurityScanResponse:
    """Get the latest security scan results for a bot. Public endpoint."""
    agent = await db.get(Entity, agent_id)
    if agent is None or not agent.is_active:
        raise HTTPException(404, "Agent not found")

    from src.scanner.service import _extract_github_repo, get_latest_scan

    scan = await get_latest_scan(db, agent_id)
    if scan is None:
        raise HTTPException(404, "No security scan available")
    repo = _extract_github_repo(agent.source_url)
    resp = _build_scan_response(agent_id, scan, repo)
    if resp is None:
        raise HTTPException(404, "No security scan available")
    return resp


@router.post(
    "/{agent_id}/security-scan",
    response_model=SecurityScanResponse,
)
async def trigger_security_scan(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_entity: Entity = Depends(get_current_entity),
    _rate: None = Depends(rate_limit_writes),
) -> SecurityScanResponse:
    """Trigger a security re-scan for a bot.

    Requires authentication — only the bot's operator or an admin can trigger.
    """
    agent = await db.get(Entity, agent_id)
    if agent is None or not agent.is_active:
        raise HTTPException(404, "Agent not found")

    # Only operator or admin can trigger re-scan
    is_operator = agent.operator_id is not None and agent.operator_id == current_entity.id
    is_own = agent.id == current_entity.id
    is_admin = current_entity.is_admin
    if not (is_operator or is_own or is_admin):
        raise HTTPException(403, "Only the bot's operator or an admin can trigger a re-scan")

    from src.scanner.service import _extract_github_repo, run_security_scan

    repo = _extract_github_repo(agent.source_url)
    if not repo:
        raise HTTPException(
            400, "This agent has no GitHub source URL. Security scanning requires a GitHub repo.",
        )

    scan = await run_security_scan(db, agent_id, force=True)
    await db.commit()
    if scan is None:
        raise HTTPException(500, "Security scan failed — please try again.")
    return _build_scan_response(agent_id, scan, repo)
