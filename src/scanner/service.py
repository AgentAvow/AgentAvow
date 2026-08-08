"""Security scan service — runs scans and stores results.

Bridges the standalone mcp-security-scan engine with the AgentGraph
database. Used by bot onboarding, re-scan triggers, and the scheduler.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Entity, FrameworkSecurityScan

logger = logging.getLogger(__name__)


async def run_security_scan(
    db: AsyncSession,
    entity_id: uuid.UUID,
    *,
    force: bool = False,
) -> FrameworkSecurityScan | None:
    """Run a security scan for an entity's source repo.

    Args:
        db: Database session
        entity_id: Entity to scan
        force: If True, re-scan even if a recent scan exists

    Returns:
        FrameworkSecurityScan record, or None if no scannable source.
    """
    entity = await db.get(Entity, entity_id)
    if not entity or not entity.is_active:
        return None

    # Need a GitHub source URL to scan
    repo_full_name = _extract_github_repo(entity.source_url)
    if not repo_full_name:
        logger.debug("Entity %s has no GitHub source URL, skipping scan", entity_id)
        return None

    # Check for recent scan (skip if <24h old and not forced)
    if not force:
        existing = await db.execute(
            select(FrameworkSecurityScan)
            .where(FrameworkSecurityScan.entity_id == entity_id)
            .order_by(FrameworkSecurityScan.scanned_at.desc())
            .limit(1)
        )
        latest = existing.scalar_one_or_none()
        if latest:
            age_hours = (
                datetime.now(timezone.utc) - latest.scanned_at
            ).total_seconds() / 3600
            if age_hours < 24:
                logger.debug(
                    "Entity %s scanned %.1fh ago, skipping", entity_id, age_hours,
                )
                return latest

    # Run the scan — use any available GitHub token for rate limits
    from src.github_auth import get_github_token
    token = await get_github_token()
    try:
        from src.scanner.scan import scan_repo

        result = await scan_repo(
            full_name=repo_full_name,
            stars=0,
            description=entity.bio_markdown or "",
            framework=entity.framework_source or "",
            token=token,
        )
    except Exception:
        logger.exception("Security scan failed for %s", repo_full_name)
        # Write error record so callers know the scan was attempted
        scan_record = FrameworkSecurityScan(
            id=uuid.uuid4(),
            entity_id=entity_id,
            framework=entity.framework_source or "unknown",
            scan_result="error",
            vulnerabilities={"error": f"Scan failed for {repo_full_name}"},
        )
        db.add(scan_record)
        await db.flush()
        return scan_record

    if result.error:
        logger.warning("Scan error for %s: %s", repo_full_name, result.error)
        # Still store the result so we don't retry immediately
        scan_record = FrameworkSecurityScan(
            id=uuid.uuid4(),
            entity_id=entity_id,
            framework=entity.framework_source or "unknown",
            scan_result="error",
            vulnerabilities={"error": result.error},
        )
        db.add(scan_record)
        await db.flush()
        return scan_record

    # Determine overall result
    if result.critical_count > 0:
        scan_result = "critical"
    elif result.high_count > 0:
        scan_result = "warnings"
    else:
        scan_result = "clean"

    # Build structured vulnerabilities
    categories: dict[str, int] = {}
    for f in result.findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    vulns = {
        "trust_score": result.trust_score,
        "files_scanned": result.files_scanned,
        "total_scannable_files": result.total_scannable_files,
        "sampled": result.sampled,
        "primary_language": result.primary_language,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "total_findings": len(result.findings),
        "categories": categories,
        "positive_signals": list(set(result.positive_signals)),
        "has_readme": result.has_readme,
        "has_license": result.has_license,
        "has_tests": result.has_tests,
        # Phase 0/1: recompute-discipline coverage block + OSV supply-chain summary.
        "coverage": getattr(result, "coverage", {}) or {},
        "supply_chain": getattr(result, "supply_chain", {}) or {},
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
            }
            for f in result.findings[:100]  # Cap at 100 for DB storage
        ],
    }

    scan_record = FrameworkSecurityScan(
        id=uuid.uuid4(),
        entity_id=entity_id,
        framework=entity.framework_source or "unknown",
        scan_result=scan_result,
        vulnerabilities=vulns,
    )
    db.add(scan_record)
    await db.flush()

    logger.info(
        "Security scan complete for %s: %s (score=%d, findings=%d)",
        repo_full_name, scan_result, result.trust_score, len(result.findings),
    )

    return scan_record


async def get_latest_scan(
    db: AsyncSession,
    entity_id: uuid.UUID,
) -> FrameworkSecurityScan | None:
    """Get the most recent scan for an entity."""
    result = await db.execute(
        select(FrameworkSecurityScan)
        .where(FrameworkSecurityScan.entity_id == entity_id)
        .order_by(FrameworkSecurityScan.scanned_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def rescan_all_agents(
    db: AsyncSession,
    limit: int | None = None,
    *,
    staleness_days: int | None = None,
    spacing_seconds: float | None = None,
    min_budget: int | None = None,
) -> int:
    """Re-scan agents with GitHub source URLs not scanned recently.

    Uses a lightweight two-step approach to avoid expensive outerjoin at scale:
    1. Fetch candidate entity IDs (active + GitHub source URL) — uses indexes
    2. For each, check latest scan age in-loop (indexed lookup, fast)

    Commits after each scan so a failure doesn't lose prior work.

    Caps default from ``config.settings`` (configurable, sized under the PAT's
    5000 req/hr budget — see the config comment). A budget guard pre-checks
    GitHub's ``/rate_limit`` and bails if core-remaining drops below
    ``min_budget`` so a run can't exhaust the hourly budget; a small
    ``spacing_seconds`` sleep smooths bursts.
    """
    from datetime import timedelta

    from src.config import settings

    if limit is None:
        limit = settings.security_rescan_limit
    if staleness_days is None:
        staleness_days = settings.security_rescan_staleness_days
    if spacing_seconds is None:
        spacing_seconds = settings.security_rescan_spacing_seconds
    if min_budget is None:
        min_budget = settings.security_rescan_min_budget

    cutoff = datetime.now(timezone.utc) - timedelta(days=staleness_days)

    # Step 1: Get active entities with GitHub source.
    # ix_entities_source_type is a B-tree index — fast even at millions of rows.
    # Avoids LIKE '%github.com%' which forces a sequential scan.
    candidates = await db.execute(
        select(Entity.id)
        .where(
            Entity.is_active.is_(True),
            Entity.source_url.isnot(None),
            Entity.source_type == "github",
        )
        .limit(limit * 5)  # Fetch extra since some will have recent scans
    )
    candidate_ids = [row[0] for row in candidates.all()]

    if not candidate_ids:
        return 0

    # Step 2: Filter to those not scanned recently.
    # Uses ix_framework_scans_entity + ix_framework_scans_scanned_at per entity.
    entity_ids: list = []
    for eid in candidate_ids:
        if len(entity_ids) >= limit:
            break
        latest = await db.execute(
            select(FrameworkSecurityScan.scanned_at)
            .where(FrameworkSecurityScan.entity_id == eid)
            .order_by(FrameworkSecurityScan.scanned_at.desc())
            .limit(1)
        )
        row = latest.scalar_one_or_none()
        if row is None or row < cutoff:
            entity_ids.append(eid)

    scanned = 0
    for idx, eid in enumerate(entity_ids):
        # Budget guard: the /rate_limit endpoint is free, so check periodically
        # and bail before we'd exhaust the hourly core budget. Guarantees a run
        # can't blow past 5000 req/hr even if every repo hits the 200-file cap.
        if idx == 0 or idx % 10 == 0:
            try:
                from src.jobs.scan_health import check_github_token_health

                health = await check_github_token_health()
                if health.remaining is not None and health.remaining < min_budget:
                    logger.warning(
                        "Re-scan stopping early: GitHub core budget low "
                        "(%d < %d) after %d scans",
                        health.remaining, min_budget, scanned,
                    )
                    break
            except Exception:
                logger.debug("Budget guard check failed, continuing", exc_info=True)

        try:
            scan = await run_security_scan(db, eid, force=True)
            if scan:
                scanned += 1
            await db.commit()
        except Exception:
            logger.exception("Scan failed for entity %s, rolling back", eid)
            await db.rollback()

        # Spacing: smooth bursts so we don't slam GitHub in a tight loop.
        if spacing_seconds and idx < len(entity_ids) - 1:
            await asyncio.sleep(spacing_seconds)

    logger.info("Re-scanned %d/%d agents", scanned, len(entity_ids))
    return scanned


async def refresh_public_scan_cache(limit: int | None = None) -> int:
    """Pre-refresh Redis cache for popular public scan repos.

    Queries cached scan results that are about to expire (> 50 min old
    from the 1-hour TTL) and re-scans them so the cache stays warm.
    Called by the scheduler alongside the agent rescan loop.

    ``limit`` defaults from ``config.settings.public_cache_refresh_limit``.
    """
    if limit is None:
        from src.config import settings

        limit = settings.public_cache_refresh_limit
    try:
        from src.redis_client import get_redis
        from src.scanner.scan import scan_repo

        r = await get_redis()
        refreshed = 0

        # Find cached public scan keys
        keys: list[bytes] = []
        async for key in r.scan_iter(match="ag:cache:public_scan:*"):
            keys.append(key)

        if not keys:
            return 0

        # Check TTL — refresh any with < 10 min remaining
        for key in keys[:limit]:
            ttl = await r.ttl(key)
            if 0 < ttl < 600:  # less than 10 min remaining
                # Extract repo name from key: ag:cache:public_scan:owner/repo
                key_str = key.decode() if isinstance(key, bytes) else key
                repo = key_str.replace("ag:cache:public_scan:", "")
                if "/" in repo:
                    from src.github_auth import get_github_token
                    token = await get_github_token()
                    try:
                        await scan_repo(
                            full_name=repo,
                            stars=0,
                            description="",
                            framework="",
                            token=token,
                        )
                        refreshed += 1
                        logger.debug("Pre-refreshed public scan cache: %s", repo)
                    except Exception:
                        logger.debug("Failed to refresh cache for %s", repo)

        return refreshed
    except Exception:
        logger.exception("Public scan cache refresh failed")
        return 0


def _extract_github_repo(source_url: str | None) -> str | None:
    """Extract 'owner/repo' from a GitHub URL."""
    if not source_url:
        return None
    url = source_url.rstrip("/")
    if "github.com" not in url:
        return None
    # Handle https://github.com/owner/repo and git@github.com:owner/repo.git
    parts = url.split("github.com")[-1]
    parts = parts.lstrip(":/")
    if parts.endswith(".git"):
        parts = parts[:-4]
    segments = parts.split("/")
    if len(segments) >= 2:
        return f"{segments[0]}/{segments[1]}"
    return None
