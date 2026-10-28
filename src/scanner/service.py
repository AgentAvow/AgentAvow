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
        # What the scan selected but could not read (disclosure only; never scored).
        "coverage_gaps": getattr(result, "coverage_gaps", {}) or {},
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
        # Phase 3: provenance / signing verification summary (empty unless the
        # scanner_verify_provenance flag is on and a package coordinate resolved).
        "provenance": getattr(result, "provenance", {}) or {},
        # Blocking (shipped / known-malicious) counts, the headline the report's
        # decide() reads; critical_count / high_count above stay the raw totals.
        "shipped_critical_count": result.shipped_critical_count,
        "shipped_high_count": result.shipped_high_count,
        "findings": _stored_finding_items(result.findings),
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


_STORED_FINDINGS_CAP = 100
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _stored_finding_items(findings: list) -> list[dict]:
    """The stored findings list: the same tags and order the public report uses
    (deciding findings first, then shipped, then severity), capped at 100. The tags
    (``shipped`` / ``kind`` / ``installed``) let ``decide()`` read a stored row the way
    it reads the report, and the order keeps the deciding findings inside the cap."""
    from src.scanner.scan import finding_is_shipped
    from src.scanner.verdict import finding_decides

    items = [
        {
            "category": f.category,
            "name": f.name,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "shipped": finding_is_shipped(f),
            "kind": getattr(f, "kind", "defect") or "defect",
            "installed": bool(getattr(f, "installed", True)),
        }
        for f in findings
    ]
    items.sort(key=lambda i: (not finding_decides(i), not i["shipped"],
                              _SEV_RANK.get(i["severity"], 5)))
    return items[:_STORED_FINDINGS_CAP]


def stored_scan_decision_input(
    vulnerabilities: object, fallback_score: int | None = None,
) -> dict:
    """The ``decide()`` input for a stored ``FrameworkSecurityScan.vulnerabilities``.

    Every surface that answers from a stored scan (the entity badge, the embed badge,
    the bot security-scan report) calls this, so they all reach the same answer.

    Shapes:
    - dict (``run_security_scan``): the scan's own 0-100 ``trust_score``, the stored
      findings as ``items``, and the blocking headline counts when the row has them.
      Rows written before the items carried a ``shipped`` tag get it inferred from the
      file path with the scanner's own rule.
    - list (framework bridge imports, ``bridges/registry_base``): ``{pattern, severity,
      location, match}`` items; the bridge stores no score, so ``fallback_score``.
    - None / empty / anything else: no findings, ``fallback_score``.
    """
    fallback = int(fallback_score or 0)
    if isinstance(vulnerabilities, list):
        items = [
            {
                "category": str(v.get("category") or "bridge"),
                "name": str(v.get("pattern") or v.get("name") or ""),
                "severity": str(v.get("severity") or "").lower(),
                "file_path": str(v.get("location") or v.get("file_path") or ""),
            }
            for v in vulnerabilities if isinstance(v, dict)
        ]
        return {"trust_score": fallback, "findings": {"items": items}}
    if not isinstance(vulnerabilities, dict):
        return {"trust_score": fallback, "findings": {"items": []}}

    from types import SimpleNamespace

    from src.scanner.scan import _finding_is_discounted, finding_is_shipped

    items = []
    for raw in vulnerabilities.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        by_path = SimpleNamespace(
            file_path=str(item.get("file_path") or ""), payload=False, test_code=False,
            installed=item.get("installed") is not False)
        if "shipped" not in item:
            item["shipped"] = finding_is_shipped(by_path)
        elif (item["shipped"] is False and _finding_is_discounted(by_path)
              and finding_is_shipped(by_path)):
            # A row written before the tag and the blocking rule agreed: the old tag
            # said not-shipped for a path that blocks (scripts/, tooling/, demo_*).
            # The path alone made it False (an inline test module's False came from
            # ``test_code``, on a path the old rule called shipped), so re-tag it with
            # today's rule and the badge reads the row the way the report does.
            item["shipped"] = True
        items.append(item)

    findings: dict = {"items": items}
    for key, stored in (("critical", "shipped_critical_count"),
                        ("high", "shipped_high_count")):
        n = vulnerabilities.get(stored)
        if isinstance(n, int) and not isinstance(n, bool):
            findings[key] = n

    score = vulnerabilities.get("trust_score")
    data: dict = {
        "trust_score": score if isinstance(score, (int, float)) and
        not isinstance(score, bool) else fallback,
        "findings": findings,
    }
    files = vulnerabilities.get("files_scanned")
    if isinstance(files, int) and not isinstance(files, bool):
        data["metadata"] = {"files_scanned": files}
    for key in ("supply_chain", "coverage", "coverage_gaps", "provenance"):
        if isinstance(vulnerabilities.get(key), dict):
            data[key] = vulnerabilities[key]
    return data


def decide_stored_scan(scan: object, fallback_score: int | None = None):
    """``decide()`` over a stored ``FrameworkSecurityScan`` (see
    :func:`stored_scan_decision_input`). ``None`` for an errored scan."""
    from src.scanner.verdict import decide

    if getattr(scan, "scan_result", None) == "error":
        return None
    return decide(stored_scan_decision_input(
        getattr(scan, "vulnerabilities", None), fallback_score))


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

    Finds cached public scan results about to expire (< 10 min left of the 1-hour
    TTL) and re-scans them so the cache stays warm. Called by the scheduler alongside
    the agent rescan loop.

    Each key is routed to its own surface (``coords_from_cache_key``): a package key
    like ``npm/react-dom`` is re-scanned as the npm package, not looked up as a GitHub
    repo (which 404'd and wasted a GitHub call per package key). The re-scan goes
    through the catalog row path, which writes the fresh result back to the cache;
    the old ``scan_repo`` call discarded its result, so nothing was ever refreshed.

    ``limit`` defaults from ``config.settings.public_cache_refresh_limit``.
    """
    from src.config import settings

    if limit is None:
        limit = settings.public_cache_refresh_limit
    try:
        from src.database import async_session
        from src.jobs.scheduler import _rescan_catalog_row
        from src.redis_client import get_redis
        from src.scanner.behavioral.trigger import coords_from_cache_key

        r = await get_redis()
        refreshed = 0
        spacing = getattr(settings, "catalog_rescan_spacing_seconds", 1.5)

        keys: list[bytes] = []
        async for key in r.scan_iter(match="ag:cache:public_scan:*"):
            keys.append(key)

        for key in keys[:limit]:
            ttl = await r.ttl(key)
            if not 0 < ttl < 600:  # refresh only what has < 10 min left
                continue
            key_str = key.decode() if isinstance(key, bytes) else key
            coords = coords_from_cache_key(key_str.replace("ag:cache:public_scan:", "", 1))
            if coords is None:
                continue
            surface, owner, repo = coords
            async with async_session() as db:
                if await _rescan_catalog_row(surface, owner, repo, db):
                    refreshed += 1
                    logger.debug("Pre-refreshed public scan cache: %s %s/%s",
                                 surface, owner, repo)
            await asyncio.sleep(spacing)

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
