"""Public scan catalog — browseable index of every scan we've run.

Surfaces the launch-scan datasets (x402 / MCP / npm / PyPI / OpenClaw)
as a single paginated catalog so journalists, partners, and any reader
can browse the receipts behind the State of Agent Security 2026 numbers.

The launch scans live as JSON reports under data/launch-scans/ and
data/. This router reads them lazily, normalizes into a unified row
shape, caches the aggregated index in memory, and serves paginated /
filtered views.

Living-record proof: AgentGraph publishes the trail, not a frozen PDF.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.rate_limit import rate_limit_reads
from src.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public/scan-catalog", tags=["public-scan"])

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _PROJECT_ROOT / "data" / "launch-scans"

_CATALOG_CACHE: dict[str, Any] | None = None


class CatalogRow(BaseModel):
    surface: str  # x402 | mcp | npm | pypi
    name: str
    repository_url: str | None = None
    full_name: str | None = None  # owner/repo for repo-based surfaces
    endpoint_url: str | None = None  # for x402 surface
    trust_score: int | None = None
    critical: int | None = None
    high: int | None = None
    findings_count: int | None = None
    primary_language: str | None = None
    is_mcp_server: bool | None = None
    scan_error: str | None = None
    skipped: str | None = None
    # x402-specific
    has_x402_header: bool | None = None
    http_status: int | None = None


class CatalogSummary(BaseModel):
    total_scans: int
    by_surface: dict[str, int]
    by_surface_critical: dict[str, int] = {}
    by_surface_high: dict[str, int] = {}
    repo_scans_total: int
    repo_scans_with_critical: int
    repo_scans_with_high: int
    x402_endpoints_total: int
    x402_compliant: int


class CatalogResponse(BaseModel):
    summary: CatalogSummary
    rows: list[CatalogRow]
    total: int  # filtered total (for pagination)
    offset: int
    limit: int
    surfaces: list[str] = ["x402", "mcp", "npm", "pypi"]


def _normalize_row(surface: str, raw: dict) -> CatalogRow:
    """Convert a per-surface raw record into the unified row shape."""
    if surface == "x402":
        url = raw.get("endpoint_url", "")
        return CatalogRow(
            surface="x402",
            name=url,
            endpoint_url=url,
            has_x402_header=raw.get("has_x402_header"),
            http_status=raw.get("http_status"),
        )
    if surface == "openclaw":
        # OpenClaw uses different field names — `repo` for owner/name,
        # `critical_count` / `high_count` instead of `critical` / `high`,
        # `error` instead of `scan_error`.
        full_name = raw.get("repo", "")
        return CatalogRow(
            surface="openclaw",
            name=full_name,
            full_name=full_name,
            repository_url=f"https://github.com/{full_name}" if full_name else None,
            trust_score=raw.get("trust_score"),
            critical=raw.get("critical_count"),
            high=raw.get("high_count"),
            findings_count=raw.get("findings_count"),
            primary_language=raw.get("primary_language"),
            scan_error=raw.get("error"),
        )
    # mcp / npm / pypi all share repo-scan shape
    return CatalogRow(
        surface=surface,
        name=raw.get("name", "") or raw.get("full_name", ""),
        repository_url=raw.get("repository_url"),
        full_name=raw.get("full_name"),
        trust_score=raw.get("trust_score"),
        critical=raw.get("critical"),
        high=raw.get("high"),
        findings_count=raw.get("findings_count"),
        primary_language=raw.get("primary_language"),
        is_mcp_server=raw.get("is_mcp_server"),
        scan_error=raw.get("scan_error"),
        skipped=raw.get("skipped"),
    )


def _load_surface(surface: str, path: Path, results_key: str = "results") -> list[CatalogRow]:
    if not path.exists():
        logger.warning("scan_catalog: missing %s", path)
        return []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        logger.error("scan_catalog: failed to parse %s: %s", path, e)
        return []
    results = data.get(results_key, data) if isinstance(data, dict) else data
    if not isinstance(results, list):
        return []
    return [_normalize_row(surface, r) for r in results if isinstance(r, dict)]


def _build_catalog() -> dict[str, Any]:
    rows: list[CatalogRow] = []
    rows += _load_surface("x402", _DATA_DIR / "x402-results.json")
    rows += _load_surface("mcp", _DATA_DIR / "mcp-registry-results.json")
    rows += _load_surface("npm", _DATA_DIR / "npm-agents-results.json")
    rows += _load_surface("pypi", _DATA_DIR / "pypi-agents-results.json")
    # OpenClaw 500-skills scan uses a different file shape: top-level
    # 'repos' key instead of 'results'.
    rows += _load_surface(
        "openclaw", _DATA_DIR / "openclaw-results.json", results_key="repos"
    )

    surfaces = ("x402", "mcp", "npm", "pypi", "openclaw")
    by_surface = {s: 0 for s in surfaces}
    by_surface_critical = {s: 0 for s in surfaces}
    by_surface_high = {s: 0 for s in surfaces}
    for r in rows:
        by_surface[r.surface] = by_surface.get(r.surface, 0) + 1
        if (r.critical or 0) > 0:
            by_surface_critical[r.surface] = by_surface_critical.get(r.surface, 0) + 1
        if (r.high or 0) > 0:
            by_surface_high[r.surface] = by_surface_high.get(r.surface, 0) + 1

    repo_rows = [r for r in rows if r.surface != "x402"]
    repo_with_critical = sum(1 for r in repo_rows if (r.critical or 0) > 0)
    repo_with_high = sum(1 for r in repo_rows if (r.high or 0) > 0)
    x402_rows = [r for r in rows if r.surface == "x402"]
    x402_compliant = sum(1 for r in x402_rows if r.has_x402_header)

    summary = CatalogSummary(
        total_scans=len(rows),
        by_surface=by_surface,
        by_surface_critical=by_surface_critical,
        by_surface_high=by_surface_high,
        repo_scans_total=len(repo_rows),
        repo_scans_with_critical=repo_with_critical,
        repo_scans_with_high=repo_with_high,
        x402_endpoints_total=len(x402_rows),
        x402_compliant=x402_compliant,
    )
    return {"rows": rows, "summary": summary}


def _get_catalog() -> dict[str, Any]:
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        _CATALOG_CACHE = _build_catalog()
    return _CATALOG_CACHE


async def _community_rows(db: AsyncSession) -> list[CatalogRow]:
    """On-demand scans users have run, persisted so the catalog grows over time.
    Best-effort — a DB hiccup must never break the static catalog."""
    from src.models import CommunityScan

    try:
        result = await db.execute(
            select(CommunityScan).order_by(CommunityScan.last_scanned_at.desc()).limit(2000)
        )
        out: list[CatalogRow] = []
        for c in result.scalars().all():
            out.append(
                CatalogRow(
                    surface="community",
                    name=c.full_name,
                    full_name=c.full_name,
                    repository_url=f"https://github.com/{c.full_name}",
                    trust_score=c.trust_score,
                    critical=c.critical,
                    high=c.high,
                    findings_count=c.findings_count,
                    primary_language=c.primary_language,
                )
            )
        return out
    except Exception:
        logger.warning("community_scans fetch failed", exc_info=True)
        return []


@router.get("", response_model=CatalogResponse, dependencies=[Depends(rate_limit_reads)])
async def scan_catalog(
    surface: str | None = Query(None, pattern="^(x402|mcp|npm|pypi|openclaw|community)$"),
    q: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|clean|skipped)$"),
    sort: str = Query("default", pattern="^(default|score-asc|score-desc|name)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> CatalogResponse:
    """Return a paginated, filterable catalog of every scan — the static launch
    corpus plus community (on-demand) scans that grow the dataset over time."""
    catalog = _get_catalog()
    rows: list[CatalogRow] = catalog["rows"]
    summary: CatalogSummary = catalog["summary"]

    # Merge in community scans (on-demand scans users ran). Search + the
    # 'community' tab see them; other single-surface tabs stay the launch corpus.
    community = await _community_rows(db)
    summary = summary.model_copy(deep=True)
    summary.by_surface = {**summary.by_surface, "community": len(community)}
    summary.total_scans += len(community)
    if community and (surface in (None, "community") or q):
        rows = rows + community

    filtered = rows
    if surface:
        filtered = [r for r in filtered if r.surface == surface]
    if q:
        # Separator-insensitive match across name / full_name / owner so
        # "news digest", "news-digest", "news_digest" and "kenneives/news-digest"
        # all find the same repo (users don't type the exact punctuation).
        def _norm(s: str) -> str:
            return re.sub(r"[-_\s./]+", "", (s or "").lower())
        needle = _norm(q)
        filtered = [
            r for r in filtered
            if needle in _norm(getattr(r, "name", ""))
            or needle in _norm(getattr(r, "full_name", ""))
            or needle in _norm(getattr(r, "owner", ""))
        ]
    if severity == "critical":
        filtered = [r for r in filtered if (r.critical or 0) > 0]
    elif severity == "high":
        filtered = [r for r in filtered if (r.high or 0) > 0 and (r.critical or 0) == 0]
    elif severity == "clean":
        filtered = [
            r for r in filtered
            if (r.critical or 0) == 0
            and (r.high or 0) == 0
            and (r.trust_score or 0) >= 80
        ]
    elif severity == "skipped":
        filtered = [r for r in filtered if r.skipped or r.scan_error]

    if sort == "score-desc":
        filtered = sorted(filtered, key=lambda r: r.trust_score or -1, reverse=True)
    elif sort == "score-asc":
        filtered = sorted(
            filtered,
            key=lambda r: r.trust_score if r.trust_score is not None else 999,
        )
    elif sort == "name":
        filtered = sorted(filtered, key=lambda r: (r.name or "").lower())

    total = len(filtered)
    page = filtered[offset:offset + limit]

    return CatalogResponse(
        summary=summary,
        rows=page,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/refresh", include_in_schema=False)
async def refresh_catalog() -> dict[str, Any]:
    """Force-rebuild the in-memory catalog from disk (admin/internal use)."""
    global _CATALOG_CACHE
    _CATALOG_CACHE = None
    catalog = _get_catalog()
    return {"status": "rebuilt", "total_scans": catalog["summary"].total_scans}
