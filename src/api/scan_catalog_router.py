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

import asyncio
import copy
import json
import logging
import re
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads
from src.database import get_db
from src.models import Entity
from src.trust_tiers import TIER_FLOORS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public/scan-catalog", tags=["public-scan"])

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _PROJECT_ROOT / "data" / "launch-scans"

_CATALOG_CACHE: dict[str, Any] | None = None
_CATALOG_BUILD_LOCK = threading.Lock()

# Per-process caches for the two hot public reads (the list and /flagged-stat). Each
# uvicorn worker has its own copy; a write in one worker invalidates only that
# worker's cache, the others pick the change up when the TTL lapses.
COMMUNITY_ROWS_TTL_SECONDS = 60
FLAGGED_STAT_TTL_SECONDS = 120
CATALOG_CACHE_CONTROL = "public, max-age=60"

# (rows, expires_at) — rows are categorized once at fill time and never mutated after.
_COMMUNITY_CACHE: tuple[list[CatalogRow], float] | None = None
# (catalog, community_rows, response, expires_at). The inputs are kept so a hit is only
# served for the same catalog object and equal community rows.
_FLAGGED_STAT_CACHE: tuple[dict[str, Any], list[CatalogRow], dict[str, Any], float] | None = None
_COMMUNITY_LOCKS: dict[int, tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}


def _now() -> float:
    return time.monotonic()


def _community_lock() -> asyncio.Lock:
    """One lock per running event loop (an asyncio.Lock is bound to the loop it first
    waits on; tests run each case in a fresh loop)."""
    loop = asyncio.get_running_loop()
    entry = _COMMUNITY_LOCKS.get(id(loop))
    if entry is None or entry[0] is not loop:
        _COMMUNITY_LOCKS.clear()
        entry = (loop, asyncio.Lock())
        _COMMUNITY_LOCKS[id(loop)] = entry
    return entry[1]


def invalidate_community_rows_cache() -> None:
    """Drop the cached community rows and the /flagged-stat response (this process).
    Call after writing a CommunityScan row."""
    global _COMMUNITY_CACHE, _FLAGGED_STAT_CACHE
    _COMMUNITY_CACHE = None
    _FLAGGED_STAT_CACHE = None


class CatalogSandbox(BaseModel):
    """Read-only summary of the behavioral (sandbox) block the public scan cached for
    this coordinate — present only when a run exists in cache."""
    ran: bool
    exercised: bool | None = None  # MCP server launched OK (None: not an MCP plan)
    findings: int = 0
    unexpected_egress: int = 0


class CatalogRow(BaseModel):
    surface: str  # x402 | mcp | npm | pypi
    name: str
    repository_url: str | None = None
    full_name: str | None = None  # owner/repo for repo-based surfaces
    endpoint_url: str | None = None  # for x402 surface
    trust_score: int | None = None
    grade: str | None = None  # letter grade WITH the A+ certified gate (roadmap §7)
    critical: int | None = None
    high: int | None = None
    findings_count: int | None = None
    primary_language: str | None = None
    category: str | None = None  # derived purpose facet for browse curation
    adoption_score: int | None = None   # 0-100 (community_scans only, loop-populated)
    adoption_count: int | None = None   # headline number (downloads/wk, stars)
    adoption_unit: str | None = None
    is_mcp_server: bool | None = None
    scan_error: str | None = None
    skipped: str | None = None
    # x402-specific
    has_x402_header: bool | None = None
    http_status: int | None = None
    # behavioral sandbox summary (npm/pypi/docker rows with a cached run; else None)
    sandbox: CatalogSandbox | None = None
    # The three-phrase headline (safe | review | do_not_connect) + its reason, decided
    # from the row's score and blocking critical/high counts (src.scanner.verdict).
    # None for a row with no trust score (skipped / errored / x402 probe).
    decision: str | None = None
    decision_reason: str | None = None

    @model_validator(mode="after")
    def _fill_decision(self) -> CatalogRow:
        if self.trust_score is not None and self.decision is None:
            from src.scanner.verdict import decide
            findings: dict[str, Any] = {}
            if isinstance(self.critical, int):
                findings["critical"] = self.critical
            if isinstance(self.high, int):
                findings["high"] = self.high
            d = decide({"trust_score": self.trust_score, "findings": findings})
            self.decision, self.decision_reason = d.decision, d.reason
        return self


_SANDBOX_SURFACES = ("npm", "pypi", "docker")


def _sandbox_candidate_keys(row: CatalogRow) -> list[str]:
    """Cache keys a row's behavioral block may live under: the plain install plan and,
    when the row is an MCP server / docker image, the exerciser plan. A declared-egress
    variant (hash suffix) needs the scan's ``.agentavow.yml`` and is not resolvable from
    a catalog row, so such rows read as "no sandbox" here."""
    from src.api.public_scan_router import _behavioral_cache_key

    surface = (row.surface or "").lower()
    if surface not in _SANDBOX_SURFACES or not row.name:
        return []
    keys = [_behavioral_cache_key(surface, row.name)]
    plan = "docker" if surface == "docker" else (f"{surface}-mcp" if row.is_mcp_server else None)
    if plan:
        keys.append(_behavioral_cache_key(surface, row.name, None, plan))
    return keys


def _sandbox_summary(block: Any) -> CatalogSandbox | None:
    if not isinstance(block, dict) or not block.get("ran"):
        return None
    ex = block.get("exercise") if isinstance(block.get("exercise"), dict) else None
    return CatalogSandbox(
        ran=True,
        exercised=(bool(ex.get("launch_ok")) if ex is not None else None),
        findings=len([f for f in (block.get("findings") or []) if isinstance(f, dict)]),
        unexpected_egress=len(block.get("unexpected_egress") or []),
    )


async def _attach_sandbox(rows: list[CatalogRow]) -> list[CatalogRow]:
    """Decorate one page of rows with their cached sandbox summary in ONE Redis round
    trip (MGET over every candidate key). Rows come from the shared in-memory catalog,
    so decorated rows are copies — the cache must never hold a stale sandbox mark.
    Best-effort: any failure leaves every row's ``sandbox`` None."""
    per_row = [_sandbox_candidate_keys(r) for r in rows]
    keys = [k for ks in per_row for k in ks]
    if not keys:
        return rows
    try:
        from src.redis_client import get_redis
        raw = await get_redis().mget(keys)
    except Exception:
        return rows
    blocks: dict[str, Any] = {}
    for key, val in zip(keys, raw or []):
        if not val:
            continue
        try:
            blocks[key] = json.loads(val)
        except Exception:
            continue
    out: list[CatalogRow] = []
    for row, ks in zip(rows, per_row):
        summary = next((s for s in (_sandbox_summary(blocks.get(k)) for k in ks) if s), None)
        out.append(row.model_copy(update={"sandbox": summary}) if summary else row)
    return out


# Purpose-category rules (first match wins) — a coarse, honest facet derived from the
# name/surface/language we already have, so browse can be filtered by what a tool DOES
# (not just its surface). Unmatched tools fall through to "Library".
_CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("LLM provider SDK", ("openai", "anthropic", "gemini", "mistral", "cohere",
                          "litellm", "bedrock", "vertexai", "together-ai")),
    ("AI framework", ("langchain", "langgraph", "llama-index", "llama_index", "llamaindex",
                      "crewai", "crew-ai", "autogen", "semantic-kernel", "semantic_kernel",
                      "haystack", "dspy", "instructor", "agent", "pydantic-ai", "swarm")),
    ("Data & ML", ("numpy", "pandas", "torch", "tensorflow", "scikit", "sklearn",
                   "transformers", "datasets", "tiktoken", "scipy", "matplotlib", "spacy")),
    ("Web & scraping", ("playwright", "puppeteer", "cheerio", "scrapy", "scrape", "crawl",
                        "selenium", "beautifulsoup", "requests", "httpx", "aiohttp",
                        "axios", "node-fetch", "undici", "urllib")),
    ("Web framework", ("fastapi", "flask", "django", "express", "uvicorn", "starlette",
                       "nestjs", "koa", "hono", "gin", "fiber")),
    ("Security", ("sigstore", "crypto", "jwt", "oauth", "bcrypt", "vault", "secret", "auth")),
    ("Dev tooling", ("cli", "commander", "dotenv", "chalk", "eslint", "prettier", "vite",
                     "webpack", "rollup", "pytest", "typer", "click", "rich")),
]


def _categorize(row: CatalogRow) -> str:
    """Coarse purpose facet from the name/surface/language we already have. Surface
    buckets first (skill/MCP/x402), then keyword rules, else 'Library'."""
    s = (row.surface or "").lower()
    if s == "openclaw":
        return "Agent skill"
    if s == "huggingface":
        return "AI model"
    if s == "docker":
        return "Container image"
    if s == "mcp" or row.is_mcp_server:
        return "MCP server"
    if s == "x402":
        return "x402 endpoint"
    hay = f"{row.name or ''} {row.full_name or ''}".lower()
    if "mcp" in hay or "modelcontextprotocol" in hay:
        return "MCP server"
    for cat, kws in _CATEGORY_RULES:
        if any(k in hay for k in kws):
            return cat
    return "Library"


class CatalogSummary(BaseModel):
    """Corpus-wide counts. Severity counters use the EXCLUSIVE buckets from
    `_severity_bucket` (the same partition the list's `severity=` filter applies):

    - `by_surface_critical` / `repo_scans_with_critical`: rows with >=1 critical finding.
    - `by_surface_high` / `repo_scans_with_high`: rows with >=1 high finding and NO
      critical ("high-only"). A row with both is counted under critical only.
    - `by_surface_scanned` / `repo_scans_scanned`: rows that have a verdict (a trust
      score; not skipped / errored). This is the honest denominator for any "% of
      scanned tools" figure.
    - `by_surface_skipped` / `repo_scans_skipped`: rows the scanner never graded.
    - `repo_scans_total` / `by_surface`: every row in the corpus, graded or not.
    """
    total_scans: int
    by_surface: dict[str, int]
    by_category: dict[str, int] = {}
    by_surface_critical: dict[str, int] = {}
    by_surface_high: dict[str, int] = {}
    by_surface_scanned: dict[str, int] = {}
    by_surface_skipped: dict[str, int] = {}
    repo_scans_total: int
    repo_scans_scanned: int = 0
    repo_scans_skipped: int = 0
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


def _row_grade(
    score: int | None, stored: str | None = None, critical: int | None = None,
) -> str | None:
    """The letter grade to show in the catalog. Prefer a STORED gated grade; else
    derive from score with the A+ certified gate applied (uncertified → capped at
    A) and the critical cap (an open critical → capped at B). This is what keeps
    Browse from showing A+ on a repo-only 96+ scan, or A over an open critical."""
    if stored:
        return stored
    if score is None:
        return None
    from src.api.public_scan_router import _display_grade
    return _display_grade(score, None, critical or 0)


def _guard_stale_score(score: int | None, critical: int | None) -> int | None:
    """Safety net for pre-calibration stored/seed rows. A row still reading Trusted
    (>=81) while carrying a critical is impossible under the fixed scorer — floor it so
    Browse can never show a 100-with-a-critical while the corpus re-scans. Correct rows
    (score<81, or no critical) pass through unchanged; re-scanned rows overwrite this."""
    if score is not None and (critical or 0) > 0 and score >= 81:
        return 45
    return score


# Exclusive severity buckets. ONE definition, shared by the summary counters, the
# list's `severity=` filter and the /flagged-stat headline, so no two numbers on the
# site can disagree about what "flagged" means.
BUCKET_NA = "n/a"          # x402 compliance probe: not a code scan, no severity
BUCKET_SKIPPED = "skipped"  # no verdict: fetch skipped, scan error, or never scored
BUCKET_CRITICAL = "critical"
BUCKET_HIGH = "high"       # >=1 high finding and NO critical ("high-only")
BUCKET_CLEAN = "clean"     # a verdict with no high or critical finding
_VERDICT_BUCKETS = (BUCKET_CRITICAL, BUCKET_HIGH, BUCKET_CLEAN)


def _is_skipped(r: CatalogRow) -> bool:
    """The scanner never graded this row (fetch skipped or scan error)."""
    return bool(r.skipped or r.scan_error)


def _severity_bucket(r: CatalogRow) -> str:
    """Put a row in exactly one bucket.

    A row with both a critical and a high finding lands in `critical` only. Counting
    `critical` and `high` as two independent `if` branches double-counted every such
    row in the headline stat (969 rows on 2026-10-01); this partition is what fixes it.
    Rows without a verdict (skipped / errored / no trust score) are `skipped` and must
    never sit in a "% of scanned" denominator.
    """
    if r.surface == "x402":
        return BUCKET_NA
    if _is_skipped(r) or r.trust_score is None:
        return BUCKET_SKIPPED
    if (r.critical or 0) > 0:
        return BUCKET_CRITICAL
    if (r.high or 0) > 0:
        return BUCKET_HIGH
    return BUCKET_CLEAN


def _flagged_counts(rows: Iterable[CatalogRow]) -> dict[str, Any]:
    """Exclusive severity counts over `rows` (x402 rows are ignored). Pure, so the
    endpoint and its tests share one implementation. Keys:

    - `scanned_total`: rows with a verdict (the denominator of every pct here)
    - `critical`: >=1 critical finding
    - `high_only`: >=1 high finding, no critical
    - `flagged`: critical + high_only (every row with a high-or-critical, counted once)
    - `clean`: a verdict with no high or critical finding (scanned_total - flagged)
    - `skipped`: rows with no verdict; `total` = scanned_total + skipped
    - `pct`: flagged / scanned_total as a whole percent (None when nothing scanned);
      `flagged_pct` / `critical_pct` carry one decimal
    """
    c = {"scanned_total": 0, "critical": 0, "high_only": 0, "clean": 0, "skipped": 0}
    for r in rows:
        b = _severity_bucket(r)
        if b == BUCKET_NA:
            continue
        if b == BUCKET_SKIPPED:
            c["skipped"] += 1
            continue
        c["scanned_total"] += 1
        if b == BUCKET_CRITICAL:
            c["critical"] += 1
        elif b == BUCKET_HIGH:
            c["high_only"] += 1
        else:
            c["clean"] += 1
    n = c["scanned_total"]
    c["flagged"] = c["critical"] + c["high_only"]
    c["total"] = n + c["skipped"]
    c["pct"] = round(c["flagged"] / n * 100) if n else None
    c["flagged_pct"] = round(c["flagged"] / n * 100, 1) if n else None
    c["critical_pct"] = round(c["critical"] / n * 100, 1) if n else None
    return c


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
        oc_err = raw.get("error")
        # A fetch failure (empty/private/unreachable repo) is UNSCANNABLE — it is not
        # a 0/Blocked grade. Null the score so it reads "fetch error", not "Blocked".
        oc_score = None if oc_err else raw.get("trust_score")
        oc_score = _guard_stale_score(oc_score, raw.get("critical_count"))
        return CatalogRow(
            surface="openclaw",
            name=full_name,
            full_name=full_name,
            repository_url=f"https://github.com/{full_name}" if full_name else None,
            trust_score=oc_score,
            grade=_row_grade(oc_score, critical=raw.get("critical_count")),
            critical=raw.get("critical_count"),
            high=raw.get("high_count"),
            findings_count=raw.get("findings_count"),
            primary_language=raw.get("primary_language"),
            scan_error=oc_err,
            adoption_count=raw.get("adoption_count") or raw.get("stars"),
            adoption_unit=raw.get("adoption_unit") or ("stars" if raw.get("stars") else None),
            adoption_score=raw.get("adoption_score"),
        )
    # mcp / npm / pypi all share repo-scan shape
    err = raw.get("scan_error")
    # Same rule: a scan that couldn't fetch the repo is unscannable, not a 0. Failed
    # fetches were stored as trust_score=0 and rendered as Blocked — null them here.
    score = None if err else raw.get("trust_score")
    score = _guard_stale_score(score, raw.get("critical"))
    return CatalogRow(
        surface=surface,
        name=raw.get("name", "") or raw.get("full_name", ""),
        repository_url=raw.get("repository_url"),
        full_name=raw.get("full_name"),
        trust_score=score,
        grade=_row_grade(score, critical=raw.get("critical")),
        critical=raw.get("critical"),
        high=raw.get("high"),
        findings_count=raw.get("findings_count"),
        primary_language=raw.get("primary_language"),
        is_mcp_server=raw.get("is_mcp_server"),
        scan_error=err,
        skipped=raw.get("skipped"),
        # Adoption signal: prefer a stored adoption_count (community rows), else fall
        # back to repo stars the scanner captured, so Browse shows adoption for the
        # static corpus too (was blank for everything but community scans).
        adoption_count=raw.get("adoption_count") or raw.get("stars"),
        adoption_unit=raw.get("adoption_unit") or ("stars" if raw.get("stars") else None),
        adoption_score=raw.get("adoption_score"),
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


def _load_rows() -> list[CatalogRow]:
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
    return rows


def _build_catalog(rows: list[CatalogRow] | None = None) -> dict[str, Any]:
    """Assemble the cached catalog (rows + summary + facets). `rows` defaults to the
    launch-scan files on disk; tests pass fixture rows directly."""
    if rows is None:
        rows = _load_rows()

    # Categorize the static corpus ONCE at build time (cached) — doing it per request
    # over ~37k rows was a real CPU cost. Community rows (small, fresh) categorize per
    # request in the handler.
    static_cats: dict[str, int] = {}
    for r in rows:
        r.category = _categorize(r)
        static_cats[r.category] = static_cats.get(r.category, 0) + 1

    surfaces = ("x402", "mcp", "npm", "pypi", "openclaw")
    by_surface = {s: 0 for s in surfaces}
    by_surface_critical = {s: 0 for s in surfaces}
    by_surface_high = {s: 0 for s in surfaces}
    by_surface_scanned = {s: 0 for s in surfaces}
    by_surface_skipped = {s: 0 for s in surfaces}
    # Exclusive buckets (see _severity_bucket): a row counts under critical OR high,
    # never both, and only rows with a verdict count as scanned.
    for r in rows:
        by_surface[r.surface] = by_surface.get(r.surface, 0) + 1
        b = _severity_bucket(r)
        if b == BUCKET_CRITICAL:
            by_surface_critical[r.surface] = by_surface_critical.get(r.surface, 0) + 1
        elif b == BUCKET_HIGH:
            by_surface_high[r.surface] = by_surface_high.get(r.surface, 0) + 1
        if b in _VERDICT_BUCKETS:
            by_surface_scanned[r.surface] = by_surface_scanned.get(r.surface, 0) + 1
        elif b == BUCKET_SKIPPED:
            by_surface_skipped[r.surface] = by_surface_skipped.get(r.surface, 0) + 1

    repo_rows = [r for r in rows if r.surface != "x402"]
    repo_counts = _flagged_counts(repo_rows)
    x402_rows = [r for r in rows if r.surface == "x402"]
    x402_compliant = sum(1 for r in x402_rows if r.has_x402_header)

    summary = CatalogSummary(
        total_scans=len(rows),
        by_surface=by_surface,
        by_surface_critical=by_surface_critical,
        by_surface_high=by_surface_high,
        by_surface_scanned=by_surface_scanned,
        by_surface_skipped=by_surface_skipped,
        repo_scans_total=len(repo_rows),
        repo_scans_scanned=repo_counts["scanned_total"],
        repo_scans_skipped=repo_counts["skipped"],
        repo_scans_with_critical=repo_counts["critical"],
        repo_scans_with_high=repo_counts["high_only"],
        x402_endpoints_total=len(x402_rows),
        x402_compliant=x402_compliant,
    )
    # Sorted score list for percentile lookups ("safer than X% of scanned tools").
    scores = sorted(r.trust_score for r in rows if r.trust_score is not None)
    return {"rows": rows, "summary": summary, "static_cats": static_cats, "scores": scores}


def _get_catalog() -> dict[str, Any]:
    global _CATALOG_CACHE
    cached = _CATALOG_CACHE
    if cached is not None:
        return cached
    # The startup warm-up builds this in a thread; a request arriving mid-build waits
    # for that build instead of starting a second one.
    with _CATALOG_BUILD_LOCK:
        if _CATALOG_CACHE is None:
            _CATALOG_CACHE = _build_catalog()
        return _CATALOG_CACHE


async def _community_rows(db: AsyncSession) -> list[CatalogRow]:
    """On-demand scans users have run, persisted so the catalog grows over time.
    Best-effort — a DB hiccup must never break the static catalog.

    Cached per process for COMMUNITY_ROWS_TTL_SECONDS; concurrent cold callers share one
    DB read. Returns a new list each call (callers may append to it); the rows are
    categorized at fill time, so callers never need to mutate them. An error result is
    not cached."""
    global _COMMUNITY_CACHE
    cached = _COMMUNITY_CACHE
    if cached is not None and cached[1] > _now():
        return list(cached[0])
    async with _community_lock():
        cached = _COMMUNITY_CACHE
        if cached is not None and cached[1] > _now():
            return list(cached[0])
        rows = await _fetch_community_rows(db)
        if rows is None:
            return []
        for r in rows:
            if r.category is None:
                r.category = _categorize(r)
        _COMMUNITY_CACHE = (rows, _now() + COMMUNITY_ROWS_TTL_SECONDS)
        return list(rows)


async def _fetch_community_rows(db: AsyncSession) -> list[CatalogRow] | None:
    """One DB read of the community rows; None on a DB error."""
    from src.models import CommunityScan

    try:
        result = await db.execute(
            select(CommunityScan).order_by(CommunityScan.last_scanned_at.desc()).limit(2000)
        )
        out: list[CatalogRow] = []
        for c in result.scalars().all():
            # Route each community row by its real surface (default github for
            # pre-t18 rows): npm/pypi → package name, mcp → endpoint URL, else repo.
            surf = (getattr(c, "surface", None) or "github").lower()
            name = c.full_name
            repository_url = None
            endpoint_url = None
            if surf in ("npm", "pypi", "crates", "huggingface", "docker"):
                name = c.repo
            elif surf == "mcp":
                name = c.repo
                endpoint_url = c.repo
            else:  # github / openclaw
                repository_url = f"https://github.com/{c.full_name}"
            out.append(
                CatalogRow(
                    surface=surf,
                    name=name,
                    full_name=c.full_name,
                    repository_url=repository_url,
                    endpoint_url=endpoint_url,
                    trust_score=c.trust_score,
                    grade=_row_grade(c.trust_score, c.grade),
                    critical=c.critical,
                    high=c.high,
                    findings_count=c.findings_count,
                    primary_language=c.primary_language,
                    adoption_score=getattr(c, "adoption_score", None),
                    adoption_count=getattr(c, "adoption_count", None),
                    adoption_unit=getattr(c, "adoption_unit", None),
                )
            )
        return out
    except Exception:
        logger.warning("community_scans fetch failed", exc_info=True)
        return None


@router.get("", response_model=CatalogResponse, dependencies=[Depends(rate_limit_reads)])
async def scan_catalog(
    surface: str | None = Query(
        None, pattern="^(x402|mcp|npm|pypi|crates|huggingface|docker|openclaw|community)$",
    ),
    q: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|clean|skipped)$"),
    grade: str | None = Query(
        None, pattern="^(certified|verified|trusted|standard|minimal|restricted|A|B|C)$",
    ),
    category: str | None = Query(None, max_length=40),
    decision: str | None = Query(None, pattern="^(safe|review|do_not_connect)$"),
    sort: str = Query("default", pattern="^(default|score-asc|score-desc|name|adoption)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    response: Response = None,  # type: ignore[assignment]  # injected by FastAPI
) -> CatalogResponse:
    """Return a paginated, filterable catalog of every scan — the static launch
    corpus plus community (on-demand) scans that grow the dataset over time."""
    if response is not None:
        response.headers["Cache-Control"] = CATALOG_CACHE_CONTROL
    catalog = _get_catalog()
    rows: list[CatalogRow] = catalog["rows"]
    summary: CatalogSummary = catalog["summary"]

    # Merge in community scans (on-demand scans users ran). Search + the
    # 'community' tab see them; other single-surface tabs stay the launch corpus.
    community = await _community_rows(db)
    summary = summary.model_copy(deep=True)
    by_surface = dict(summary.by_surface)
    by_surface["community"] = len(community)
    # Community rows carry their real surface — count them into their own tab so
    # surfaces with no static launch corpus (crates, huggingface) show a live count.
    for _r in community:
        _s = (_r.surface or "").lower()
        if _s and _s != "community":
            by_surface[_s] = by_surface.get(_s, 0) + 1
    summary.by_surface = by_surface
    summary.total_scans += len(community)
    # Community rows now carry their REAL surface (npm/pypi/mcp/github/openclaw), so
    # a published package appears in its own surface tab too. Add them everywhere
    # except the dedicated 'community' tab (which shows them all, below).
    if community and surface != "community":
        rows = rows + community

    # Static rows are already categorized at build time (cached). Only categorize the
    # small community set here, and merge its counts onto the cached static counts.
    cat_counts = dict(catalog.get("static_cats") or {})
    for _r in community:
        if _r.category is None:
            _r.category = _categorize(_r)
        cat_counts[_r.category or "Library"] = cat_counts.get(_r.category or "Library", 0) + 1
    summary.by_category = dict(sorted(cat_counts.items(), key=lambda kv: -kv[1]))

    filtered = rows
    if surface == "community":
        filtered = community  # the 'community' tab = every on-demand scan, any surface
    elif surface:
        filtered = [r for r in filtered if r.surface == surface]
    if category:
        filtered = [r for r in filtered if r.category == category]
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
    # Severity = the exclusive buckets from _severity_bucket, so these totals are the
    # same numbers /flagged-stat reports. "clean" is stricter than the stat's clean
    # bucket: it also requires a Trusted-band score (>= 80), i.e. "safe to connect",
    # not merely "no high or critical finding".
    if severity == "critical":
        filtered = [r for r in filtered if _severity_bucket(r) == BUCKET_CRITICAL]
    elif severity == "high":
        filtered = [r for r in filtered if _severity_bucket(r) == BUCKET_HIGH]
    elif severity == "clean":
        filtered = [
            r for r in filtered
            if _severity_bucket(r) == BUCKET_CLEAN and (r.trust_score or 0) >= 80
        ]
    elif severity == "skipped":
        filtered = [r for r in filtered if _severity_bucket(r) == BUCKET_SKIPPED]

    # Grade filter (curation): "certified" = A+ only; a tier value (verified … minimal)
    # = that tier's score floor and above (src/trust_tiers.py); A/B/C = the legacy
    # letter band and above, kept for links already in the wild.
    if grade in TIER_FLOORS:
        _floor = TIER_FLOORS[grade]
        filtered = [r for r in filtered if r.trust_score is not None and r.trust_score >= _floor]
    elif grade:
        _min_ok = {
            "certified": {"A+"},
            "A": {"A+", "A"},
            "B": {"A+", "A", "B"},
            "C": {"A+", "A", "B", "C"},
        }.get(grade)
        if _min_ok:
            filtered = [r for r in filtered if (r.grade or "") in _min_ok]

    # Three-phrase filter: Safe to connect / Review before you connect / Do not connect.
    if isinstance(decision, str) and decision:  # (a direct call passes the Query default)
        filtered = [r for r in filtered if r.decision == decision]

    if sort == "score-desc":
        filtered = sorted(filtered, key=lambda r: r.trust_score or -1, reverse=True)
    elif sort == "score-asc":
        filtered = sorted(
            filtered,
            key=lambda r: r.trust_score if r.trust_score is not None else 999,
        )
    elif sort == "name":
        filtered = sorted(filtered, key=lambda r: (r.name or "").lower())
    elif sort == "adoption":
        # "Widely relied upon" — most-adopted first (only community rows carry adoption
        # today; unknown adoption sorts last).
        filtered = sorted(filtered, key=lambda r: (r.adoption_count or -1), reverse=True)
    else:
        # DEFAULT rank (no explicit sort): "widely relied upon" first — the most-adopted
        # tools lead (stars for repos, downloads for packages/community rows), which
        # surfaces a natural spread of real scores (popular != perfect) instead of leading
        # with a block of 100s. Skipped/errored scrapes (e.g. thousands of unscannable
        # MCP-registry entries) still sink to the bottom; trust_score is only a tiebreaker
        # among rows of equal adoption. (Kenne 2026-08-26: default to widely-relied-upon.)
        def _rank(r: CatalogRow):
            junk = bool(r.skipped or r.scan_error)
            return (
                junk,
                -(r.adoption_count or -1),
                -(r.trust_score if r.trust_score is not None else -1),
            )
        filtered = sorted(filtered, key=_rank)

    total = len(filtered)
    page = await _attach_sandbox(filtered[offset:offset + limit])

    return CatalogResponse(
        summary=summary,
        rows=page,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/refresh", include_in_schema=False)
async def refresh_catalog(
    current_entity: Entity = Depends(get_current_entity),
) -> dict[str, Any]:
    """Force-rebuild the in-memory catalog from disk. Admin only: the rebuild reads
    every scan file on disk, so an anonymous caller must not be able to trigger it."""
    require_admin(current_entity)
    global _CATALOG_CACHE, _FLAGGED_STAT_CACHE
    _CATALOG_CACHE = None
    _FLAGGED_STAT_CACHE = None
    catalog = _get_catalog()
    return {"status": "rebuilt", "total_scans": catalog["summary"].total_scans}


@router.get("/flagged-stat", dependencies=[Depends(rate_limit_reads)])
async def flagged_stat(
    db: AsyncSession = Depends(get_db),
    response: Response = None,  # type: ignore[assignment]  # injected by FastAPI
) -> dict[str, Any]:
    """Single source of truth for the headline stat: the share of SCANNED tools that carry
    a high or critical finding. The homepage, the Index and the State of Agent Security
    report all read this, computed server-side over the launch corpus + community rows.

    Every count is an exclusive bucket (see `_severity_bucket`), so a tool is counted
    once no matter how many findings it has, and the denominator is only tools that
    actually received a verdict. x402 endpoints are compliance probes, not code scans,
    and are excluded entirely.

    Response:
    - `scanned_total`: tools with a verdict (the denominator). Alias: `scanned`.
    - `critical`: tools with >=1 critical finding.
    - `high_only`: tools with >=1 high finding and no critical.
    - `flagged`: critical + high_only. Every flagged tool counted exactly once.
    - `clean`: scanned tools with no high or critical finding.
    - `skipped`: catalog rows with no verdict (fetch skipped / scan error). NOT in the
      denominator. `total` = scanned_total + skipped.
    - `pct`: flagged / scanned_total, whole percent (None if nothing scanned);
      `flagged_pct` and `critical_pct` carry one decimal.
    - `by_surface`: the same keys per surface (mcp, npm, pypi, openclaw, github, ...).

    `pct`, `flagged` and `scanned` are kept for existing callers. Before 2026-10-01 they
    double-counted tools with both a critical and a high finding and divided by every
    catalog row including never-scanned ones; they are now the honest figures.

    Agreement guarantee: `critical`, `high_only` and `skipped` (overall and per surface)
    equal the `total` of `GET /public/scan-catalog?severity=critical|high|skipped`. The
    list's `severity=clean` additionally requires a score >= 80, so it is a subset of
    `clean` here.
    """
    global _FLAGGED_STAT_CACHE
    if response is not None:
        response.headers["Cache-Control"] = CATALOG_CACHE_CONTROL
    catalog = _get_catalog()
    community = await _community_rows(db)
    # Served from cache only for the same catalog object and equal community rows
    # (the stat is a pure function of those two), within FLAGGED_STAT_TTL_SECONDS.
    cached = _FLAGGED_STAT_CACHE
    if (
        cached is not None
        and cached[3] > _now()
        and cached[0] is catalog
        and len(cached[1]) == len(community)
        and all(a is b or a == b for a, b in zip(cached[1], community))
    ):
        return copy.deepcopy(cached[2])
    out = _compute_flagged_stat(catalog, community)
    _FLAGGED_STAT_CACHE = (catalog, community, out, _now() + FLAGGED_STAT_TTL_SECONDS)
    return copy.deepcopy(out)


def _compute_flagged_stat(
    catalog: dict[str, Any], community: list[CatalogRow],
) -> dict[str, Any]:
    rows: list[CatalogRow] = list(catalog["rows"]) + community
    totals = _flagged_counts(rows)
    grouped: dict[str, list[CatalogRow]] = {}
    for r in rows:
        if r.surface != "x402":
            grouped.setdefault(r.surface, []).append(r)
    by_surface = {s: _flagged_counts(grouped[s]) for s in sorted(grouped)}
    return {
        # legacy keys (same meaning as the new ones, now computed honestly)
        "pct": totals["pct"],
        "flagged": totals["flagged"],
        "scanned": totals["scanned_total"],
        # explicit, exclusive counts
        "scanned_total": totals["scanned_total"],
        "critical": totals["critical"],
        "high_only": totals["high_only"],
        "clean": totals["clean"],
        "skipped": totals["skipped"],
        "total": totals["total"],
        "flagged_pct": totals["flagged_pct"],
        "critical_pct": totals["critical_pct"],
        "by_surface": by_surface,
    }


@router.get("/percentile", dependencies=[Depends(rate_limit_reads)])
async def score_percentile(score: int = Query(..., ge=0, le=100)) -> dict[str, Any]:
    """"Safer than X% of scanned tools." Returns the percentile of `score` against the
    catalog's scored-tool distribution (share scoring strictly lower), plus the population."""
    import bisect
    scores: list[int] = _get_catalog().get("scores") or []
    n = len(scores)
    if not n:
        return {"score": score, "percentile": None, "population": 0}
    below = bisect.bisect_left(scores, score)
    pct = round((below / n) * 100)
    return {"score": score, "percentile": pct, "population": n}


@router.get("/recent", dependencies=[Depends(rate_limit_reads)])
async def recent_scans(
    limit: int = Query(15, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """The N most-recently-scanned tools — the live 'just scanned…' feed. Real scans only."""
    from src.models import CommunityScan
    try:
        rows = (await db.execute(
            select(CommunityScan)
            .where(CommunityScan.trust_score.isnot(None))
            .order_by(CommunityScan.last_scanned_at.desc())
            .limit(limit)
        )).scalars().all()
    except Exception:
        logger.warning("recent_scans fetch failed", exc_info=True)
        return {"items": []}
    items = []
    for c in rows:
        surf = (getattr(c, "surface", None) or "github").lower()
        _pkg = surf in ("npm", "pypi", "crates", "huggingface", "docker", "mcp")
        name = c.repo if _pkg else c.full_name
        items.append({
            "surface": surf,
            "name": name,
            "full_name": c.full_name,
            "trust_score": c.trust_score,
            "critical": c.critical,
            "high": c.high,
            "at": c.last_scanned_at.isoformat() if c.last_scanned_at else None,
        })
    return {"items": items}
