"""Per-row tool summaries for the account lists: watches, claims and watch alerts.

Each row on My Tools, Watches & alerts and Notifications shows the same artwork as a
Browse row: the trust (or Certified) mini and the adoption gauge. This module reads
what those need (trust score, answer, Certified mark, adoption count and unit) from
stored scan data only:

  1. community_scans, in ONE query for every coordinate on the page;
  2. the static launch catalog, only when it is already in memory.

It never starts a scan and never fetches anything over the network, so a list of N
rows costs one query, not N. A tool with no stored row gets no summary, and the UI
shows its "New" adoption state.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

# Coordinates are stored as (surface, owner, repo), the same shape on ToolWatch,
# RepoClaim and CommunityScan: github/openclaw → owner/repo · packages → owner is the
# surface, repo the package · mcp → owner 'mcp', repo the endpoint URL.
Coord = tuple[str, str, str]

PACKAGE_SURFACES = ("npm", "pypi", "crates", "huggingface", "docker")
_SUMMARY_SURFACES = ("github", "openclaw", "mcp", *PACKAGE_SURFACES)

# The fields every summary carries (None when unknown). Additive on each API row.
SUMMARY_FIELDS = (
    "trust_score", "decision", "decision_reason", "certified_mark",
    "adoption_count", "adoption_unit",
)


def coord_key(surface: str | None, owner: str, repo: str) -> Coord:
    """The lookup key for a stored coordinate. GitHub names are case-insensitive and
    so are registry names here; an MCP URL is compared as stored, lower-cased."""
    s = (surface or "github").lower()
    owner = (owner or "").strip()
    repo = (repo or "").strip()
    if s in PACKAGE_SURFACES:
        owner = s
    elif s == "mcp":
        owner = "mcp"
    return (s, owner.lower(), repo.lower())


def coords_from_reference(reference_id: str | None) -> list[Coord]:
    """Candidate coordinates for a watch alert's ``reference_id`` ("owner/repo" of the
    watch: "npm/zod", "mcp/https://…", "acme/tool"). An owner/repo pair may be a GitHub
    repo or an OpenClaw skill, so both are returned, GitHub first."""
    if not reference_id or "/" not in reference_id:
        return []
    head, rest = reference_id.split("/", 1)
    h = head.lower()
    if not rest:
        return []
    if h in PACKAGE_SURFACES or h == "mcp":
        return [coord_key(h, h, rest)]
    return [coord_key("github", head, rest), coord_key("openclaw", head, rest)]


def _summary(
    trust_score: Any, decision: Any, decision_reason: Any, certified_mark: Any,
    adoption_count: Any, adoption_unit: Any,
) -> dict[str, Any]:
    has_decision = decision in ("safe", "review", "do_not_connect")
    return {
        "trust_score": trust_score,
        "decision": decision if has_decision else None,
        # A string whenever there is a decision: the web client only trusts a stored
        # decision that carries its reason (gradeSystem.ts decisionOf).
        "decision_reason": (decision_reason or "") if has_decision else None,
        # The mark only ever sits beside Safe to connect.
        "certified_mark": bool(certified_mark) and decision == "safe",
        "adoption_count": adoption_count if (adoption_count or 0) > 0 else None,
        "adoption_unit": adoption_unit if (adoption_count or 0) > 0 else None,
    }


def empty_summary() -> dict[str, Any]:
    return dict.fromkeys(SUMMARY_FIELDS)


def summary_from_score(
    trust_score: int | None, critical: int | None = None, high: int | None = None,
) -> dict[str, Any]:
    """A summary decided from a score and its blocking counts alone (private reports,
    which have no catalog row and no adoption)."""
    if trust_score is None:
        return empty_summary()
    from src.api.scan_catalog_router import CatalogRow

    row = CatalogRow(surface="github", name="", trust_score=trust_score,
                     critical=critical, high=high, certified_mark=False)
    return _summary(trust_score, row.decision, row.decision_reason, False, None, None)


async def _community_summaries(db: AsyncSession, keys: set[Coord]) -> dict[Coord, dict]:
    from src.api.scan_catalog_router import CatalogRow, _row_grade, community_mark_grade
    from src.models import CommunityScan

    out: dict[Coord, dict] = {}
    if not keys:
        return out
    rows = (await db.execute(
        select(CommunityScan)
        .where(tuple_(
            CommunityScan.surface,
            func.lower(CommunityScan.owner),
            func.lower(CommunityScan.repo),
        ).in_(sorted(keys)))
        # Newest first, so a case-only duplicate keeps its latest scan.
        .order_by(CommunityScan.last_scanned_at.desc())
    )).scalars().all()
    for c in rows:
        key = coord_key(c.surface, c.owner, c.repo)
        if key in out:
            continue
        grade = _row_grade(c.trust_score, await community_mark_grade(c))
        stored = c.decision if (c.decision in ("safe", "review", "do_not_connect")
                                and c.trust_score is not None) else None
        row = CatalogRow(
            surface=c.surface or "github", name=c.full_name or "",
            trust_score=c.trust_score, grade=grade,
            critical=c.critical, high=c.high,
            decision=stored, decision_reason=c.decision_reason if stored else None,
        )
        out[key] = _summary(
            row.trust_score, row.decision, row.decision_reason, row.certified_mark,
            c.adoption_count, c.adoption_unit,
        )
    return out


# The static-catalog index, rebuilt only when the cached catalog object changes.
_STATIC_INDEX: tuple[Any, dict[Coord, Any]] | None = None


def _static_index() -> dict[Coord, Any]:
    """Coordinate → static CatalogRow, from the launch catalog ONLY if it is already
    built (the startup warm-up builds it). A cold catalog is never built here: that is
    a disk read of every launch file, too slow for an account page."""
    global _STATIC_INDEX
    from src.api import scan_catalog_router as cat

    catalog = cat._CATALOG_CACHE
    if catalog is None:
        return {}
    cached = _STATIC_INDEX
    if cached is not None and cached[0] is catalog:
        return cached[1]
    index: dict[Coord, Any] = {}
    for r in catalog.get("rows", []):
        if r.trust_score is None:
            continue
        if r.surface in PACKAGE_SURFACES and r.name:
            index.setdefault(coord_key(r.surface, r.surface, r.name), r)
            continue
        fn = r.full_name or ""
        if fn.count("/") == 1 and "://" not in fn:
            o, n = fn.split("/")
            # Launch "mcp" and "openclaw" rows are GitHub repos.
            index.setdefault(coord_key("github", o, n), r)
            if r.surface == "openclaw":
                index.setdefault(coord_key("openclaw", o, n), r)
    _STATIC_INDEX = (catalog, index)
    return index


async def tool_summaries(db: AsyncSession, coords: Iterable[Coord]) -> dict[Coord, dict]:
    """Summaries for many coordinates at once (keys from ``coord_key``). Missing
    coordinates are left out. Fail-soft: a read error returns what was found."""
    import logging

    keys = {k for k in coords if k[0] in _SUMMARY_SURFACES and k[2]}
    out: dict[Coord, dict] = {}
    try:
        out = await _community_summaries(db, keys)
    except Exception:  # noqa: BLE001 — artwork is optional; the list must still load
        logging.getLogger(__name__).warning("tool summary read failed", exc_info=True)
    missing = keys - out.keys()
    if missing:
        try:
            index = _static_index()
        except Exception:  # noqa: BLE001
            index = {}
        for k in missing:
            r = index.get(k)
            if r is not None:
                out[k] = _summary(
                    r.trust_score, r.decision, r.decision_reason, r.certified_mark,
                    r.adoption_count, r.adoption_unit,
                )
    return out
