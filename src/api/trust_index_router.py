"""Trust Index weekly cards: "Do not connect this week" and "Most checked this week".

Owner rule (2026-11-11): no Do not connect result is put in front of the public as a
highlight until a person has read its finding. So:

* ``/admin/dnc-reviews`` (full admin only, never a viewer) lists the candidates, every
  catalog tool that reads Do not connect now and was scanned in the last 7 days (plus
  the catalog-growth job's ``dnc-review.jsonl`` when the backend can read it), with its
  reason, its top critical finding and its review status; POST records a person's
  read: ``confirmed`` or ``not_confirmed``.
* ``/public/trust-index/do-not-connect-week`` lists up to 5 tools confirmed in the last
  7 days, newest first, re-checked at read time: a tool that no longer reads Do not
  connect, or reads it for a different reason than the one the reviewer read, drops out.
* ``/public/trust-index/most-checked-week`` lists the top 5 tools by checks in the last
  7 days (``src.tool_checks``), each with its answer and Certified mark. A tool that
  reads Do not connect is left out unless a person confirmed it (same rule). Empty
  until at least 3 tools have 3+ checks.

Both public reads are cached 10 minutes and rate-limited like every public read. Nothing
here changes a scan, a score or any other public number.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src import cache
from src.api.deps import get_current_entity, require_admin
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import DncReview, Entity

logger = logging.getLogger(__name__)

public_router = APIRouter(prefix="/public/trust-index", tags=["public-scan"])
admin_router = APIRouter(prefix="/admin/dnc-reviews", tags=["admin"])

DNC = "do_not_connect"
WINDOW_DAYS = 7
CARD_LIMIT = 5
MIN_TOOLS = 3          # most-checked shows only once this many tools have...
MIN_CHECKS = 3         # ...at least this many checks each
CACHE_TTL = 600
DNC_CACHE_KEY = "trust_index:dnc_week:v1"
CHECKED_CACHE_KEY = "trust_index:most_checked:v1"
CANDIDATES_MAX = 200
JSONL_TAIL = 5000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- the catalog as its pages show it right now ----------------------------------------
async def catalog_rows(db: AsyncSession) -> list[Any]:
    """Every catalog row, one per result page, as Browse lists it (a live re-scan replaces
    the launch-corpus row for its page). Rows carry ``decision`` / ``decision_reason`` /
    ``page_path`` / ``certified_mark``."""
    from src.api.scan_catalog_router import _community_rows, _get_catalog, _supersede

    catalog = _get_catalog()
    community = await _community_rows(db)
    merged, _listed, _dropped = _supersede(catalog, community)
    return merged


def _row_key(row: Any) -> str | None:
    from src.api.scan_catalog_router import page_key
    return page_key(row)


async def rows_for_keys(db: AsyncSession, keys: set[str]) -> dict[str, Any]:
    if not keys:
        return {}
    out: dict[str, Any] = {}
    for r in await catalog_rows(db):
        k = _row_key(r)
        if k in keys and k not in out:
            out[k] = r
    return out


def _confirmed_now(review: DncReview | None, row: Any) -> bool:
    """A confirmed review still stands: the tool reads Do not connect today, for the
    reason the reviewer read."""
    return (review is not None and review.verdict == "confirmed" and row is not None
            and getattr(row, "decision", None) == DNC
            and (review.reason_at_review or "") == (getattr(row, "decision_reason", None) or ""))


def _row_public(row: Any) -> dict[str, Any]:
    return {
        "page_path": row.page_path,
        "surface": row.surface,
        "name": row.name,
        "full_name": row.full_name,
        "endpoint_url": row.endpoint_url,
    }


# --- public reads ----------------------------------------------------------------------
async def build_dnc_week(db: AsyncSession, now: datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    since = now - timedelta(days=WINDOW_DAYS)
    reviews = (await db.execute(
        select(DncReview).where(DncReview.verdict == "confirmed",
                                DncReview.reviewed_at >= since)
        .order_by(DncReview.reviewed_at.desc())
    )).scalars().all()
    rows = await rows_for_keys(db, {r.page_key for r in reviews})
    items: list[dict[str, Any]] = []
    for rv in reviews:
        row = rows.get(rv.page_key)
        if not _confirmed_now(rv, row):
            continue
        items.append({**_row_public(row), "decision": DNC,
                      "decision_reason": row.decision_reason,
                      "confirmed_at": _aware(rv.reviewed_at).isoformat()})
        if len(items) >= CARD_LIMIT:
            break
    return {"window_days": WINDOW_DAYS, "items": items}


async def build_most_checked(db: AsyncSession, counts: dict[str, int] | None = None
                             ) -> dict[str, Any]:
    from src import tool_checks

    if counts is None:
        counts = await tool_checks.week_counts()
    ranked = sorted(((k, n) for k, n in counts.items() if n >= MIN_CHECKS),
                    key=lambda kv: (-kv[1], kv[0]))
    # A few spares past the limit, so dropped tools still leave a full card.
    pool = ranked[:CARD_LIMIT * 6]
    keys = {k for k, _ in pool}
    rows = await rows_for_keys(db, keys)
    dnc_keys = {k for k, r in rows.items() if getattr(r, "decision", None) == DNC}
    reviews: dict[str, DncReview] = {}
    if dnc_keys:
        reviews = {rv.page_key: rv for rv in (await db.execute(
            select(DncReview).where(DncReview.page_key.in_(dnc_keys))
        )).scalars().all()}
    items: list[dict[str, Any]] = []
    for k, n in pool:
        row = rows.get(k)
        if row is None or row.trust_score is None or row.decision is None:
            continue
        if row.decision == DNC and not _confirmed_now(reviews.get(k), row):
            continue
        items.append({**_row_public(row), "trust_score": row.trust_score,
                      "decision": row.decision, "certified_mark": bool(row.certified_mark),
                      "critical": row.critical, "high": row.high, "checks": n})
        if len(items) >= CARD_LIMIT:
            break
    if len(items) < MIN_TOOLS:
        items = []
    return {"window_days": WINDOW_DAYS, "min_checks": MIN_CHECKS, "items": items}


@public_router.get("/do-not-connect-week", dependencies=[Depends(rate_limit_reads)])
async def dnc_week(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Up to 5 tools whose Do not connect answer a person confirmed in the last 7 days,
    newest first, that still read Do not connect for the same reason now."""
    hit = await cache.get(DNC_CACHE_KEY)
    if isinstance(hit, dict):
        return hit
    data = await build_dnc_week(db)
    await cache.set(DNC_CACHE_KEY, data, ttl=CACHE_TTL)
    return data


@public_router.get("/most-checked-week", dependencies=[Depends(rate_limit_reads)])
async def most_checked_week(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """The top 5 tools by checks in the last 7 days (people and agents only; crawlers,
    scripts, our own clients and the owner's machines are not counted)."""
    hit = await cache.get(CHECKED_CACHE_KEY)
    if isinstance(hit, dict):
        return hit
    data = await build_most_checked(db)
    await cache.set(CHECKED_CACHE_KEY, data, ttl=CACHE_TTL)
    return data


# --- admin: the review queue ------------------------------------------------------------
def _cache_coords(row: Any) -> tuple[str, str] | None:
    """(owner, repo) the public scan cache keys this row's last result under."""
    s = (row.surface or "").lower()
    if s in ("npm", "pypi", "crates", "huggingface", "docker"):
        return s, row.name
    if s == "mcp":
        ep = row.endpoint_url or row.name
        return ("mcp", "mcp_" + hashlib.sha256(ep.encode()).hexdigest()[:22]) if ep else None
    fn = row.full_name or ""
    if s == "openclaw":
        return ("skill", fn) if fn else None
    if "/" in fn:
        owner, repo = fn.split("/", 1)
        return owner, repo
    return None


async def top_critical(row: Any) -> dict[str, Any] | None:
    """The first critical finding of the row's cached scan (the list leads with the
    findings that decided the answer), or None when no cached scan is at hand."""
    try:
        from src.api.public_scan_router import _CACHE_PREFIX, _STALE_CACHE_PREFIX

        coords = _cache_coords(row)
        if coords is None:
            return None
        k = f"{coords[0]}/{coords[1]}"
        data = await cache.get(f"{_CACHE_PREFIX}{k}") or await cache.get(
            f"{_STALE_CACHE_PREFIX}{k}")
        items = ((data or {}).get("findings") or {}).get("items") or []
        for f in items:
            if isinstance(f, dict) and f.get("severity") == "critical":
                return {"category": f.get("category"), "name": f.get("name"),
                        "file_path": f.get("file_path"), "line_number": f.get("line_number")}
    except Exception:
        logger.debug("top critical lookup failed", exc_info=True)
    return None


def growth_review_keys(since: datetime) -> dict[str, str]:
    """{page_key: at} from the catalog-growth job's dnc-review.jsonl (its Do not connect
    answers waiting for a person), newest entries in the window only. Empty when the
    file is not readable from this process (it lives on the host the job runs on)."""
    from src.api.scan_catalog_router import _path_key, community_row_coords, page_path_for

    out: dict[str, str] = {}
    try:
        from src.catalog_growth.state import data_dir

        path = data_dir() / "dnc-review.jsonl"
        if not path.is_file():
            return out
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-JSONL_TAIL:]
    except Exception:
        return out
    for line in lines:
        try:
            rec = json.loads(line)
            at = _aware(datetime.fromisoformat(str(rec.get("at"))))
            if at is None or at < since:
                continue
            owner, repo = str(rec.get("owner") or ""), str(rec.get("repo") or "")
            surf, name, _url, ep = community_row_coords(
                rec.get("surface"), repo, f"{owner}/{repo}")
            key = _path_key(page_path_for(surf, name, f"{owner}/{repo}", ep))
            if key:
                out[key] = at.isoformat()
        except Exception:
            continue
    return out


def _status(review: DncReview | None, row: Any) -> str:
    if review is None:
        return "pending"
    if (review.reason_at_review or "") != (getattr(row, "decision_reason", None) or ""):
        return "changed"  # the reason moved since the review: read it again
    return review.verdict


async def build_candidates(db: AsyncSession, now: datetime | None = None) -> list[dict]:
    now = now or _now()
    since = now - timedelta(days=WINDOW_DAYS)
    growth = growth_review_keys(since)
    picked: dict[str, Any] = {}
    for r in await catalog_rows(db):
        if r.decision != DNC:
            continue
        k = _row_key(r)
        if not k or k in picked:
            continue
        seen = _aware(r.last_scanned_at)
        if (seen is not None and seen >= since) or k in growth:
            picked[k] = r
    reviews = {rv.page_key: rv for rv in (await db.execute(
        select(DncReview).where(DncReview.page_key.in_(set(picked)))
    )).scalars().all()} if picked else {}
    rank = {"pending": 0, "changed": 1, "not_confirmed": 2, "confirmed": 3}
    rows = sorted(
        picked.items(),
        key=lambda kv: (rank[_status(reviews.get(kv[0]), kv[1])],
                        -(_aware(kv[1].last_scanned_at) or since).timestamp()))[:CANDIDATES_MAX]
    out: list[dict] = []
    for k, r in rows:
        rv = reviews.get(k)
        out.append({
            **_row_public(r),
            "page_key": k,
            "trust_score": r.trust_score,
            "decision": r.decision,
            "decision_reason": r.decision_reason,
            "last_scanned_at": _aware(r.last_scanned_at).isoformat()
            if r.last_scanned_at else None,
            "from_catalog_growth": k in growth,
            "top_critical": await top_critical(r),
            "status": _status(rv, r),
            "reviewed_at": _aware(rv.reviewed_at).isoformat() if rv else None,
            "note": rv.note if rv else None,
        })
    return out


@admin_router.get("")
async def list_candidates(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Do not connect answers from the last 7 days waiting for (or carrying) a person's
    read. Full admin only."""
    require_admin(current_entity)
    return {"window_days": WINDOW_DAYS, "items": await build_candidates(db)}


class ReviewIn(BaseModel):
    page_path: str = Field(..., min_length=2, max_length=1024)
    verdict: Literal["confirmed", "not_confirmed"]
    note: str | None = Field(None, max_length=2000)


@admin_router.post("", dependencies=[Depends(rate_limit_writes)])
async def record_review(
    body: ReviewIn,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Record a person's read of one result page's Do not connect answer. A later review
    of the same page replaces the earlier one. Full admin only."""
    require_admin(current_entity)
    from src.api.scan_catalog_router import _path_key

    key = _path_key(body.page_path.strip())
    if not key or not key.startswith("/check/"):
        raise HTTPException(400, "page_path must be a result page path (/check/...)")
    row = (await rows_for_keys(db, {key})).get(key)
    if row is None:
        raise HTTPException(404, "No catalog tool has that result page")
    if body.verdict == "confirmed" and row.decision != DNC:
        raise HTTPException(409, "That tool does not read Do not connect now")
    review = (await db.execute(
        select(DncReview).where(DncReview.page_key == key))).scalar_one_or_none()
    if review is None:
        review = DncReview(page_key=key)
        db.add(review)
    review.page_path = row.page_path or key
    review.surface = (row.surface or "")[:16]
    review.name = (row.full_name or row.name or "")[:512]
    review.decision_at_review = row.decision or ""
    review.reason_at_review = row.decision_reason
    review.verdict = body.verdict
    review.note = (body.note or "").strip() or None
    review.reviewed_by = current_entity.id
    review.reviewed_at = _now()
    await db.flush()
    from src.audit import log_action

    await log_action(db, action="admin.dnc_review", entity_id=current_entity.id,
                     resource_type="dnc_review", resource_id=review.id,
                     details={"page_key": key, "verdict": body.verdict,
                              "decision": row.decision})
    await db.commit()
    await cache.invalidate(DNC_CACHE_KEY)
    await cache.invalidate(CHECKED_CACHE_KEY)
    return {"page_key": key, "verdict": review.verdict,
            "reviewed_at": _aware(review.reviewed_at).isoformat()}
