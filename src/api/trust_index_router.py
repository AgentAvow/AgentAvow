"""Trust Index weekly cards: "Do not connect this week" and "Most checked this week".

Owner rule (2026-11-11): no Do not connect result is put in front of the public as a
highlight until a person has read its finding. So:

* ``/admin/dnc-reviews`` (full admin only, never a viewer) answers this week's
  ``shortlist``: at most 3 tools that read Do not connect and that people or agents
  checked this week (``src.tool_checks``), most checks first, skipping ones a person
  already read unless the reason changed since. ``items`` is the full reference list:
  every catalog tool that reads Do not connect now and was scanned in the last 7 days
  (plus the catalog-growth job's ``dnc-review.jsonl`` when the backend can read it),
  with its reason, its top critical finding and its review status. POST records a
  person's read: ``confirmed`` or ``not_confirmed``.
* ``/public/trust-index/do-not-connect-week`` lists up to 5 tools, re-checked at read
  time. First the ones a person confirmed in the last 7 days, newest first (a tool that
  no longer reads Do not connect, or reads it for a different reason than the one the
  reviewer read, drops out). Then, to fill the card, tools scanned in the last 7 days
  whose answer needs no judgment, found from structured fields of the cached scan
  (free text is never searched for a signal): a known-malicious package
  (``incident_history.current_version_affected``: this version itself has a malware
  advisory), a known-malicious dependency (``supply_chain.malicious``: OpenSSF MAL
  advisory ids), or a planted credential the sandbox saw leaving (``behavioral.canary_exfil`` or a
  ``credential_canary_exfiltrated`` finding on a finished, non-advisory run, stamped
  with the scanned version). ``auto_kind`` requires that ``decide()`` over the cached
  scan and its version-checked sandbox block reads Do not connect for the same rule as
  the row's stored reason, and that the cache is not older than the row. A tool a
  person marked Not confirmed stays off for as long as that review stands. Each item
  says why it is listed: ``listed_because`` = ``confirmed`` | ``known_malicious`` |
  ``malicious_dependency`` | ``sandbox``. One worker rebuilds the card at a time.
* ``/public/trust-index/most-checked-week`` lists the top 5 tools by checks in the last
  7 days (``src.tool_checks``), each with its answer and Certified mark. A tool that
  reads Do not connect is left out unless a person confirmed it (same rule). Empty
  until at least 3 tools have 3+ checks.

Both public reads are cached 10 minutes and rate-limited like every public read. Nothing
here changes a scan, a score or any other public number.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import secrets
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
DNC_CACHE_KEY = "trust_index:dnc_week:v2"
DNC_LAST_KEY = "trust_index:dnc_week:last:v2"
DNC_LOCK_KEY = "trust_index:dnc_week:lock"
DNC_GEN_KEY = "trust_index:dnc_week:gen"
CHECKED_CACHE_KEY = "trust_index:most_checked:v1"
CANDIDATES_MAX = 200
JSONL_TAIL = 5000
SHORTLIST_LIMIT = 3    # the owner reads at most this many a week
AUTO_LOOKUPS_MAX = 300  # cached scans read per card build for the automatic fill
AUTO_CONCURRENCY = 16   # cached-scan / sandbox reads in flight at once
REBUILD_LOCK_TTL = 10   # seconds one worker holds the card-rebuild lock
LAST_GOOD_TTL = 3600   # the last built card, served while another worker rebuilds


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
async def cached_scan(row: Any) -> dict | None:
    """The row's last scan result from the public scan cache (fresh copy, else the
    7-day stale copy), or None when none is at hand."""
    try:
        from src.api.public_scan_router import _CACHE_PREFIX, _STALE_CACHE_PREFIX

        coords = _cache_coords(row)
        if coords is None:
            return None
        k = f"{coords[0]}/{coords[1]}"
        data = await cache.get(f"{_CACHE_PREFIX}{k}") or await cache.get(
            f"{_STALE_CACHE_PREFIX}{k}")
        return data if isinstance(data, dict) else None
    except Exception:
        logger.debug("cached scan lookup failed", exc_info=True)
        return None


def _scan_version(data: dict, surface: str | None) -> str | None:
    """The exact release a cached package scan resolved (npm / PyPI / docker), else None."""
    if surface not in ("npm", "pypi", "docker"):
        return None
    pkg = data.get("package_coordinate") if isinstance(data.get("package_coordinate"),
                                                       dict) else {}
    ver = data.get("package_version") or pkg.get("version")
    return (str(ver).strip() or None) if ver else None


async def cached_behavioral(data: dict, row: Any | None = None) -> dict | None:
    """The sandbox block cached for a scan's coordinate, found the way the result page
    finds it (``_package_sandbox_input``), and checked against the scan's version: a
    block stamped for another release is a miss. Cache only: never starts a sandbox run.
    A run still pending has no say, so it reads as None."""
    try:
        from src.api.public_scan_router import (
            _behavioral_plan,
            _behavioral_target,
            _declared_egress,
            _get_cached_behavioral,
            _package_sandbox_input,
        )

        coords = _cache_coords(row) if row is not None else None
        inp = _package_sandbox_input(data, coords)
        target = _behavioral_target(inp)
        if target is None:
            return None
        surface, name = target
        block = await _get_cached_behavioral(
            surface, str(name), _declared_egress(inp), _behavioral_plan(inp, surface),
            _scan_version(data, surface))
        if not isinstance(block, dict) or block.get("pending"):
            return None
        return block
    except Exception:
        logger.debug("cached sandbox lookup failed", exc_info=True)
        return None


def auto_reason(data: dict | None, block: dict | None) -> str | None:
    """Which no-judgment Do not connect rule the structured fields show, in the order
    ``src.scanner.verdict.decide`` applies them: ``sandbox`` (a planted credential left
    the sandbox on a finished, non-advisory run), ``known_malicious`` (this version of
    the tool itself has a malware advisory), ``malicious_dependency`` (a dependency has
    an OpenSSF MAL advisory), else None. Never reads reason text."""
    from src.scanner.verdict import is_advisory_block

    if isinstance(block, dict) and block.get("ran") and not block.get("pending") \
            and not is_advisory_block(block):
        findings = [f for f in (block.get("findings") or []) if isinstance(f, dict)]
        if block.get("canary_exfil") or any(
                f.get("rule") == "credential_canary_exfiltrated" for f in findings):
            return "sandbox"
    data = data if isinstance(data, dict) else {}
    inc = data.get("incident_history")
    if isinstance(inc, dict) and inc.get("current_version_affected") is True:
        return "known_malicious"
    sc = data.get("supply_chain")
    mal = sc.get("malicious") if isinstance(sc, dict) else None
    if isinstance(mal, list) and any(mal):
        return "malicious_dependency"
    return None


@functools.lru_cache(maxsize=1)
def _rule_reasons() -> tuple[str, str, str]:
    """The reasons ``decide()`` gives for its three no-judgment rules, taken from
    ``decide()`` itself so a wording change there cannot drift from here:
    (canary, this version malicious, malicious-dependency prefix)."""
    from src.scanner.verdict import decide

    canary = decide({"behavioral": {"ran": True, "canary_exfil": ["x"]}}).reason
    malware = decide({"incident_history": {"current_version_affected": True}}).reason
    marker = "MAL-0000-0"
    dep = decide({"supply_chain": {"malicious": [marker]}}).reason
    return canary, malware, dep[:dep.index(marker)] if marker in dep else dep


def rule_kind(reason: str | None) -> str | None:
    """The no-judgment rule a Do not connect reason names (``sandbox`` /
    ``known_malicious`` / ``malicious_dependency``), ignoring the "sandbox still
    running" / "waiting for a sandbox slot" suffix and which MAL id a dependency reason
    names. None for any other reason."""
    from src.scanner.verdict import PENDING_SUFFIX, QUEUED_SUFFIX

    r = str(reason or "")
    for suffix in (PENDING_SUFFIX, QUEUED_SUFFIX):
        if r.endswith(suffix):
            r = r[:-len(suffix)]
    canary, malware, dep_prefix = _rule_reasons()
    if r == canary:
        return "sandbox"
    if r == malware:
        return "known_malicious"
    if dep_prefix and r.startswith(dep_prefix):
        return "malicious_dependency"
    return None


AUTO_SKEW = timedelta(minutes=15)


async def auto_kind(row: Any) -> str | None:
    """Why this row's Do not connect answer needs no person's read, or None. Rests on the
    same result the row shows:

    * the row reads Do not connect and its reason names a no-judgment rule;
    * a cached scan is at hand and is not older than the row (``scanned_at`` versus
      ``last_scanned_at``), so a leftover cache from an earlier scan never decides;
    * ``decide()`` over that scan with the version-checked cached sandbox block (folded
      in as the result page folds it) reads Do not connect for the same rule, and the
      structured fields (``auto_reason``) agree;
    * for the sandbox rule, the block is stamped with the scan's own version (an
      unstamped block never earns the tag)."""
    if getattr(row, "decision", None) != DNC:
        return None
    kind = rule_kind(getattr(row, "decision_reason", None))
    if kind is None:
        return None
    data = await cached_scan(row)
    if data is None:
        return None
    seen = _aware(getattr(row, "last_scanned_at", None))
    try:
        scanned = _aware(datetime.fromisoformat(str(data.get("scanned_at")).replace(
            "Z", "+00:00"))) if data.get("scanned_at") else None
    except ValueError:
        scanned = None
    if seen is not None and (scanned is None or scanned < seen - AUTO_SKEW):
        return None
    block = await cached_behavioral(data, row)
    try:
        from src.api.public_scan_router import _apply_behavioral_score
        from src.scanner.verdict import decide

        applied = _apply_behavioral_score(data, block) if block else data
        d = decide({**applied, "behavioral": block})
    except Exception:
        logger.debug("auto decision failed", exc_info=True)
        return None
    if d.decision != DNC or rule_kind(d.reason) != kind or auto_reason(data, block) != kind:
        return None
    if kind == "sandbox":
        coords = _cache_coords(row)
        ver = _scan_version(data, coords[0] if coords else None)
        stamped = (block or {}).get("version")
        if not stamped or not ver or str(stamped) != ver:
            return None
    return kind


async def _gather_kinds(rows: list[Any]) -> list[str | None]:
    """``auto_kind`` for each row, a few at a time (Redis reads only, no DB)."""
    sem = asyncio.Semaphore(AUTO_CONCURRENCY)

    async def one(r: Any) -> str | None:
        async with sem:
            try:
                return await auto_kind(r)
            except Exception:
                return None

    return list(await asyncio.gather(*(one(r) for r in rows)))


async def build_dnc_week(db: AsyncSession, now: datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    since = now - timedelta(days=WINDOW_DAYS)
    reviews = (await db.execute(
        select(DncReview).where(DncReview.verdict == "confirmed",
                                DncReview.reviewed_at >= since)
        .order_by(DncReview.reviewed_at.desc())
    )).scalars().all()
    all_rows = await catalog_rows(db)
    by_key: dict[str, Any] = {}
    for r in all_rows:
        k = _row_key(r)
        if k and k not in by_key:
            by_key[k] = r
    items: list[dict[str, Any]] = []
    listed: set[str] = set()
    for rv in reviews:
        row = by_key.get(rv.page_key)
        if not _confirmed_now(rv, row):
            continue
        items.append({**_row_public(row), "decision": DNC,
                      "decision_reason": row.decision_reason,
                      "listed_because": "confirmed",
                      "confirmed_at": _aware(rv.reviewed_at).isoformat()})
        listed.add(rv.page_key)
        if len(items) >= CARD_LIMIT:
            break
    if len(items) < CARD_LIMIT:
        items.extend(await _auto_items(db, by_key, listed, since, CARD_LIMIT - len(items)))
    return {"window_days": WINDOW_DAYS, "items": items}


async def _auto_items(db: AsyncSession, by_key: dict[str, Any], listed: set[str],
                      since: datetime, room: int) -> list[dict[str, Any]]:
    """Up to ``room`` tools scanned since ``since`` whose Do not connect answer needs no
    person's read (``auto_kind``), newest scan first. A tool a person marked Not
    confirmed stays off for as long as that review stands, whatever its reason reads
    now (the owner can confirm it instead)."""
    recent = []
    for k, r in by_key.items():
        seen = _aware(getattr(r, "last_scanned_at", None))
        if (k in listed or getattr(r, "decision", None) != DNC or seen is None
                or seen < since or rule_kind(getattr(r, "decision_reason", None)) is None):
            continue
        recent.append((seen, k, r))
    recent.sort(key=lambda t: (-t[0].timestamp(), t[1]))
    recent = recent[:AUTO_LOOKUPS_MAX]
    if not recent:
        return []
    kept_off = set((await db.execute(
        select(DncReview.page_key).where(DncReview.page_key.in_({k for _, k, _ in recent}),
                                         DncReview.verdict == "not_confirmed")
    )).scalars().all())
    recent = [t for t in recent if t[1] not in kept_off]
    out: list[dict[str, Any]] = []
    for i in range(0, len(recent), AUTO_CONCURRENCY):
        chunk = recent[i:i + AUTO_CONCURRENCY]
        kinds = await _gather_kinds([r for _, _, r in chunk])
        for (seen, _k, r), why in zip(chunk, kinds):
            if why is None:
                continue
            out.append({**_row_public(r), "decision": DNC,
                        "decision_reason": r.decision_reason,
                        "listed_because": why, "confirmed_at": None,
                        "scanned_at": seen.isoformat()})
            if len(out) >= room:
                return out
    return out


async def build_most_checked(db: AsyncSession, counts: dict[str, int] | None = None
                             ) -> dict[str, Any]:
    from src import tool_checks

    if counts is None:
        counts = await tool_checks.week_counts() or {}
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
    """Up to 5 tools that read Do not connect now: first those a person confirmed in the
    last 7 days (newest first, still for the same reason), then tools scanned this week
    that are known malicious, ship a known-malicious dependency, or leaked a planted
    credential in the sandbox."""
    hit = await cache.get(DNC_CACHE_KEY)
    if isinstance(hit, dict):
        return hit
    proceed, token = await _take_rebuild_lock()
    if not proceed:
        # Another worker is rebuilding: serve the last card, or wait briefly for theirs.
        last = await cache.get(DNC_LAST_KEY)
        if isinstance(last, dict):
            return last
        for _ in range(12):
            await asyncio.sleep(0.25)
            hit = await cache.get(DNC_CACHE_KEY)
            if isinstance(hit, dict):
                return hit
    gen = await _card_generation()
    try:
        data = await build_dnc_week(db)
        # A review landed while this card was being built: it may list a tool the
        # review just took off, so it is served once but never stored.
        if gen == await _card_generation():
            await cache.set(DNC_CACHE_KEY, data, ttl=CACHE_TTL)
            await cache.set(DNC_LAST_KEY, data, ttl=LAST_GOOD_TTL)
    finally:
        if token:
            await _release_rebuild_lock(token)
    return data


# Bumped by every review write. Kept in Redis so a write on one worker stops a rebuild
# on another; the process counter covers a Redis that cannot be asked.
_CARD_GEN = 0


async def _card_generation() -> tuple[int, str | None]:
    try:
        from src.redis_client import get_redis

        raw = await get_redis().get(DNC_GEN_KEY)
        shared = raw.decode() if isinstance(raw, bytes) else (str(raw) if raw else "0")
    except Exception:
        shared = None
    return _CARD_GEN, shared


async def _bump_card_generation() -> None:
    global _CARD_GEN
    _CARD_GEN += 1
    try:
        from src.redis_client import get_redis

        await get_redis().incr(DNC_GEN_KEY)
    except Exception:
        logger.debug("card generation not bumped in redis", exc_info=False)


async def _take_rebuild_lock() -> tuple[bool, str | None]:
    """One worker rebuilds the card at a time (Redis SET NX, a few seconds). Returns
    (proceed, token): the token when this caller holds the lock; (True, None) when
    Redis cannot be asked (then everyone builds); (False, None) when another holds it."""
    try:
        from src.redis_client import get_redis

        token = secrets.token_hex(16)
        got = await get_redis().set(DNC_LOCK_KEY, token, nx=True, ex=REBUILD_LOCK_TTL)
        return (True, token) if got else (False, None)
    except Exception:
        return True, None


_RELEASE_IF_MINE = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end")


async def _release_rebuild_lock(token: str) -> None:
    """Free the lock only if it is still this caller's (it may have expired and been
    taken by another worker meanwhile)."""
    try:
        from src.redis_client import get_redis

        await get_redis().eval(_RELEASE_IF_MINE, 1, DNC_LOCK_KEY, token)
    except Exception:
        logger.debug("card rebuild lock not released", exc_info=False)


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


async def top_critical(row: Any, data: dict | None = None) -> dict[str, Any] | None:
    """The first critical finding of the row's cached scan (the list leads with the
    findings that decided the answer), or None when no cached scan is at hand."""
    try:
        if data is None:
            data = await cached_scan(row)
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


def _candidate(k: str, r: Any, rv: DncReview | None, *, growth: bool, checks: int,
               top: dict[str, Any] | None) -> dict[str, Any]:
    return {
        **_row_public(r),
        "page_key": k,
        "trust_score": r.trust_score,
        "decision": r.decision,
        "decision_reason": r.decision_reason,
        "last_scanned_at": _aware(r.last_scanned_at).isoformat()
        if r.last_scanned_at else None,
        "from_catalog_growth": growth,
        "top_critical": top,
        "checks_week": checks,
        "status": _status(rv, r),
        "reviewed_at": _aware(rv.reviewed_at).isoformat() if rv else None,
        "note": rv.note if rv else None,
    }


async def build_shortlist(db: AsyncSession, counts: dict[str, int] | None = None,
                          rows: list[Any] | None = None) -> list[dict]:
    """This week's shortlist for a person's read: at most SHORTLIST_LIMIT tools that read
    Do not connect now and that people or agents checked this week, most checks first.
    A tool a person already read (confirmed / not confirmed) is skipped unless its
    reason changed since, and so is one with no review that goes on the public card by
    itself (``auto_kind``: known malicious, a malicious dependency, or a planted
    credential seen leaving the sandbox), since it needs no read."""
    from src import tool_checks

    if counts is None:
        counts = await tool_checks.week_counts() or {}
    if rows is None:
        rows = await catalog_rows(db)
    dnc: dict[str, Any] = {}
    for r in rows:
        if getattr(r, "decision", None) != DNC:
            continue
        k = _row_key(r)
        if k and k not in dnc and counts.get(k, 0) > 0:
            dnc[k] = r
    if not dnc:
        return []
    reviews = {rv.page_key: rv for rv in (await db.execute(
        select(DncReview).where(DncReview.page_key.in_(set(dnc)))
    )).scalars().all()}
    ranked = sorted(dnc, key=lambda k: (-counts[k], k))
    out: list[dict] = []
    for k in ranked:
        r, rv = dnc[k], reviews.get(k)
        if _status(rv, r) in ("confirmed", "not_confirmed"):
            continue
        # The card lists it by itself (no read needed), unless a person already read it:
        # a Not-confirmed tool whose reason changed comes back here, never to the card.
        if rv is None and await auto_kind(r):
            continue
        out.append(_candidate(k, r, rv, growth=False, checks=counts[k],
                              top=await top_critical(r)))
        if len(out) >= SHORTLIST_LIMIT:
            break
    return out


async def build_candidates(db: AsyncSession, now: datetime | None = None,
                           rows: list[Any] | None = None,
                           counts: dict[str, int] | None = None) -> list[dict]:
    now = now or _now()
    since = now - timedelta(days=WINDOW_DAYS)
    growth = growth_review_keys(since)
    counts = counts or {}
    picked: dict[str, Any] = {}
    for r in (rows if rows is not None else await catalog_rows(db)):
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
    ordered = sorted(
        picked.items(),
        key=lambda kv: (rank[_status(reviews.get(kv[0]), kv[1])],
                        -(_aware(kv[1].last_scanned_at) or since).timestamp()))[:CANDIDATES_MAX]
    return [_candidate(k, r, reviews.get(k), growth=k in growth, checks=counts.get(k, 0),
                       top=await top_critical(r))
            for k, r in ordered]


@admin_router.get("")
async def list_candidates(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """This week's shortlist (at most 3 Do not connect tools people checked, waiting for
    a person's read) and, for reference, every Do not connect answer from the last 7
    days. Full admin only."""
    require_admin(current_entity)
    from src import tool_checks

    rows = await catalog_rows(db)
    counts = await tool_checks.week_counts()
    # None = the check counts could not be read: the panel says so instead of "nothing
    # needs a look", and the shortlist stays empty.
    unavailable = counts is None
    counts = counts or {}
    return {"window_days": WINDOW_DAYS, "shortlist_limit": SHORTLIST_LIMIT,
            "counts_unavailable": unavailable,
            "shortlist": [] if unavailable else await build_shortlist(
                db, counts=counts, rows=rows),
            "items": await build_candidates(db, rows=rows, counts=counts)}


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
    await _bump_card_generation()
    await cache.invalidate(DNC_CACHE_KEY)
    await cache.invalidate(DNC_LAST_KEY)
    await cache.invalidate(CHECKED_CACHE_KEY)
    return {"page_key": key, "verdict": review.verdict,
            "reviewed_at": _aware(review.reviewed_at).isoformat()}
