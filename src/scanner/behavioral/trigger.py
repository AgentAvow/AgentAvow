"""Event-driven sandbox runs: re-run a tool when it CHANGES, not on a calendar.

The public scan path (``public_scan_router._behavioral_block``) runs the sandbox the
first time a viewer asks for a coordinate and caches the block for 24 h. That is a
viewer-driven schedule: a package that ships a new version five minutes after a run
keeps serving the old observation until the cache expires AND someone looks again.

This module adds two other ways a run can start, both reusing the router's own
target / plan / lock / slot helpers so there is exactly one definition of "what the
sandbox runs for this scan":

* ``on_scan_change`` — called by the catalog and watch re-scan loops after a fresh
  static scan. When the coordinate's published VERSION or tool digest moved vs the
  previous cached scan, the cached sandbox block(s) for it are dropped and a run is
  enqueued (reason ``version_change``). A watched coordinate whose block is simply
  missing is enqueued too (reason ``watch``) so watchers always have a fresh-enough
  observation to diff. Nothing changed → nothing happens; the 24 h cache expires on
  its own and the next viewer re-triggers.

* ``enqueue_behavioral`` — the one entry point for starting a background run. A
  ``normal`` run (watch triggers) takes a slot exactly like the viewer path; a ``low``
  run (catalog re-score, the backfill in ``src/jobs/behavioral_backfill.py``) only
  takes slots 1.. while slot 0 is free (``slots.py``). With no slot the coordinate
  joins the sandbox queue (``queued``); the backfill opts out (``deferred``) because
  it is itself a queue.

Every function here is fail-open: a Redis blip or a malformed scan dict means "no
run this time", never an exception into the scheduler loops.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Surfaces the sandbox can install something for. ``github`` only when the cached scan
# maps the repo to a package or it is a JS/TS / Python project — decided by
# ``_behavioral_target`` on the shaped scan data, not by the surface alone.
SANDBOX_SURFACES = ("npm", "pypi", "docker", "openclaw", "github")

ENQUEUE_OUTCOMES = ("started", "cached", "locked", "queued", "deferred", "ineligible")


# ── scan-cache coordinates ──────────────────────────────────────────────────
def scan_cache_coords(surface: str, owner: str, repo: str) -> tuple[str, str]:
    """(cache_owner, cache_repo) under which ``public_scan_router`` caches the static
    scan for a catalog / watch coordinate — the same keys the public endpoints use."""
    s = (surface or "github").lower()
    if s in ("npm", "pypi", "docker", "crates", "huggingface"):
        return s, repo
    if s == "openclaw":
        return "skill", f"{owner}/{repo}"
    if s == "mcp":
        return "mcp", repo
    return owner, repo


_PACKAGE_CACHE_OWNERS = ("npm", "pypi", "docker", "crates", "huggingface")


def coords_from_cache_key(key: str) -> tuple[str, str, str] | None:
    """Inverse of ``scan_cache_coords``: the (surface, owner, repo) catalog coordinate a
    public scan cache key (``owner/repo`` part, prefix stripped) belongs to. A package
    key such as ``npm/react-dom`` is the npm package, never a GitHub repo named
    ``npm/react-dom``. None for a key that maps to no single coordinate."""
    head, sep, rest = (key or "").partition("/")
    if not sep or not head or not rest:
        return None
    if head in _PACKAGE_CACHE_OWNERS:
        return head, head, rest
    if head == "mcp":
        return "mcp", "mcp", rest
    if head == "skill":
        owner, sep2, repo = rest.partition("/")
        if not sep2 or not owner or not repo or "/" in repo:
            return None  # a per-skill sub-path is not a catalog row
        return "openclaw", owner, repo
    if "/" in rest:
        return None
    return "github", head, rest


async def cached_scan_data(
    surface: str, owner: str, repo: str, *, stale: bool = True,
) -> dict | None:
    """The cached static scan for a coordinate (fresh 1 h copy, then the 7 d stale copy
    when ``stale``). None when nothing is cached — callers never scan from here."""
    try:
        from src.api.public_scan_router import _get_cached, _get_stale_cached
        o, r = scan_cache_coords(surface, owner, repo)
        data = await _get_cached(o, r)
        if data is None and stale:
            data = await _get_stale_cached(o, r)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


async def set_scan_cache(surface: str, owner: str, repo: str, data: dict) -> None:
    """Write a fresh static scan under the public endpoint's key (fresh + stale copies)
    so the next re-scan has a baseline to diff and the backfill has data to shape."""
    try:
        from src.api.public_scan_router import _set_cached
        o, r = scan_cache_coords(surface, owner, repo)
        await _set_cached(o, r, data)
    except Exception:
        logger.debug("scan cache write failed for %s %s/%s", surface, owner, repo, exc_info=True)


def behavioral_scan_data(surface: str, owner: str, repo: str, data: dict | None) -> dict:
    """Shape a cached scan dict for a catalog / watch coordinate into what the router's
    ``_behavioral_target`` / ``_behavioral_plan`` key on — the same additions the public
    endpoints make before calling ``_behavioral_block`` (``package_coordinate`` for a
    package surface, ``surface_kind: skill`` + ``repo_full_name`` for a skill,
    ``repo_full_name`` for a repo). ``primary_language`` is lifted out of ``metadata``
    for repos so a JS/TS / Python repo without a published package gets the git plan."""
    s = (surface or "github").lower()
    out = dict(data or {})
    if s in ("npm", "pypi", "docker"):
        out["package_coordinate"] = {"surface": s, "name": repo}
    elif s == "openclaw":
        out["surface_kind"] = "skill"
        out["repo_full_name"] = f"{owner}/{repo}"
    elif s == "github":
        out["repo_full_name"] = f"{owner}/{repo}"
        if not out.get("primary_language"):
            meta = out.get("metadata") if isinstance(out.get("metadata"), dict) else {}
            lang = (meta or {}).get("primary_language")
            if lang:
                out["primary_language"] = lang
    return out


# ── change detection ────────────────────────────────────────────────────────
def change_signature(data: dict | None) -> dict[str, str | None]:
    """The three things that mean "the artifact the sandbox would run is different":
    the published version, the signed tool-manifest digest, the artifact digest."""
    d = data if isinstance(data, dict) else {}
    art = d.get("artifact_scan") or d.get("surface_detail") or {}
    if not isinstance(art, dict):
        art = {}
    cov = d.get("coverage") if isinstance(d.get("coverage"), dict) else {}

    def _s(v: object) -> str | None:
        return str(v) if v not in (None, "") else None

    return {
        "version": _s(d.get("package_version")) or _s(art.get("version")),
        "manifest_digest": _s(d.get("tool_manifest_digest")),
        "artifact_digest": _s(art.get("digest")) or _s((cov or {}).get("artifact_digest")),
    }


def scan_changed(prev: dict | None, new: dict | None) -> list[str]:
    """Names of the signature fields that moved between two scans. A field missing on
    either side is NOT a change (a scan that observed no manifest must not look like a
    rewrite — same rule as ``scheduler._watch_digest_state``). Empty = nothing changed
    or nothing to compare against."""
    if not prev or not new:
        return []
    a, b = change_signature(prev), change_signature(new)
    return [k for k in a if a[k] and b[k] and a[k] != b[k]]


# ── cache invalidation ──────────────────────────────────────────────────────
def _glob_escape(s: str) -> str:
    return "".join(f"\\{c}" if c in "*?[]\\" else c for c in s)


async def invalidate_behavioral_cache(surface: str, name: str) -> int:
    """Delete every cached sandbox block for a coordinate — every declared-egress and
    plan variant — leaving in-flight ``:lock`` keys alone. Returns the count deleted."""
    try:
        from src.api.public_scan_router import _behavioral_cache_key
        from src.redis_client import get_redis
        base = _behavioral_cache_key(surface, name, None)
        r = get_redis()
        deleted = 0
        cursor = 0
        while True:
            cursor, keys = await r.scan(cursor, match=f"{_glob_escape(base)}*", count=200)
            for k in keys or []:
                ks = k.decode() if isinstance(k, bytes) else str(k)
                if ks != base and not ks.startswith(base + ":"):
                    continue  # a longer name sharing the prefix (foo vs foo-bar)
                if ks.endswith(":lock"):
                    continue
                deleted += int(await r.delete(ks) or 0)
            if not cursor or str(cursor) == "0":
                break
        return deleted
    except Exception:
        logger.debug("behavioral cache invalidation failed for %s:%s", surface, name,
                     exc_info=True)
        return 0


# ── enqueue ─────────────────────────────────────────────────────────────────
async def _acquire_low_priority_slot():
    """A slot for a low-priority run, or None: only slots 1.. and only while slot 0 is
    free, so one slot always stays open for real scans (``slots.acquire_slot``).
    Fails CLOSED — a low-priority run never guesses at capacity."""
    from src.scanner.behavioral.slots import acquire_slot
    return await acquire_slot("low")


async def _bump(name: str) -> None:
    from src.api.public_scan_router import _bump_behavioral
    await _bump_behavioral(name)


async def enqueue_behavioral(data: dict, *, reason: str, priority: str = "normal",
                             queue: bool = True) -> str:
    """Start a background sandbox run for a scan's coordinate, resolved exactly like
    ``_behavioral_block`` (same target, plan, declared egress, cache key, lock, slot).

    Returns one of ``started`` (a run is now in flight), ``cached`` (a block already
    exists — nothing to do), ``locked`` (a run for this coordinate is already in
    flight), ``queued`` (no slot; the coordinate waits in the sandbox queue and starts
    when one frees), ``deferred`` (no slot and ``queue=False``: the backfill retries on
    its next pass), ``ineligible`` (tier off / nothing to install). A ``normal`` run
    takes any free slot; a ``low`` run only slots 1.. while slot 0 is free.

    Counts ``ag:metrics:behavioral:trigger:<reason>`` (calls) and
    ``trigger:<reason>:<outcome>`` per UTC day.
    """
    from src.api import public_scan_router as psr
    from src.config import settings
    from src.scanner.behavioral import slots

    if priority not in ("normal", "low"):
        raise ValueError(f"priority must be 'normal' or 'low', got {priority!r}")
    await _bump(f"trigger:{reason}")

    async def _done(outcome: str) -> str:
        await _bump(f"trigger:{reason}:{outcome}")
        return outcome

    if not getattr(settings, "scanner_behavioral_enabled", False):
        return await _done("ineligible")
    target = psr._behavioral_target(data)
    if not target:
        return await _done("ineligible")
    surface, name = target
    name = str(name)
    declared = psr._declared_egress(data)
    plan = psr._behavioral_plan(data, surface)
    run_kwargs = {"plan": plan, "env_names": psr._behavioral_env_names(data),
                  "readme_text": psr._behavioral_readme(data)}
    payload = psr._queue_payload(surface, name, declared, run_kwargs)
    outcome = await psr._start_behavioral_payload(payload, priority)
    if outcome == "started":
        logger.info("behavioral run enqueued (%s, %s priority): %s:%s plan=%s",
                    reason, priority, surface, name, plan)
        return await _done("started")
    if outcome in ("cached", "locked"):
        return await _done(outcome)
    # no slot
    if priority == "normal":
        await psr._bump_behavioral("slot_rejected")
    if not queue or (priority == "low" and slots.max_slots() < 2):
        return await _done("deferred")  # (a low run can never get a slot when max is 1)
    pos = await slots.enqueue(psr._behavioral_cache_key(surface, name, declared, plan),
                              payload, priority)
    return await _done("queued" if pos is not None else "deferred")


# ── on-change hooks (called by the re-scan loops) ───────────────────────────
async def on_scan_change(
    surface: str, owner: str, repo: str, prev: dict | None, data: dict | None,
    *, watched: bool = False,
) -> str | None:
    """After a fresh static scan of a catalog / watch coordinate: if its version or
    tool digest moved vs ``prev`` (the previous cached scan), drop the cached sandbox
    block(s) and enqueue a run (``version_change``). A ``watched`` coordinate with no
    cached block is enqueued too (``watch``). Returns the enqueue outcome, or None
    when nothing was done. Never raises."""
    try:
        from src.api import public_scan_router as psr
        from src.config import settings
        if not getattr(settings, "scanner_behavioral_enabled", False) or not data:
            return None
        shaped = behavioral_scan_data(surface, owner, repo, data)
        target = psr._behavioral_target(shaped)
        if not target:
            return None
        s, n = target
        changed = scan_changed(prev, data)
        if changed:
            dropped = await invalidate_behavioral_cache(s, str(n))
            logger.info("%s:%s changed (%s) — dropped %d cached sandbox block(s)",
                        s, n, ", ".join(changed), dropped)
            # A catalog re-score is background work (LOW); a watched tool's change
            # is what a watcher is waiting for (NORMAL).
            return await enqueue_behavioral(
                shaped, reason="version_change", priority="normal" if watched else "low")
        if watched:
            block = await psr._get_cached_behavioral(
                s, str(n), psr._declared_egress(shaped), psr._behavioral_plan(shaped, s))
            if not block:
                return await enqueue_behavioral(shaped, reason="watch")
        return None
    except Exception:
        logger.debug("on_scan_change failed for %s %s/%s", surface, owner, repo, exc_info=True)
        return None


async def on_watch_rescan(
    surface: str, owner: str, repo: str, prev: dict | None, ws_data: dict | None,
    *, new_digest: str | None = None, last_manifest_digest: str | None = None,
) -> str | None:
    """The watch loop's flavour of ``on_scan_change``: the fresh scan is the public
    cache entry when the scan path wrote one (github / skill), else the WatchScan data
    (packages — carries the artifact version); the watch's stored manifest digest
    stands in for a missing previous scan. Always ``watched``."""
    try:
        fresh = await cached_scan_data(surface, owner, repo, stale=False) or dict(ws_data or {})
        if new_digest and not fresh.get("tool_manifest_digest"):
            fresh["tool_manifest_digest"] = new_digest
        if prev is None and last_manifest_digest:
            prev = {"tool_manifest_digest": last_manifest_digest}
        return await on_scan_change(surface, owner, repo, prev, fresh, watched=True)
    except Exception:
        return None
