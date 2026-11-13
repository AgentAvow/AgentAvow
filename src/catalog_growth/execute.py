"""Scan the work queue, one tool at a time, at low priority. ``on`` mode only.

Each item is scanned by ``scheduler._rescan_catalog_row`` (the catalog re-scan loop's
own path: the live scan, the community_scans upsert Browse reads, adoption, and the
on-change sandbox trigger, which enqueues at LOW priority, so the two sandbox slots go
to real users first). Items stop at ``max_scans``; the rest wait in pending.json for
the next run. GitHub-backed items wait while the GitHub budget is low.

A live MCP endpoint is checked by the SSRF guard (src/ssrf.py: https only, no internal
or rebinding addresses, no credential-looking paths) before anything is fetched; an
endpoint that fails it is dropped and never scanned.

A Do-not-connect answer is written to dnc-review.jsonl, marked not indexable and
pending review. Nothing here writes a sitemap, pings IndexNow or marks a page for
search: owner decision 2026-11-11 (B11), third-party Do-not-connect pages are
human-reviewed before any indexing.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from src.catalog_growth.state import Store, now_iso

logger = logging.getLogger(__name__)

ScanFn = Callable[[str, str, str, Any], Awaitable[bool]]


def ssrf_check_endpoint(url: str) -> str | None:
    """The endpoint identity when ``url`` passes the SSRF guard (DNS-resolving check),
    else None. Must equal its own identity: a URL carrying credentials is refused."""
    from src.ssrf import mcp_endpoint_identity, validate_url_https

    try:
        ident = mcp_endpoint_identity(validate_url_https(url, field_name="endpoint"))
    except Exception:
        return None
    return ident if ident == url else None


async def _default_scan(surface: str, owner: str, repo: str, db: Any) -> bool:
    from src.jobs.scheduler import _rescan_catalog_row
    return await _rescan_catalog_row(surface, owner, repo, db)


async def _default_gh_ok(min_budget: int) -> bool:
    try:
        from src.jobs.scan_health import check_and_alert_token
        h = await check_and_alert_token()
        return not h.dead and (h.remaining is None or h.remaining >= min_budget)
    except Exception:
        return True


async def _stored_decision(db: Any, surface: str, owner: str, repo: str) -> str | None:
    from sqlalchemy import func, select

    from src.models import CommunityScan

    q = select(CommunityScan.decision, CommunityScan.trust_score).where(
        CommunityScan.surface == surface)
    if surface in ("github", "openclaw"):
        q = q.where(func.lower(CommunityScan.owner) == owner.lower(),
                    func.lower(CommunityScan.repo) == repo.lower())
    else:
        q = q.where(CommunityScan.owner == owner, CommunityScan.repo == repo)
    row = (await db.execute(q.limit(1))).first()
    if row is None:
        return None
    decision, score = row
    if decision:
        return decision
    if score is not None:
        from src.scanner.verdict import decide
        return decide({"trust_score": score, "findings": {}}).decision
    return None


def write_mcp_endpoint(name: str, endpoint: str) -> bool:
    """Add a skipped launch row's scanned endpoint to the catalog overlay
    (data/launch-scans/mcp-endpoints.json). False when the directory is read-only."""
    from src.api import scan_catalog_router as scr
    from src.catalog_growth.state import read_json, write_json_atomic

    path = scr._DATA_DIR / scr._MCP_ENDPOINTS_FILE
    doc = read_json(path, {})
    eps = doc.get("endpoints") if isinstance(doc, dict) else None
    eps = dict(eps) if isinstance(eps, dict) else {}
    if eps.get(name) == endpoint:
        return True
    eps[name] = endpoint
    try:
        write_json_atomic(path, {"endpoints": eps, "updated_at": now_iso()})
        return True
    except OSError:
        logger.warning("catalog_growth: %s is not writable; overlay not updated", path)
        return False


async def execute(
    store: Store, state: dict, pending: list[dict], *, session_factory: Callable[[], Any],
    max_scans: int, spacing: float, github_min_budget: int,
    scan_fn: ScanFn = _default_scan,
    gh_ok_fn: Callable[[int], Awaitable[bool]] = _default_gh_ok,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    rss_check: Callable[[str], None] | None = None,
    save_every: int = 10,
) -> tuple[list[dict], dict]:
    """Scan up to ``max_scans`` items from ``pending`` (in order). Returns (the queue
    left, report). Mutates ``state`` (baselines, failed) and saves state + queue every
    ``save_every`` items and at the end, so a killed run resumes."""
    import asyncio

    sleep = sleep or asyncio.sleep
    report: dict = {"by_source": {}}

    def count(src: str, field: str) -> None:
        b = report["by_source"].setdefault(src, {})
        b[field] = b.get(field, 0) + 1

    gh_ok = await gh_ok_fn(github_min_budget)
    left: list[dict] = []
    done = 0
    attempted = 0
    for i, item in enumerate(pending):
        if attempted >= max_scans:
            left.extend(pending[i:])
            break
        surface, owner, repo = item["surface"], item["owner"], item["repo"]
        src = item.get("source") or surface
        if surface in ("github", "openclaw"):
            if attempted and attempted % 25 == 0:
                gh_ok = await gh_ok_fn(github_min_budget)
            if not gh_ok:
                count(src, "deferred")
                left.append(item)
                continue
        if surface == "mcp" and ssrf_check_endpoint(repo) is None:
            count(src, "failed")
            state["failed"][item["key"]] = now_iso()
            continue
        attempted += 1
        async with session_factory() as db:
            ok = False
            try:
                ok = await scan_fn(surface, owner, repo, db)
            except Exception:
                logger.debug("catalog_growth scan failed for %s", item["key"], exc_info=True)
            if ok:
                count(src, "scanned")
                if item.get("reason") == "changed" or item.get("version"):
                    state["baselines"][item["key"]] = {
                        "v": item.get("version"),
                        **({"etag": item["etag"]} if item.get("etag") else {}),
                        "checked_at": now_iso()}
                state["failed"].pop(item["key"], None)
                decision = None
                try:
                    decision = await _stored_decision(db, surface, owner, repo)
                except Exception:
                    logger.debug("decision read failed for %s", item["key"], exc_info=True)
                if decision == "do_not_connect":
                    count(src, "dnc_held")
                    store.add_dnc_review({
                        "at": now_iso(), "key": item["key"], "surface": surface,
                        "owner": owner, "repo": repo, "reason": item.get("reason"),
                        "source": src, "decision": decision,
                        "indexable": False, "review": "pending"})
                if item.get("reason") == "skipped_url" and item.get("registry_name"):
                    write_mcp_endpoint(item["registry_name"], repo)
            else:
                count(src, "failed")
                state["failed"][item["key"]] = now_iso()
        done += 1
        if done % save_every == 0:
            store.save_state(state)
            store.save_pending(left + pending[i + 1:])
        if rss_check is not None:
            try:
                rss_check(f"scanned {done}")
            except SystemExit as e:
                left.extend(pending[i + 1:])
                report["stopped"] = str(e)
                break
        await sleep(spacing)
    store.save_state(state)
    store.save_pending(left)
    return left, report
