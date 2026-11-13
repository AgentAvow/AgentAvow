"""CLI: ``python -m src.catalog_growth {discover|refresh|status}``.

Run as a one-off container of the backend image, never in a web worker (see
scripts/catalog_growth.sh for the cron wrapper and the exact docker command). The
switches CATALOG_DISCOVERY / CATALOG_REFRESH (off | dry-run | on, default off) decide
what a run does; there is no flag to override them from the command line.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from src.catalog_growth import state as st

logger = logging.getLogger("catalog_growth")


def peak_rss_mb() -> float:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024, 1)


def make_rss_check(max_mb: float | None):
    def check(phase: str) -> None:
        peak = peak_rss_mb()
        logger.info("[catalog_growth mem] %s: peak RSS %s MB", phase, peak)
        if max_mb is not None and peak > max_mb:
            raise SystemExit(f"peak RSS {peak} MB over --max-rss-mb {max_mb} after {phase}")
    return check


def _sum_totals(*reports: dict) -> dict[str, int]:
    tot: dict[str, int] = {}
    for rep in reports:
        for counts in (rep.get("by_source") or {}).values():
            for k, v in counts.items():
                tot[k] = tot.get(k, 0) + v
    return tot


def _merge_by_source(*reports: dict) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for rep in reports:
        for src, counts in (rep.get("by_source") or {}).items():
            b = out.setdefault(src, {})
            for k, v in counts.items():
                b[k] = b.get(k, 0) + v
    return out


async def run_job(
    job: str, *, settings: Any = None, client: Any = None, session_factory: Any = None,
    github_token: Any = "auto", max_scans: int | None = None,
    max_rss_mb: float | None = None, now: datetime | None = None,
    execute_kwargs: dict | None = None, fetcher_kwargs: dict | None = None,
    record: Any = None,
) -> dict:
    """One run of ``job``. Returns the run record (also written to runs.jsonl and Redis).
    Everything external is injectable for tests."""
    from src.catalog_growth import discover, execute, refresh
    from src.catalog_growth.http import Fetcher
    from src.catalog_growth.index import build_index

    if settings is None:
        from src.config import settings as _s
        settings = _s
    mode = st.mode_for(job, settings)
    if mode == "off":
        flag = "CATALOG_DISCOVERY" if job == "discover" else "CATALOG_REFRESH"
        logger.info("%s is off: nothing to do", flag)
        return {"job": job, "mode": "off"}
    now = now or datetime.now(timezone.utc)
    started = time.monotonic()
    rss_check = make_rss_check(max_rss_mb)
    store = st.Store(st.data_dir(settings))
    with st.run_lock(store.dir) as lock:
        if not lock.acquired:
            logger.warning("another catalog_growth run holds %s; exiting", lock.path)
            return {"job": job, "mode": mode, "stopped": "another run in progress"}
        state = store.load_state()
        if session_factory is None:
            from src.database import async_session as session_factory
        own_client = client is None
        if own_client:
            import httpx
            client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        if github_token == "auto":
            try:
                from src.github_auth import get_github_token
                github_token = await get_github_token()
            except Exception:
                github_token = None
        try:
            f = Fetcher(client, **(fetcher_kwargs or {}))
            async with session_factory() as db:
                index = await build_index(db)
            rss_check("catalog index built")
            retry_after = (now - timedelta(
                days=int(getattr(settings, "catalog_growth_retry_failed_days", 30))
            )).isoformat(timespec="seconds")
            extra: dict = {}
            if job == "discover":
                items, plan_rep, smithery_resolved = await discover.plan_discovery(
                    f, index, state, github_token=github_token,
                    smithery_detail_max=int(getattr(
                        settings, "catalog_growth_smithery_detail_max", 300)),
                    retry_after_iso=retry_after)
                updates: dict = {}
            else:
                items, plan_rep, updates = await refresh.plan_refresh(
                    f, index, state,
                    top_n=int(getattr(settings, "catalog_growth_top_n", 2000)), now=now,
                    github_token=github_token,
                    github_calls=int(getattr(settings, "catalog_growth_github_calls_per_run",
                                             2500)),
                    github_min_budget=int(getattr(
                        settings, "catalog_growth_github_min_budget", 1500)),
                    retry_after_iso=(now - timedelta(days=7)).isoformat(timespec="seconds"))
                smithery_resolved = {}
            del index
            rss_check("planned")
            plan = {"at": now.isoformat(timespec="seconds"), "job": job, "mode": mode,
                    "counts": _merge_by_source(plan_rep), "totals": _sum_totals(plan_rep),
                    "notes": plan_rep.get("notes"), "stopped": plan_rep.get("stopped"),
                    "requests": dict(f.calls), "items": items}
            plan_path = store.write_plan(job, mode, plan)
            exec_rep: dict = {}
            if mode == "on":
                state["baselines"].update(updates)
                state["smithery_seen"].update(smithery_resolved)
                state["last_run"][f"{job}_on"] = now.isoformat(timespec="seconds")
                pending = st.merge_pending(store.load_pending(), items)
                store.save_state(state)
                store.save_pending(pending)
                limit = max_scans if max_scans is not None else int(getattr(
                    settings, "catalog_growth_max_scans_per_run", 150))
                left, exec_rep = await execute.execute(
                    store, state, pending, session_factory=session_factory,
                    max_scans=limit,
                    spacing=float(getattr(settings, "catalog_growth_scan_spacing_seconds", 3.0)),
                    github_min_budget=int(getattr(
                        settings, "catalog_growth_github_min_budget", 1500)),
                    rss_check=rss_check, **(execute_kwargs or {}))
                extra["pending_left"] = len(left)
        finally:
            if own_client:
                await client.aclose()
        totals = _sum_totals(plan_rep, exec_rep)
        run = {
            "at": now.isoformat(timespec="seconds"), "job": job, "mode": mode,
            "totals": totals, "by_source": _merge_by_source(plan_rep, exec_rep),
            "requests": dict(f.calls),
            "duration_s": int(time.monotonic() - started),
            "stopped": exec_rep.get("stopped") or plan_rep.get("stopped"),
            "plan_file": str(plan_path), **extra,
        }
        store.add_run(run)
        await (record or st.record_run)(run)
        return run


async def status(settings: Any = None) -> dict:
    store = st.Store(st.data_dir(settings))
    pending = store.load_pending()
    reasons: dict[str, int] = {}
    for i in pending:
        reasons[i.get("reason", "?")] = reasons.get(i.get("reason", "?"), 0) + 1
    return {"discover": st.mode_for("discover", settings),
            "refresh": st.mode_for("refresh", settings),
            "data_dir": str(store.dir), "pending": len(pending), "pending_by_reason": reasons,
            "last_runs": await st.recent_runs(5)}


def _print_run(run: dict) -> None:
    import json
    print(json.dumps({k: v for k, v in run.items() if k != "items"}, indent=1,
                     sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m src.catalog_growth", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("job", choices=("discover", "refresh", "status"))
    p.add_argument("--max-scans", type=int, default=None,
                   help="scans this run may start (on mode); default from settings")
    p.add_argument("--max-rss-mb", type=float, default=None,
                   help="stop cleanly when peak RSS passes this (set under the container "
                        "--memory limit)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    if args.job == "status":
        _print_run(asyncio.run(status()))
        return 0
    run = asyncio.run(run_job(args.job, max_scans=args.max_scans, max_rss_mb=args.max_rss_mb))
    _print_run(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
