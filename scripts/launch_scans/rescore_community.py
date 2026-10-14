"""Re-score every CommunityScan row (live-accrued user scans across ALL surfaces —
github/npm/pypi/crates/docker/huggingface/openclaw/mcp) with the CURRENT scorer, so
they pick up the 2026-08-19 critical-consistency fix like the seed corpus does.

The seed grind (rescore_corpus.py) only touches the seed *-results.json files; this
covers the ~hundreds of rows that live only in the community_scans table. Each row goes
through ``_rescan_catalog_row`` (src/jobs/scheduler.py), the same service path the
catalog re-scan loop uses: scanner -> ``_capture_community_scan`` upsert (score, counts,
decision) -> adoption -> scan cache. It does NOT call the FastAPI route functions: called
directly, a parameter left out arrives as its ``Query(...)`` default object, which is
truthy (a bogus ``version`` skipped the catalog write; ``behavioral`` / ``probe`` forced
sandbox runs). Run on the host.

    ./.venv/bin/python3 scripts/launch_scans/rescore_community.py
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select


async def _rescore_one(r) -> bool:
    """Re-scan one community row and upsert it. True on success."""
    from src.database import async_session
    from src.jobs.scheduler import _rescan_catalog_row

    surface = (r.surface or "github").lower()
    async with async_session() as db:
        return await _rescan_catalog_row(surface, r.owner, r.repo, db)


async def main() -> None:
    from src.database import async_session
    from src.models import CommunityScan

    async with async_session() as s:
        rows = (await s.execute(select(CommunityScan))).scalars().all()
    total = len(rows)
    print(f"[rescore_community] {total} rows to re-score", flush=True)
    ok = err = 0
    for i, r in enumerate(rows, 1):
        try:
            done = await _rescore_one(r)
        except Exception as e:  # noqa: BLE001 — fail-open per row
            done = False
            print(f"  {i}/{total} ERR {r.surface} {r.owner}/{r.repo}: {type(e).__name__}",
                  flush=True)
        if done:
            ok += 1
        else:
            err += 1
            print(f"  {i}/{total} not re-scored: {r.surface} {r.owner}/{r.repo}", flush=True)
        if i % 25 == 0:
            print(f"  {i}/{total} (ok={ok} err={err})", flush=True)
    print(f"[rescore_community] done: ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
