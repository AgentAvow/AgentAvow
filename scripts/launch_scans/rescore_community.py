"""Re-score every CommunityScan row (live-accrued user scans across ALL surfaces —
github/npm/pypi/crates/docker/huggingface/openclaw/mcp) with the CURRENT scorer, so
they pick up the 2026-08-19 critical-consistency fix like the seed corpus does.

The seed grind (rescore_corpus.py) only touches the seed *-results.json files; this
covers the ~hundreds of rows that live only in the community_scans table. Calls the
scan endpoints directly with request=None (reuses the full pipeline + the
_capture_community_scan upsert, and skips the per-IP rate limits). Run on the host.

    ./.venv/bin/python3 scripts/launch_scans/rescore_community.py
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select

_PKG = {"npm", "pypi", "crates", "docker", "huggingface"}


async def _rescore_one(r) -> None:
    from src.api.public_scan_router import (
        public_scan,
        scan_mcp_endpoint,
        scan_package_endpoint,
        scan_skill_endpoint,
    )
    from src.database import async_session

    surface = (r.surface or "github").lower()
    async with async_session() as db:
        if surface in _PKG:
            await scan_package_endpoint(
                surface=surface, name=r.repo, request=None, force=True, db=db)
        elif surface == "openclaw":
            await scan_skill_endpoint(
                owner=r.owner, repo=r.repo, request=None, force=True, db=db)
        elif surface == "mcp":
            await scan_mcp_endpoint(endpoint=r.repo, request=None, force=True, db=db)
        else:  # github / anything else
            await public_scan(
                owner=r.owner, repo=r.repo, request=None, force=True, db=db)


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
            await _rescore_one(r)
            ok += 1
        except Exception as e:  # noqa: BLE001 — fail-open per row
            err += 1
            print(f"  {i}/{total} ERR {r.surface} {r.owner}/{r.repo}: {type(e).__name__}",
                  flush=True)
        if i % 25 == 0:
            print(f"  {i}/{total} (ok={ok} err={err})", flush=True)
    print(f"[rescore_community] done: ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
