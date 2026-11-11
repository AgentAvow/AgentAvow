"""One-off: tool watches the re-scan loop could not score (2026-11-10).

A verified crates claim auto-watched the crate through ``_ensure_watch``, which skipped
the surface check ``POST /watches`` applies, and the watch scan had no crates branch:
it fell through to the GitHub scan of ``crates/<name>``. The fix gives crates and
huggingface real branches and makes any other unsupported surface fail closed.

READ-ONLY by default: prints counts and the rows. ``--apply`` (only after review):

* crates / huggingface rows: clears the stored baselines (score, decision, Certified,
  digests) so the first correct scan sets a fresh baseline and cannot alert against a
  value from the wrong scan. The watch itself stays.
* rows on any other unsupported surface: set ``active = false``. Nothing is deleted.

Usage (prod, one-off container):
    python3 scripts/watch_surface_cleanup.py            # counts only
    python3 scripts/watch_surface_cleanup.py --apply    # after review
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESCORED = ("crates", "huggingface")
_BASELINE_COLS = ("last_score", "last_decision", "last_certified", "last_manifest_digest",
                  "last_behavioral_digest", "last_icon_digest")


async def run(apply: bool) -> dict:
    from sqlalchemy import select, update

    from src.api.watch_router import WATCH_SURFACES
    from src.database import async_session
    from src.models import ToolWatch

    async with async_session() as db:
        rows = (await db.execute(select(ToolWatch))).scalars().all()
        by_surface = Counter((w.surface or "github").lower() for w in rows)
        rescored = [w for w in rows if (w.surface or "").lower() in RESCORED]
        unsupported = [w for w in rows
                       if (w.surface or "github").lower() not in WATCH_SURFACES]
        out = {
            "total_watches": len(rows),
            "by_surface": dict(sorted(by_surface.items())),
            "crates_hf_rows": len(rescored),
            "crates_hf_with_a_stored_score": sum(1 for w in rescored
                                                 if w.last_score is not None),
            "unsupported_surface_rows": len(unsupported),
            "unsupported_active": sum(1 for w in unsupported if w.active),
            "rows": [
                {"id": str(w.id), "surface": w.surface, "owner": w.owner, "repo": w.repo,
                 "active": w.active, "last_score": w.last_score,
                 "last_checked_at": w.last_checked_at.isoformat()
                 if w.last_checked_at else None}
                for w in rescored + unsupported
            ],
            "applied": False,
        }
        if apply:
            if rescored:
                await db.execute(update(ToolWatch)
                                 .where(ToolWatch.id.in_([w.id for w in rescored]))
                                 .values({c: None for c in _BASELINE_COLS}))
            if unsupported:
                await db.execute(update(ToolWatch)
                                 .where(ToolWatch.id.in_([w.id for w in unsupported]))
                                 .values(active=False))
            await db.commit()
            out["applied"] = True
    return out


def main(argv: list[str] | None = None) -> int:
    import json

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true",
                    help="reset crates/hf baselines and deactivate unsupported rows")
    args = ap.parse_args(argv)
    print(json.dumps(asyncio.run(run(args.apply)), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
