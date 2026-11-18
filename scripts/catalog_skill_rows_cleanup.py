"""One-off: find launch-corpus skill rows with no SKILL.md (or a deleted repo) and write
them to the catalog's skill-rows.json overlay (src/api/catalog_skill_rows.py).

The catalog re-scan loop records these on its own as it reaches each row; this script
only gets there sooner. DRY RUN by default: it prints what it would record and writes
nothing. Read-only against GitHub (repo metadata + the git tree), one repo at a time.

    # the rows the round-2 verdict audit found (dry run)
    python3 scripts/catalog_skill_rows_cleanup.py --audit-rows
    # every skill row in the corpus (about 500 repos, ~2 GitHub calls each)
    python3 scripts/catalog_skill_rows_cleanup.py --all
    # write the overlay (the catalog reloads it on its next source check)
    python3 scripts/catalog_skill_rows_cleanup.py --audit-rows --apply

Needs GITHUB_TOKEN (or the app's GitHub auth) for a useful rate limit. Run it where the
catalog's data/launch-scans directory lives (the API host), as the user that owns it.
A truncated or empty tree, or any non-404 error, leaves the repo alone. A 404 is only
noted: a repo is recorded as gone when a second run, at least three hours later, gets a
404 again (src/api/catalog_skill_rows.GONE_CONFIRM_GAP).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

AUDIT_ROWS = (
    "zhaoxinyi02/ClawPanel", "riba2534/happyclaw", "robsannaa/openclaw-mission-control",
    "openclaw/openclaw-ansible", "pjasicek/OpenClaw", "milady-ai/milady",
    "byJoey/openclawctl", "itq5/OpenClaw-Admin", "MemTensor/MemOS-Cloud-OpenClaw-Plugin",
    "kwalus/Canopy", "bgdnvk/clanker", "LycheeMem/LycheeMem",
)


def corpus_skill_repos() -> list[str]:
    from src.api import scan_catalog_router as scr

    doc = json.loads((scr._DATA_DIR / "openclaw-results.json").read_text())
    repos = doc.get("repos", []) if isinstance(doc, dict) else doc
    return [r["repo"] for r in repos if isinstance(r, dict) and "/" in (r.get("repo") or "")]


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    which = ap.add_mutually_exclusive_group(required=True)
    which.add_argument("--audit-rows", action="store_true", help="the 12 audited rows")
    which.add_argument("--all", action="store_true", help="every corpus skill row")
    ap.add_argument("--apply", action="store_true", help="write the overlay (default: dry run)")
    ap.add_argument("--spacing", type=float, default=1.0, help="seconds between repos")
    args = ap.parse_args()

    import httpx

    from src.api import catalog_skill_rows as sr
    from src.github_auth import get_github_token

    names = list(AUDIT_ROWS) if args.audit_rows else corpus_skill_repos()
    headers = {"Accept": "application/vnd.github+json"}
    token = await get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    found: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=20.0) as client:
        for i, name in enumerate(names):
            try:
                kind = await sr.classify(client, headers, name)
            except httpx.HTTPError as e:
                print(f"skip {name}: {e.__class__.__name__}")
                kind = None
            if kind:
                found[name] = kind
                print(f"{kind:12} {name}")
            if i + 1 < len(names):
                await asyncio.sleep(args.spacing)
    print(f"{len(found)} of {len(names)} rows to record"
          + ("" if args.apply else " (dry run: nothing written; add --apply)"))
    if args.apply:
        for name, kind in found.items():
            if kind == sr.REPO_GONE:
                if not sr.note_404(name):
                    print(f"first 404 noted for {name}; run again in 3+ hours to confirm")
                continue
            if not sr.record(name, kind):
                print(f"could not write the overlay for {name}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
