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
A truncated tree or any non-404 error leaves the repo alone.
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


async def classify(client, headers: dict, full_name: str) -> str | None:
    """no_skill_md / repo_gone / None (a skill, or unknown)."""
    from src.api.catalog_skill_rows import NO_SKILL_MD, REPO_GONE

    meta = await client.get(f"https://api.github.com/repos/{full_name}", headers=headers)
    if meta.status_code in (404, 451):
        return REPO_GONE
    if meta.status_code != 200:
        return None
    branch = (meta.json() or {}).get("default_branch") or "HEAD"
    tree = await client.get(
        f"https://api.github.com/repos/{full_name}/git/trees/{branch}",
        headers=headers, params={"recursive": "1"})
    if tree.status_code != 200:
        return None
    body = tree.json() or {}
    if body.get("truncated"):
        return None
    paths = [it.get("path", "") for it in body.get("tree") or [] if it.get("type") == "blob"]
    return None if any(p.lower().endswith("skill.md") for p in paths) else NO_SKILL_MD


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
                kind = await classify(client, headers, name)
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
            if not sr.record(name, kind):
                print(f"could not write the overlay for {name}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
