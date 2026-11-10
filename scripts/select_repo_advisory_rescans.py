"""Which packages need a re-scan now that the scanner reads repository security advisories.

PR #270 (2026-11-10) made ``scan_package`` read the declared source repo's own GitHub
security advisories. Those can be published without ever reaching OSV or the global
advisory DB (server-everything 2.0.0 read Safe + Certified while GHSA-mvf5-2qqv-rg3c
affected it). A stored package answer from before #270 never saw them. This script finds
the packages whose stored answer can change and writes the list. It never re-scans.

READ-ONLY. It reads ``community_scans`` (``SELECT`` only) and/or the static catalog's
launch-scan results files, the registries' public metadata (latest version + declared
repository), and ``GET repos/{o}/{r}/security-advisories`` once per distinct repo. It
writes nothing to the DB, Redis or the results files.

Outputs (in ``--out-dir``, default the scratch dir given):
  ``repo-advisory-candidates.json``  every package checked, with slug, version, and the
                                      repo advisories that name it
  ``repo-advisory-rescan.txt``       ``surface:name`` per line; packages with at least one
                                      advisory naming them, affected-at-latest first
  ``repo-advisory-summary.json``     counts, lookup failures, and the run parameters

The re-scan itself is a separate, reviewed step (force a package scan of each line).

Usage (prod, one-off container, nice 19):
    python3 scripts/select_repo_advisory_rescans.py --source db --out-dir /tmp/advsel
    python3 scripts/select_repo_advisory_rescans.py --source files --limit 50 --out-dir /tmp/a
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SURFACES = ("npm", "pypi", "crates")
# (surface, results file, list key) for the static catalog's package rows.
_FILES = (("npm", "npm-agents-results.json", "results"),
          ("pypi", "pypi-agents-results.json", "results"))


@dataclass
class Candidate:
    surface: str
    name: str
    version: str | None = None
    slug: str | None = None
    repo_advisories: int | None = None  # published advisories on the repo (None = unread)
    naming_this_package: list[str] = field(default_factory=list)
    affected_at_latest: list[str] = field(default_factory=list)
    unparsed_range: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def needs_rescan(self) -> bool:
        return bool(self.naming_this_package)


# ── universe ─────────────────────────────────────────────────────────────────
async def coords_from_db() -> list[tuple[str, str]]:
    """``(surface, name)`` of every package row in ``community_scans``. SELECT only."""
    from sqlalchemy import select

    from src.database import async_session
    from src.models import CommunityScan

    async with async_session() as db:
        rows = (await db.execute(
            select(CommunityScan.surface, CommunityScan.repo)
            .where(CommunityScan.surface.in_(SURFACES)))).all()
    return [(str(s).lower(), str(r)) for s, r in rows if r]


def coords_from_files(data_dir: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for surface, fname, key in _FILES:
        p = data_dir / fname
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
        except ValueError:
            continue
        rows = data.get(key, []) if isinstance(data, dict) else data
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and r.get("name"):
                out.append((surface, str(r["name"])))
    return out


def dedupe(coords: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out = []
    for s, n in coords:
        k = (s, n.lower() if s != "pypi" else n.lower().replace("_", "-"))
        if s in SURFACES and k not in seen:
            seen.add(k)
            out.append((s, n))
    return out


# ── registry metadata: latest version + declared repo ────────────────────────
async def resolve(c: Candidate, client) -> None:
    """Fill ``version`` (the registry's latest: npm dist-tag, PyPI info.version, crates
    max_stable_version — the same picks ``scan_package`` makes) and ``slug``."""
    from urllib.parse import quote

    from src.scanner.artifact_fetch import (
        CRATES_META,
        NPM_REGISTRY,
        PYPI_JSON,
        ArtifactFetchError,
        _get_json,
    )
    from src.scanner.scan import _declared_source_slug

    try:
        if c.surface == "npm":
            doc = await _get_json(f"{NPM_REGISTRY}/{quote(c.name, safe='@')}/latest", client)
            c.version = str(doc.get("version") or "") or None
            c.slug = _declared_source_slug("npm", doc)
        elif c.surface == "pypi":
            from src.scanner.artifact_fetch import _pypi_declared_manifest
            meta = await _get_json(PYPI_JSON.format(name=quote(c.name)), client)
            c.version = str((meta.get("info") or {}).get("version") or "") or None
            c.slug = _declared_source_slug("pypi", _pypi_declared_manifest(meta))
        elif c.surface == "crates":
            meta = await _get_json(CRATES_META.format(name=quote(c.name)), client)
            crate = meta.get("crate") or {}
            c.version = str(crate.get("max_stable_version") or "") or None
            c.slug = _declared_source_slug("crates", crate)
    except ArtifactFetchError as exc:
        c.error = f"registry: {exc}"[:200]
    except Exception as exc:  # noqa: BLE001 — one bad row never stops the run
        c.error = f"registry: {type(exc).__name__}"


# ── main ─────────────────────────────────────────────────────────────────────
async def run(args: argparse.Namespace) -> dict:
    import httpx

    from src.scanner.incident_history import (
        _OSV_ECOSYSTEM,
        fetch_repo_advisories,
        summarize_repo_advisories,
    )

    coords: list[tuple[str, str]] = []
    if args.source in ("db", "both"):
        coords += await coords_from_db()
    if args.source in ("files", "both"):
        coords += coords_from_files(Path(args.data_dir))
    for raw in args.coord or []:  # explicit surface:name, e.g. for a spot check
        s, _, n = raw.partition(":")
        if s and n:
            coords.append((s.lower(), n))
    coords = dedupe(coords)
    if args.limit:
        coords = coords[: args.limit]
    cands = [Candidate(s, n) for s, n in coords]

    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(headers={"User-Agent": "AgentAvow-AdvisorySelect"}) as client:
        async def _one(c: Candidate) -> None:
            async with sem:
                await resolve(c, client)
                await asyncio.sleep(args.delay)
        await asyncio.gather(*(_one(c) for c in cands))

    token = args.github_token or os.environ.get("GITHUB_TOKEN") or None
    if not token:
        try:
            from src.config import settings
            token = getattr(settings, "github_token", None) or None
        except Exception:  # noqa: BLE001
            token = None

    slugs = sorted({c.slug for c in cands if c.slug})
    repo_adv: dict[str, dict] = {}
    for slug in slugs:  # sequential: GitHub's secondary rate limits punish bursts
        repo_adv[slug] = await fetch_repo_advisories(slug, token)
        await asyncio.sleep(args.gh_delay)

    lookup_failed = []
    for c in cands:
        if not c.slug or not c.version:
            continue
        got = repo_adv.get(c.slug) or {}
        if got.get("checked") is not True:
            c.error = c.error or f"repo advisories: {got.get('reason') or 'not read'}"
            lookup_failed.append(c.slug)
            continue
        advs = got.get("advisories") or []
        c.repo_advisories = len(advs)
        eco = _OSV_ECOSYSTEM.get(c.surface)
        mine = summarize_repo_advisories(advs, eco, c.name, c.version) if eco else []
        c.naming_this_package = [a["id"] for a in mine]
        c.affected_at_latest = [a["id"] for a in mine if a.get("affects_scanned_version")]
        c.unparsed_range = [a["id"] for a in mine if a.get("range_unparsed")]

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "repo-advisory-candidates.json").write_text(
        json.dumps([asdict(c) for c in cands], indent=1))
    rescan = sorted((c for c in cands if c.needs_rescan),
                    key=lambda c: (not c.affected_at_latest, not c.unparsed_range,
                                   c.surface, c.name.lower()))
    (out / "repo-advisory-rescan.txt").write_text(
        "".join(f"{c.surface}:{c.name}\n" for c in rescan))
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": args.source, "limit": args.limit,
        "packages_checked": len(cands),
        "with_declared_github_repo": sum(1 for c in cands if c.slug),
        "distinct_repos": len(slugs),
        "repos_with_published_advisories": sum(
            1 for s in slugs if (repo_adv[s].get("advisories") or [])),
        "repo_lookup_failed": sorted(set(lookup_failed)),
        "registry_errors": sum(1 for c in cands if c.error and c.error.startswith("registry")),
        "rescan": len(rescan),
        "affected_at_latest": sum(1 for c in rescan if c.affected_at_latest),
        "unparsed_range": sum(1 for c in rescan if c.unparsed_range),
        "github_token": bool(token),
    }
    (out / "repo-advisory-summary.json").write_text(json.dumps(summary, indent=1))
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", choices=("db", "files", "both", "none"), default="both")
    ap.add_argument("--coord", action="append", help="extra surface:name (repeatable)")
    ap.add_argument("--data-dir", default=str(ROOT / "data" / "launch-scans"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--limit", type=int, default=0, help="first N packages only (0 = all)")
    ap.add_argument("--concurrency", type=int, default=4, help="registry requests at once")
    ap.add_argument("--delay", type=float, default=0.1, help="seconds after each registry call")
    ap.add_argument("--gh-delay", type=float, default=0.5, help="seconds between repo lookups")
    ap.add_argument("--github-token", default=None, help="else GITHUB_TOKEN / settings")
    args = ap.parse_args(argv)
    summary = asyncio.run(run(args))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
