"""Measure what the MCP icon checks (src/scanner/mcp_icons.py) do to real servers.

Handshakes each endpoint with the scanner's own SSRF-guarded ``fetch_mcp_tools`` (icons
are never fetched), grades it with and without the icon findings, and prints how many
servers carry icons, how many get each icon finding, and every score / decision change.
Read-only: writes nothing to the DB or the cache.

    # endpoints from a JSON list (or {url: name} map)
    python scripts/measure_mcp_icons.py urls.json
    # the catalog's live MCP endpoints (community_scans, surface 'mcp')
    python scripts/measure_mcp_icons.py --db
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _decision(r) -> str:
    """The decide() outcome for a live MCP scan (no advisories / deprecation there)."""
    if r.shipped_critical_count:
        return "do_not_connect"
    if r.shipped_high_count or r.trust_score < 51:
        return "review"
    return "safe"


async def _db_urls() -> list[str]:
    from sqlalchemy import text

    from src.database import async_session
    async with async_session() as db:
        rows = await db.execute(text(
            "SELECT DISTINCT repo FROM community_scans WHERE surface = 'mcp'"))
        return [r[0] for r in rows if str(r[0]).startswith("https://")]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="?")
    ap.add_argument("--db", action="store_true")
    ap.add_argument("--concurrency", type=int, default=8)
    args = ap.parse_args()
    from src.scanner import mcp_icons, mcp_scan
    from src.scanner.scan import scan_mcp

    if args.db:
        urls = await _db_urls()
    else:
        loaded = json.loads(Path(args.urls).read_text())
        urls = list(loaded)
    sem = asyncio.Semaphore(args.concurrency)
    served: dict = {}

    async def fetch(u):
        async with sem:
            try:
                served[u] = await asyncio.wait_for(mcp_scan.fetch_mcp_tools(u), 60)
            except Exception:
                served[u] = None

    real_fetch, real_icons = mcp_scan.fetch_mcp_tools, mcp_icons.icon_findings
    await asyncio.gather(*(fetch(u) for u in urls))

    with_icons = 0
    per_rule: collections.Counter = collections.Counter()
    moves: collections.Counter = collections.Counter()
    changed = []
    ok = {u: d for u, d in served.items() if d}
    for u, d in sorted(ok.items()):
        d.pop("client_view", None)
        if any(True for _ in mcp_icons.iter_icons(d.get("tools"), d.get("resources"),
                                                  d.get("prompts"), d.get("server_info"))):
            with_icons += 1

        async def _served(_url, _d=d):
            return _d
        mcp_scan.fetch_mcp_tools = _served
        try:
            mcp_icons.icon_findings = lambda *a, **k: []
            before = await scan_mcp(u)
            mcp_icons.icon_findings = real_icons
            after = await scan_mcp(u)
        finally:
            mcp_scan.fetch_mcp_tools, mcp_icons.icon_findings = real_fetch, real_icons
        for sev, rule in {(f.severity, f.name.split(":")[0].split("(")[0].strip())
                          for f in after.findings if f.file_path.endswith(":icons")}:
            per_rule[(sev, rule)] += 1
        moves[(_decision(before), _decision(after))] += 1
        if before.trust_score != after.trust_score or _decision(before) != _decision(after):
            changed.append((u, before.trust_score, after.trust_score,
                            _decision(before), _decision(after)))
    print(f"endpoints: {len(urls)}  handshaken: {len(ok)}  serving icons: {with_icons}")
    for (sev, rule), n in per_rule.most_common():
        print(f"  {sev:6} {rule}: {n} server(s)")
    print("decision before -> after:", dict(moves))
    for row in changed:
        print("  changed:", row)


if __name__ == "__main__":
    asyncio.run(main())
