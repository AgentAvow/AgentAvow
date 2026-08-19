"""Re-score EXISTING corpus entries in place — the safe, non-destructive re-scan.

Unlike the discover+scan launch scripts (which re-search registries and, via their
progress/`done` skip-set, can OVERWRITE the results file with a shrunken subset), this
iterates the entries already in each ``*-results.json`` and re-runs the scanner on each
by coordinate, updating scores IN PLACE. It never drops a row: a fetch failure is marked
unscannable (``trust_score=None`` + a ``scan_error``), never removed, never a 0.

Bounded + resumable: processes ``--limit`` scannable rows per surface per run, advancing
a per-file cursor, so an hourly cron works down the whole corpus and loops. By default it
SKIPS rows that already carry a fetch error (known empty/private repos) so a pass spends
its budget re-scoring the rows that actually have a gradeable coordinate; pass
``--retry-errors`` to attempt those too.

Usage:
    python3 scripts/launch_scans/rescore_corpus.py --limit 150
    python3 scripts/launch_scans/rescore_corpus.py --surface npm --limit 50
    python3 scripts/launch_scans/rescore_corpus.py --retry-errors --limit 300
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import _common  # noqa: E402

# surface -> (results filename, top-level list key)
SURFACES = {
    "npm": ("npm-agents-results.json", "results"),
    "pypi": ("pypi-agents-results.json", "results"),
    "mcp": ("mcp-registry-results.json", "results"),
    "openclaw": ("openclaw-results.json", "repos"),
}


def _coord(surface: str, row: dict) -> str | None:
    """The owner/repo coordinate for a row, or None if it can't be re-scanned."""
    full = row.get("repo") if surface == "openclaw" else row.get("full_name")
    return full if (full and "/" in full) else None


def _row_has_error(surface: str, row: dict) -> bool:
    return bool(row.get("error") if surface == "openclaw" else row.get("scan_error"))


def _apply_summary(surface: str, row: dict, summ: dict) -> None:
    """Write a fresh scan summary back onto a row, respecting per-surface field names."""
    if surface == "openclaw":
        row["trust_score"] = summ["trust_score"]
        row["critical_count"] = summ["critical"]
        row["high_count"] = summ["high"]
        row["findings_count"] = summ["findings_count"]
        row["files_scanned"] = summ["files_scanned"]
        row["error"] = summ["scan_error"]
    else:
        row.update(summ)


async def _rescore_surface(
    surface: str, limit: int, retry_errors: bool, token: str | None,
    min_score: int | None = None,
) -> int:
    fn, key = SURFACES[surface]
    path = _common.DATA_DIR / fn
    data = _common.read_json(path, default=None)
    if not isinstance(data, dict):
        print(f"[{surface}] no results file, skip")
        return 0
    rows = data.get(key, [])
    n = len(rows)
    if not n:
        print(f"[{surface}] empty, skip")
        return 0

    # Targeted high-priority pass (--min-score): sweep the WHOLE file for rows at or
    # above min_score, ignoring (and never advancing) the grind's persistent cursor so
    # a concurrent/subsequent full grind resumes exactly where it left off.
    prioritized = min_score is not None
    cursor_path = _common.DATA_DIR / f".rescore-cursor-{surface}.json"
    start = 0 if prioritized else int(_common.read_json(cursor_path, default={"i": 0}).get("i", 0)) % n

    from src.scanner.scan import scan_repo

    policy = _common.RateLimitPolicy(surface if surface in ("npm", "pypi") else "github")
    done = 0
    stepped = 0
    i = start
    while done < limit and stepped < n:
        row: dict[str, Any] = rows[i]
        i = (i + 1) % n
        stepped += 1
        full = _coord(surface, row)
        if not full:
            continue
        if _row_has_error(surface, row) and not retry_errors:
            continue  # known-unfetchable; a full pass would just re-fail it
        if prioritized:
            sc = row.get("trust_score")
            if sc is None or sc < min_score:
                continue  # only the high-scorers this pass
        print(f"[{surface}] rescore {done + 1}/{limit}: {full}")
        try:
            result = await scan_repo(full, token=token)
            _apply_summary(surface, row, _common.summarize_scan_result(result))
        except Exception as exc:  # noqa: BLE001 — keep the row, mark unscannable
            if surface == "openclaw":
                row["error"] = str(exc)
            else:
                row["scan_error"] = str(exc)
            row["trust_score"] = None
        done += 1
        if done % 15 == 0:  # periodic durable checkpoint
            _common.write_json_atomic(path, data)
            if not prioritized:
                _common.write_json_atomic(cursor_path, {"i": i})
        policy.wait()

    _common.write_json_atomic(path, data)
    if not prioritized:
        _common.write_json_atomic(cursor_path, {"i": i})
    print(f"[{surface}] re-scored {done} rows"
          + ("" if prioritized else f"; cursor {start} -> {i} of {n}"))
    return done


async def _main_async(
    surfaces: list[str], limit: int, retry_errors: bool, token: str | None,
    min_score: int | None = None,
) -> None:
    total = 0
    for s in surfaces:
        total += await _rescore_surface(s, limit, retry_errors, token, min_score=min_score)
    print(f"[rescore] complete — {total} rows re-scored across {len(surfaces)} surface(s)")


def main() -> int:
    _common.require_py39()
    _common.ensure_data_dir()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=list(SURFACES), help="only this surface (default: all)")
    parser.add_argument("--limit", type=int, default=150, help="scannable rows per surface per run")
    parser.add_argument("--retry-errors", action="store_true",
                        help="also re-attempt rows that previously failed to fetch")
    parser.add_argument("--min-score", type=int, default=None,
                        help="targeted pass: only re-score rows whose current trust_score >= N "
                             "(sweeps the whole file, ignores + never advances the grind cursor)")
    args = parser.parse_args()
    surfaces = [args.surface] if args.surface else list(SURFACES)
    token = _common.load_secret("GITHUB_TOKEN")
    asyncio.run(_main_async(surfaces, args.limit, args.retry_errors, token, min_score=args.min_score))
    return 0


if __name__ == "__main__":
    sys.exit(main())
