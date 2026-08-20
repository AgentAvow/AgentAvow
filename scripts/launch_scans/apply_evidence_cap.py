"""One-time backfill: apply the evidence-confidence cap to existing catalog rows.

The scoring cap (src/scanner/scan.py) bounds a clean score by how much we could inspect —
a thin scan (few files, no tests) can't read as "excellent". New scans get it for free;
this backfills the STORED corpus so Browse de-saturates immediately instead of waiting for
the grind to re-score everything. Safe: it's a pure min(stored_score, cap) over fields the
row already carries (trust_score, files_scanned, has_tests), never raises a score, and
writes each file atomically. Idempotent — re-running changes nothing further.

Run from the repo root:  ./.venv/bin/python3 scripts/launch_scans/apply_evidence_cap.py
"""
from __future__ import annotations

import glob
import json
import os

# MUST mirror the constants in src/scanner/scan.py (_EVIDENCE_*).
_MIN_FILES = 8
_VERY_THIN_FILES = 3
_THIN_CAP = 82
_VERY_THIN_CAP = 74
_TESTS_HEADROOM = 5

_DATA_GLOB = "data/launch-scans/*-results.json"


def _cap_for(files: int, has_tests: bool) -> int | None:
    if not files or files <= 0 or files >= _MIN_FILES:
        return None
    cap = _VERY_THIN_CAP if files <= _VERY_THIN_FILES else _THIN_CAP
    if has_tests:
        cap += _TESTS_HEADROOM
    return cap


def main() -> int:
    changed = 0
    total = 0
    for path in glob.glob(_DATA_GLOB):
        with open(path) as fh:
            data = json.load(fh)
        key = "repos" if "repos" in data else "results"
        rows = data.get(key) or []
        dirty = False
        for row in rows:
            score = row.get("trust_score")
            if score is None:
                continue
            total += 1
            cap = _cap_for(row.get("files_scanned", 0) or 0, bool(row.get("has_tests")))
            if cap is not None and score > cap:
                row["trust_score"] = cap
                changed += 1
                dirty = True
        if dirty:
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh)
            os.replace(tmp, path)
    print(f"evidence cap backfill: {changed} rows lowered of {total} scored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
