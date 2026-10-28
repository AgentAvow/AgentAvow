"""Validate emitted v0.1 reports with the reference reader.

The reference reader is ``agent_evidence_vectors.w3creport`` in
probityai/agent-evidence-vectors, cited at release v0.18.1. This script imports
it from a checkout at that tag and, for every report under ``<records>/reports``,
prints the reader's shape errors and the rows it rejects the report under, then
recomputes the check-set root with the reader's own function. Only glue lives
here; nothing is judged by this script.

    python3 validate.py --reader <agent-evidence-vectors checkout at v0.18.1> --records records

Exit 0 only when every report has no shape error, no rejection, and a check-set
root the reader recomputes to the declared value.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

TAG = "v0.18.1"
COMMIT = "33d545104ff2f8c124cff465c96c013eeb809156"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--reader", type=Path, required=True,
                        help=f"agent-evidence-vectors checkout at {TAG}")
    parser.add_argument("--records", type=Path, required=True, help="emitted records directory")
    args = parser.parse_args()

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(args.reader),
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        sys.exit(f"reader checkout is at {head}; {TAG} is {COMMIT}")
    sys.path.insert(0, str(args.reader / "packaging"))
    from agent_evidence_vectors import w3creport  # noqa: E402

    print(f"reference reader {w3creport.__name__} at {TAG} ({COMMIT[:12]})")
    ok = True
    reports = sorted((args.records / "reports").glob("*.json"))
    if not reports:
        sys.exit(f"no reports under {args.records / 'reports'}")
    for path in reports:
        report = w3creport.load_json(path.read_bytes())
        shape = w3creport.shape_errors(report)
        rejected = [] if shape else w3creport.rejections(report)
        root = None if shape else w3creport.check_set_root(
            report["checks"], report["check-set"]["tree-shape"])
        root_ok = root is not None and root == report["check-set"]["sha256"]
        ok = ok and not shape and not rejected and root_ok
        print(f"{path.name}: checks {len(report.get('checks', []))}, "
              f"shape errors {json.dumps(shape)}, rejections {json.dumps(rejected)}, "
              f"check-set root {'recomputes' if root_ok else 'DIFFERS'}")
    print("result: " + ("every report conforms" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
