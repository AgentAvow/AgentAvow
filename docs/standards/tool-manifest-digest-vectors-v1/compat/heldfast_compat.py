"""Run heldfast's agentavow.mcp-tool-definition.v1 profile against a v1 vector file.

heldfast (rufat325/heldfast, Apache-2.0) implements the profile in
``src/heldfast/profiles.py`` from the published rules, with no file of ours
copied. Its own check, ``tests/test_profile_agentavow.py``, reads the vector file
from a local directory and compares the per-tool digests and the thirteen
name-to-key pairs. This driver imports the two functions that check calls from a
checkout pinned by commit (``heldfast-pin.json``) and asks the same questions,
writing the answers as JSON so they can be recorded per check.

Only glue lives here. No encoding or hashing logic is reimplemented. heldfast
claims the digests and the key pairs only, so nothing else is asked of it: no
signature, no canonical-bytes check, no case verdicts.

    python heldfast_compat.py --heldfast <checkout> --vectors <file> --out <report.json>

Exit 0 only when every key pair and every served-definition digest agrees with
the vector file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROFILE = "agentavow-ci.heldfast-v1-compat"


def git_head(checkout: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip()


def run(checkout: Path, vectors: Path) -> dict[str, Any]:
    sys.path.insert(0, str(checkout / "src"))
    from heldfast.profiles import (  # noqa: E402  (heldfast, from the pinned checkout)
        agentavow_v1_digest,
        agentavow_v1_key,
    )

    raw = vectors.read_bytes()
    fixture = json.loads(raw.decode("utf-8"))
    # heldfast's own test compares against the convenience map in the file, not the
    # signed payload; the native verifier is what checks that the two are equal.
    signed = fixture["attestation"]["toolDigests"]

    keys = []
    for pair in fixture["key_encoding"]:
        got = agentavow_v1_key(pair["name"])
        keys.append(
            {"name": pair["name"], "key": pair["key"], "heldfast": got,
             "matches": got == pair["key"]}
        )
    definitions = []
    for tool in fixture["observed_tools"]:
        key = agentavow_v1_key(tool["name"])
        got = agentavow_v1_digest(tool)
        want = signed.get(key) if key is not None else None
        definitions.append(
            {"key": key, "signed": want, "heldfast": got,
             "matches": got is not None and got == want}
        )
    return {
        "profile": PROFILE,
        "heldfast": {
            "repository": "rufat325/heldfast",
            "module": "src/heldfast/profiles.py",
            "commit": git_head(checkout),
        },
        "vectors_file": vectors.name,
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "key_pairs": keys,
        "definitions": definitions,
        "passed": all(k["matches"] for k in keys) and all(d["matches"] for d in definitions),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--heldfast", type=Path, required=True, help="pinned heldfast checkout")
    parser.add_argument("--vectors", type=Path, required=True, help="v1 vector file")
    parser.add_argument("--out", type=Path, required=True, help="JSON report path")
    args = parser.parse_args()

    report = run(args.heldfast, args.vectors)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    keys = [k["matches"] for k in report["key_pairs"]]
    defs = [d["matches"] for d in report["definitions"]]
    print(
        f"heldfast @ {report['heldfast']['commit'][:12]}: keys {sum(keys)}/{len(keys)}, "
        f"definitions {sum(defs)}/{len(defs)}, result {'PASS' if report['passed'] else 'FAIL'}"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
