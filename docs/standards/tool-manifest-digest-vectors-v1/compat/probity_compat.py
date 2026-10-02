"""Run Probity's signed-map reader against the current v1 vector file.

Probity's own driver (``run_agentavow.py``) refuses any fixture whose bytes differ
from the one it recorded at producer commit 36426cf. That is the right control for
their repository and the wrong one for ours: here the vector file is the thing that
changes, and the question is whether an outside reader still agrees with it. So this
driver imports Probity's ``map_reader`` (the independent implementation: name
encoding, JWS and canonical-bytes checks, the six axes, the served-definition digest)
from a checkout pinned by commit and runs the same sequence their driver runs, on
whatever vector file it is given.

Only glue lives here. No encoding, hashing or verification logic is reimplemented.

    python probity_compat.py --probity <checkout> --vectors <file> --out <report.json>

Exit 0 only when every key-encoding pair, every served-definition digest, the payload
digest and every case verdict agree with the vector file. Any refusal from the reader
is written into the report as ``refusal`` and exits 1.

The signing key comes from Probity's ``selection.json`` by default (a key the consumer
chose, not one the packet offered), so a rotated issuer key is reported as a mismatch
until the consumer updates its selection. ``--key-from-fixture`` uses the JWK carried in
the vector file instead, to separate a key change from everything else.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROFILE = "agentavow-ci.probity-v1-compat"
READER_DIR = Path("interop") / "agentavow-signed-map-v1"


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


def run(checkout: Path, vectors: Path, key_from_fixture: bool) -> dict[str, Any]:
    reader_root = checkout / READER_DIR
    sys.path.insert(0, str(reader_root))
    import map_reader  # noqa: E402  (Probity's reader, from the pinned checkout)

    raw = vectors.read_bytes()
    fixture_sha256 = hashlib.sha256(raw).hexdigest()
    lock = map_reader.load_json((reader_root / "source-lock.json").read_bytes())
    selection = map_reader.load_json((reader_root / "selection.json").read_bytes())

    report: dict[str, Any] = {
        "profile": PROFILE,
        "probity": {
            "repository": lock.get("repository", "probityai/agent-evidence-vectors"),
            "reader": str(READER_DIR / "map_reader.py"),
            "commit": git_head(checkout),
        },
        "vectors_file": vectors.name,
        "fixture_sha256": fixture_sha256,
        "fixture_matches_probity_lock": fixture_sha256 == lock["fixture"]["sha256"],
        "key_source": "fixture" if key_from_fixture else "probity selection.json",
        "passed": False,
    }

    try:
        fixture = map_reader.load_json(raw)
        if key_from_fixture:
            jwk, issuer = fixture["issuer"]["jwk"], fixture["issuer"]["id"]
        else:
            jwk, issuer = selection["jwk"], selection["issuer"]
        report["kid"] = jwk.get("kid")
        jws = fixture["attestation"]["jws"]
        payload, _, _ = map_reader.read_jws(jws, jwk)

        keys = [
            {
                "name": pair["name"],
                "key": pair["key"],
                "probity": map_reader.tool_key(pair["name"]),
                "matches": map_reader.tool_key(pair["name"]) == pair["key"],
            }
            for pair in fixture["key_encoding"]
        ]
        definitions = []
        for tool in fixture["observed_tools"]:
            key = map_reader.tool_key(tool["name"])
            got = map_reader.capture_digest(fixture["observed_tools"], tool["name"])
            signed = payload["scan"]["toolDigests"].get(key)
            definitions.append(
                {"key": key, "signed": signed, "probity": got, "matches": got == signed}
            )
        definition_count_matches = len(definitions) == len(payload["scan"]["toolDigests"])

        reference_bytes = map_reader.decode_base64url(jws.split(".")[1])
        payload_sha256 = hashlib.sha256(reference_bytes).hexdigest()
        payload_matches = payload_sha256 == fixture["attestation"]["payload_sha256"]

        results = []
        for case in fixture["vectors"]:
            candidate = jws if case["jws"] == "reference" else case["jws"]
            axes = map_reader.evaluate(candidate, jwk, issuer, case["gate"])
            mismatches = {
                axis: {"want": want, "probity": axes.get(axis)}
                for axis, want in case["expect"].items()
                if axes.get(axis) != want
            }
            results.append(
                {
                    "name": case["name"],
                    "axes": axes,
                    "matches": not mismatches,
                    "mismatches": mismatches,
                }
            )

        positive = fixture["vectors"][0]["gate"]
        pin = map_reader.extract_pin(jws, jwk, issuer, positive)

        report.update(
            {
                "key_pairs": keys,
                "key_pair_matches": [k["matches"] for k in keys],
                "definitions": definitions,
                "definition_matches": [d["matches"] for d in definitions],
                "definition_count_matches": definition_count_matches,
                "payload_sha256": payload_sha256,
                "payload_digest_matches": payload_matches,
                "results": results,
                "positive_pin": pin,
                "passed": all(k["matches"] for k in keys)
                and all(d["matches"] for d in definitions)
                and definition_count_matches
                and payload_matches
                and all(r["matches"] for r in results),
            }
        )
    except map_reader.InputError as exc:
        report["refusal"] = str(exc)
    except (KeyError, TypeError, IndexError) as exc:
        report["refusal"] = f"vector file shape differs from what the reader expects: {exc!r}"
    return report


def summarize(report: dict[str, Any]) -> str:
    if "refusal" in report:
        return f"REFUSED: {report['refusal']}"
    keys = report["key_pair_matches"]
    defs = report["definition_matches"]
    cases = [r["matches"] for r in report["results"]]
    return (
        f"keys {sum(keys)}/{len(keys)}, definitions {sum(defs)}/{len(defs)}, "
        f"payload digest {'ok' if report['payload_digest_matches'] else 'MISMATCH'}, "
        f"cases {sum(cases)}/{len(cases)}, "
        f"result {'PASS' if report['passed'] else 'FAIL'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--probity", type=Path, required=True, help="pinned Probity checkout")
    parser.add_argument("--vectors", type=Path, required=True, help="v1 vector file")
    parser.add_argument("--out", type=Path, required=True, help="JSON report path")
    parser.add_argument("--key-from-fixture", action="store_true")
    args = parser.parse_args()

    report = run(args.probity, args.vectors, args.key_from_fixture)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"probity reader @ {report['probity']['commit'][:12]}: {summarize(report)}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
