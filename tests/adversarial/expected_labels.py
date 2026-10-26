"""Regenerate ``expected.json`` for the adversarial attack sets.

    python -I tests/adversarial/expected_labels.py            # print diffs vs expected.json
    python -I tests/adversarial/expected_labels.py --write    # rewrite expected.json

Run it in the same PR as a scanner change that moves a case, so the move is reviewed.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = HERE / "expected.json"
SETS = ("cases_npm_scripts", "cases_printed_hint", "cases_trifecta", "cases_exfil_precision")


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"adversarial_{name}", HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def label_of(mod, name: str, files) -> str:
    """The case's decision label through the production package path."""
    if mod.__name__.endswith("cases_npm_scripts"):
        return mod.run(name, files)[0]
    return mod.run(files)[0]


def current() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for s in SETS:
        mod = load(s)
        out[s] = {n: label_of(mod, n, f) for n, f in mod.CASES.items()}
    return out


def main() -> int:
    now = current()
    if "--write" in sys.argv:
        EXPECTED.write_text(json.dumps(now, indent=2, sort_keys=True) + "\n")
        print(f"wrote {EXPECTED} ({sum(len(v) for v in now.values())} cases)")
        return 0
    old = json.loads(EXPECTED.read_text()) if EXPECTED.exists() else {}
    moves = [(s, n, old.get(s, {}).get(n), lab) for s, cases in now.items()
             for n, lab in cases.items() if old.get(s, {}).get(n) != lab]
    for m in moves:
        print("  move", m)
    print(f"{len(moves)} moves")
    return 1 if moves else 0


if __name__ == "__main__":
    sys.exit(main())
