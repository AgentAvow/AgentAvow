"""Adversarial recall gate for the scanner's relaxing rules.

Hand-built npm tarballs where the payload IS reachable or used, run through the
production package path (npm_result_from_tarball -> apply_artifact_scan -> trust score
-> verdict.decide). Four sets, each written against a relaxing PR:

* ``cases_npm_scripts``  - maintainer-only package.json scripts (#181)
* ``cases_printed_hint`` - printed install hints / console + stream replacement (#185, #186)
* ``cases_trifecta``     - the lethal-trifecta outbound leg (#187, #199, #201)
* ``cases_exfil_precision`` - own-vendor .env key, signed payload, signature arrays
  (2026-10-26)

Every case's label is pinned in ``expected.json``. A scanner change that moves one fails
here; regenerate with ``python -I tests/adversarial/expected_labels.py --write`` in the
same PR so the move is reviewed. Controls (names starting ``ctl``, ``xctl`` or
``control``) are the shapes a rule SHOULD relax; every other case is an attack and may
never be pinned ``safe`` unless it is listed in ``KNOWN_GAPS`` with the label it should
have (a strict xfail: closing the gap fails the test until the entry is removed).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "expected.json").read_text())
SETS = ("cases_npm_scripts", "cases_printed_hint", "cases_trifecta", "cases_exfil_precision")

# Attacks that still read safe today, with the label they should read.
KNOWN_GAPS: dict[tuple[str, str], str] = {
    # An exfil through a `.use(` handler on a non-HTTP event bus: the untrusted-input leg
    # only knows HTTP request objects.
    ("cases_trifecta", "socket_use_handler"): "review",
    # Found while building the 2026-10-26 set, and older than it: a Python list of
    # string elements reads as prose to the line engine, so its webhook hosts are never
    # flagged, even when the list is handed to an imported sender.
    ("cases_exfil_precision", "py_signature_list_to_imported_sender"): "do_not_connect",
}

_mods: dict[str, object] = {}


def _mod(name: str):
    if name not in _mods:
        spec = importlib.util.spec_from_file_location(f"adversarial_{name}", HERE / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _mods[name] = mod
    return _mods[name]


def _label(set_name: str, case: str) -> str:
    mod = _mod(set_name)
    files = mod.CASES[case]
    if set_name == "cases_npm_scripts":
        return mod.run(case, files)[0]
    return mod.run(files)[0]


def _is_control(case: str) -> bool:
    return case.startswith(("ctl", "xctl", "control"))


def _params():
    for s in SETS:
        for case in EXPECTED[s]:
            marks = []
            if (s, case) in KNOWN_GAPS:
                marks.append(pytest.mark.xfail(
                    strict=True, reason=f"known gap: should read {KNOWN_GAPS[(s, case)]}"))
            yield pytest.param(s, case, id=f"{s}:{case}", marks=marks)


@pytest.mark.parametrize("set_name,case", list(_params()))
def test_attack_case_label(set_name: str, case: str) -> None:
    got = _label(set_name, case)
    want = KNOWN_GAPS.get((set_name, case), EXPECTED[set_name][case])
    assert got == want, (
        f"{set_name}:{case} reads {got!r}, pinned {want!r}. If the move is intended, run "
        "`python -I tests/adversarial/expected_labels.py --write` and explain it in the PR.")


def test_expected_covers_every_case() -> None:
    for s in SETS:
        assert set(EXPECTED[s]) == set(_mod(s).CASES), f"{s}: expected.json is stale"


def test_no_attack_pinned_safe() -> None:
    """An attack may never be pinned safe (regenerating expected.json after a recall
    regression must still fail); a known gap is listed in KNOWN_GAPS instead."""
    bad = [f"{s}:{c}" for s in SETS for c, lab in EXPECTED[s].items()
           if lab == "safe" and not _is_control(c) and (s, c) not in KNOWN_GAPS]
    assert not bad, f"attack cases pinned safe: {bad}"


def test_known_gaps_are_pinned_as_they_read() -> None:
    for (s, c), want in KNOWN_GAPS.items():
        assert c in EXPECTED[s], f"KNOWN_GAPS names a missing case {s}:{c}"
        assert EXPECTED[s][c] != want, f"{s}:{c} already reads {want}; drop it from KNOWN_GAPS"
