"""The behavioral eval corpus holds: every fixture raises what it must and nothing it must
not, through the real exerciser and graders (no sandbox). This is the CI gate for the tier."""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "run_eval", ROOT / "scripts" / "sandbox" / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_eval)

CORPUS = run_eval.load_corpus()


@pytest.mark.parametrize("entry", CORPUS["fixtures"], ids=[e["label"] for e in CORPUS["fixtures"]])
def test_fixture_meets_its_expectations(entry):
    result = run_fixture = run_eval.run_fixture_local(entry)
    assert result.ran
    failures = run_eval.check_expectations(entry, run_fixture)
    assert not failures, failures


def test_every_fixture_file_in_the_corpus_exists():
    for entry in CORPUS["fixtures"]:
        assert (run_eval.FIXTURE_DIR / entry["file"]).is_file(), entry["file"]


def test_known_good_entries_are_well_formed():
    for pkg in CORPUS["known_good"]:
        assert pkg["surface"] in ("npm", "pypi")
        assert pkg["name"]


def test_sandbox_mode_ships_files_that_exist():
    """Regression: the generator lives under src/, not scripts/sandbox/."""
    for rel in ("scripts/sandbox/mcp_exercise.py", "src/scanner/behavioral/synthetic_args.py",
                "tests/fixtures/behavioral/_mcp_stdio.py"):
        assert (run_eval.ROOT / rel).is_file(), rel
