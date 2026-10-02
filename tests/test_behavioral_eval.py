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


@pytest.mark.parametrize("entry", CORPUS["skill_fixtures"],
                         ids=[e["label"] for e in CORPUS["skill_fixtures"]])
def test_skill_fixture_meets_its_expectations(entry):
    """Fixture SKILLS through the real in-container exerciser (skill_exercise.sh), locally:
    hooks and scripts run against a temp mount, the network stubbed out, the entry's
    ``simulated_egress`` standing in for the sandbox's capture."""
    result = run_eval.run_skill_fixture_local(entry)
    assert result.ran and result.plan == "skill"
    failures = run_eval.check_expectations(entry, result)
    assert not failures, failures


def test_every_fixture_file_in_the_corpus_exists():
    for entry in CORPUS["fixtures"]:
        assert (run_eval.FIXTURE_DIR / entry["file"]).is_file(), entry["file"]
    for entry in CORPUS["skill_fixtures"]:
        assert (run_eval.SKILL_FIXTURE_DIR / entry["dir"] / "SKILL.md").is_file(), entry["dir"]


def test_known_good_entries_are_well_formed():
    for pkg in CORPUS["known_good"]:
        assert pkg["surface"] in ("npm", "pypi")
        assert pkg["name"]
    for skill in CORPUS.get("known_good_skills", []):
        assert skill["repo"].count("/") == 1, skill


def test_sandbox_mode_ships_files_that_exist():
    """Regression: the generator lives under src/, not scripts/sandbox/."""
    for rel in ("scripts/sandbox/mcp_exercise.py", "src/scanner/behavioral/synthetic_args.py",
                "tests/fixtures/behavioral/_mcp_stdio.py"):
        assert (run_eval.ROOT / rel).is_file(), rel
