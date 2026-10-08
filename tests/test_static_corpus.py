"""Static recall gate: the known-bad fixtures must keep raising their rule after the
precision pass, as a BLOCKING defect.

Fixtures live in ``tests/fixtures/static/known_bad/<technique>/`` — synthetic
reproductions of the technique behind a known-malicious package (tagged with the OSV
id they mirror in ``manifest.json``). They are scanned through the artifact path
(``scan_artifact_files``) exactly like a downloaded package; nothing is executed or
installed.

The known-good side (PR 2): ``tests/corpus/static/`` pins the top 200 PyPI + top 200 npm
packages; ``scripts/corpus/run_static_corpus.py`` runs all of them in CI. Here, a
20-package subset (``subset.json``) is re-scanned from the archive cache and must match
the committed ``expected.json`` exactly. No network: when the cache
(``AGENTAVOW_CORPUS_CACHE`` or ``~/.cache/agentavow-static-corpus``) lacks an archive,
that package is skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.corpus.run_static_corpus import THIN_COVERAGE_REASON
from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.artifact_scan import scan_artifact_files
from src.scanner.scan import (
    _CRITICAL_CEILING,
    _HIGH_CEILING,
    ScanResult,
    _calculate_trust_score,
    _finding_is_blocking,
)

FIXTURES = Path(__file__).parent / "fixtures" / "static" / "known_bad"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _load_fixture(entry: dict) -> ArtifactFetchResult:
    root = FIXTURES / entry["dir"]
    eco = entry["ecosystem"]
    fetched = ArtifactFetchResult(
        ecosystem=eco, name=f"synthetic-{entry['dir']}", version="0.0.0",
        kind="tarball" if eco == "npm" else "sdist", ok=True,
    )
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            fetched.files[rel] = _make_file(rel, p.read_bytes())
    fetched.file_count = len(fetched.files)
    if eco == "npm" and "package.json" in fetched.files:
        fetched.packaged_manifest = json.loads(fetched.files["package.json"].text or "{}")
    return fetched


def _scan(entry: dict) -> tuple[list, ScanResult]:
    fetched = _load_fixture(entry)
    findings, files_scanned, _hook = scan_artifact_files(fetched)
    result = ScanResult(repo=f"{entry['ecosystem']}:{entry['dir']}", stars=0,
                        description="", framework="")
    result.findings = findings
    result.files_scanned = files_scanned
    result.total_scannable_files = files_scanned
    result.trust_score = _calculate_trust_score(result)
    return findings, result


def _at_least(sev: str, floor: str) -> bool:
    return _SEV_RANK[sev] <= _SEV_RANK[floor]


@pytest.mark.parametrize("entry", MANIFEST["fixtures"], ids=[e["dir"] for e in MANIFEST["fixtures"]])
def test_known_bad_fixture_raises_a_blocking_defect(entry):
    findings, result = _scan(entry)
    expectations = [entry["must_raise"]]
    if entry.get("must_also_raise"):
        expectations.append(entry["must_also_raise"])
    for exp in expectations:
        hits = [f for f in findings if f.name.startswith(exp["name_prefix"])]
        assert hits, (
            f"{entry['dir']} ({entry['mirrors']}): no finding named "
            f"{exp['name_prefix']!r}; got {[f.name for f in findings]}"
        )
        best = min(hits, key=lambda f: _SEV_RANK.get(f.severity, 9))
        assert _at_least(best.severity, exp["min_severity"]), (
            f"{entry['dir']}: {best.name} is {best.severity}, expected >= {exp['min_severity']}"
        )
        assert best.kind == "defect", f"{entry['dir']}: {best.name} was downgraded to a capability"
        assert best.installed, f"{entry['dir']}: {best.name} was gated as not-installed"
        assert _finding_is_blocking(best), f"{entry['dir']}: {best.name} is not blocking"
    # The headline number must agree: a blocking critical/high caps the score.
    floor = entry["must_raise"]["min_severity"]
    ceiling = _CRITICAL_CEILING if floor == "critical" else _HIGH_CEILING
    assert result.trust_score <= ceiling, (
        f"{entry['dir']}: score {result.trust_score} above the {floor} ceiling {ceiling}"
    )


def test_manifest_tags_every_fixture_with_its_osv_mirror():
    dirs = {p.name for p in FIXTURES.iterdir() if p.is_dir()}
    listed = {e["dir"] for e in MANIFEST["fixtures"]}
    assert dirs == listed, f"fixture dirs {dirs ^ listed} missing from manifest or disk"
    for e in MANIFEST["fixtures"]:
        assert e["mirrors"], e["dir"]


# ── known-good subset (from the archive cache; skipped without it) ─────────────

CORPUS = Path(__file__).parent / "corpus" / "static"
_CORPUS_MANIFEST = {e["id"]: e for e in json.loads((CORPUS / "manifest.json").read_text())
                    ["packages"]}
_EXPECTED = json.loads((CORPUS / "expected.json").read_text())["packages"]
_SUBSET = json.loads((CORPUS / "subset.json").read_text())["ids"]


def _cache_dir() -> Path:
    from scripts.corpus.corpus_lib import default_cache_dir

    return default_cache_dir()


def _cached(entry: dict) -> bool:
    from scripts.corpus.corpus_lib import cache_path

    shas = [entry["archive"]["sha256"]]
    if entry.get("wheel"):
        shas.append(entry["wheel"]["sha256"])
    return all(cache_path(_cache_dir(), s).is_file() for s in shas)


def test_subset_is_twenty_pinned_packages_with_snapshots():
    assert len(_SUBSET) == 20 and "pypi/mcp" in _SUBSET
    for pid in _SUBSET:
        assert pid in _CORPUS_MANIFEST and pid in _EXPECTED, pid


def test_no_known_good_package_is_do_not_connect_in_the_snapshot():
    """The committed snapshot itself honours the gate: do_not_connect only where the
    manifest records a reviewed, open false-positive class."""
    for pid, r in _EXPECTED.items():
        if r.get("label") == "do_not_connect":
            assert (_CORPUS_MANIFEST[pid].get("known_fp") or {}).get("label") == \
                "do_not_connect", pid
        exp = _CORPUS_MANIFEST.get(pid, {}).get("expect")
        # Thin coverage ("nothing found, but little code to inspect") is not a finding:
        # a package expected safe may read it (open decision, follow-up #19).
        thin = r["label"] == "review" and r.get("reason") == THIN_COVERAGE_REASON
        if exp and not (exp == "safe" and thin):
            assert r["label"] == exp, (pid, r["label"], exp)


@pytest.mark.parametrize("pid", _SUBSET)
def test_subset_package_matches_snapshot(pid):
    entry = _CORPUS_MANIFEST[pid]
    if not _cached(entry):
        pytest.skip(f"{pid}: archive not in the corpus cache (no network in the unit suite)")
    from scripts.corpus.run_static_corpus import public, scan_entry

    got = public(scan_entry(entry, str(_cache_dir()), offline=True))
    assert got == _EXPECTED[pid], f"{pid} drifted from expected.json: {got}"
