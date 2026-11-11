"""Versions the registry no longer serves, and yanked PyPI releases (gap audit A3,
design reviewed by agentgraph-83 2026-11-11).

(a) removed + a compromise record listing that exact version -> Do not connect;
(b) removed, known to have existed, no such record -> Review, never Certified;
(c) a yanked release is scanned as usual; the yank is LOW (MEDIUM when its reason says
    security), so a clean yanked version stays Safe with a note.
Twins: a record for a NEIGHBOURING version never trips (a); a typo stays an error."""
from __future__ import annotations

import pytest

from src.config import settings
from src.scanner import artifact_fetch as af
from src.scanner import incident_history as ih
from src.scanner import verdict

MAL = {"id": "MAL-2026-1234", "summary": "compromised release",
       "affected": [{"package": {"ecosystem": "PyPI", "name": "litellm"},
                     "versions": ["1.107.0"]}]}
MAL_NEIGHBOUR = {"id": "MAL-2026-9999", "summary": "compromised release",
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "litellm"},
                               "versions": ["1.107.1"]}]}
MAL_RANGE_ONLY = {"id": "MAL-2026-5555", "affected": [{
    "package": {"ecosystem": "PyPI", "name": "litellm"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}


def test_exact_version_incidents_needs_the_exact_version():
    assert ih.exact_version_incidents([MAL], "1.107.0", "PyPI", "litellm") == ["MAL-2026-1234"]
    assert ih.exact_version_incidents([MAL_NEIGHBOUR], "1.107.0", "PyPI", "litellm") == []
    assert ih.exact_version_incidents([MAL_RANGE_ONLY], "1.107.0", "PyPI", "litellm") == []
    # another package in the same record never counts
    other = {**MAL, "affected": [{"package": {"ecosystem": "PyPI", "name": "x"},
                                  "versions": ["1.107.0"]}]}
    assert ih.exact_version_incidents([other], "1.107.0", "PyPI", "litellm") == []
    # a plain advisory (not a compromise record) is not an incident
    plain = {**MAL, "id": "GHSA-aaaa-bbbb-cccc"}
    assert ih.exact_version_incidents([plain], "1.107.0", "PyPI", "litellm") == []


@pytest.mark.parametrize("eco,msg,ok", [
    ("npm", "npm version not found: x@1.0.0", True),
    ("pypi", "not found: https://pypi.org/pypi/litellm/1.107.0/json", True),
    ("pypi", "not found: https://pypi.org/pypi/litellm/json", True),
    ("npm", "registry status 500 for https://registry.npmjs.org/x", False),
    ("crates", "npm version not found: x@1", False),
])
def test_version_missing_error(eco, msg, ok):
    assert af.is_version_missing_error(eco, msg) is ok


def _data(res):
    items = [{"severity": f.severity, "name": f.name, "category": f.category,
              "file_path": f.file_path} for f in res.findings]
    counts = {s: sum(1 for f in res.findings if f.severity == s)
              for s in ("critical", "high", "medium", "low")}
    return {"trust_score": res.trust_score, "findings": {"items": items, **counts},
            "metadata": {"files_scanned": res.files_scanned},
            "coverage_gaps": res.coverage_gaps or {}, "coverage": {"surface": "pypi"},
            "incident_history": res.incident_history or {}}


@pytest.fixture
def removed(monkeypatch):
    monkeypatch.setattr(settings, "scanner_scan_artifact", True)
    state = {"probe": {"published_before": False}, "vulns": [MAL]}

    async def missing(name, version=None, *, client=None):
        raise af.ArtifactFetchError(f"not found: https://pypi.org/pypi/{name}/{version}/json")

    async def probe(eco, name, version, *, client=None):
        return state["probe"]

    async def vulns(surface, name):
        return state["vulns"]
    monkeypatch.setattr(af, "fetch_pypi_artifact", missing)
    monkeypatch.setattr(af, "probe_removed_version", probe)
    monkeypatch.setattr(ih, "fetch_osv_vulns", vulns)
    return state


async def test_a_removed_after_compromise_is_do_not_connect(removed):
    from src.scanner.scan import scan_package
    res = await scan_package("pypi", "litellm", "1.107.0")
    assert res.error is None
    (f,) = res.findings
    assert f.severity == "critical" and "MAL-2026-1234" in f.name
    assert res.coverage_gaps["version_removed"] is True and res.files_scanned == 0
    d = verdict.decide(_data(res))
    assert d.decision == "do_not_connect" and "malicious" in d.reason


async def test_a_neighbour_record_does_not_trip_and_unknown_stays_an_error(removed):
    from src.scanner.scan import scan_package
    removed["vulns"] = [MAL_NEIGHBOUR]
    res = await scan_package("pypi", "litellm", "1.107.0")
    assert res.error and res.error.startswith("not found")   # a typo looks the same


async def test_b_removed_without_a_record_is_review(removed):
    from src.scanner.scan import scan_package
    removed["vulns"] = []
    removed["probe"] = {"published_before": True}           # npm's time map lists it
    res = await scan_package("pypi", "litellm", "1.107.0")
    (f,) = res.findings
    assert f.severity == "high" and "removed from the registry" in f.name
    d = verdict.decide(_data(res))
    assert d.decision == "review"
    assert res.certified is False


async def test_package_that_cannot_be_read_keeps_the_error(removed):
    from src.scanner.scan import scan_package
    removed["probe"] = None
    res = await scan_package("pypi", "litellm", "1.107.0")
    assert res.error


async def test_no_version_given_keeps_the_error(removed):
    from src.scanner.scan import scan_package
    res = await scan_package("pypi", "litellm")
    assert res.error


def test_yank_severity():
    from src.scanner.scan import _yank_finding
    assert _yank_finding("x", "1.0", None).severity == "low"
    assert _yank_finding("x", "1.0", "broken wheel for py3.13").severity == "low"
    sec = _yank_finding("x", "1.0", "Compromised release, see GHSA-xxxx")
    assert sec.severity == "medium" and "security" in sec.name


def test_yanked_release_files_are_still_read():
    urls = [{"packagetype": "bdist_wheel", "url": "https://f/x-1.0-py3-none-any.whl",
             "filename": "x-1.0-py3-none-any.whl", "yanked": True, "size": 10}]
    assert af._wheel_candidates(urls)
    mixed = urls + [{"packagetype": "bdist_wheel", "url": "https://f/x-1.0-cp312.whl",
                     "filename": "x-1.0-cp312-cp312-linux.whl", "size": 10}]
    assert [u for _, _, u in af._wheel_candidates(mixed)] == ["https://f/x-1.0-cp312.whl"]
