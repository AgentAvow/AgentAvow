"""A package scan whose critical advisory has a version range we cannot read never shows
the Certified mark (Kenne, 2026-11-19). The answer itself does not move: an unreadable
range is disclosed, never read as affecting.

Two ways in:

- a repository security advisory (``repo_advisory_range_unparsed``, any severity), the
  real case being PyPI jupyter-mcp-server 2.2.6 and GHSA-rvjm-7hvp-f868 (CVSS 9.6,
  range ``<= commit fe0a1d4f0592``; the fixture is the repository's advisory list);
- an advisory from the vulnerability database (OSV) whose only ranges are commit
  ranges or versions we cannot parse (``advisory_range_unparsed``, critical label or
  CVSS >= 9.0). Before this, such a record read as "not affected" with no disclosure.

No network: the repository lookup is replaced with the fixture."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.scanner import incident_history as ih
from src.scanner import scan as scanmod
from src.scanner.incident_history import (
    REPO_ADVISORY_SOURCE,
    advisory_readable,
    summarize_advisories,
    unreadable_critical_advisories,
)
from src.scanner.verdict import (
    certified_mark_status,
    cheap_coverage_gap,
    coverage_gap_notes,
    decide,
)

FIXTURE = (Path(__file__).parent / "fixtures" / "repo_advisories"
           / "datalayer_jupyter-mcp-server.json")
PKG = "jupyter-mcp-server"
MANIFEST = {"declared_repository": "https://github.com/datalayer/jupyter-mcp-server"}
CERTIFIED = {"eligible": True, "checks": {"no_critical_or_high": True}}


def _result(version: str, osv_advisories: list | None = None):
    r = scanmod.ScanResult(repo=f"pypi:{PKG}", stars=0, description="", framework="")
    r.artifact_scan = {"version": version}
    r.incident_history = {"checked": True, "advisories": list(osv_advisories or [])}
    return r


def _view(r) -> dict:
    """The fields the mark and the answer read, as the API serves them."""
    return {"trust_score": 92, "findings": {"items": []},
            "metadata": {"files_scanned": 70}, "certified": CERTIFIED,
            "coverage_gaps": r.coverage_gaps or {},
            "incident_history": r.incident_history}


def _fixture_lookup(monkeypatch):
    advisories = json.loads(FIXTURE.read_text())

    async def fake(slug, token=None):
        assert slug == "datalayer/jupyter-mcp-server"
        return {"checked": True, "advisories": advisories}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)


def _scan_advisories(r) -> None:
    asyncio.run(scanmod._apply_repo_advisories(r, "pypi", PKG, MANIFEST))
    scanmod._flag_unreadable_critical_advisories(r)


def test_jupyter_mcp_server_repo_case_is_safe_without_the_mark(monkeypatch):
    _fixture_lookup(monkeypatch)
    r = _result("2.2.6")
    _scan_advisories(r)
    by_id = {a["id"]: a for a in r.incident_history["advisories"]}
    rvjm = by_id["GHSA-rvjm-7hvp-f868"]
    assert rvjm["range_unparsed"] is True and rvjm["affects_scanned_version"] is False
    assert rvjm["cvss"] == 9.6 and rvjm["severity"] == "critical"
    assert not any(a["affects_scanned_version"] for a in by_id.values())
    assert not r.findings  # nothing read as affecting 2.2.6
    assert r.coverage_gaps == {"repo_advisory_range_unparsed": 1}
    view = _view(r)
    d = decide(view)
    assert d.decision == "safe"  # the answer stays Safe
    assert cheap_coverage_gap(view)
    assert certified_mark_status(view, d) == (False, "coverage_gaps")


def test_an_older_affected_release_still_answers_do_not_connect(monkeypatch):
    _fixture_lookup(monkeypatch)
    r = _result("1.0.2")
    _scan_advisories(r)
    # A critical CVE that affects the version decides (the readable ranges do).
    assert r.findings and decide(_view(r)).decision == "do_not_connect"


def _osv(vid, severity=None, ranges=None, versions=None, cvss=None, aliases=()):
    rec = {"id": vid, "aliases": list(aliases), "summary": "flaw",
           "affected": [{"package": {"ecosystem": "PyPI", "name": PKG},
                         "ranges": ranges or [], "versions": versions or []}]}
    if severity:
        rec["database_specific"] = {"severity": severity}
    if cvss is not None:
        rec["severity"] = [{"type": "CVSS_V3", "score": str(cvss)}]
    return rec


GIT_ONLY = [{"type": "GIT", "repo": "https://github.com/datalayer/jupyter-mcp-server",
             "events": [{"introduced": "0"}, {"fixed": "fe0a1d4f0592"}]}]
READABLE = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.1.3"}]}]
BAD_EVENT = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                               {"fixed": "commit fe0a1d4"}]}]


@pytest.mark.parametrize("rec,readable", [
    (_osv("GHSA-a", ranges=GIT_ONLY), False),
    (_osv("GHSA-b", ranges=READABLE), True),
    (_osv("GHSA-c", ranges=BAD_EVENT), False),
    (_osv("GHSA-d", ranges=GIT_ONLY, versions=["1.0.0"]), True),  # listed versions
    (_osv("GHSA-e"), False),  # no range, no versions
])
def test_advisory_readable(rec, readable):
    assert advisory_readable(rec, "PyPI", "2.2.6", PKG) is readable


def test_an_unparseable_scanned_version_cannot_be_placed_in_a_range():
    # Deliberate: with ranges alone, no range can place a version that does not parse.
    assert advisory_readable(_osv("GHSA-b", ranges=READABLE), "PyPI", "not a version",
                             PKG) is False


def test_an_exact_versions_list_answers_an_unparseable_scanned_version():
    rec = _osv("GHSA-b", "CRITICAL", ranges=READABLE, versions=["1.0.0", "weird-1"])
    assert advisory_readable(rec, "PyPI", "not a version", PKG) is True
    (clean,) = summarize_advisories([rec], "PyPI", "not a version", PKG)
    assert clean["affects_scanned_version"] is False and "range_unparsed" not in clean
    (hit,) = summarize_advisories([rec], "PyPI", "weird-1", PKG)
    assert hit["affects_scanned_version"] is True and "range_unparsed" not in hit


def test_osv_flags_only_records_it_could_not_read():
    out = {a["id"]: a for a in summarize_advisories([
        _osv("GHSA-git", "CRITICAL", GIT_ONLY),
        _osv("GHSA-ok", "CRITICAL", READABLE),
    ], "PyPI", "2.2.6", PKG)}
    assert out["GHSA-git"]["range_unparsed"] is True
    assert "range_unparsed" not in out["GHSA-ok"]  # other entries keep their shape
    assert out["GHSA-ok"]["affects_scanned_version"] is False


def test_osv_one_readable_record_of_the_same_flaw_answers_for_it():
    out = summarize_advisories([
        _osv("GHSA-x", "CRITICAL", GIT_ONLY, aliases=["PYSEC-1"]),
        _osv("PYSEC-1", None, READABLE, aliases=["GHSA-x"]),
    ], "PyPI", "2.2.6", PKG)
    assert len(out) == 1 and "range_unparsed" not in out[0]


def test_osv_affected_is_never_flagged_unparsed():
    out = summarize_advisories([_osv("GHSA-x", "CRITICAL", READABLE)], "PyPI", "2.0.0", PKG)
    assert out[0]["affects_scanned_version"] is True and "range_unparsed" not in out[0]


def test_unreadable_entries_survive_the_20_entry_cut():
    recs = [_osv(f"GHSA-{i:04d}", "LOW", READABLE) for i in range(30)]
    recs.append(_osv("GHSA-zzzz", "CRITICAL", GIT_ONLY))
    out = summarize_advisories(recs, "PyPI", "2.2.6", PKG)
    assert len(out) == 20 and out[0]["id"] == "GHSA-zzzz"


@pytest.mark.parametrize("entry,counted", [
    ({"severity": "critical"}, True),
    ({"severity": "medium", "cvss": 9.0}, True),
    ({"severity": "high", "cvss": 8.9}, False),
    ({"severity": "high"}, False),
    ({"severity": "critical", "affects_scanned_version": True}, False),
    ({"severity": "critical", "range_unparsed": False}, False),
    ({"severity": "critical", "source": REPO_ADVISORY_SOURCE}, False),  # counted apart
    ({"severity": "medium", "cvss": True}, False),
])
def test_unreadable_critical_count(entry, counted):
    a = {"id": "GHSA-x", "range_unparsed": True, "affects_scanned_version": False, **entry}
    assert unreadable_critical_advisories([a]) == (1 if counted else 0)


def test_osv_unreadable_critical_withholds_the_mark_and_keeps_safe(monkeypatch):
    async def none(slug, token=None):
        return {"checked": True, "advisories": []}
    monkeypatch.setattr(ih, "fetch_repo_advisories", none)
    osv = summarize_advisories([_osv("GHSA-git", "CRITICAL", GIT_ONLY)], "PyPI", "2.2.6", PKG)
    r = _result("2.2.6", osv)
    _scan_advisories(r)
    assert r.coverage_gaps == {"advisory_range_unparsed": 1}
    assert not r.findings
    view = _view(r)
    d = decide(view)
    assert d.decision == "safe"
    assert certified_mark_status(view, d) == (False, "coverage_gaps")
    assert coverage_gap_notes(view) == [
        "1 critical security advisory had a version range that could not be read"]


def test_osv_unreadable_high_keeps_the_mark(monkeypatch):
    async def none(slug, token=None):
        return {"checked": True, "advisories": []}
    monkeypatch.setattr(ih, "fetch_repo_advisories", none)
    osv = summarize_advisories([_osv("GHSA-git", "HIGH", GIT_ONLY)], "PyPI", "2.2.6", PKG)
    r = _result("2.2.6", osv)
    _scan_advisories(r)
    assert not r.coverage_gaps
    assert certified_mark_status(_view(r)) == (True, "")


def test_osv_copy_of_the_repo_advisory_still_withholds_the_mark(monkeypatch):
    """When the repository's advisory reaches OSV with only a commit range, the repo copy
    merges into the OSV entry (no ``repo_advisory_range_unparsed``); the OSV entry's own
    unreadable range, scored 9.6 from the repository, still takes the mark off."""
    _fixture_lookup(monkeypatch)
    osv = summarize_advisories([_osv("GHSA-rvjm-7hvp-f868", None, GIT_ONLY)],
                               "PyPI", "2.2.6", PKG)
    assert osv[0]["severity"] == "medium" and osv[0]["cvss"] is None
    r = _result("2.2.6", osv)
    _scan_advisories(r)
    rvjm = next(a for a in r.incident_history["advisories"]
                if a["id"] == "GHSA-rvjm-7hvp-f868")
    assert rvjm.get("source") != REPO_ADVISORY_SOURCE and rvjm["cvss"] == 9.6
    assert "repo_advisory_range_unparsed" not in r.coverage_gaps
    assert r.coverage_gaps["advisory_range_unparsed"] == 1
    view = _view(r)
    d = decide(view)
    assert d.decision == "safe"
    assert certified_mark_status(view, d) == (False, "coverage_gaps")


def test_a_withdrawn_record_never_costs_the_mark():
    rec = _osv("GHSA-gone", "CRITICAL", GIT_ONLY) | {"withdrawn": "2026-11-01T00:00:00Z"}
    (a,) = summarize_advisories([rec], "PyPI", "2.2.6", PKG)
    assert "range_unparsed" not in a
    assert unreadable_critical_advisories([a]) == 0


def test_a_withdrawn_readable_twin_does_not_answer_for_a_live_record():
    live = _osv("GHSA-x", "CRITICAL", GIT_ONLY, aliases=["PYSEC-1"])
    gone = _osv("PYSEC-1", None, READABLE, aliases=["GHSA-x"]) | {"withdrawn": "2026-11-01"}
    (a,) = summarize_advisories([live, gone], "PyPI", "2.2.6", PKG)
    assert a["range_unparsed"] is True


def test_a_record_without_an_entry_for_this_package_is_ignored():
    rec = {"id": "GHSA-other", "summary": "flaw", "database_specific": {"severity": "CRITICAL"},
           "affected": [{"package": {"ecosystem": "PyPI", "name": "some-other-package"},
                         "ranges": GIT_ONLY}]}
    (a,) = summarize_advisories([rec], "PyPI", "2.2.6", PKG)
    assert "range_unparsed" not in a
    assert unreadable_critical_advisories([a]) == 0


def _many_with_one_unreadable_critical():
    recs = [_osv(f"GHSA-a{i:03d}", "LOW", READABLE) for i in range(25)]
    return recs + [_osv("GHSA-zzzz", "CRITICAL", GIT_ONLY)]


def test_an_unreadable_critical_past_the_cut_still_withholds_the_mark(monkeypatch):
    """25 readable low OSV advisories, one critical with only a commit range, and one
    repository advisory: the merge re-sorts and cuts to 20, and the critical must still
    be counted (it is counted before any cut, and the merge sorts the same way)."""
    async def osv(surface, name):
        return _many_with_one_unreadable_critical()
    monkeypatch.setattr(ih, "fetch_osv_vulns", osv)
    repo = {"ghsa_id": "GHSA-repo-only-0001", "state": "published", "severity": "low",
            "summary": "repo-only flaw",
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": PKG},
                                 "vulnerable_version_range": "< 1.0.0",
                                 "patched_versions": "1.0.0"}]}

    async def repo_lookup(slug, token=None):
        return {"checked": True, "advisories": [repo]}
    monkeypatch.setattr(ih, "fetch_repo_advisories", repo_lookup)
    inc = asyncio.run(ih.fetch_incident_history("pypi", PKG, "2.2.6"))
    assert inc["unreadable_critical"] == ["GHSA-zzzz"]
    r = _result("2.2.6")
    r.incident_history = inc
    _scan_advisories(r)
    ids = [a["id"] for a in r.incident_history["advisories"]]
    assert len(ids) == 20 and ids[0] == "GHSA-zzzz"  # same 3-key order after the merge
    assert r.coverage_gaps == {"advisory_range_unparsed": 1}
    assert certified_mark_status(_view(r))[0] is False


def test_a_counted_id_cut_from_the_list_still_counts_once():
    kept = [{"id": "GHSA-zzzz", "severity": "critical", "range_unparsed": True,
             "affects_scanned_version": False}]
    assert unreadable_critical_advisories(kept, ["GHSA-zzzz"]) == 1
    assert unreadable_critical_advisories([], ["GHSA-zzzz"]) == 1
    assert unreadable_critical_advisories([], "GHSA-zzzz") == 0  # not a list: ignored
