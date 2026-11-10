"""A repository-only security advisory (published on the source repo, never reviewed into
GitHub's global database, so absent from OSV) is read from the repo and scored like an
OSV advisory. GHSA-mvf5-2qqv-rg3c, @modelcontextprotocol/server-everything < 2.0.1, is
the case that motivated it."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from src.scanner import incident_history as ih
from src.scanner import scan as scanmod
from src.scanner.incident_history import (
    REPO_ADVISORY_SOURCE,
    gh_range_affects,
    merge_advisories,
    summarize_repo_advisories,
)
from src.scanner.verdict import cheap_coverage_gap, coverage_gap_notes, decide

PKG = "@modelcontextprotocol/server-everything"

# Shape as GET repos/modelcontextprotocol/servers/security-advisories returns it.
EVERYTHING = {
    "ghsa_id": "GHSA-mvf5-2qqv-rg3c", "cve_id": None, "state": "published",
    "severity": "medium", "withdrawn_at": None,
    "html_url": "https://github.com/modelcontextprotocol/servers/security/advisories/"
                "GHSA-mvf5-2qqv-rg3c",
    "summary": "Cross-Origin Environment Variable Exfiltration in "
               "@modelcontextprotocol/server-everything",
    "vulnerabilities": [
        {"package": {"ecosystem": "npm", "name": PKG},
         "vulnerable_version_range": ">= 2025.9.24, <= 2026.8.31", "patched_versions": ""},
        {"package": {"ecosystem": "npm", "name": PKG},
         "vulnerable_version_range": ">= 1.0.0, < 2.0.1", "patched_versions": "2.0.1"},
    ],
}
# Attack twin: the same monorepo publishes an advisory for a SIBLING package. It must
# never be applied to server-everything.
SIBLING = {
    "ghsa_id": "GHSA-sibl-ing0-0000", "state": "published", "severity": "critical",
    "summary": "flaw in server-git",
    "vulnerabilities": [{"package": {"ecosystem": "npm",
                                     "name": "@modelcontextprotocol/server-git"},
                         "vulnerable_version_range": "< 9.0.0", "patched_versions": "9.0.0"}],
}
# Same name, other ecosystem: never applied.
OTHER_ECO = {
    "ghsa_id": "GHSA-othe-reco-0000", "state": "published", "severity": "high",
    "vulnerabilities": [{"package": {"ecosystem": "pip", "name": PKG},
                         "vulnerable_version_range": "< 9.0.0"}],
}


def test_github_ranges():
    assert gh_range_affects(">= 1.0.0, < 2.0.1", "npm", "2.0.0") is True
    assert gh_range_affects(">= 1.0.0, < 2.0.1", "npm", "2.0.1") is False
    assert gh_range_affects(">= 1.0.0, < 2.0.1", "npm", "0.9.0") is False
    assert gh_range_affects("= 1.2.3", "npm", "1.2.3") is True
    assert gh_range_affects("<= 1.2.3", "npm", "1.2.4") is False
    assert gh_range_affects("> 1.2.3", "npm", "1.2.4") is True
    # date-numbered releases
    assert gh_range_affects(">= 2025.9.24, <= 2026.8.31", "npm", "2026.1.14") is True
    assert gh_range_affects(">= 2025.9.24, <= 2026.8.31", "npm", "2.0.0") is False
    assert gh_range_affects("< 2.0", "PyPI", "1.9.9") is True


def test_unparseable_range_is_unknown_never_unaffected():
    assert gh_range_affects("1.x || 2.x", "npm", "1.0.0") is None
    assert gh_range_affects(">= banana", "npm", "1.0.0") is None
    assert gh_range_affects("", "npm", "1.0.0") is None
    assert gh_range_affects(None, "npm", "1.0.0") is None
    assert gh_range_affects("< 2.0.1", "npm", "not-a-version") is None
    # one bad part spoils the whole range, even if another part already excludes it
    assert gh_range_affects("< 1.0.0, ^^^", "npm", "2.0.0") is None


def test_server_everything_200_is_affected_and_221_is_not():
    hit = summarize_repo_advisories([EVERYTHING, SIBLING, OTHER_ECO], "npm", PKG, "2.0.0")
    assert [a["id"] for a in hit] == ["GHSA-mvf5-2qqv-rg3c"]
    a = hit[0]
    assert a["affects_scanned_version"] is True and a["fixed_in"] == "2.0.1"
    assert a["severity"] == "medium" and a["source"] == REPO_ADVISORY_SOURCE
    assert a["range_unparsed"] is False
    clean = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2.2.1")
    assert clean[0]["affects_scanned_version"] is False
    # a date-numbered release sits in the range with no fix: no upgrade is named
    (dated,) = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2026.1.14")
    assert dated["affects_scanned_version"] is True and dated["fixed_in"] is None
    (f,) = scanmod._own_advisory_findings(PKG, "2026.1.14", [dated])
    assert "No fixed release" in f.remediation


def test_sibling_package_in_the_same_repo_never_matches():
    assert summarize_repo_advisories([SIBLING, OTHER_ECO], "npm", PKG, "1.0.0") == []


def test_withdrawn_and_draft_advisories_are_ignored():
    gone = {**EVERYTHING, "withdrawn_at": "2026-11-01T00:00:00Z"}
    draft = {**EVERYTHING, "state": "draft"}
    assert summarize_repo_advisories([gone, draft], "npm", PKG, "2.0.0") == []


def test_unparsed_range_is_recorded_not_scored():
    odd = {**EVERYTHING, "vulnerabilities": [
        {"package": {"ecosystem": "npm", "name": PKG}, "vulnerable_version_range": "1.x"}]}
    out = summarize_repo_advisories([odd], "npm", PKG, "1.4.0")
    assert out[0]["affects_scanned_version"] is False and out[0]["range_unparsed"] is True
    assert scanmod._own_advisory_findings(PKG, "1.4.0", out) == []


def test_severity_is_the_advisorys_own():
    hi = {**EVERYTHING, "severity": "high"}
    assert summarize_repo_advisories([hi], "npm", PKG, "2.0.0")[0]["severity"] == "high"
    none = {**EVERYTHING, "severity": None}
    assert summarize_repo_advisories([none], "npm", PKG, "2.0.0")[0]["severity"] == "medium"


def test_pypi_and_crates_ecosystem_ids():
    py = {"ghsa_id": "GHSA-py00-0000-0000", "severity": "low", "vulnerabilities": [
        {"package": {"ecosystem": "pip", "name": "Foo_Bar"},
         "vulnerable_version_range": "< 1.1"}]}
    assert summarize_repo_advisories([py], "PyPI", "foo-bar", "1.0")[0][
        "affects_scanned_version"] is True
    rs = {"ghsa_id": "GHSA-rs00-0000-0000", "vulnerabilities": [
        {"package": {"ecosystem": "rust", "name": "foo"}, "vulnerable_version_range": "< 1.1"}]}
    assert summarize_repo_advisories([rs], "crates.io", "foo", "1.0.0")[0][
        "affects_scanned_version"] is True


def test_merge_dedupes_against_osv_by_id_and_alias():
    osv = [{"id": "GHSA-mvf5-2qqv-rg3c", "aliases": []}]
    repo = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2.0.0")
    assert merge_advisories(osv, repo) == []
    with_cve = [{**repo[0], "aliases": ["CVE-2026-1"]}]
    assert merge_advisories([{"id": "GHSA-x", "aliases": ["CVE-2026-1"]}], with_cve) == []
    assert merge_advisories([], repo) == repo


def test_finding_names_the_repository_as_its_source():
    repo = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2.0.0")
    (f,) = scanmod._own_advisory_findings(PKG, "2.0.0", repo)
    assert f.file_path == REPO_ADVISORY_SOURCE and f.severity == "medium"
    assert "2.0.1" in f.remediation


def test_decide_reads_review_for_an_affecting_repo_advisory():
    repo = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2.0.0")
    data = {"trust_score": 86, "findings": {"items": []},
            "metadata": {"files_scanned": 49}, "advisories": repo}
    d = decide(data)
    assert d.decision == "review"
    assert "GHSA-mvf5-2qqv-rg3c" in d.reason and "2.0.1" in d.reason
    clean = summarize_repo_advisories([EVERYTHING], "npm", PKG, "2.2.1")
    assert decide({**data, "trust_score": 90, "advisories": clean}).decision == "safe"


def test_gap_notes_and_certified_hold():
    assert coverage_gap_notes({"coverage_gaps": {"repo_advisory_lookup": "failed"}}) == [
        "the source repository's security advisories could not be read"]
    assert coverage_gap_notes({"coverage_gaps": {"repo_advisory_range_unparsed": 2}}) == [
        "2 repository security advisories had a version range that could not be read"]
    assert cheap_coverage_gap({"coverage_gaps": {"repo_advisory_range_unparsed": 1}})
    # a failed lookup is disclosed, but it is not something an attacker controls
    assert not cheap_coverage_gap({"coverage_gaps": {"repo_advisory_lookup": "failed"}})
    base = {"trust_score": 92, "findings": {"items": []}, "metadata": {"files_scanned": 99}}
    assert decide({**base, "coverage_gaps": {"repo_advisory_lookup": "failed"}}).decision \
        == decide(base).decision


def test_declared_source_slug():
    s = scanmod._declared_source_slug
    assert s("npm", {"repository": {"url": "git+https://github.com/modelcontextprotocol/"
                                           "servers.git"}}) == "modelcontextprotocol/servers"
    assert s("npm", {"repository": "github:o/r"}) == "o/r"
    assert s("crates", {"repository": "https://github.com/o/r"}) == "o/r"
    assert s("pypi", {"declared_repository": "https://github.com/O/R"}) == "o/r"
    assert s("npm", {"repository": "https://gitlab.com/o/r"}) is None
    assert s("docker", {"repository": "https://github.com/o/r"}) is None
    assert s("npm", None) is None


_REAL_CLIENT = httpx.AsyncClient


def _client_factory(handler):
    def make(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return _REAL_CLIENT(*a, **kw)
    return make


def test_fetch_success_is_cached_and_errors_are_not_clean(monkeypatch):
    ih._repo_adv_cache.clear()
    calls = []

    def ok(req):
        calls.append(str(req.url))
        assert req.url.params["state"] == "published"
        return httpx.Response(200, json=[EVERYTHING])
    monkeypatch.setattr(ih.httpx, "AsyncClient", _client_factory(ok))
    got = asyncio.run(ih.fetch_repo_advisories("modelcontextprotocol/servers"))
    assert got["checked"] is True and got["advisories"][0]["ghsa_id"] == EVERYTHING["ghsa_id"]
    again = asyncio.run(ih.fetch_repo_advisories("ModelContextProtocol/servers"))
    assert again.get("cached") is True and len(calls) == 1

    for status in (403, 404, 429, 500):
        ih._repo_adv_cache.clear()
        monkeypatch.setattr(ih.httpx, "AsyncClient", _client_factory(
            lambda req, s=status: httpx.Response(s, json={"message": "no"})))
        got = asyncio.run(ih.fetch_repo_advisories("o/r"))
        assert got["checked"] is False, status
    assert asyncio.run(ih.fetch_repo_advisories("../etc"))["checked"] is False
    ih._repo_adv_cache.clear()


def test_fetch_sends_token_when_configured(monkeypatch):
    ih._repo_adv_cache.clear()
    seen = {}

    def ok(req):
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json=[])
    monkeypatch.setattr(ih.httpx, "AsyncClient", _client_factory(ok))
    asyncio.run(ih.fetch_repo_advisories("o/r", token="t0k"))
    assert seen["auth"] == "Bearer t0k"
    ih._repo_adv_cache.clear()


def _result(version="2.0.0"):
    r = scanmod.ScanResult(repo=f"npm:{PKG}", stars=0, description="", framework="")
    r.artifact_scan = {"version": version}
    r.incident_history = {"checked": True, "advisories": []}
    return r


MANIFEST = {"repository": {"url": "git+https://github.com/modelcontextprotocol/servers.git"}}


@pytest.mark.parametrize("version,affected", [("2.0.0", True), ("2.2.1", False)])
def test_apply_adds_finding_only_for_affected_version(monkeypatch, version, affected):
    async def fake(slug, token=None):
        assert slug == "modelcontextprotocol/servers"
        return {"checked": True, "advisories": [EVERYTHING, SIBLING]}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)
    r = _result(version)
    asyncio.run(scanmod._apply_repo_advisories(r, "npm", PKG, MANIFEST))
    ids = [a["id"] for a in r.incident_history["advisories"]]
    assert ids == ["GHSA-mvf5-2qqv-rg3c"]
    assert bool([f for f in r.findings if f.file_path == REPO_ADVISORY_SOURCE]) is affected


def test_apply_discloses_a_failed_lookup(monkeypatch):
    async def fake(slug, token=None):
        return {"checked": False, "reason": "http_403"}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)
    r = _result()
    asyncio.run(scanmod._apply_repo_advisories(r, "npm", PKG, MANIFEST))
    assert r.coverage_gaps.get("repo_advisory_lookup") == "failed" and not r.findings


def test_apply_skips_an_advisory_osv_already_has(monkeypatch):
    async def fake(slug, token=None):
        return {"checked": True, "advisories": [EVERYTHING]}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)
    r = _result()
    r.incident_history = {"checked": True, "advisories": [
        {"id": "GHSA-mvf5-2qqv-rg3c", "aliases": [], "affects_scanned_version": True}]}
    asyncio.run(scanmod._apply_repo_advisories(r, "npm", PKG, MANIFEST))
    assert len(r.incident_history["advisories"]) == 1 and not r.findings


def test_apply_does_nothing_without_a_github_repo(monkeypatch):
    async def boom(slug, token=None):
        raise AssertionError("should not fetch")
    monkeypatch.setattr(ih, "fetch_repo_advisories", boom)
    r = _result()
    asyncio.run(scanmod._apply_repo_advisories(r, "npm", PKG, {"repository": "https://x.org/a"}))
    assert not r.findings and not r.coverage_gaps


# Regression pins: two advisories from the 11-09 news sweep that DO reach OSV, so they
# reach a scan through the OSV path (records trimmed to the fields the reducer reads).
FASTMCP = {"id": "GHSA-vqqp-x5qm-5qp4", "aliases": [],
           "summary": "OAuth client providers trust the issuer an MCP server advertises",
           "database_specific": {"severity": "HIGH"},
           "affected": [{"package": {"ecosystem": "PyPI", "name": "fastmcp"},
                         "ranges": [{"type": "ECOSYSTEM",
                                     "events": [{"introduced": "0"}, {"fixed": "4.1.2"}]}]}]}
SDK = {"id": "GHSA-jm63-cq47-j5jp", "aliases": [],
       "summary": "Shared transport can deliver one client's messages to another",
       "database_specific": {"severity": "HIGH"},
       "affected": [{"package": {"ecosystem": "npm", "name": "@modelcontextprotocol/server"},
                     "ranges": [{"type": "SEMVER",
                                 "events": [{"introduced": "2.0.0"}, {"fixed": "2.3.0"}]}]}]}


@pytest.mark.parametrize("rec,eco,name,bad,good,fix", [
    (FASTMCP, "PyPI", "fastmcp", "4.1.1", "4.1.2", "4.1.2"),
    (SDK, "npm", "@modelcontextprotocol/server", "2.2.0", "2.3.0", "2.3.0"),
])
def test_osv_path_pins(rec, eco, name, bad, good, fix):
    from src.scanner.incident_history import summarize_advisories
    (hit,) = summarize_advisories([rec], eco, bad, name)
    assert hit["affects_scanned_version"] is True and hit["fixed_in"] == fix
    assert hit["severity"] == "high"
    (ok,) = summarize_advisories([rec], eco, good, name)
    assert ok["affects_scanned_version"] is False
    data = {"trust_score": 80, "findings": {"items": []}, "metadata": {"files_scanned": 9},
            "advisories": [hit]}
    assert decide(data).decision == "review"
