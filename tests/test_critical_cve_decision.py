"""A published advisory with CVSS 9.0 or more that affects the scanned version answers
Do not connect (Kenne, 2026-11-18), and every reason names an affecting advisory by its
CVE. The decision table itself (both twins) is in tests/test_decision.py; this file pins
where the CVSS score comes from: the repository's own security advisory as GitHub
returns it (records trimmed to the fields the reducer reads)."""
from __future__ import annotations

import asyncio

from src.scanner import incident_history as ih
from src.scanner import scan as scanmod
from src.scanner.incident_history import (
    enrich_cvss,
    gh_advisory_cvss,
    summarize_repo_advisories,
)
from src.scanner.verdict import advisory_is_critical, decide

TODOIST = "@doist/todoist-mcp"
MSSQL = "@connorbritain/mssql-mcp-core"

# GET repos/<owner>/<repo>/security-advisories, one record each.
TODOIST_ADVISORY = {
    "ghsa_id": "GHSA-833v-v58w-294h", "cve_id": "CVE-2026-76807", "state": "published",
    "severity": "critical", "withdrawn_at": None, "summary": "Critical flaw",
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", "score": 9.3},
    "cvss_severities": {
        "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                    "score": 9.3},
        "cvss_v4": {"vector_string": None, "score": None}},
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": TODOIST},
                         "vulnerable_version_range": "<= 10.3.2",
                         "patched_versions": "10.3.3"}],
}
MSSQL_ADVISORY = {
    "ghsa_id": "GHSA-mssq-0000-0001", "cve_id": "CVE-2026-63129", "state": "published",
    "severity": "high", "withdrawn_at": None, "summary": "High flaw",
    "cvss": {"vector_string": "CVSS:3.1/AV:N", "score": 8.8},
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": MSSQL},
                         "vulnerable_version_range": "< 0.6.0", "patched_versions": "0.6.0"}],
}


def test_cvss_prefers_v4_then_v3_then_legacy():
    assert gh_advisory_cvss(TODOIST_ADVISORY) == 9.3
    assert gh_advisory_cvss({"cvss_severities": {"cvss_v4": {"score": 9.1},
                                                 "cvss_v3": {"score": 8.0}}}) == 9.1
    assert gh_advisory_cvss(MSSQL_ADVISORY) == 8.8
    assert gh_advisory_cvss({"cvss_severities": {"cvss_v3": {"score": 7.5}},
                             "cvss": {"score": 9.9}}) == 7.5
    for bad in ({}, {"cvss": None}, {"cvss": {"score": 0}}, {"cvss": {"score": True}},
                {"cvss": {"score": "9.8"}}, {"cvss": {"score": 11}}, None, "x"):
        assert gh_advisory_cvss(bad) is None


def test_repo_advisory_carries_cvss():
    (a,) = summarize_repo_advisories([TODOIST_ADVISORY], "npm", TODOIST, "10.3.2")
    assert a["cvss"] == 9.3 and a["aliases"] == ["CVE-2026-76807"]
    assert a["affects_scanned_version"] is True and advisory_is_critical(a)
    (b,) = summarize_repo_advisories([MSSQL_ADVISORY], "npm", MSSQL, "0.5.0")
    assert b["cvss"] == 8.8 and not advisory_is_critical(b)


def _data(advisories, items=(), high=0, crit=0, score=60):
    return {"trust_score": score,
            "findings": {"items": list(items), "critical": crit, "high": high},
            "metadata": {"files_scanned": 120},
            "incident_history": {"checked": True, "advisories": advisories}}


def test_critical_cve_on_the_scanned_version_is_do_not_connect():
    adv = summarize_repo_advisories([TODOIST_ADVISORY], "npm", TODOIST, "10.3.2")
    trifecta = {"category": "prompt_injection", "name": "Lethal trifecta", "severity": "high",
                "file_path": "src/index.ts", "line_number": 1, "shipped": True,
                "kind": "defect", "installed": True}
    d = decide(_data(adv, [trifecta], high=1, score=45))
    assert d.decision == "do_not_connect"
    assert d.reason == ("critical known vulnerability CVE-2026-76807 affects this version "
                        "(CVSS 9.3; fixed in 10.3.3)")


def test_fixed_version_is_unchanged():
    adv = summarize_repo_advisories([TODOIST_ADVISORY], "npm", TODOIST, "10.3.3")
    assert adv[0]["affects_scanned_version"] is False
    d = decide(_data(adv, score=90))
    assert d.decision == "safe" and "CVE" not in d.reason


def test_high_cve_stays_review_and_is_named():
    adv = summarize_repo_advisories([MSSQL_ADVISORY], "npm", MSSQL, "0.5.0")
    d = decide(_data(adv))
    assert d.decision == "review"
    assert d.reason == "known vulnerability CVE-2026-63129 affects this version (fixed in 0.6.0)"


def _result(version, advisories):
    r = scanmod.ScanResult(repo=f"npm:{TODOIST}", stars=0, description="", framework="")
    r.artifact_scan = {"version": version}
    r.incident_history = {"checked": True, "advisories": advisories}
    return r


def test_osv_entry_takes_the_repositorys_cvss(monkeypatch):
    """The same advisory already read from OSV (which carries only a vector) keeps its
    entry and gains the repository's CVSS score; no second finding is added."""
    async def fake(slug, token=None):
        return {"checked": True, "advisories": [TODOIST_ADVISORY]}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)
    osv = {"id": "GHSA-833v-v58w-294h", "aliases": ["CVE-2026-76807"], "severity": "critical",
           "fixed_in": "10.3.3", "affects_scanned_version": True}
    r = _result("10.3.2", [osv])
    manifest = {"repository": {"url": "git+https://github.com/todoist/todoist-mcp.git"}}
    asyncio.run(scanmod._apply_repo_advisories(r, "npm", TODOIST, manifest))
    (a,) = r.incident_history["advisories"]
    assert a["cvss"] == 9.3 and not r.findings
    assert "cvss" not in osv  # the caller's dict is not modified


def test_enrich_never_overwrites_a_score():
    existing = [{"id": "GHSA-a", "cvss": 7.0}, {"id": "GHSA-b", "aliases": ["CVE-1"]}]
    enrich_cvss(existing, [{"id": "GHSA-a", "cvss": 9.9}, {"id": "GHSA-x", "aliases": ["CVE-1"],
                                                          "cvss": 9.1}])
    assert existing == [{"id": "GHSA-a", "cvss": 7.0},
                        {"id": "GHSA-b", "aliases": ["CVE-1"], "cvss": 9.1}]
