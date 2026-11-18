"""Repository advisories on date-numbered versions, copied from
GET repos/modelcontextprotocol/servers/security-advisories (2026-11-16).

A live scan of PyPI mcp-server-git 2026.11.11 reported all three of its advisories as
"a version range that could not be read". The ranges were fine: the prod image had no
``packaging`` module (only dev tools pulled it in), and the PEP 440 comparison swallowed
the ImportError, so every PyPI version read as unparseable. These pins hold the ranges
and the dependency.
"""
from __future__ import annotations

import asyncio
import pathlib

import pytest
import tomllib

from src.scanner import incident_history as ih
from src.scanner import scan as scanmod
from src.scanner.incident_history import REPO_ADVISORY_SOURCE, summarize_repo_advisories
from src.scanner.verdict import decide

GIT = "mcp-server-git"
EVERYTHING_PKG = "@modelcontextprotocol/server-everything"


def _pip(ghsa, severity, rng, patch):
    return {"ghsa_id": ghsa, "cve_id": None, "state": "published", "severity": severity,
            "withdrawn_at": None, "summary": f"mcp-server-git {ghsa}",
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": GIT},
                                 "vulnerable_version_range": rng,
                                 "patched_versions": patch}]}


GIT_ADVISORIES = [
    _pip("GHSA-6hqx-gqrx-c5r2", "high", "< 2026.11.11", "2026.11.11"),
    _pip("GHSA-q74p-4wrc-q7w6", "medium", ">= 2026.10.28, < 2026.11.11", "2026.11.11"),
    _pip("GHSA-w766-5x43-whvw", "medium", "< 2026.10.28", "2026.10.28"),
]
EVERYTHING = {
    "ghsa_id": "GHSA-mvf5-2qqv-rg3c", "cve_id": None, "state": "published",
    "severity": "medium", "withdrawn_at": None, "summary": "server-everything exfiltration",
    "vulnerabilities": [
        {"package": {"ecosystem": "npm", "name": EVERYTHING_PKG},
         "vulnerable_version_range": ">= 2025.9.24, <= 2026.8.31", "patched_versions": None},
        {"package": {"ecosystem": "npm", "name": EVERYTHING_PKG},
         "vulnerable_version_range": ">= 1.0.0, < 2.0.1", "patched_versions": "2.0.1"},
    ],
}
MANIFEST_PY = {"declared_repository": "https://github.com/modelcontextprotocol/servers"}
MANIFEST_NPM = {"repository": {"url": "git+https://github.com/modelcontextprotocol/servers.git"}}


def test_packaging_is_a_declared_runtime_dependency():
    root = pathlib.Path(__file__).resolve().parents[1]
    deps = tomllib.loads((root / "pyproject.toml").read_text())["project"]["dependencies"]
    assert any(d.split(">")[0].split("=")[0].strip().lower() == "packaging" for d in deps)


@pytest.mark.parametrize("version,affected", [
    ("2026.11.11", set()),
    ("2026.10.28", {"GHSA-6hqx-gqrx-c5r2", "GHSA-q74p-4wrc-q7w6"}),
    ("2026.11.10", {"GHSA-6hqx-gqrx-c5r2", "GHSA-q74p-4wrc-q7w6"}),
    ("2026.10.27", {"GHSA-6hqx-gqrx-c5r2", "GHSA-w766-5x43-whvw"}),
    ("2025.1.14", {"GHSA-6hqx-gqrx-c5r2", "GHSA-w766-5x43-whvw"}),
])
def test_mcp_server_git_ranges(version, affected):
    out = summarize_repo_advisories(GIT_ADVISORIES, "PyPI", GIT, version)
    assert len(out) == 3
    assert not [a["id"] for a in out if a["range_unparsed"]]
    assert {a["id"] for a in out if a["affects_scanned_version"]} == affected
    for a in out:
        if a["affects_scanned_version"]:
            assert a["fixed_in"] == ("2026.10.28" if a["id"] == "GHSA-w766-5x43-whvw"
                                     else "2026.11.11")


@pytest.mark.parametrize("version,affected,fixed", [
    ("2.0.0", True, "2.0.1"),
    ("1.0.0", True, "2.0.1"),
    ("2.0.1", False, None),
    ("2026.8.31", True, None),   # the date-numbered line has no fix: none is named
    ("2025.9.24", True, None),
    ("2026.9.1", False, None),
])
def test_server_everything_ranges(version, affected, fixed):
    (a,) = summarize_repo_advisories([EVERYTHING], "npm", EVERYTHING_PKG, version)
    assert a["range_unparsed"] is False
    assert a["affects_scanned_version"] is affected
    if affected:
        assert a["fixed_in"] == fixed


def _result(name, version):
    r = scanmod.ScanResult(repo=name, stars=0, description="", framework="")
    r.artifact_scan = {"version": version}
    r.incident_history = {"checked": True, "advisories": []}
    return r


def _apply(monkeypatch, advisories, eco, name, version, manifest):
    async def fake(slug, token=None):
        assert slug == "modelcontextprotocol/servers"
        return {"checked": True, "advisories": advisories}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)
    r = _result(f"{eco}:{name}", version)
    asyncio.run(scanmod._apply_repo_advisories(r, eco, name, manifest))
    return r


def _decide(r):
    return decide({"trust_score": 90, "findings": {"items": []},
                   "metadata": {"files_scanned": 40},
                   "advisories": r.incident_history["advisories"],
                   "coverage_gaps": r.coverage_gaps or {}})


def test_pinned_mcp_server_git_2026_10_28_is_affected(monkeypatch):
    r = _apply(monkeypatch, GIT_ADVISORIES, "pypi", GIT, "2026.10.28", MANIFEST_PY)
    assert not (r.coverage_gaps or {}).get("repo_advisory_range_unparsed")
    found = {f.snippet.split(": ", 1)[1]: f.severity for f in r.findings
             if f.file_path == REPO_ADVISORY_SOURCE}
    assert found == {"GHSA-6hqx-gqrx-c5r2": "high", "GHSA-q74p-4wrc-q7w6": "medium"}
    d = _decide(r)
    assert d.decision != "safe"
    assert "GHSA-6hqx-gqrx-c5r2" in d.reason and "2026.11.11" in d.reason


def test_latest_mcp_server_git_stays_clear(monkeypatch):
    r = _apply(monkeypatch, GIT_ADVISORIES, "pypi", GIT, "2026.11.11", MANIFEST_PY)
    assert not r.findings and not r.coverage_gaps
    assert len(r.incident_history["advisories"]) == 3
    assert _decide(r).decision == "safe"


@pytest.mark.parametrize("version,affected", [
    ("2.0.0", True), ("2.0.1", False), ("2026.8.31", True)])
def test_server_everything_scan(monkeypatch, version, affected):
    r = _apply(monkeypatch, [EVERYTHING], "npm", EVERYTHING_PKG, version, MANIFEST_NPM)
    assert not r.coverage_gaps
    assert bool([f for f in r.findings if f.file_path == REPO_ADVISORY_SOURCE]) is affected
    assert (_decide(r).decision == "safe") is (not affected)
