"""A container image scan reads the security advisories of the GitHub repository the image
declares as its source (``org.opencontainers.image.source``), matched against the image
tag, the way npm / PyPI / crates scans read their repository's. And an npm deprecation
message that names a CVE or GHSA id is quoted in the finding.

No live network: the advisory list is a recorded GitHub response
(tests/fixtures/image_repo_advisories/), and every HTTP call is refused."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from src.scanner import incident_history as ih
from src.scanner import scan as scanmod
from src.scanner.artifact_fetch import ArtifactFetchResult
from src.scanner.incident_history import (
    REPO_ADVISORY_SOURCE,
    image_tag_version,
    summarize_image_repo_advisories,
)
from src.scanner.verdict import coverage_gap_notes, decide

FIX = Path(__file__).parent / "fixtures" / "image_repo_advisories"
# GET repos/reza-gholizade/k8s-mcp-server/security-advisories?state=published
K8S = json.loads((FIX / "k8s_mcp_server_security_advisories.json").read_text())
SLUG = "reza-gholizade/k8s-mcp-server"
IMAGE = "ginnux/k8s-mcp-server"

# A monorepo advisory for a sibling package: never applied to the image.
SIBLING = {
    "ghsa_id": "GHSA-sibl-ing0-0000", "cve_id": "CVE-2026-1", "state": "published",
    "severity": "critical",
    "vulnerabilities": [{"package": {"ecosystem": "go",
                                     "name": "github.com/reza-gholizade/other-server"},
                         "vulnerable_version_range": "< 9.0.0", "patched_versions": "9.0.0"}],
}
# The repository's own npm package (an image built from a JS repo).
NPM_SAME_NAME = {
    "ghsa_id": "GHSA-npmx-same-0000", "cve_id": None, "state": "published",
    "severity": "medium",
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "@someone/k8s-mcp-server"},
                         "vulnerable_version_range": "< 1.0.30", "patched_versions": "1.0.30"}],
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    async def refuse(self, request, **kw):
        raise httpx.ConnectError(f"network refused in tests: {request.url}")
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    ih._repo_adv_cache.clear()
    yield
    ih._repo_adv_cache.clear()


@pytest.mark.parametrize("tag,want", [
    ("1.0.25", "1.0.25"), ("v1.0.25", "1.0.25"), ("1.0.25-alpine", "1.0.25"),
    ("1.0.25-rc1", "1.0.25-rc1"), ("1.0.25_amd64", "1.0.25"),
    ("latest", None), ("1", None), ("1.0", None), ("main", None), ("", None), (None, None),
    ("sha-abc1234", None),
])
def test_image_tag_version(tag, want):
    assert image_tag_version(tag) == want


def test_the_tag_in_the_range_is_affected_and_the_fix_is_not():
    (a,) = summarize_image_repo_advisories(K8S, SLUG, "1.0.25")
    assert a["id"] == "GHSA-m932-63jc-4jqq" and a["aliases"] == ["CVE-2026-130007"]
    assert a["affects_scanned_version"] is True and a["fixed_in"] == "1.1.0"
    assert a["source"] == REPO_ADVISORY_SOURCE and a["severity"] == "high"
    assert a["cvss"] is None  # GitHub lists no score for this one: the label stands in
    (b,) = summarize_image_repo_advisories(K8S, SLUG, "1.1.0")
    assert b["affects_scanned_version"] is False


def test_an_unversioned_tag_lists_the_advisory_as_context_only():
    (a,) = summarize_image_repo_advisories(K8S, SLUG, "latest")
    assert a["affects_scanned_version"] is False and a["range_unparsed"] is False
    assert a["fixed_in"] == "1.1.0"


def test_only_the_repositorys_own_package_counts():
    got = summarize_image_repo_advisories(K8S + [SIBLING, NPM_SAME_NAME], SLUG, "1.0.25")
    assert [a["id"] for a in got] == ["GHSA-m932-63jc-4jqq", "GHSA-npmx-same-0000"]
    assert summarize_image_repo_advisories(K8S, "someone/else", "1.0.25") == []
    assert summarize_image_repo_advisories(K8S, "not a slug", "1.0.25") == []


def _fetched(labels_source=SLUG, tag="1.0.25", version_label=None):
    image = {"registry": "dockerhub", "repo": IMAGE, "tag": tag,
             "source_label": (f"https://github.com/{labels_source}" if labels_source
                              else None),
             "version_label": version_label}
    return ArtifactFetchResult(ecosystem="docker", name=IMAGE, version=tag, kind="image",
                               ok=True, image=image)


def _result(tag="1.0.25"):
    r = scanmod.ScanResult(repo=f"docker:{IMAGE}", stars=0, description="", framework="")
    r.artifact_scan = {"version": tag}
    r.incident_history = {"checked": False}
    r.files_scanned = 40
    return r


def _fake_fetch(monkeypatch, body=None, checked=True, seen=None):
    async def fake(slug, token=None):
        if seen is not None:
            seen.append(slug)
        return {"checked": checked, "advisories": K8S if body is None else body}
    monkeypatch.setattr(ih, "fetch_repo_advisories", fake)


def test_apply_adds_the_finding_and_the_answer_names_the_cve(monkeypatch):
    seen: list = []
    _fake_fetch(monkeypatch, seen=seen)
    r = _result()
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched()))
    assert seen == [SLUG]
    (f,) = r.findings
    assert f.category == "known_vulnerability" and f.severity == "high"
    assert f.file_path == REPO_ADVISORY_SOURCE and "1.1.0" in f.remediation
    assert r.incident_history["advisories"][0]["affects_scanned_version"] is True
    d = decide({"trust_score": 68, "findings": {"items": [
        {"category": f.category, "name": f.name, "severity": f.severity,
         "file_path": f.file_path, "line_number": 0, "kind": "defect", "installed": True}]},
        "metadata": {"files_scanned": 40}, "incident_history": r.incident_history})
    assert d.decision == "review"
    assert d.reason == "known vulnerability CVE-2026-130007 affects this version (fixed in 1.1.0)"


def test_apply_on_the_fixed_tag_adds_nothing_but_context(monkeypatch):
    _fake_fetch(monkeypatch)
    r = _result("1.1.0")
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched(tag="1.1.0")))
    assert not r.findings and not r.coverage_gaps
    assert r.incident_history["advisories"][0]["affects_scanned_version"] is False


def test_latest_reads_the_version_label(monkeypatch):
    _fake_fetch(monkeypatch)
    r = _result("latest")
    asyncio.run(scanmod._apply_image_repo_advisories(
        r, _fetched(tag="latest", version_label="v1.0.25")))
    assert [f.category for f in r.findings] == ["known_vulnerability"]
    assert "@1.0.25:" in r.findings[0].snippet


def test_latest_without_a_version_label_is_context_only(monkeypatch):
    _fake_fetch(monkeypatch)
    r = _result("latest")
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched(tag="latest")))
    assert not r.findings and not r.coverage_gaps


def test_no_source_label_reads_nothing(monkeypatch):
    seen: list = []
    _fake_fetch(monkeypatch, seen=seen)
    r = _result()
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched(labels_source=None)))
    assert seen == [] and not r.findings and r.incident_history == {"checked": False}
    # a label that is not a GitHub repository is not read either
    f = _fetched()
    f.image["source_label"] = "https://gitlab.com/o/r"
    asyncio.run(scanmod._apply_image_repo_advisories(r, f))
    assert seen == []


def test_a_failed_lookup_is_disclosed(monkeypatch):
    _fake_fetch(monkeypatch, checked=False)
    r = _result()
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched()))
    assert r.coverage_gaps == {"repo_advisory_lookup": "failed"} and not r.findings
    assert coverage_gap_notes({"coverage_gaps": r.coverage_gaps}) == [
        "the source repository's security advisories could not be read"]


def test_the_real_fetch_runs_offline_and_fails_closed():
    """With the network refused, the real fetch reports a failed lookup: never clean."""
    r = _result()
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched()))
    assert r.coverage_gaps == {"repo_advisory_lookup": "failed"}


def test_scan_package_wires_it_for_docker(monkeypatch):
    """End to end through scan_package with the image fetch and the advisory list
    recorded: the CVE reaches the findings and the answer."""
    from src.scanner import artifact_fetch as af

    async def fake_docker(name, version=None, **kw):
        return _fetched()
    monkeypatch.setattr(af, "fetch_docker_artifact", fake_docker)
    _fake_fetch(monkeypatch)
    res = asyncio.run(scanmod.scan_package("docker", IMAGE, "1.0.25"))
    assert any(f.category == "known_vulnerability" and "1.1.0" in f.remediation
               for f in res.findings)
    ids = [a["id"] for a in res.incident_history.get("advisories") or []]
    assert ids == ["GHSA-m932-63jc-4jqq"]


# ── npm deprecation that names a CVE ─────────────────────────────────────────────────

def test_deprecation_naming_a_cve_is_quoted():
    msg = ("Deprecated: depends on @connorbritain/mssql-mcp-core < 0.6.0 "
           "(CVE-2026-63129). Upgrade to 0.6.0.")
    f = scanmod._deprecation_finding("npm", "@connorbritain/mssql-mcp-server", "0.5.0", msg)
    assert f.name == f'Package deprecated by its maintainer: "{msg}"'
    assert f.severity == "medium" and f.category == "maintenance"


@pytest.mark.parametrize("msg", [
    "See GHSA-m932-63jc-4jqq", "fixed: cve-2026-1234 in 2.0", "nothing here",
])
def test_deprecation_quote_rule(msg):
    name = scanmod._deprecation_name(msg)
    named = "GHSA-m932" in msg or "cve-2026" in msg
    assert name.startswith('Package deprecated by its maintainer: "') is named


def test_deprecation_without_an_id_is_unchanged():
    for msg in ("Package no longer supported.", "use foo2", "", None,
                "CVE handling moved to foo", "GHSA-1"):
        assert scanmod._deprecation_name(msg) == "Package deprecated by its maintainer"


def test_deprecation_quote_is_capped_and_cleaned():
    msg = "CVE-2026-63129\n\x1b[31m" + "x" * 500
    name = scanmod._deprecation_name(msg)
    quoted = name.split(": ", 1)[1]
    assert len(quoted) == scanmod.DEPRECATION_QUOTE_MAX + 2  # the two quote marks
    assert "\n" not in name and "\x1b" not in name and quoted.endswith('…"')
