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
# The same repository name in npm too: two ecosystems, so neither can be matched.
NPM_SAME_NAME = {
    "ghsa_id": "GHSA-npmx-same-0000", "cve_id": None, "state": "published",
    "severity": "medium",
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "@someone/k8s-mcp-server"},
                         "vulnerable_version_range": "< 1.0.30", "patched_versions": "1.0.30"}],
}


_REAL_SEND = httpx.AsyncClient.send


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    async def refuse(self, request, **kw):
        raise httpx.ConnectError(f"network refused in tests: {request.url}")
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    ih._repo_adv_cache.clear()
    yield
    ih._repo_adv_cache.clear()


@pytest.mark.parametrize("tag,want", [
    ("1.0.25", "1.0.25"), ("v1.0.25", "1.0.25"),
    # pre-releases stay pre-releases (they sort below the release)
    ("1.0.25-rc1", "1.0.25-rc1"), ("1.0.25-rc", "1.0.25-rc"), ("1.0.25-dev", "1.0.25-dev"),
    ("1.0.25-SNAPSHOT", "1.0.25-SNAPSHOT"), ("1.0.25-beta.2", "1.0.25-beta.2"),
    # not mapped with confidence
    ("1.0.25-alpine", None), ("1.0.25_amd64", None), ("2024.01.05", None),
    ("2026.11.18", None), ("1.02.3", None),
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
    assert a["unmatched"] is False
    assert a["cvss"] is None  # GitHub lists no score for this one: the label stands in
    (b,) = summarize_image_repo_advisories(K8S, SLUG, "1.1.0")
    assert b["affects_scanned_version"] is False


def _range_adv(rng, eco="go", name=f"github.com/{SLUG}", patched="2.0.0", gid="GHSA-rang-e000-0000"):
    return {"ghsa_id": gid, "state": "published", "severity": "high",
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": name},
                                 "vulnerable_version_range": rng,
                                 "patched_versions": patched}]}


def test_a_pre_release_tag_sorts_below_its_release():
    # "< 1.2.3" covers 1.2.3-dev and 1.2.3-SNAPSHOT, not 1.2.3
    for tag, hit in (("1.2.3-dev", True), ("1.2.3-SNAPSHOT", True), ("1.2.3-rc1", True),
                     ("1.2.3", False)):
        (a,) = summarize_image_repo_advisories([_range_adv("< 1.2.3")], SLUG, tag)
        assert a["affects_scanned_version"] is hit, tag


@pytest.mark.parametrize("tag", ["latest", "1.0.25-alpine", "2024.01.05"])
def test_an_unmappable_tag_is_unmatched_never_affected(tag):
    (a,) = summarize_image_repo_advisories(K8S, SLUG, tag)
    assert a["affects_scanned_version"] is False and a["unmatched"] is True
    assert a["range_unparsed"] is False and a["fixed_in"] == "1.1.0"


def test_only_the_repositorys_own_package_counts():
    got = summarize_image_repo_advisories(K8S + [SIBLING], SLUG, "1.0.25")
    assert [a["id"] for a in got] == ["GHSA-m932-63jc-4jqq"]
    assert summarize_image_repo_advisories(K8S, "someone/else", "1.0.25") == []
    assert summarize_image_repo_advisories(K8S, "not a slug", "1.0.25") == []


@pytest.mark.parametrize("name,hit", [
    (f"github.com/{SLUG}", True), (f"github.com/{SLUG}/v2", True),
    (f"github.com/{SLUG}/v11", True), (f"github.com/{SLUG}/v1", False),
    (f"github.com/{SLUG}/v0", False), (f"github.com/{SLUG}/api", False),
    (f"github.com/{SLUG}/pkg/client", False), (f"github.com/{SLUG}/v2/api", False),
    (f"github.com/{SLUG}x", False),
])
def test_go_module_paths(name, hit):
    got = summarize_image_repo_advisories([_range_adv("< 9.0.0", name=name)], SLUG, "1.0.25")
    assert bool(got) is hit, name


def test_the_same_name_in_two_ecosystems_is_unmatched():
    got = summarize_image_repo_advisories(K8S + [NPM_SAME_NAME], SLUG, "1.0.25")
    assert {a["id"] for a in got} == {"GHSA-m932-63jc-4jqq", "GHSA-npmx-same-0000"}
    assert all(a["unmatched"] and not a["affects_scanned_version"] for a in got)


def test_pypi_ranges_are_read_with_pep440():
    adv = _range_adv("< 1.0.25", eco="pip", name="k8s_mcp_server")
    (a,) = summarize_image_repo_advisories([adv], SLUG, "1.0.25-rc1")
    assert a["affects_scanned_version"] is True and a["unmatched"] is False
    (b,) = summarize_image_repo_advisories([adv], SLUG, "1.0.25")
    assert b["affects_scanned_version"] is False
    # a tag PEP 440 cannot read is unmatched, not guessed
    (c,) = summarize_image_repo_advisories([adv], SLUG, "1.0.24-SNAPSHOT")
    assert c["unmatched"] is True and c["affects_scanned_version"] is False


def test_an_unreadable_ecosystem_is_unmatched():
    adv = _range_adv("< 9.0.0", eco="maven", name="io.example:k8s-mcp-server")
    (a,) = summarize_image_repo_advisories([adv], SLUG, "1.0.25")
    assert a["unmatched"] is True and a["affects_scanned_version"] is False


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


def test_latest_without_a_version_label_is_disclosed_unmatched(monkeypatch):
    _fake_fetch(monkeypatch)
    r = _result("latest")
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched(tag="latest")))
    assert not r.findings
    assert r.coverage_gaps == {"repo_advisory_unmatched": 1}
    assert coverage_gap_notes({"coverage_gaps": r.coverage_gaps}) == [
        "1 repository security advisory could not be matched to this image's version"]


def test_apply_merges_into_existing_advisories(monkeypatch):
    _fake_fetch(monkeypatch)
    r = _result()
    other = {"id": "GHSA-othr-0000-0000", "aliases": [], "affects_scanned_version": False}
    same = {"id": "GHSA-m932-63jc-4jqq", "aliases": [], "affects_scanned_version": True}
    r.incident_history = {"checked": False, "advisories": [other, same]}
    asyncio.run(scanmod._apply_image_repo_advisories(r, _fetched()))
    ids = [a["id"] for a in r.incident_history["advisories"]]
    assert sorted(ids) == ["GHSA-m932-63jc-4jqq", "GHSA-othr-0000-0000"]
    assert not r.findings  # already listed: no second finding


def test_a_raising_lookup_is_disclosed_as_failed(monkeypatch, caplog):
    from src.scanner import artifact_fetch as af

    async def fake_docker(name, version=None, **kw):
        return _fetched()

    async def boom(result, fetched):
        raise RuntimeError("bad")
    monkeypatch.setattr(af, "fetch_docker_artifact", fake_docker)
    monkeypatch.setattr(scanmod, "_apply_image_repo_advisories", boom)
    with caplog.at_level("WARNING"):
        res = asyncio.run(scanmod.scan_package("docker", IMAGE, "1.0.25"))
    assert res.coverage_gaps.get("repo_advisory_lookup") == "failed"
    assert any("repo advisory lookup failed" in r.message for r in caplog.records)


def test_a_raising_npm_lookup_is_disclosed_as_failed(monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("bad")
    monkeypatch.setattr(scanmod, "_apply_repo_advisories", boom)
    r = _result()
    scanmod._repo_advisory_lookup_failed(r, "npm:x")
    assert r.coverage_gaps == {"repo_advisory_lookup": "failed"}
    import inspect
    src = inspect.getsource(scanmod.scan_package)
    assert "_repo_advisory_lookup_failed(result, f\"{eco}:{name}\")" in src


@pytest.mark.parametrize("slug,ok", [
    ("o/r", True), ("o.x/r.y", True), ("o/.github", True), ("./r", False),
    ("../r", False), ("o/.", False), ("o/..", False), ("o/r/x", False), ("o", False),
])
def test_slug_rejects_dot_segments(slug, ok):
    assert bool(ih._SLUG_OK_RE.match(slug)) is ok


def test_repo_advisory_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ih, "_REPO_ADV_CACHE_MAX", 3)
    monkeypatch.setattr(httpx.AsyncClient, "send", _REAL_SEND)  # mock transport only

    def handler(req):
        return httpx.Response(200, json=[])
    real = httpx.AsyncClient

    def make(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(ih.httpx, "AsyncClient", make)
    for i in range(5):
        assert asyncio.run(ih.fetch_repo_advisories(f"o/r{i}"))["checked"] is True
    assert list(ih._repo_adv_cache) == ["o/r2", "o/r3", "o/r4"]
    asyncio.run(ih.fetch_repo_advisories("o/r2"))  # a hit moves it to the end
    assert list(ih._repo_adv_cache)[-1] == "o/r2"


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

def test_deprecation_naming_a_cve_cites_the_id_not_the_message():
    msg = ("Deprecated: depends on @connorbritain/mssql-mcp-core < 0.6.0 "
           "(CVE-2026-63129). Upgrade to 0.6.0.")
    f = scanmod._deprecation_finding("npm", "@connorbritain/mssql-mcp-server", "0.5.0", msg)
    assert f.name == "Package deprecated by its maintainer, citing CVE-2026-63129"
    assert f.severity == "medium" and f.category == "maintenance"
    assert msg in f.snippet  # the message stays in the unsigned snippet


@pytest.mark.parametrize("msg,want", [
    ("See GHSA-M932-63JC-4JQQ", "citing GHSA-m932-63jc-4jqq"),
    ("fixed: cve-2026-1234 in 2.0", "citing CVE-2026-1234"),
    ("CVE-2026-1, wait CVE-2026-12345 and CVE-2026-12345 again",
     "citing CVE-2026-12345"),
    ("CVE-2026-1001 CVE-2026-1002 GHSA-m932-63jc-4jqq CVE-2026-1003 CVE-2026-1004",
     "citing CVE-2026-1001, CVE-2026-1002, GHSA-m932-63jc-4jqq and 2 more"),
])
def test_deprecation_ids_are_cited_whole(msg, want):
    assert scanmod._deprecation_name(msg) == f"Package deprecated by its maintainer, {want}"


def test_deprecation_without_an_id_is_unchanged():
    for msg in ("Package no longer supported.", "use foo2", "", None,
                "CVE handling moved to foo", "GHSA-1", "x" * 500 + "\n\x1b[31m"):
        assert scanmod._deprecation_name(msg) == "Package deprecated by its maintainer"


def test_a_long_message_never_truncates_an_id():
    name = scanmod._deprecation_name("x" * 1000 + " CVE-2026-99999999 " + "y" * 1000)
    assert name.endswith("citing CVE-2026-99999999") and "x" not in name
