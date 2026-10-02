"""A published advisory against the package ITSELF that affects the scanned version is
a finding; one fixed before the scanned version is context only."""
from __future__ import annotations

from src.scanner.incident_history import advisory_affects, summarize_advisories
from src.scanner.scan import _own_advisory_findings

GHSA = {
    "id": "GHSA-5cgr-j3jf-jw3v", "aliases": ["CVE-2025-68143", "PYSEC-2026-1621"],
    "summary": "unrestricted git_init allows repository creation at arbitrary paths",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "2025.9.25"}]}]}],
}
PYSEC_DUP = {"id": "PYSEC-2026-1621", "aliases": ["GHSA-5cgr-j3jf-jw3v"], "affected": []}
MAL = {"id": "MAL-2025-1", "affected": []}
NPM = {"id": "GHSA-npm-1", "affected": [{"ranges": [{"type": "SEMVER", "events": [
    {"introduced": "1.2.0"}, {"fixed": "1.4.1"}]}]}]}


def test_pypi_ranges():
    assert advisory_affects(GHSA, "PyPI", "2025.7.1") is True
    assert advisory_affects(GHSA, "PyPI", "2025.9.25") is False
    assert advisory_affects(GHSA, "PyPI", "2026.8.18") is False
    assert advisory_affects(GHSA, "PyPI", None) is False


def test_semver_ranges():
    assert advisory_affects(NPM, "npm", "1.1.9") is False
    assert advisory_affects(NPM, "npm", "1.2.0") is True
    assert advisory_affects(NPM, "npm", "1.4.0") is True
    assert advisory_affects(NPM, "npm", "1.4.1") is False
    assert advisory_affects(NPM, "npm", "2.0.0-beta.1") is False


def test_summary_dedupes_aliases_and_skips_mal():
    out = summarize_advisories([GHSA, PYSEC_DUP, MAL], "PyPI", "2025.7.1")
    assert [a["id"] for a in out] == ["GHSA-5cgr-j3jf-jw3v"]
    assert out[0]["severity"] == "high" and out[0]["fixed_in"] == "2025.9.25"
    assert out[0]["affects_scanned_version"] is True


def test_only_affecting_advisories_become_findings():
    affected = summarize_advisories([GHSA], "PyPI", "2025.7.1")
    fixed = summarize_advisories([GHSA], "PyPI", "2026.8.18")
    f = _own_advisory_findings("mcp-server-git", "2025.7.1", affected)
    assert len(f) == 1 and f[0].category == "known_vulnerability" and f[0].severity == "high"
    assert "Upgrade to 2025.9.25" in f[0].remediation and "CVE-2025-68143" in f[0].snippet
    assert _own_advisory_findings("mcp-server-git", "2026.8.18", fixed) == []
