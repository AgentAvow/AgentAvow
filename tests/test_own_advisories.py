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


# GHSA-f29h-pxvx-f335 (July 2025) covers several packages, one release line each.
# Another package's range (got-fetch 5.1.11–6.0.0) must not hit eslint-plugin-prettier 5.5.7.
MULTI = {
    "id": "GHSA-f29h-pxvx-f335",
    "summary": "eslint-config-prettier, eslint-plugin-prettier, synckit, @pkgr/core, "
               "napi-postinstall have embedded malicious code",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {"package": {"ecosystem": "npm", "name": "eslint-config-prettier"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "10.1.6"}, {"fixed": "10.1.8"}]}]},
        {"package": {"ecosystem": "npm", "name": "eslint-plugin-prettier"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.2.2"}, {"fixed": "4.2.4"}]}]},
        {"package": {"ecosystem": "npm", "name": "got-fetch"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "5.1.11"}, {"fixed": "6.0.0"}]}]},
    ],
}


def test_multi_package_advisory_only_uses_the_scanned_packages_ranges():
    assert advisory_affects(MULTI, "npm", "5.5.7", "eslint-plugin-prettier") is False
    assert advisory_affects(MULTI, "npm", "4.2.3", "eslint-plugin-prettier") is True
    assert advisory_affects(MULTI, "npm", "5.5.7", "got-fetch") is True
    assert advisory_affects(MULTI, "npm", "10.1.7", "eslint-config-prettier") is True
    assert advisory_affects(MULTI, "npm", "10.1.8", "eslint-config-prettier") is False


def test_multi_package_summary_and_fix_version():
    clean = summarize_advisories([MULTI], "npm", "5.5.7", "eslint-plugin-prettier")
    assert clean[0]["affects_scanned_version"] is False
    assert not _own_advisory_findings("eslint-plugin-prettier", "5.5.7", clean)
    hit = summarize_advisories([MULTI], "npm", "4.2.3", "eslint-plugin-prettier")
    assert hit[0]["affects_scanned_version"] is True and hit[0]["fixed_in"] == "4.2.4"


def test_pypi_names_are_normalized():
    adv = {"id": "GHSA-x", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Foo_Bar"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "other"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert advisory_affects(adv, "PyPI", "1.0", "foo-bar") is True
    assert advisory_affects(adv, "PyPI", "3.0", "foo.bar") is False


def test_other_ecosystems_with_the_same_name_do_not_count():
    # GHSA-6c3j-c64m-qhgq: npm jquery <3.4.0, but also NuGet jQuery and RubyGems jquery-rails.
    adv = {"id": "GHSA-6c3j-c64m-qhgq", "affected": [
        {"package": {"ecosystem": "npm", "name": "jquery"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.1.4"}, {"fixed": "3.4.0"}]}]},
        {"package": {"ecosystem": "RubyGems", "name": "jquery-rails"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.3.4"}]}]},
        {"package": {"ecosystem": "NuGet", "name": "jQuery"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert advisory_affects(adv, "npm", "4.0.0", "jquery") is False
    assert advisory_affects(adv, "npm", "3.3.1", "jquery") is True


# litellm 1.105.1's page listed GHSA-53gh-p8jc-7rg8 / GHSA-5mg7-485q-xm76 under "fixed in
# this version" with no fix: their OSV ranges close on `last_affected`, not `fixed`.
LAST_AFFECTED = {
    "id": "GHSA-53gh-p8jc-7rg8", "summary": "LiteLLM Vulnerable to Remote Code Execution",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "litellm"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [
                      {"introduced": "1.40.3.dev2"}, {"last_affected": "1.40.12"}]}]}],
}


def test_last_affected_range_reports_its_bound():
    out = summarize_advisories([LAST_AFFECTED], "PyPI", "1.105.1", "litellm")
    assert out[0]["affects_scanned_version"] is False
    assert out[0]["fixed_in"] is None and out[0]["last_affected"] == "1.40.12"
    hit = summarize_advisories([LAST_AFFECTED], "PyPI", "1.40.5", "litellm")
    assert hit[0]["affects_scanned_version"] is True and hit[0]["last_affected"] == "1.40.12"


def test_last_affected_picks_the_highest_bound_and_is_none_with_a_fix():
    adv = {"id": "GHSA-y", "affected": [{"ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.9"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"last_affected": "2.10"}]},
    ]}]}
    assert summarize_advisories([adv], "PyPI", "3.0")[0]["last_affected"] == "2.10"
    assert summarize_advisories([GHSA], "PyPI", "2026.8.18")[0]["last_affected"] is None
