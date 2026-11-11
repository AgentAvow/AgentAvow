"""Repository-advisory range formats from the 2026-11-10 catalog review (design review
approved): hyphen ranges, OR-ed branches with paired patches, all-versions words,
`N.x` lines and release suffixes. Prose stays unparsed (disclosure only). Every shape
is copied from a live advisory; each has an affected twin and a later-line twin.
"""
from __future__ import annotations

import pytest

from src.scanner.incident_history import gh_range_affects, summarize_repo_advisories


def _adv(pkg, rng, patch, ghsa="GHSA-test-0000-0000"):
    return {"ghsa_id": ghsa, "state": "published", "severity": "high", "summary": "x",
            "vulnerabilities": [{"package": {"ecosystem": "npm" if not pkg.startswith("py:")
                                             else "pip", "name": pkg.removeprefix("py:")},
                                 "vulnerable_version_range": rng,
                                 "patched_versions": patch}]}


def _read(pkg, rng, patch, version):
    eco = "PyPI" if pkg.startswith("py:") else "npm"
    (a,) = summarize_repo_advisories([_adv(pkg, rng, patch)], eco,
                                     pkg.removeprefix("py:"), version)
    if a["affects_scanned_version"]:
        return "affected"
    return "unparsed" if a["range_unparsed"] else "clear"


@pytest.mark.parametrize("pkg,rng,patch,version,want", [
    # (1) hyphen ranges, inclusive (kysely-org/kysely, yt-dlp/yt-dlp)
    ("kysely", "0.26.0 - 0.28.16", ">= 0.28.17", "0.28.16", "affected"),
    ("kysely", "0.26.0 - 0.28.16", ">= 0.28.17", "0.29.8", "clear"),
    ("kysely", "0.26.0 - 0.28.16", ">= 0.28.17", "0.25.9", "clear"),
    ("py:yt-dlp", "2023.09.24 - 2024.07.02", "2024.07.07", "2024.7.1", "affected"),
    ("py:yt-dlp", "2023.09.24 - 2024.07.02", "2024.07.07", "2026.10.26", "clear"),
    # (2) OR as ";" (expressjs/body-parser), each branch with its own patch
    ("body-parser", "< 1.20.6; >= 2.0.0, < 2.3.0", "1.20.6; 2.3.0", "1.20.5", "affected"),
    ("body-parser", "< 1.20.6; >= 2.0.0, < 2.3.0", "1.20.6; 2.3.0", "2.2.9", "affected"),
    ("body-parser", "< 1.20.6; >= 2.0.0, < 2.3.0", "1.20.6; 2.3.0", "2.4.0", "clear"),
    ("body-parser", "< 1.20.6; >= 2.0.0, < 2.3.0", "1.20.6; 2.3.0", "1.20.6", "clear"),
    # nodejs/undici: "7.0.0 < 7.24.0" and a ":"-separated patch list
    ("undici", "< 6.24.0; 7.0.0 < 7.24.0", "6.24.0: 7.24.0", "7.23.9", "affected"),
    ("undici", "< 6.24.0; 7.0.0 < 7.24.0", "6.24.0: 7.24.0", "6.23.0", "affected"),
    ("undici", "< 6.24.0; 7.0.0 < 7.24.0", "6.24.0: 7.24.0", "8.12.4", "clear"),
    ("undici", "< 6.24.0; 7.0.0 < 7.24.0", "6.24.0: 7.24.0", "6.24.1", "clear"),
    # an unreadable branch with none affecting: unparsed; one affecting: affected
    ("p", "see notes; < 1.0.0", "", "2.0.0", "unparsed"),
    ("p", "see notes; < 3.0.0", "", "2.0.0", "affected"),
    # (3) all versions, no patch at all (rustcrypto/rsa "*")
    ("rsa", "*", "", "0.10.0", "affected"),
    ("rsa", "*", None, "99.0.0", "affected"),
    ("rsa", "all", "", "1.0.0", "affected"),
    # all + a patch list (pydantic: v1 lines only): at/above a fix on its line is clear;
    # below it on its line is affected; a LATER line than every fix is unparsed
    ("py:pydantic", "all", "v1.8.2,v1.7.4,v1.6.2", "1.8.2", "clear"),
    ("py:pydantic", "all", "v1.8.2,v1.7.4,v1.6.2", "1.8.1", "affected"),
    ("py:pydantic", "all", "v1.8.2,v1.7.4,v1.6.2", "1.5.0", "affected"),
    ("py:pydantic", "all", "v1.8.2,v1.7.4,v1.6.2", "2.14.3", "unparsed"),
    # N.x lines (aws/aws-sdk-js "2.x")
    ("aws-sdk", "2.x", "", "2.1693.0", "affected"),
    ("aws-sdk", "2.x", "", "3.0.0", "clear"),
    ("aws-sdk", "2.x", "", "1.9.0", "clear"),
    ("p", "2.3.x", "", "2.3.9", "affected"),
    ("p", "2.3.x", "", "2.4.0", "clear"),
    # (4) release suffixes (berriai/litellm): "-stable" is the release itself
    ("py:litellm", "< 1.83.10-stable", ">= 1.83.10-stable", "1.83.10", "clear"),
    ("py:litellm", "< 1.83.10-stable", ">= 1.83.10-stable", "1.83.9", "affected"),
    ("py:litellm", "< 1.83.10-stable", ">= 1.83.10-stable", "1.108.5", "clear"),
    # (5) prose: unparsed, never guessed
    ("py:ipython", "All version prior and including to 8.0.0, 7.31.0, 5.10",
     "8.0.1, 7.31.1, 7.16.3, 5.11 (source only)", "7.0.0", "unparsed"),
    ("py:lupa", "<= 2.6 and later", "", "2.8", "unparsed"),
])
def test_formats(pkg, rng, patch, version, want):
    assert _read(pkg, rng, patch, version) == want


def test_a_real_prerelease_stays_a_prerelease():
    assert gh_range_affects("< 2.0.0", "npm", "2.0.0-rc1") is True
    assert gh_range_affects("< 2.0.0", "npm", "2.0.0-stable") is False
    assert gh_range_affects("< 2.0.0", "npm", "2.0.0+build.5") is False
    assert gh_range_affects("< 2.0.0", "PyPI", "2.0.0rc1") is True


def test_hyphen_inside_a_version_is_not_a_range():
    # "1.0.0-beta.1" is one version, not "1.0.0 - beta.1"
    assert gh_range_affects("< 1.0.0-beta.2", "npm", "1.0.0-beta.1") is True
