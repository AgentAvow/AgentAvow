"""Repository advisories: a release past the fix is not affected (live wrong answer,
2026-11-10: axios 1.21.1 read Review 63 for GHSA-898c-q2cr-xwhg, fixed in 1.16.0).

GitHub's repository-advisory LIST endpoint can publish an open-ended
``vulnerable_version_range`` (``">=1.0.0"``) and carry the fix only in
``patched_versions`` (``">=1.16.0"``); it can list one entry per release line; and
maintainers write ranges by hand (spaces, ``and``, ``≤``, ``=<``, ``16.3.?``). Every
shape below is copied from a live advisory.
"""
from __future__ import annotations

import pytest

from src.scanner.incident_history import (
    gh_patched_includes,
    gh_range_affects,
    summarize_repo_advisories,
)


def _adv(ghsa, pkg, *vulns, eco="npm"):
    return {"ghsa_id": ghsa, "state": "published", "severity": "high", "summary": "x",
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": pkg},
                                 "vulnerable_version_range": r, "patched_versions": p}
                                for r, p in vulns]}


def _one(adv, pkg, version, eco="npm"):
    (a,) = summarize_repo_advisories([adv], eco, pkg, version)
    return a


# ── the five live false hits: NOT affected ────────────────────────────────────

@pytest.mark.parametrize("adv,pkg,version", [
    # axios/axios: open range, fix only in patched_versions (two lines)
    (_adv("GHSA-898c-q2cr-xwhg", "axios", (">=1.0.0", ">=1.16.0"), ("<=0.31.1", ">=0.32.0")),
     "axios", "1.21.1"),
    (_adv("GHSA-35jp-ww65-95wh", "axios", (">=1.0.0", ">=1.16.0")), "axios", "1.21.1"),
    # vercel/next.js: a wildcard patch on an open range
    (_adv("GHSA-39w2-rjm5-chcv", "next", (">= 16.0.0", "16.3.?")), "next", "16.4.6"),
    # nextauthjs/next-auth: one entry per release line
    (_adv("GHSA-5jpx-9hw9-2fx4", "next-auth", ("<4.24.12", "4.24.12"),
          ("<5.0.0-beta.30", "5.0.0-beta.30")), "next-auth", "4.24.15"),
    # drizzle-team/drizzle-orm: 0.x line plus a 1.0 beta line
    (_adv("GHSA-gpj5-g38j-94v9", "drizzle-orm", ("<= 0.45.1", "0.45.2"),
          ("<= 1.0.0-beta.19", "1.0.0-beta.20")), "drizzle-orm", "0.45.4"),
    # vercel/next.js: space-separated AND
    (_adv("GHSA-2464-fhr4-w9xw", "next", (">= 10.0.0  <= 15.5.27", "15.5.28"),
          ("> 16.0.0 <= 16.4.0", "16.4.1")), "next", "16.4.6"),
    # vercel/next.js: `and`
    (_adv("GHSA-67rr-84xm-4c7r", "next", (">15.0.4 and <15.2.0", "≤15.0.4 and ≥15.2.0")),
     "next", "16.4.6"),
    # withastro/astro: reversed operator
    (_adv("GHSA-g735-7g2w-hh3f", "astro", ("> 2.10.10 =< 5.18.0", "5.18.1")),
     "astro", "7.4.10"),
    (_adv("GHSA-hr2q-hp5q-x767", "astro", ("=< 2.16.0", ">= 5.15.5")), "astro", "7.4.10"),
    # Flux159/mcp-server-kubernetes: Unicode operator and a note
    (_adv("GHSA-6mx4-4h42-r8vh", "mcp-server-kubernetes",
          ("≤ 3.6.2 (all versions)", ">= 3.7.0")), "mcp-server-kubernetes", "4.2.2"),
])
def test_past_the_fix_is_not_affected(adv, pkg, version):
    a = _one(adv, pkg, version)
    assert a["affects_scanned_version"] is False, a
    assert a["range_unparsed"] is False, a


@pytest.mark.parametrize("ghsa,pkg,rng,patched,version", [
    # the remaining three of design review's five, as the global DB states the ranges
    # and the repo list states the fix
    ("GHSA-gw32-9rmw-qwww", "svelte", ">= 3.0.0", ">= 3.59.2", "5.57.3"),
    ("GHSA-p7fg-763f-g4gf", "@anthropic-ai/sdk", ">= 0.79.0", "0.91.1", "1.8.0"),
    ("GHSA-39w2-rjm5-chcv", "next", ">= 16.0.0", "16.3.8", "16.4.6"),
])
def test_design_review_cases_not_affected(ghsa, pkg, rng, patched, version):
    a = _one(_adv(ghsa, pkg, (rng, patched)), pkg, version)
    assert a["affects_scanned_version"] is False and a["range_unparsed"] is False


# ── still affected ────────────────────────────────────────────────────────────

SE = "@modelcontextprotocol/server-everything"
EVERYTHING = _adv("GHSA-mvf5-2qqv-rg3c", SE, (">= 2025.9.24, <= 2026.8.31", None),
                  (">= 1.0.0, < 2.0.1", "2.0.1"))


@pytest.mark.parametrize("version,affected", [
    ("2.0.0", True), ("1.0.0", True), ("2026.8.31", True),
    ("2.0.1", False), ("2.2.1", False),
])
def test_server_everything(version, affected):
    assert _one(EVERYTHING, SE, version)["affects_scanned_version"] is affected


@pytest.mark.parametrize("adv,pkg,version", [
    # inside the open range, below the fix
    (_adv("GHSA-898c-q2cr-xwhg", "axios", (">=1.0.0", ">=1.16.0")), "axios", "1.15.9"),
    # an open range with no fix at all: every release is affected
    (_adv("GHSA-open-0000-0000", "p", (">= 1.0.0", None)), "p", "9.9.9"),
    (_adv("GHSA-open-0000-0001", "p", (">= 1.0.0", "")), "p", "9.9.9"),
    # rusqlite/rusqlite (repo-only, 11-07): the exact latest release, no fix
    (_adv("GHSA-68ch-232w-w277", "rusqlite", ("0.41.1", ""), eco="rust"),
     "rusqlite", "0.41.1"),
    # a wildcard patch never lowers the floor into its own line: 16.3.9 may be unfixed
    (_adv("GHSA-39w2-rjm5-chcv", "next", (">= 16.0.0", "16.3.?")), "next", "16.3.9"),
    # a fix on ANOTHER line does not cover this one
    (_adv("GHSA-line-0000-0000", "p", ("< 1.9.5", "1.9.5"), ("< 2.0.1", "2.0.1")),
     "p", "2.0.0"),
    # 0.x lines are major.minor: 0.44.9 is not covered by a 0.45.2 fix
    (_adv("GHSA-gpj5-g38j-94v9", "drizzle-orm", ("<= 0.45.1", "0.45.2"),
          ("<= 1.0.0-beta.19", "1.0.0-beta.20")), "drizzle-orm", "0.44.9"),
])
def test_still_affected(adv, pkg, version):
    eco = "crates.io" if pkg == "rusqlite" else "npm"
    a = _one(adv, pkg, version, eco=eco)
    assert a["affects_scanned_version"] is True, a


def test_patched_or_list_reads_as_and_the_conservative_side():
    # "1.2.3, 2.0.1" as two first fixes: only >= 2.0.1 counts as patched here
    assert gh_patched_includes("1.2.3, 2.0.1", "npm", "1.5.0") is False
    assert gh_patched_includes("1.2.3, 2.0.1", "npm", "2.0.1") is True


# ── unparsed stays unparsed: disclosed, not scored ────────────────────────────

def test_open_range_with_an_unreadable_patch_is_unparsed():
    a = _one(_adv("GHSA-odd0-0000-0000", "p", (">= 1.0.0", "see release notes")), "p", "3.0.0")
    assert a["affects_scanned_version"] is False and a["range_unparsed"] is True


def test_bounded_range_with_an_unreadable_patch_still_reads_the_range():
    a = _one(_adv("GHSA-odd0-0000-0001", "p", (">= 1.0.0, < 2.0.0", "soon")), "p", "1.5.0")
    assert a["affects_scanned_version"] is True


@pytest.mark.parametrize("rng", [">= banana", "All version prior and including to 8.0.0",
                                 "<= 2.6 and later", "see advisory"])
def test_unreadable_range_is_unparsed(rng):
    a = _one(_adv("GHSA-odd0-0000-0002", "p", (rng, "9.0.0")), "p", "1.0.0")
    assert a["affects_scanned_version"] is False and a["range_unparsed"] is True


def test_range_parts():
    assert gh_range_affects(">= 10.0.0  <= 15.5.27", "npm", "15.0.0") is True
    assert gh_range_affects(">= 10.0.0  <= 15.5.27", "npm", "15.5.28") is False
    assert gh_range_affects("≤ 3.6.2 (all versions)", "npm", "3.6.2") is True
    assert gh_range_affects("> 2.10.10 =< 5.18.0", "npm", "5.18.0") is True
    assert gh_range_affects(">15.0.4 and <15.2.0", "npm", "15.1.0") is True
