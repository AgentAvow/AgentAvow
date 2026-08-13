"""Phase 0/1 supply-chain: lockfile parsing, OSV reducers, coverage, GitHub-depth.

All offline — the pure parsers and reducers are driven with canned JSON, and the
fail-open orchestrator is exercised with a mock transport, so no network is hit.
"""
from __future__ import annotations

import httpx
import pytest

from src.scanner import lockfiles as lf
from src.scanner.coverage import (
    EVIDENCE_ANCHOR_STATIC,
    build_coverage,
    build_evidence_anchors,
)
from src.scanner.lockfiles import Dep
from src.scanner.supply_chain import (
    analyze_supply_chain,
    hash_pinned_actions_ratio,
    is_malicious,
    severity_for_vuln,
    signed_commit_ratio,
    summarize_osv,
)

# ── lockfile parsers ─────────────────────────────────────────────────────────

def test_parse_requirements_exact_pins_only():
    txt = "requests==2.19.1\nurllib3>=1.26\n# comment\nflask==2.0.1\n-e .\n"
    deps = lf.parse_requirements_txt(txt)
    names = {(d.name, d.version) for d in deps}
    assert ("requests", "2.19.1") in names
    assert ("flask", "2.0.1") in names
    # range-only + editable installs are not OSV-queryable → excluded
    assert all(d.name != "urllib3" for d in deps)
    assert all(d.ecosystem == lf.ECO_PYPI for d in deps)


def test_parse_package_lock_v3_packages():
    txt = """
    {"lockfileVersion": 3, "packages": {
      "": {"name": "root"},
      "node_modules/lodash": {"version": "4.17.20"},
      "node_modules/foo/node_modules/bar": {"version": "1.0.0"}
    }}"""
    deps = lf.parse_package_lock(txt)
    got = {(d.name, d.version) for d in deps}
    assert ("lodash", "4.17.20") in got
    assert ("bar", "1.0.0") in got  # nested → strip to last node_modules segment
    assert all(d.ecosystem == lf.ECO_NPM for d in deps)


def test_parse_package_lock_v1_dependencies():
    txt = """
    {"lockfileVersion": 1, "dependencies": {
      "minimist": {"version": "1.2.0", "dependencies": {
        "nested": {"version": "0.1.0"}}}}}"""
    got = {(d.name, d.version) for d in lf.parse_package_lock(txt)}
    assert ("minimist", "1.2.0") in got
    assert ("nested", "0.1.0") in got


def test_parse_yarn_lock():
    txt = (
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n'
        '  version "7.10.0"\n'
        "\n"
        "lodash@^4.17.0:\n"
        '  version "4.17.15"\n'
    )
    got = {(d.name, d.version) for d in lf.parse_yarn_lock(txt)}
    assert ("@babel/core", "7.10.0") in got  # scope preserved, range stripped
    assert ("lodash", "4.17.15") in got


def test_parse_pnpm_lock_v6_and_v9():
    v6 = "packages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@babel/core/7.10.0:\n    x: y\n"
    got6 = {(d.name, d.version) for d in lf.parse_pnpm_lock(v6)}
    assert ("lodash", "4.17.20") in got6
    assert ("@babel/core", "7.10.0") in got6
    v9 = "packages:\n  lodash@4.17.21:\n    resolution: {}\n  react@18.0.0(x@1):\n    y: z\n"
    got9 = {(d.name, d.version) for d in lf.parse_pnpm_lock(v9)}
    assert ("lodash", "4.17.21") in got9
    assert ("react", "18.0.0") in got9  # peer-suffix stripped


def test_parse_poetry_and_cargo_lock():
    poetry = (
        '[[package]]\nname = "requests"\nversion = "2.19.1"\n\n'
        '[[package]]\nname = "flask"\nversion = "2.0.1"\n'
    )
    got = {(d.name, d.version, d.ecosystem) for d in lf.parse_poetry_lock(poetry)}
    assert ("requests", "2.19.1", lf.ECO_PYPI) in got
    cargo = '[[package]]\nname = "serde"\nversion = "1.0.100"\n'
    gotc = {(d.name, d.version, d.ecosystem) for d in lf.parse_cargo_lock(cargo)}
    assert ("serde", "1.0.100", lf.ECO_CRATES) in gotc


def test_parse_pipfile_lock():
    txt = (
        '{"default": {"requests": {"version": "==2.19.1"}}, '
        '"develop": {"pytest": {"version": "==7.0.0"}}}'
    )
    got = {(d.name, d.version) for d in lf.parse_pipfile_lock(txt)}
    assert ("requests", "2.19.1") in got
    assert ("pytest", "7.0.0") in got


def test_parse_go_sum_dedupes_gomod():
    txt = (
        "github.com/pkg/errors v0.9.1 h1:abc=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:def=\n"
    )
    deps = lf.parse_go_sum(txt)
    assert deps == [Dep(lf.ECO_GO, "github.com/pkg/errors", "0.9.1")]


def test_parse_all_dedupes_and_is_fail_safe():
    files = {
        "requirements.txt": "requests==2.19.1\nrequests==2.19.1\n",
        "broken.txt": "not a lockfile we know",
        "package-lock.json": "{ this is not valid json",
    }
    deps = lf.parse_all(files)
    assert deps == [Dep(lf.ECO_PYPI, "requests", "2.19.1")]  # deduped, no crash


# ── OSV severity mapping + MAL ───────────────────────────────────────────────

def test_mal_advisory_is_critical_and_flagged():
    v = {"id": "MAL-2024-1234", "summary": "malware"}
    assert is_malicious(v)
    assert severity_for_vuln(v) == "critical"


def test_mal_via_alias_is_critical():
    v = {"id": "GHSA-xxxx", "aliases": ["MAL-2024-9"]}
    assert is_malicious(v)
    assert severity_for_vuln(v) == "critical"


def test_cvss_vector_bands():
    crit = {"id": "CVE-1", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert severity_for_vuln(crit) == "critical"
    med = {"id": "CVE-2", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}]}
    assert severity_for_vuln(med) in ("low", "medium")


def test_numeric_cvss_score_band():
    v = {"id": "CVE-3", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert severity_for_vuln(v) == "high"


def test_database_specific_label_fallback():
    v = {"id": "GHSA-y", "database_specific": {"severity": "HIGH"}}
    assert severity_for_vuln(v) == "high"


# ── summarize_osv reducer ────────────────────────────────────────────────────

def test_summarize_osv_counts_and_findings():
    deps = [
        Dep(lf.ECO_NPM, "lodash", "4.17.15"),
        Dep(lf.ECO_NPM, "clean-pkg", "1.0.0"),
        Dep(lf.ECO_NPM, "evil", "6.6.6"),
    ]
    batch = [
        {"vulns": [{"id": "GHSA-lodash"}]},
        {},  # clean
        {"vulns": [{"id": "MAL-2024-1"}]},
    ]
    details = {
        "GHSA-lodash": {"id": "GHSA-lodash", "database_specific": {"severity": "HIGH"}},
        "MAL-2024-1": {"id": "MAL-2024-1", "summary": "backdoor"},
    }
    findings, counts, malicious = summarize_osv(deps, batch, details)
    assert counts.get("high") == 1
    assert counts.get("critical") == 1  # MAL forced to critical
    assert malicious == ["MAL-2024-1"]
    assert any("Known-malicious" in f["name"] for f in findings)
    assert all(f["category"] == "dependency" for f in findings)


def test_summarize_osv_dedupes_same_vuln():
    deps = [Dep(lf.ECO_NPM, "a", "1.0.0")]
    batch = [{"vulns": [{"id": "V1"}, {"id": "V1"}]}]
    findings, counts, _ = summarize_osv(deps, batch, {"V1": {"id": "V1"}})
    assert len(findings) == 1


# ── GitHub-depth signals ─────────────────────────────────────────────────────

def test_hash_pinned_actions_ratio():
    wf = [
        "jobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n"
        "      - uses: actions/setup-node@v3\n"
        "      - uses: ./local-action\n"
    ]
    r = hash_pinned_actions_ratio(wf)
    assert r["total"] == 2  # local action ignored
    assert r["pinned"] == 1
    assert r["ratio"] == 0.5


def test_signed_commit_ratio():
    commits = [
        {"commit": {"verification": {"verified": True}}},
        {"commit": {"verification": {"verified": False}}},
    ]
    r = signed_commit_ratio(commits)
    assert r == {"verified": 1, "total": 2, "ratio": 0.5}


# ── coverage block (Phase 0) ─────────────────────────────────────────────────

def test_build_coverage_shape():
    cov = build_coverage(
        surface="github",
        repo_url="https://github.com/o/r",
        commit="main",
        db_snapshots={"osv": "2026-08-08"},
    )
    assert cov["surface"] == "github"
    assert cov["scan_depth"] == "repo-only"
    assert cov["db_snapshots"] == {"osv": "2026-08-08"}
    assert cov["provenance_binding"] == "n/a"
    assert cov["artifact_digest"] == "repo:https://github.com/o/r@main"
    assert cov["linked_repo"]["commit"] == "main"
    assert cov["live_observed"] is False
    assert "point_in_time" in cov


def test_build_coverage_prefers_explicit_digest():
    cov = build_coverage(artifact_digest="sha512-abc", repo_url="https://github.com/o/r")
    assert cov["artifact_digest"] == "sha512-abc"


def test_evidence_anchors():
    assert build_evidence_anchors() == [EVIDENCE_ANCHOR_STATIC]
    anchors = build_evidence_anchors(has_sbom=True, has_provenance=True)
    assert len(anchors) == 3
    assert EVIDENCE_ANCHOR_STATIC in anchors


# ── fail-open orchestrator (mock transport) ──────────────────────────────────

def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_analyze_supply_chain_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}]}]})
        if request.url.path.startswith("/v1/vulns/"):
            return httpx.Response(200, json={
                "id": "GHSA-1", "summary": "bug",
                "database_specific": {"severity": "HIGH"}})
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await analyze_supply_chain(
            {"requirements.txt": "requests==2.19.1\n"},
            owner="o", repo="r",
            use_depsdev=False, use_scorecard=False,
            client=client,
        )
    assert res.ok is True
    assert res.deps_total == 1
    assert res.counts.get("high") == 1
    assert res.db_snapshots.get("osv")  # snapshot pinned for recompute
    assert any(f["category"] == "dependency" for f in res.findings)


@pytest.mark.asyncio
async def test_analyze_supply_chain_fails_open_on_osv_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)  # OSV down

    async with _mock_client(handler) as client:
        res = await analyze_supply_chain(
            {"requirements.txt": "requests==2.19.1\n"},
            owner="o", repo="r",
            use_depsdev=False, use_scorecard=False,
            client=client,
        )
    assert res.ok is False  # signals caller to keep the legacy regex path
    assert res.error is not None


@pytest.mark.asyncio
async def test_analyze_supply_chain_no_lockfiles_uses_depth_only():
    res = await analyze_supply_chain(
        {},  # no lockfiles
        owner="o", repo="r",
        workflow_texts=["jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
                        "      - uses: x/y@z\n      - uses: p/q@deadbeef\n"],
    )
    # No OSV call happened, but the depth signals still computed.
    assert res.deps_total == 0
    assert "hash_pinned_actions" in res.github_depth


# --- Bounded dependency-penalty aggregation (advisory flip gate) -------------
from src.scanner.scan import (  # noqa: E402
    _DEP_MAL_PENALTY,
    _DEP_VULN_CAP,
    _dependency_penalty,
)
from src.scanner.scan import Finding as _F  # noqa: E402,N814


def _deps(n, sev, name="Vulnerable dependency: pkg@1.0 (CVE-x)"):
    return [_F("dependency", f"{name}#{i}", sev, "lock", 1, "") for i in range(n)]


def test_dep_penalty_none():
    assert _dependency_penalty([]) == 0


def test_dep_penalty_single_medium_is_minor():
    assert 0 < _dependency_penalty(_deps(1, "medium")) <= 3


def test_dep_penalty_single_critical_modest():
    # A lone critical is modest while reachability is unknown.
    assert 4 <= _dependency_penalty(_deps(1, "critical")) <= 10


def test_dep_penalty_is_capped_no_false_f():
    # next.js's real distribution + an extreme one both cap out — never a false-F.
    nextjs = _deps(5, "critical") + _deps(65, "high") + _deps(21, "medium")
    heavy = _deps(20, "critical") + _deps(100, "high")
    assert _dependency_penalty(nextjs) == _DEP_VULN_CAP
    assert _dependency_penalty(heavy) == _DEP_VULN_CAP


def test_dep_penalty_malicious_is_disqualifying():
    mal = [_F("dependency", "Known-malicious package: evil@1.0 (MAL-2024-1)",
              "critical", "lock", 1, "")]
    assert _dependency_penalty(mal) == _DEP_MAL_PENALTY
    assert _DEP_MAL_PENALTY > _DEP_VULN_CAP * 3


def test_dep_penalty_ignores_non_dep_findings():
    code = [_F("unsafe_exec", "eval()", "critical", "a.py", 1, "")]
    assert _dependency_penalty(code) == 0


# ── dev-dependency exclusion (precision: dev vulns never ship to consumers) ────

def test_package_lock_captures_dev_flag():
    text = """
    {"lockfileVersion": 3, "packages": {
      "": {"name": "root"},
      "node_modules/left-pad": {"version": "1.3.0"},
      "node_modules/mocha": {"version": "2.0.0", "dev": true},
      "node_modules/eslint": {"version": "1.0.0", "devOptional": true}
    }}
    """
    deps = lf.parse_package_lock(text)
    by_name = {d.name: d for d in deps}
    assert by_name["left-pad"].dev is False
    assert by_name["mocha"].dev is True
    assert by_name["eslint"].dev is True


def test_pnpm_lock_v9_importers_dev_only():
    """pnpm v9 dropped inline ``dev: true``; dev-ness comes from ``importers:``.
    A devDependencies-only package is flagged dev; a production dep is NOT."""
    text = (
        "lockfileVersion: '9.0'\n"
        "\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      react:\n"
        "        specifier: ^18.0.0\n"
        "        version: 18.0.0\n"
        "    devDependencies:\n"
        "      eslint:\n"
        "        specifier: ^8.0.0\n"
        "        version: 8.0.0\n"
        "\n"
        "packages:\n"
        "  react@18.0.0:\n"
        "    resolution: {}\n"
        "  eslint@8.0.0:\n"
        "    resolution: {}\n"
    )
    deps = lf.parse_pnpm_lock(text)
    by_name = {d.name: d for d in deps}
    assert by_name["react"].dev is False  # production dependency stays full weight
    assert by_name["eslint"].dev is True  # devDependencies-only → dev-only


def test_pipfile_lock_develop_is_dev():
    text = """
    {"default": {"requests": {"version": "==2.0.0"}},
     "develop": {"pytest": {"version": "==7.0.0"}}}
    """
    deps = lf.parse_pipfile_lock(text)
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].dev is False
    assert by_name["pytest"].dev is True


@pytest.mark.asyncio
async def test_analyze_excludes_dev_deps_from_osv():
    """A lockfile of ONLY dev deps yields no production deps to query — so no OSV
    call, no vuln findings (mirrors lodash: zero runtime deps, heavy dev tree)."""
    lockfiles = {
        "package-lock.json": (
            '{"lockfileVersion": 3, "packages": {'
            '"": {"name": "root"},'
            '"node_modules/mocha": {"version": "2.0.0", "dev": true},'
            '"node_modules/grunt": {"version": "0.4.0", "dev": true}}}'
        )
    }
    # No transport needed: with all deps dev-excluded, the pipeline returns before
    # any network call.
    result = await analyze_supply_chain(lockfiles)
    assert result.deps_total == 0
    assert result.deps_dev_excluded == 2
    assert result.findings == []


# --- Reachability tuning: direct-prod CVEs weigh full, transitive sub-weighted ---

def _dep_finding(severity, reachability="direct"):
    return _F(category="dependency", name=f"Vulnerable dependency: x@1 (CVE-{severity})",
                   severity=severity, file_path="package-lock.json", line_number=1,
                   snippet="", remediation="", reachability=reachability)


def test_transitive_cve_weighs_less_than_direct():
    from src.scanner.scan import _dependency_penalty
    direct = _dependency_penalty([_dep_finding("high", "direct")])
    transitive = _dependency_penalty([_dep_finding("high", "transitive")])
    assert transitive < direct  # a buried transitive CVE hurts less
    assert direct > 0 and transitive > 0  # but still counts


def test_malicious_disqualifying_regardless_of_reachability():
    from src.scanner.scan import _DEP_MAL_PENALTY, Finding, _dependency_penalty
    f = Finding(category="dependency", name="Known-malicious package: evil@1 (MAL-1)",
                severity="critical", file_path="p", line_number=1, snippet="", remediation="",
                reachability="transitive")
    assert _dependency_penalty([f]) == _DEP_MAL_PENALTY  # depth never softens malicious


def test_direct_finding_unchanged_from_legacy():
    # A finding with no explicit reachability defaults to "direct" = full weight, so
    # legacy behavior (a lone direct critical in the 4–10 band) is preserved.
    from src.scanner.scan import _dependency_penalty
    p = _dependency_penalty([_dep_finding("critical")])
    assert 4 <= p <= 10


def test_package_lock_marks_direct_vs_transitive():
    import json

    from src.scanner.lockfiles import parse_package_lock
    lock = json.dumps({
        "packages": {
            "": {"dependencies": {"express": "^4.0.0"}},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/body-parser": {"version": "1.20.0"},  # transitive (not declared)
        }
    })
    deps = {d.name: d for d in parse_package_lock(lock)}
    assert deps["express"].direct is True
    assert deps["body-parser"].direct is False


# ── deps.dev reachability (cross-ecosystem direct/transitive classification) ──

@pytest.mark.asyncio
async def test_depsdev_indirect_keys_parses_relations():
    from src.scanner.supply_chain import fetch_depsdev_indirect_keys

    def handler(request):
        return httpx.Response(200, json={"nodes": [
            {"versionKey": {"name": "root", "version": "1.0"}, "relation": "SELF"},
            {"versionKey": {"name": "direct-dep", "version": "2.0"}, "relation": "DIRECT"},
            {"versionKey": {"name": "Buried-Dep", "version": "3.1"}, "relation": "INDIRECT"},
        ]})

    async with _mock_client(handler) as client:
        keys = await fetch_depsdev_indirect_keys("crates.io", "root", "1.0", client)
    assert keys == {"buried-dep@3.1"}  # lowercased name, only INDIRECT


@pytest.mark.asyncio
async def test_depsdev_default_version():
    from src.scanner.supply_chain import fetch_depsdev_default_version

    def handler(request):
        return httpx.Response(200, json={"versions": [
            {"versionKey": {"version": "0.9"}, "isDefault": False},
            {"versionKey": {"version": "1.2.3"}, "isDefault": True},
        ]})

    async with _mock_client(handler) as client:
        assert await fetch_depsdev_default_version("PyPI", "x", client) == "1.2.3"


@pytest.mark.asyncio
async def test_depsdev_unknown_ecosystem_is_none():
    from src.scanner.supply_chain import fetch_depsdev_indirect_keys

    def handler(request):
        return httpx.Response(200, json={"nodes": []})

    async with _mock_client(handler) as client:
        assert await fetch_depsdev_indirect_keys("rubygems", "x", "1", client) is None
