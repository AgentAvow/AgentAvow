"""Session-start hook, dependency pass: the project's DIRECT dependencies are graded
(capped per start, re-graded only when the declared version changes), reported as
advice ("needs a look"), and the whole pass fails open. Most projects have no MCP
servers; this is what gives a first session something to say.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_precheck.py"


def _load():
    spec = importlib.util.spec_from_file_location("precheck_deps", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "CACHE", tmp_path / "cache" / "scanned.json")
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(mod.DEPS_ENV, raising=False)
    monkeypatch.setattr(mod, "_targets", lambda: [])  # no MCP servers unless a test says so
    monkeypatch.setattr(mod, "_servers_elsewhere", lambda here: 0)
    return mod


def _ok(score, verdict, blocking=0, **extra):
    base = {"score": score, "verdict": verdict, "blocking": blocking, "tier": "standard",
            "grade": "B", "tool_digests": {}, "tool_manifest_digest": None, "sandbox": "",
            "deprecated": False}
    base.update(extra)
    return base


def _run(hook, monkeypatch, capsys, scan):
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    return json.loads(out) if out else {}


# --- manifests -----------------------------------------------------------------

def test_package_json_direct_runtime_deps_only(hook, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"left-pad": "^1.3.0", "chalk": "5.3.0", "local": "file:../x",
                         "gitdep": "github:a/b", "ws": "workspace:*"},
        "devDependencies": {"vitest": "^2"}}))
    deps = hook._dependency_targets()
    assert [(d["registry"], d["pkg"], d["spec"]) for d in deps] == [
        ("npm", "left-pad", "^1.3.0"), ("npm", "chalk", "5.3.0")]
    assert deps[0]["name"] == "dep:npm:left-pad" and deps[0]["id"] == "dep:npm:left-pad@^1.3.0"


def test_requirements_txt_parsing(hook, tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# pinned\nrequests==2.32.0\nfastapi>=0.110,<1  # api\n"
        "uvicorn[standard]~=0.30\n-r base.txt\n--index-url https://x\n"
        "./local/pkg\ngit+https://github.com/a/b\n\npydantic ; python_version>'3.8'\n")
    deps = hook._dependency_targets()
    assert [(d["pkg"], d["spec"]) for d in deps] == [
        ("requests", "==2.32.0"), ("fastapi", ">=0.110,<1"), ("uvicorn", "~=0.30"), ("pydantic", "")]
    assert all(d["registry"] == "pypi" for d in deps)


def test_pyproject_project_dependencies(hook, tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n  "httpx>=0.27",\n  "rich",\n]\n'
        '[tool.ruff]\nline-length = 100\n')
    deps = hook._dependency_targets()
    assert [(d["pkg"], d["spec"]) for d in deps] == [("httpx", ">=0.27"), ("rich", "")]


def test_pyproject_fallback_parser_without_tomllib(hook, tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_tomllib(name, *a, **kw):
        if name == "tomllib":
            raise ImportError("no tomllib")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_tomllib)
    text = '[build-system]\nrequires=["x"]\n[project]\ndependencies = ["httpx>=0.27", \'rich\']\n[tool.y]\n'
    assert [(d["pkg"], d["spec"]) for d in hook._pyproject_deps(text)] == [("httpx", ">=0.27"), ("rich", "")]


def test_same_package_in_two_manifests_once_and_no_manifest_means_none(hook, tmp_path):
    assert hook._dependency_targets() == []
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests>=2"]\n')
    assert [d["pkg"] for d in hook._dependency_targets()] == ["requests"]


def test_off_switch(hook, tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    monkeypatch.setenv(hook.DEPS_ENV, "off")
    assert hook._dependency_targets() == []


# --- grading, cap, cache --------------------------------------------------------

def test_deps_are_graded_reported_and_summarized(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {
        "chalk": "5.3.0", "left-pad": "1.3.0", "lodash": "4.17.21"}}))
    scores = {"chalk": _ok(90, "safe"), "left-pad": _ok(70, "needs review", 0, deprecated=True),
              "lodash": _ok(88, "safe")}
    out = _run(hook, monkeypatch, capsys, lambda t, force=False: scores[t["pkg"]])
    msg = out["systemMessage"]
    assert msg.startswith("AgentAvow pre-check: no MCP servers in this project.")
    assert "Dependencies: graded all 3 — 2 OK, 1 needs a look (lowest: 'left-pad' 70/100, deprecated)." in msg
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "📦 dependency 'left-pad' (npm:left-pad@1.3.0): AgentAvow 70/100 — needs a look: DEPRECATED" in ctx
    assert "✅ dependency 'chalk' (npm:chalk@5.3.0): AgentAvow 90/100 — safe." in ctx
    assert "already installed: its grade is advice, not a stop" in ctx
    cache = json.loads(hook.CACHE.read_text())
    assert cache["dep:npm:left-pad"]["spec"] == "1.3.0" and cache["dep:npm:left-pad"]["score"] == 70


def test_cap_per_session_and_the_rest_next_time(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {f"p{i}": "1.0.0" for i in range(20)}}))
    calls = []

    def scan(t, force=False):
        calls.append(t["pkg"])
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == hook.DEPS_CAP == 8
    assert "Dependencies: graded 8 of 20 — 8 OK, 0 need a look." in out["systemMessage"]
    out2 = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == 16
    assert "Dependencies: graded 16 of 20 — 16 OK, 0 need a look." in out2["systemMessage"]
    out3 = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == 20
    assert "Dependencies: graded all 20 — 20 OK, 0 need a look." in out3["systemMessage"]
    assert _run(hook, monkeypatch, capsys, scan) == {}  # nothing new: silent
    assert len(calls) == 20


def test_rate_limit_stops_the_pass_and_says_so(hook, monkeypatch, capsys, tmp_path):
    import urllib.error
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1", "b": "1", "c": "1"}}))
    calls = []

    def scan(t, force=False):
        calls.append(t["pkg"])
        if t["pkg"] == "b":
            raise urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    assert calls == ["a", "b"]  # stopped at the 429; 'c' waits for next session
    assert "Dependencies: graded 1 of 3 — 1 OK, 0 need a look (paused: rate limited; continues next session)." in out["systemMessage"]
    out2 = _run(hook, monkeypatch, capsys, scan)
    assert calls == ["a", "b", "b"]  # 'b' retried first next time (still 429 here)
    assert "paused: rate limited" in out2["systemMessage"]


def test_regraded_only_when_the_declared_version_changes(hook, monkeypatch, capsys, tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"dependencies": {"chalk": "5.3.0"}}))
    calls = []

    def scan(t, force=False):
        calls.append(t["id"])
        return _ok(85, "safe")

    _run(hook, monkeypatch, capsys, scan)
    assert _run(hook, monkeypatch, capsys, scan) == {} and calls == ["dep:npm:chalk@5.3.0"]
    pj.write_text(json.dumps({"dependencies": {"chalk": "5.4.0"}}))
    out = _run(hook, monkeypatch, capsys, scan)
    assert calls == ["dep:npm:chalk@5.3.0", "dep:npm:chalk@5.4.0"]
    assert "chalk@5.4.0" in out["hookSpecificOutput"]["additionalContext"]


def test_unscannable_and_transient_failures_fail_open(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1", "b": "1", "c": "1"}}))

    def scan(t, force=False):
        if t["pkg"] == "a":
            raise hook._UnscannableError("422")
        if t["pkg"] == "b":
            raise TimeoutError("slow")
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "➖ dependency 'a'" in ctx and "not scanned" in ctx
    assert "dependency 'b'" not in ctx  # transient: silent, retried next session
    assert "Dependencies: graded 1 of 3 — 1 OK, 0 need a look." in out["systemMessage"]
    cache = json.loads(hook.CACHE.read_text())
    assert "retry_after" in cache["dep:npm:a"] and "dep:npm:b" not in cache


def test_servers_and_deps_share_one_summary_line(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    monkeypatch.setattr(hook, "_targets", lambda: [
        {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp", "url": "https://mcp.deepwiki.com/mcp"}])

    def scan(t, force=False):
        return _ok(74, "needs review") if t["kind"] == "mcp" and "url" in t else _ok(90, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    msg = out["systemMessage"]
    assert msg.startswith("AgentAvow pre-check: graded 1 MCP server — 0 safe, 1 needs review (lowest: 'dw' 74/100).")
    assert "Dependencies: graded all 1 — 1 OK, 0 need a look." in msg
    assert msg.endswith("Ask for the AgentAvow pre-check for details.")


def test_dependency_pass_errors_never_break_the_server_report(hook, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(hook, "_targets", lambda: [
        {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp", "url": "https://mcp.deepwiki.com/mcp"}])
    monkeypatch.setattr(hook, "_dependency_targets", lambda: [{"broken": True}])
    out = _run(hook, monkeypatch, capsys, lambda t, force=False: _ok(90, "safe"))
    assert "graded 1 MCP server — 1 safe" in out["systemMessage"]


def test_intro_only_when_neither_servers_nor_manifests(hook, monkeypatch, capsys):
    out = _run(hook, monkeypatch, capsys, lambda t, force=False: _ok(90, "safe"))
    assert "nothing to grade here yet" in out["systemMessage"]
    assert "package.json / requirements.txt" in out["systemMessage"]


def test_pattern_only_highs_are_reported_but_not_flagged(hook, monkeypatch, capsys, tmp_path):
    """fastapi-style: 30 high-severity regex hits, 0 critical, 0 advisories -> shown with
    its score as info, counted OK. A critical finding or an advisory -> needs a look."""
    (tmp_path / "requirements.txt").write_text("fastapi\nevil-pkg\nold-pkg\n")
    scores = {"fastapi": _ok(40, "needs review", 30),
              "evil-pkg": _ok(20, "needs review", 3, critical=2),
              "old-pkg": _ok(60, "needs review", 0, advisories=1)}
    out = _run(hook, monkeypatch, capsys, lambda t, force=False: scores[t["pkg"]])
    msg = out["systemMessage"]
    assert "Dependencies: graded all 3 — 1 OK, 2 need a look (lowest: 'evil-pkg' 20/100, 2 critical)." in msg
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ("ℹ️ dependency 'fastapi' (pypi:fastapi): AgentAvow 40/100 — no critical findings, no "
            "advisories; 30 high-severity pattern hit(s) (common in large frameworks), see the report.") in ctx
    assert "📦 dependency 'evil-pkg' (pypi:evil-pkg): AgentAvow 20/100 — needs a look: 2 critical finding(s)." in ctx
    assert "📦 dependency 'old-pkg' (pypi:old-pkg): AgentAvow 60/100 — needs a look: 1 advisory(ies) for this version." in ctx


def test_dep_needs_look_rule(hook):
    assert not hook._dep_needs_look(_ok(90, "safe"))
    assert not hook._dep_needs_look(_ok(40, "needs review", 30))  # pattern hits only
    assert hook._dep_needs_look(_ok(40, "needs review", 1, critical=1))
    assert hook._dep_needs_look(_ok(70, "needs review", 0, deprecated=True))
    assert hook._dep_needs_look(_ok(70, "needs review", 0, advisories=2))
    assert hook._dep_needs_look(_ok(70, "needs review", 0, incident=True))
    assert hook._dep_needs_look(_ok(8, "needs review", 0, tier="blocked"))


def test_verdict_carries_the_risk_signals_from_either_api_shape(hook):
    v = hook._verdict({"trust_score": 40, "findings": {"items": [
        {"severity": "high"}, {"severity": "critical"}, {"severity": "medium"}]},
        "advisories_affecting_version": [{"id": "GHSA-1"}], "incident": {"id": "x"}})
    assert v["blocking"] == 2 and v["critical"] == 1 and v["advisories"] == 1 and v["incident"] is True
    # Raw API shape: 'advisories' list + 'incident_history' dict. chalk: a past incident
    # that does NOT affect the installed version is not an incident for this grade.
    v = hook._verdict({"trust_score": 82, "advisories": [],
                       "incident_history": {"has_incident": True, "current_version_affected": False}})
    assert v["advisories"] == 0 and v["incident"] is False
    v = hook._verdict({"trust_score": 50, "advisories": [{"id": "GHSA-2", "affects_current_version": False},
                                                          {"id": "GHSA-3"}],
                       "incident_history": {"has_incident": True, "current_version_affected": True}})
    assert v["advisories"] == 1 and v["incident"] is True  # GHSA-3: no fix, no flag → counts
    assert hook._verdict({"trust_score": 90})["advisories"] == 0
    # fastapi as the raw API returns it: two advisories, both FIXED long ago, no flag.
    # History, not evidence against 0.142.2 → 0.
    v = hook._verdict({"trust_score": 40, "package_version": "0.142.2", "advisories": [
        {"id": "GHSA-2jv5-9r88-3w3p", "severity": "medium", "fixed_in": "9d34ad0e"},
        {"id": "GHSA-8h2j-cgx8-6xv7", "severity": "high", "fixed_in": "0.65.2"}]})
    assert v["advisories"] == 0
    assert hook._advisory_applies({"id": "x", "affects_current_version": True, "fixed_in": "1.0"})
    assert not hook._advisory_applies("GHSA-string")
