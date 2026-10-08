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


def _run(hook, monkeypatch, capsys, scan, raw=False):
    """Hook output. A quiet start (nothing new: context for Claude only, nothing shown to
    the person) reads as {} unless ``raw`` — most tests ask "was anything reported"."""
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    data = json.loads(out) if out else {}
    ctx = data.get("hookSpecificOutput", {}).get("additionalContext", "")
    if not raw and "systemMessage" not in data and ctx.startswith("AgentAvow pre-check: nothing new"):
        return {}
    return data


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
    # The real failure on Kenne's Mac (python 3.9, no tomllib): a multi-line list whose
    # entries carry extras in brackets. The old regex stopped at the first ']' and found
    # one dependency out of 25.
    real = ('[project]\nname = "agentgraph"\ndependencies = [\n    "fastapi>=0.104.0,<1.0",\n'
            '    "uvicorn[standard]>=0.24.0,<1.0",  # ASGI server\n    "sqlalchemy>=2.0",\n'
            '    "pydantic-settings>=2.0",\n]\n\n[project.optional-dependencies]\ndev = ["pytest"]\n')
    got = [(d["pkg"], d["spec"]) for d in hook._pyproject_deps(real)]
    assert got == [("fastapi", ">=0.104.0,<1.0"), ("uvicorn", ">=0.24.0,<1.0"),
                   ("sqlalchemy", ">=2.0"), ("pydantic-settings", ">=2.0")]
    assert hook._pyproject_deps("[project]\nname = \"x\"\n") == []


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
    scores = {"chalk": _ok(90, "safe"), "left-pad": _ok(70, "needs review", 0, deprecated=True, decision="review",
                              decision_reason="the maintainer has deprecated this package"),
              "lodash": _ok(88, "safe")}
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: scores[t["pkg"]])
    msg = out["systemMessage"]
    assert msg.startswith("AgentAvow pre-check: no MCP servers in this project.")
    assert ("Dependencies: graded all 3 — 2 Safe, 1 Review (needs attention: 'left-pad' Review "
            "before you connect — the maintainer has deprecated this package).") in msg
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ("⚠️ dependency 'left-pad' (npm:left-pad@1.3.0): Review before you connect — the "
            "maintainer has deprecated this package · AgentAvow 70/100.") in ctx
    assert "✅ dependency 'chalk' (npm:chalk@5.3.0): Safe to connect — nothing found · AgentAvow 90/100." in ctx
    assert "already installed: their answer is advice" in ctx and "Do not interpret the raw cache file" in ctx
    cache = json.loads(hook.CACHE.read_text())
    assert cache["dep:npm:left-pad"]["spec"] == "1.3.0" and cache["dep:npm:left-pad"]["score"] == 70


def test_cap_per_session_and_the_rest_next_time(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {f"p{i}": "1.0.0" for i in range(20)}}))
    calls = []

    def scan(t, force=False, stored=False):
        calls.append(t["pkg"])
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == hook.DEPS_CAP == 8
    assert "Dependencies: graded 8 of 20 — 8 Safe, 0 Review." in out["systemMessage"]
    out2 = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == 16
    assert "Dependencies: graded 16 of 20 — 16 Safe, 0 Review." in out2["systemMessage"]
    out3 = _run(hook, monkeypatch, capsys, scan)
    assert len(calls) == 20
    assert "Dependencies: graded all 20 — 20 Safe, 0 Review." in out3["systemMessage"]
    assert _run(hook, monkeypatch, capsys, scan) == {}  # nothing new: silent
    assert len(calls) == 20


def test_rate_limit_stops_the_pass_and_says_so(hook, monkeypatch, capsys, tmp_path):
    import urllib.error
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1", "b": "1", "c": "1"}}))
    calls = []

    def scan(t, force=False, stored=False):
        calls.append(t["pkg"])
        if t["pkg"] == "b":
            raise urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    assert calls == ["a", "b"]  # stopped at the 429; 'c' waits for next session
    assert "Dependencies: graded 1 of 3 — 1 Safe, 0 Review (paused: rate limited; continues next session)." in out["systemMessage"]
    out2 = _run(hook, monkeypatch, capsys, scan)
    assert calls == ["a", "b", "b"]  # 'b' retried first next time (still 429 here)
    assert "paused: rate limited" in out2["systemMessage"]


def test_regraded_only_when_the_declared_version_changes(hook, monkeypatch, capsys, tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"dependencies": {"chalk": "5.3.0"}}))
    calls = []

    def scan(t, force=False, stored=False):
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

    def scan(t, force=False, stored=False):
        if t["pkg"] == "a":
            raise hook._UnscannableError("422")
        if t["pkg"] == "b":
            raise TimeoutError("slow")
        return _ok(85, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "➖ dependency 'a'" in ctx and "not scanned" in ctx
    assert "dependency 'b'" not in ctx  # transient: silent, retried next session
    # A refused dependency counts as done (it will not become gradable by waiting).
    assert "Dependencies: graded 2 of 3 — 1 Safe, 0 Review (1 could not be graded)." in out["systemMessage"]
    cache = json.loads(hook.CACHE.read_text())
    assert "retry_after" in cache["dep:npm:a"] and "dep:npm:b" not in cache


def test_servers_and_deps_share_one_summary_line(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    monkeypatch.setattr(hook, "_targets", lambda: [
        {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp", "url": "https://mcp.deepwiki.com/mcp"}])

    def scan(t, force=False, stored=False):
        return _ok(74, "needs review", reason="thin_coverage") if t["kind"] == "mcp" and "url" in t else _ok(90, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    msg = out["systemMessage"]
    # thin coverage reads Safe (2026-10-08, #19), so nothing needs attention
    assert msg.startswith("AgentAvow pre-check: graded 1 MCP server — 1 Safe, 0 Review.")
    assert "Dependencies: graded all 1 — 1 Safe, 0 Review." in msg
    assert msg.endswith("Ask for the AgentAvow pre-check for details.")


def test_dependency_pass_errors_never_break_the_server_report(hook, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(hook, "_targets", lambda: [
        {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp", "url": "https://mcp.deepwiki.com/mcp"}])
    monkeypatch.setattr(hook, "_dependency_targets", lambda: [{"broken": True}])
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(90, "safe"))
    assert "graded 1 MCP server — 1 Safe" in out["systemMessage"]


def test_intro_only_when_neither_servers_nor_manifests(hook, monkeypatch, capsys):
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(90, "safe"))
    assert "nothing to grade here yet" in out["systemMessage"]
    assert "package.json / requirements.txt" in out["systemMessage"]


def test_dependency_lines_lead_with_the_phrase_and_never_block(hook, monkeypatch, capsys, tmp_path):
    """Each dependency line leads with the API's answer + reason; the summary counts the
    three answers and names the one needing attention most. Dependencies are already
    installed: even "Do not connect" is advice, never a prompt."""
    (tmp_path / "requirements.txt").write_text("fastapi\nevil-pkg\nold-pkg\n")
    scores = {
        "fastapi": _ok(40, "needs review", 30, decision="review",
                       decision_reason="30 high findings, including eval of input"),
        "evil-pkg": _ok(20, "needs review", 3, critical=2, decision="do_not_connect",
                        decision_reason="2 critical findings, including hardcoded key"),
        "old-pkg": _ok(60, "needs review", 0, advisories=1, decision="review",
                       decision_reason="a published advisory affects this version (GHSA-1)"),
    }
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: scores[t["pkg"]])
    msg = out["systemMessage"]
    assert ("Dependencies: graded all 3 — 0 Safe, 2 Review, 1 Blocked (needs attention: "
            "'evil-pkg' Do not connect — 2 critical findings, including hardcoded key).") in msg
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ("⚠️ dependency 'fastapi' (pypi:fastapi): Review before you connect — 30 high "
            "findings, including eval of input · AgentAvow 40/100.") in ctx
    assert ("⛔ dependency 'evil-pkg' (pypi:evil-pkg): Do not connect — 2 critical findings, "
            "including hardcoded key · AgentAvow 20/100.") in ctx
    assert "Review before you connect — a published advisory affects this version" in ctx
    assert "permissionDecision" not in json.dumps(out)


def test_dep_needs_look_rule(hook):
    """Any answer other than Safe to connect counts as needing a look (advice only); a
    record cached before 0.1.20 maps its old binary verdict."""
    assert not hook._dep_needs_look(_ok(90, "safe", decision="safe"))
    assert hook._dep_needs_look(_ok(90, "safe", decision="review"))
    assert hook._dep_needs_look(_ok(20, "needs review", decision="do_not_connect"))
    assert not hook._dep_needs_look(_ok(90, "safe"))  # legacy record
    assert hook._dep_needs_look(_ok(40, "needs review", 30))  # legacy record


def test_verdict_reads_the_api_decision_and_falls_back_to_the_same_rule(hook):
    v = hook._verdict({"trust_score": 92, "decision": "review", "decision_final": False,
                       "decision_reason": "one high finding: x; sandbox still running",
                       "certified": {"eligible": True}})
    assert (v["decision"], v["decision_final"], v["certified"]) == ("review", False, True)
    assert hook._answer(v) == ("Review before you connect · Certified — one high finding: x; "
                               "sandbox still running · AgentAvow 92/100")
    # older API response: decided locally
    assert hook._verdict({"trust_score": 40, "findings": {"critical": 1}})["decision"] == \
        "do_not_connect"
    assert hook._verdict({"trust_score": 90, "findings": {"high": 2}})["decision"] == "review"
    assert hook._verdict({"trust_score": 45})["decision"] == "review"
    thin = hook._verdict({"trust_score": 95, "metadata": {"files_scanned": 3}})
    assert (thin["decision"], thin["decision_reason"]) == (
        "safe", "nothing found; little code to inspect")
    remote = hook._verdict({"trust_score": 82, "metadata": {"files_scanned": 4},
                            "coverage": {"surface": "mcp"}})
    assert (remote["decision"], remote["decision_reason"]) == (
        "safe", "tool definitions clean; server code not inspected")
    assert hook._verdict({"trust_score": 90, "behavioral": {
        "ran": True, "canary_exfil": [{"host": "x"}]}})["decision"] == "do_not_connect"
    assert hook._verdict({"trust_score": 90, "behavioral": {
        "ran": True, "plan": "live-probe", "findings": [{"severity": "critical"}]}})[
        "decision"] == "safe"
    assert hook._verdict({"trust_score": 90})["decision"] == "safe"


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


def test_session_cwd_from_the_hook_payload_wins_over_the_process_cwd(hook, monkeypatch, capsys, tmp_path):
    """Claude Desktop's Code tab starts in a scratch workspace and the person moves into
    the project; the SessionStart payload's ``cwd`` is the session folder."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.chdir(scratch)  # process cwd: nothing here
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "SessionStart",
                                                             "source": "clear", "cwd": str(project)})))
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(90, "safe"))
    assert "Dependencies: graded all 1 — 1 Safe, 0 Review." in out["systemMessage"]
    assert hook._cwd() == project


def test_bad_or_missing_cwd_falls_back_to_the_process_cwd(hook, tmp_path):
    hook._set_session_cwd({"cwd": str(tmp_path / "does-not-exist")})
    assert hook._cwd() == pathlib.Path.cwd()
    hook._set_session_cwd({"cwd": 42})
    assert hook._cwd() == pathlib.Path.cwd()
    hook._set_session_cwd("not a dict")
    assert hook._cwd() == pathlib.Path.cwd()
    hook._set_session_cwd({"cwd": str(tmp_path)})
    assert hook._cwd() == tmp_path
    hook._set_session_cwd(None)


# --- stored grades: the dependency pass never triggers a fresh scan ---------------------

def test_dependencies_ask_for_the_stored_grade(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    seen = []

    def scan(t, force=False, stored=False):
        seen.append(stored)
        return _ok(90, "safe")

    _run(hook, monkeypatch, capsys, scan)
    assert seen == [True]


def test_scan_passes_stored_only_for_packages_and_fetch_raises_queued_on_202(hook, monkeypatch):
    calls = []

    def fetch(path, params):
        calls.append((path, params))
        return {"trust_score": 90, "findings": {"items": []}}

    monkeypatch.setattr(hook, "_fetch", fetch)
    hook._scan({"kind": "package", "registry": "npm", "pkg": "chalk"}, stored=True)
    hook._scan({"kind": "package", "registry": "npm", "pkg": "chalk"})
    hook._scan({"kind": "mcp", "url": "https://a.example/mcp"}, stored=True)
    assert calls == [("/package/npm/chalk", {"stored": "true"}), ("/package/npm/chalk", {}),
                     ("/mcp", {"endpoint": "https://a.example/mcp"})]


def test_fetch_raises_queued_on_a_202(hook, monkeypatch):
    class _Resp:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"status": "queued", "detail": "No stored grade yet"}'

    monkeypatch.setattr(hook.urllib.request, "urlopen", lambda req, timeout=0: _Resp())
    with pytest.raises(hook._QueuedError):
        hook._fetch("/package/npm/new-pkg", {"stored": "true"})


def test_queued_dependencies_are_counted_retried_soon_and_never_block(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1", "b": "1", "c": "1"}}))
    calls = []

    def scan(t, force=False, stored=False):
        calls.append(t["pkg"])
        if t["pkg"] in ("b", "c"):
            raise hook._QueuedError("queued")
        return _ok(90, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    msg = out["systemMessage"]
    assert "Dependencies: graded 1 of 3 — 1 Safe, 0 Review (2 queued for grading)." in msg
    cache = json.loads(hook.CACHE.read_text())
    assert cache["dep:npm:b"]["retry_after"] - hook.time.time() < hook.RETRY_QUEUED + 5
    # Next session (within the retry window): nothing new is asked about, so silence.
    assert _run(hook, monkeypatch, capsys, scan) == {}
    assert calls == ["a", "b", "c"]
    # Only queued items and no graded ones → one explanatory line, no empty report.
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"d": "1"}}))

    def all_queued(t, force=False, stored=False):
        raise hook._QueuedError("queued")

    out = _run(hook, monkeypatch, capsys, all_queued)
    assert "1 dependency not graded yet" in out["hookSpecificOutput"]["additionalContext"]
    assert "Dependencies: 0 of 1 graded yet (1 queued for grading)." in out["systemMessage"]


# --- summary wording ------------------------------------------------------------------

def test_summary_does_not_claim_a_server_failed_when_only_dependencies_are_new(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    dw = {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp", "url": "https://mcp.deepwiki.com/mcp"}
    monkeypatch.setattr(hook, "_targets", lambda: [dw])
    monkeypatch.setattr(hook, "_servers_elsewhere", lambda here: 3)
    # Session 1: server + dependency both new.
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(74, "needs review", 0, reason="thin_coverage", decision="review", decision_reason="the maintainer has deprecated this package")
               if t["kind"] == "mcp" and "url" in t else _ok(90, "safe"))
    assert out["systemMessage"].startswith("AgentAvow pre-check: graded 1 MCP server — 0 Safe, 1 Review (needs attention: 'dw' Review before you connect — the maintainer has deprecated this package).")
    assert out["systemMessage"].endswith("3 more MCP servers configured for other projects, graded when you open them.")
    assert "⚠️ MCP 'dw' (https://mcp.deepwiki.com/mcp): Review before you connect — the maintainer has deprecated this package · AgentAvow 74/100." in out["hookSpecificOutput"]["additionalContext"]
    # Session 2: a NEW dependency appears, the server is unchanged → no "could not be scanned".
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5", "lodash": "4"}}))
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(90, "safe"))
    assert out["systemMessage"].startswith("AgentAvow pre-check: MCP servers unchanged. Dependencies: graded all 2 — 2 Safe, 0 Review.")
    assert "could not be scanned" not in out["systemMessage"]



# --- acceptance-run fixes (0.1.18) -------------------------------------------------------

def test_refusal_reason_is_shown_and_the_count_completes(hook, monkeypatch, capsys, tmp_path):
    """sqlalchemy: the API refuses it (artifact over the unpacked-size cap). It must read
    'not scanned (reason)' and let the count reach 'all', not stay 'queued' forever."""
    (tmp_path / "requirements.txt").write_text("sqlalchemy\nuvicorn\n")

    def scan(t, force=False, stored=False):
        if t["pkg"] == "sqlalchemy":
            raise hook._UnscannableError("Not scannable: artifact exceeds unpacked-size cap (zip bomb?)")
        return _ok(92, "safe")

    out = _run(hook, monkeypatch, capsys, scan)
    assert "Dependencies: graded all 2 — 1 Safe, 0 Review (1 could not be graded)." in out["systemMessage"]
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ("➖ dependency 'sqlalchemy' (pypi:sqlalchemy): not scanned — AgentAvow couldn't grade it "
            "(artifact exceeds unpacked-size cap (zip bomb?)). Neither safe nor unsafe.") in ctx
    assert _run(hook, monkeypatch, capsys, scan) == {}  # done: silence next start


def test_fetch_keeps_the_api_refusal_reason(hook, monkeypatch):
    import io as _io
    import urllib.error

    def raise_422(req, timeout=0):
        raise urllib.error.HTTPError("u", 422, "Unprocessable", {},
                                     _io.BytesIO(b'{"detail": "Not scannable: too big"}'))

    monkeypatch.setattr(hook.urllib.request, "urlopen", raise_422)
    with pytest.raises(hook._UnscannableError) as ei:
        hook._fetch("/package/pypi/sqlalchemy", {"stored": "true"})
    assert str(ei.value) == "Not scannable: too big"


def test_detail_view_includes_items_graded_at_earlier_starts(hook, monkeypatch, capsys, tmp_path):
    """After a quiet start, a change to one pin re-grades only that one; the context
    must still list everything else so 'show the pre-check' can answer in full."""
    pj = tmp_path / "package.json"
    pj.write_text(json.dumps({"dependencies": {"chalk": "5", "fastapi-like": "1", "httpx-like": "1"}}))
    scores = {"chalk": _ok(90, "safe"), "fastapi-like": _ok(40, "needs review", 30),
              "httpx-like": _ok(88, "safe")}
    _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: scores[t["pkg"]])
    pj.write_text(json.dumps({"dependencies": {"chalk": "5", "fastapi-like": "1", "httpx-like": "2"}}))
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: scores[t["pkg"]])
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "✅ dependency 'httpx-like' (npm:httpx-like@2)" in ctx  # the re-graded one, in full
    assert "Graded at an earlier session start (unchanged since):" in ctx
    assert "  ✅ dependency 'chalk': Safe to connect — nothing found · AgentAvow 90/100" in ctx
    assert "  ⚠️ dependency 'fastapi-like': Review before you connect — 30 high finding(s) · AgentAvow 40/100" in ctx
    earlier = ctx.split("Graded at an earlier session start (unchanged since):", 1)[1]
    assert "httpx-like" not in earlier  # the re-graded one is not repeated in the earlier list



def test_quiet_start_is_silent_for_the_person_but_gives_claude_the_full_list(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("uvicorn\nfastapi\nsqlalchemy\n")

    def scan(t, force=False, stored=False):
        if t["pkg"] == "sqlalchemy":
            raise hook._UnscannableError("Not scannable: artifact exceeds unpacked-size cap (zip bomb?)")
        return _ok(92, "safe") if t["pkg"] == "uvicorn" else _ok(40, "needs review", 30)

    _run(hook, monkeypatch, capsys, scan)
    out = _run(hook, monkeypatch, capsys, scan, raw=True)  # nothing new
    assert "systemMessage" not in out  # the person sees nothing
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ctx.startswith("AgentAvow pre-check: nothing new since the last session start. Do NOT mention")
    assert "  ✅ dependency 'uvicorn': Safe to connect — nothing found · AgentAvow 92/100" in ctx
    assert "  ⚠️ dependency 'fastapi': Review before you connect — 30 high finding(s) · AgentAvow 40/100" in ctx
    assert "Safe to connect" in ctx and "Do not connect" in ctx  # the legend names all three
    assert "  ➖ dependency 'sqlalchemy': not graded (artifact exceeds unpacked-size cap (zip bomb?))" in ctx
    assert "Do not interpret the raw cache file" in ctx


def test_quiet_start_with_nothing_graded_prints_nothing(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("x\n")

    def queued(t, force=False, stored=False):
        raise hook._QueuedError("q")

    _run(hook, monkeypatch, capsys, queued)
    assert _run(hook, monkeypatch, capsys, queued, raw=True) == {}


# --- compact lines carry the reason and agree with the full line ------------------

def test_compact_server_line_carries_the_reason(hook, monkeypatch, capsys, tmp_path):
    """deepwiki in Kenne's acceptance run: the compact line must say why, like the full
    line does, including for a record cached by an older version (verdict + reason only)."""
    dw = {"name": "dw", "kind": "mcp", "id": "https://mcp.deepwiki.com/mcp",
          "url": "https://mcp.deepwiki.com/mcp"}
    monkeypatch.setattr(hook, "_targets", lambda: [dw])
    full = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: _ok(
        74, "needs review", 0, reason="thin_coverage"))["hookSpecificOutput"]["additionalContext"]
    want = "Safe to connect — nothing found; little code to inspect · AgentAvow 74/100"
    assert f"✅ MCP 'dw' (https://mcp.deepwiki.com/mcp): {want}" in full
    compact = hook._previously_graded(json.loads(hook.CACHE.read_text()), [dw], [], [])
    assert compact == [f"  ✅ MCP 'dw': {want}"]


def test_no_findings_dependency_reads_safe_with_a_reason(hook, monkeypatch, capsys, tmp_path):
    """aiosmtplib: 0 findings, verdict_reason low_signals. Under the three-phrase rule a
    dependency with nothing found is Safe (unless coverage is thin); full line, compact
    line and decide() agree. A dependency with only high findings says so."""
    from src.scanner.verdict import decide
    assert decide({"trust_score": 74, "findings": {"items": []},
                   "metadata": {"files_scanned": 40}}).decision == "safe"
    (tmp_path / "requirements.txt").write_text("aiosmtplib\nhighs\n")
    scores = {"aiosmtplib": _ok(74, "needs review", 0, reason="low_signals"),
              "highs": _ok(66, "needs review", 4, reason="blocking_findings")}
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: scores[t["pkg"]])
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert ("✅ dependency 'aiosmtplib' (pypi:aiosmtplib): Safe to connect — nothing found "
            "(low signals only) · AgentAvow 74/100.") in ctx
    assert ("⚠️ dependency 'highs' (pypi:highs): Review before you connect — 4 high "
            "finding(s) · AgentAvow 66/100.") in ctx
    deps = hook._dependency_targets()
    compact = hook._previously_graded(json.loads(hook.CACHE.read_text()), [], deps, [])
    assert ("  ✅ dependency 'aiosmtplib': Safe to connect — nothing found (low signals only) "
            "· AgentAvow 74/100") in compact
    assert "  ⚠️ dependency 'highs': Review before you connect — 4 high finding(s) · AgentAvow 66/100" in compact
    assert not any("pattern hits only" in ln for ln in compact)


# --- grade freshness (0.1.22) --------------------------------------------------------

def test_api_advisory_flag_affects_scanned_version_is_honoured(hook):
    """PyJWT: three advisories, all fixed in earlier releases, each flagged
    affects_scanned_version=False by the API. None may count against the install."""
    v = hook._verdict({"trust_score": 92, "advisories": [
        {"id": "GHSA-2gx3", "fixed_in": "2.14.0", "affects_scanned_version": False},
        {"id": "GHSA-42vr", "fixed_in": "2.15.0", "affects_scanned_version": False},
        {"id": "GHSA-x", "affects_scanned_version": True}]})
    assert v["advisories"] == 1


def test_pre_epoch_cache_is_rechecked_and_a_changed_answer_is_reported(hook, monkeypatch, capsys, tmp_path):
    """A cache written before the scoring epoch (fastapi 40, 30 highs) must be re-checked
    and the corrected answer reported once, naming the old one."""
    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn\n")
    old = {"id": "dep:pypi:fastapi@", "kind": "package", "approved_at": hook.time.time() - 60,
           "registry": "pypi", "pkg": "fastapi", "spec": "", **_ok(40, "needs review", 30)}
    same = {"id": "dep:pypi:uvicorn@", "kind": "package", "approved_at": hook.time.time() - 60,
            "registry": "pypi", "pkg": "uvicorn", "spec": "", **_ok(92, "safe")}
    hook.CACHE.parent.mkdir(parents=True, exist_ok=True)
    hook.CACHE.write_text(json.dumps({"dep:pypi:fastapi": old, "dep:pypi:uvicorn": same}))
    live = {"fastapi": _ok(88, "safe"), "uvicorn": _ok(92, "safe")}
    out = _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: live[t["pkg"]])
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "dependency 'fastapi'" in ctx and "updated grade (was:" in ctx
    assert "dependency 'uvicorn' (" not in ctx  # re-checked, same answer: silent
    cache = json.loads(hook.CACHE.read_text())
    assert cache["dep:pypi:fastapi"]["score"] == 88 and cache["dep:pypi:fastapi"]["epoch"] == hook.GRADE_EPOCH
    assert cache["dep:pypi:uvicorn"]["epoch"] == hook.GRADE_EPOCH
    assert _run(hook, monkeypatch, capsys, lambda t, force=False, stored=False: live[t["pkg"]]) == {}


def test_grades_older_than_the_max_age_are_rechecked_quietly(hook, monkeypatch, capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text("uvicorn\n")
    calls = []

    def scan(t, force=False, stored=False):
        calls.append(t["pkg"])
        return _ok(92, "safe")

    _run(hook, monkeypatch, capsys, scan)
    assert _run(hook, monkeypatch, capsys, scan) == {} and calls == ["uvicorn"]
    cache = json.loads(hook.CACHE.read_text())
    cache["dep:pypi:uvicorn"]["approved_at"] -= hook.GRADE_MAX_AGE + 60
    hook.CACHE.write_text(json.dumps(cache))
    assert _run(hook, monkeypatch, capsys, scan) == {}  # same answer: nothing reported
    assert calls == ["uvicorn", "uvicorn"]
