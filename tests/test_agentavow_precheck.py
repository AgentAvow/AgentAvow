"""Tests for the Claude Code SessionStart pre-check hook (plugin + manual copy)."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "plugins" / "agentavow-trust"
PLUGIN_COPY = PLUGIN_DIR / "scripts" / "agentavow_precheck.py"
MANUAL_COPY = ROOT / "integrations" / "claude-code" / "agentavow_precheck.py"
GATE_COPY = PLUGIN_DIR / "scripts" / "agentavow_pretool_gate.py"
GATE_MANUAL_COPY = ROOT / "integrations" / "claude-code" / "agentavow_pretool_gate.py"


def _load(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(f"precheck_{path.parent.name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook(tmp_path, monkeypatch):
    mod = _load(PLUGIN_COPY)
    monkeypatch.setattr(mod, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    # The repo root has a pyproject.toml; run from an empty folder so the dependency
    # pass has nothing to grade unless a test writes a manifest.
    monkeypatch.chdir(tmp_path)
    return mod


def _run(hook, monkeypatch, capsys, targets, scan):
    monkeypatch.setattr(hook, "_targets", lambda: targets)
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    if not out:
        return ""
    data = json.loads(out)
    ctx = data.get("hookSpecificOutput", {}).get("additionalContext", "")
    # A quiet start (nothing new) gives Claude the list but shows the person nothing;
    # these tests ask "was anything reported", so treat it as no report.
    if "systemMessage" not in data and ctx.startswith("AgentAvow pre-check: nothing new"):
        return ""
    return ctx


def _run_raw(hook, monkeypatch, capsys, targets, scan) -> dict:
    monkeypatch.setattr(hook, "_targets", lambda: targets)
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    data = json.loads(out) if out else {}
    ctx = data.get("hookSpecificOutput", {}).get("additionalContext", "")
    if "systemMessage" not in data and ctx.startswith("AgentAvow pre-check: nothing new"):
        return {}
    return data


def _mcp(name: str, url: str) -> dict:
    return {"name": name, "kind": "mcp", "id": url, "url": url}


def _ok(score: int, verdict: str, blocking: int, **extra) -> dict:
    """A scan result as _scan returns it."""
    base = {"score": score, "verdict": verdict, "blocking": blocking, "tier": "standard",
            "grade": "C", "tool_digests": {}, "tool_manifest_digest": None}
    base.update(extra)
    return base


def test_both_copies_are_identical():
    assert PLUGIN_COPY.read_text() == MANUAL_COPY.read_text()
    assert GATE_COPY.read_text() == GATE_MANUAL_COPY.read_text()
    assert ((PLUGIN_DIR / "scripts" / "agentavow_pre_install.py").read_text()
            == (ROOT / "integrations" / "claude-code" / "agentavow_pre_install.py").read_text())


def test_versions_agree():
    hook = _load(PLUGIN_COPY)
    gate = _load(GATE_COPY)
    plugin = json.loads((PLUGIN_DIR / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert hook.__version__ == plugin["version"] == market["plugins"][0]["version"]
    assert gate.__version__ == plugin["version"]
    assert _load(PLUGIN_DIR / "scripts" / "agentavow_pre_install.py").__version__ == plugin["version"]


def test_plugin_registers_both_hooks_with_short_timeouts():
    hooks = json.loads((PLUGIN_DIR / "hooks" / "hooks.json").read_text())["hooks"]
    manual = json.loads((ROOT / "integrations" / "claude-code" / "settings.hooks.json")
                        .read_text())["hooks"]
    for cfg in (hooks, manual):
        gate = cfg["PreToolUse"][0]
        assert gate["matcher"] == "mcp__.*"
        assert gate["hooks"][0]["timeout"] <= 10
        assert "agentavow_pretool_gate.py" in gate["hooks"][0]["command"]
        assert "agentavow_precheck.py" in cfg["SessionStart"][0]["hooks"][0]["command"]
        assert cfg["SessionStart"][0]["matcher"] == "startup|resume|clear"
        install = cfg["PreToolUse"][1]
        assert install["matcher"] == "Bash|Write|Edit|MultiEdit"
        assert install["hooks"][0]["timeout"] <= 20
        assert "agentavow_pre_install.py" in install["hooks"][0]["command"]


def test_user_agent_names_the_install_source():
    assert _load(PLUGIN_COPY)._user_agent().endswith("(plugin)")
    assert _load(MANUAL_COPY)._user_agent().endswith("(manual)")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/mcp",
    "http://localhost:3000/mcp",
    "http://[::1]/mcp",
    "http://10.0.0.4:8188/mcp",
    "http://192.168.1.20/mcp",
    "http://169.254.169.254/latest",
    "http://devbox:9000/mcp",
    "https://tools.internal/mcp",
    "https://printer.local/mcp",
])
def test_local_and_private_urls_never_become_targets(hook, url):
    assert hook._resolve_target("srv", {"url": url}) is None


@pytest.mark.parametrize("url", [
    "https://mcp.example.com/api/mcp/s/QmFzZTY0VG9rZW5Mb29raW5nU2VnbWVudEZvclRlc3Rz/mcp",
    "https://mcp.example.com/v3/mcp/550e8400-e29b-41d4-a716-446655440000/mcp",
    "https://mcp.example.com/u/k7Qp2mX9vT4bN8wR3zL6/mcp",
    "https://mcp.example.com/functions/v1/a1b2c3d4e5f6a7b8c9d0/mcp",
    "https://mcp.example.com/mcp/%35%35%30e8400-e29b-41d4-a716-446655440000",
])
def test_url_with_a_secret_looking_path_is_withheld(hook, url):
    t = hook._resolve_target("srv", {"url": url + "?api_key=x"})
    assert t == {"name": "srv", "kind": "withheld",
                 "id": "withheld:mcp.example.com", "host": "mcp.example.com"}


@pytest.mark.parametrize("url", [
    "https://mcp.context7.com/mcp",
    "https://api.githubcopilot.com/mcp/",
    "https://learn.microsoft.com/api/mcp",
    "https://mcp.example.com/v1alpha2/mcp",
    "https://mcp.example.com/release-2026-09-30/model-context-protocol-v2/mcp",
    "https://mcp.example.com/org/12345678901234567890/mcp",
    "https://mcp.example.com/workspaces/my-team-workspace-production/mcp",
])
def test_ordinary_paths_are_not_mistaken_for_secrets(hook, url):
    assert hook._resolve_target("srv", {"url": url})["kind"] == "mcp"


def test_withheld_url_is_never_scanned_and_is_reported_once(hook, monkeypatch, capsys):
    calls = []
    target = hook._resolve_target(
        "zap", {"url": "https://mcp.example.com/s/QmFzZTY0VG9rZW5Mb29raW5nU2VnbWVudEZvclRlc3Rz/mcp"})
    first = _run(hook, monkeypatch, capsys, [target], lambda t: calls.append(t))
    second = _run(hook, monkeypatch, capsys, [target], lambda t: calls.append(t))
    assert "not scanned" in first and "mcp.example.com" in first
    assert "QmFzZTY0" not in first and "QmFzZTY0" not in hook.CACHE.read_text()
    assert second == ""
    assert calls == []


def test_plugin_ships_a_readable_readme_and_the_skill():
    readme = (PLUGIN_DIR / "README.md").read_text()
    assert len(readme.split()) >= 40  # the directory blocks a shorter README
    assert "What the hook reads and what leaves your machine" in readme
    skill = (PLUGIN_DIR / "skills" / "scan-before-connect" / "SKILL.md").read_text()
    front = skill.split("---")[1]
    assert "name: scan-before-connect" in front and "description: " in front


def test_public_url_is_sanitized_before_it_leaves_the_machine(hook):
    t = hook._resolve_target("srv", {"url": "https://user:pw@mcp.example.com/mcp?token=abc#x"})
    assert t == {"name": "srv", "kind": "mcp",
                 "id": "https://mcp.example.com/mcp", "url": "https://mcp.example.com/mcp"}


def test_stdio_package_targets(hook):
    npm = hook._resolve_target("a", {"command": "npx", "args": ["-y", "@scope/pkg@1.2"]})
    pypi = hook._resolve_target("b", {"command": "uvx", "args": ["mcp-server-git==0.1"]})
    assert npm["id"] == "npm:@scope/pkg"
    assert pypi["id"] == "pypi:mcp-server-git"
    assert hook._resolve_target("c", {"command": "node", "args": ["server.js"]}) is None


def test_scanned_target_is_reported_once(hook, monkeypatch, capsys):
    calls = []

    def scan(t, force=False):
        calls.append(t["id"])
        return _ok(92, "safe", 0, tool_digests={"tool:a": "sha256:aa"},
                   tool_manifest_digest="sha256:mm", tier="trusted", grade="A")

    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    first = _run(hook, monkeypatch, capsys, targets, scan)
    second = _run(hook, monkeypatch, capsys, targets, scan)
    assert "✅ MCP 'a' (https://mcp.example.com/mcp): Safe to connect · AgentAvow 92/100" in first
    assert second == ""
    assert len(calls) == 1
    rec = json.loads(hook.CACHE.read_text())["a"]
    assert rec["id"] == rec["url"] == "https://mcp.example.com/mcp"
    assert rec["kind"] == "mcp" and rec["approved_at"] > 0
    assert (rec["score"], rec["tier"], rec["grade"], rec["verdict"]) == (92, "trusted", "A", "safe")
    assert rec["tool_digests"] == {"tool:a": "sha256:aa"}
    assert rec["tool_manifest_digest"] == "sha256:mm"
    assert rec["report_url"] == "https://agentavow.com/check/mcp?endpoint=https%3A%2F%2Fmcp.example.com%2Fmcp"


def test_package_record_carries_no_live_digests(hook, monkeypatch, capsys):
    target = hook._resolve_target("git", {"command": "uvx", "args": ["mcp-server-git"]})
    out = _run(hook, monkeypatch, capsys, [target],
               lambda t, force=False: _ok(70, "needs review", 1, tool_digests={"tool:x": "y"}))
    assert "70/100" in out
    rec = json.loads(hook.CACHE.read_text())["git"]
    assert rec["kind"] == "package" and rec["id"] == "pypi:mcp-server-git"
    assert rec["tool_digests"] == {} and rec["tool_manifest_digest"] is None
    assert rec["report_url"] == "https://agentavow.com/check/pkg/pypi/mcp-server-git"


def test_drifted_server_is_regraded_with_force_and_reported_again(hook, monkeypatch, capsys):
    url = "https://mcp.example.com/mcp"
    calls = []

    def scan(t, force=False):
        calls.append(force)
        return _ok(61, "needs review", 0, tool_digests={"tool:a": "sha256:new"})

    hook.CACHE.write_text(json.dumps({"a": {
        "id": url, "kind": "mcp", "url": url, "approved_at": 1, "score": 90,
        "tool_digests": {"tool:a": "sha256:old"},
        "last_seen": {"at": 2, "ok": True, "tool_digests": {"tool:a": "sha256:new"}},
    }}))
    out = _run(hook, monkeypatch, capsys, [_mcp("a", url)], scan)
    assert calls == [True]
    assert ("tool definitions changed since the last grade; re-graded: Review before you "
            "connect · AgentAvow 61/100") in out
    rec = json.loads(hook.CACHE.read_text())["a"]
    assert rec["tool_digests"] == {"tool:a": "sha256:new"} and "last_seen" not in rec
    assert _run(hook, monkeypatch, capsys, [_mcp("a", url)], scan) == ""


def test_unhashable_tools_do_not_count_as_drift(hook):
    rec = {"id": "x", "approved_at": 1, "tool_digests": {"tool:a": "1", "tool:b": "2"},
           "last_seen": {"tool_digests": {"tool:a": "1"}, "unhashable": ["tool:b"]}}
    assert hook._drifted(rec) is False
    rec["last_seen"]["tool_digests"]["tool:a"] = "9"
    assert hook._drifted(rec) is True
    assert hook._drifted({"id": "x", "approved_at": 1, "tool_digests": {"tool:a": "1"},
                          "last_seen": {"ok": False, "tool_digests": {}}}) is False


def test_unscannable_target_is_cached_not_retried_every_session(hook, monkeypatch, capsys):
    calls = []

    def scan(t, force=False):
        calls.append(t["id"])
        raise hook._UnscannableError("422")

    targets = [_mcp("figma", "https://mcp.figma.com/mcp")]
    first = _run(hook, monkeypatch, capsys, targets, scan)
    second = _run(hook, monkeypatch, capsys, targets, scan)
    assert "not scanned" in first and "figma" in first
    assert second == ""
    assert len(calls) == 1


def test_unscannable_target_is_retried_after_the_retry_window(hook, monkeypatch, capsys):
    url = "https://mcp.figma.com/mcp"
    hook.CACHE.write_text(json.dumps({"figma": {"id": url, "retry_after": 1}}))
    out = _run(hook, monkeypatch, capsys, [_mcp("figma", url)],
               lambda t, force=False: _ok(88, "safe", 0))
    assert "Safe to connect · AgentAvow 88/100" in out


def test_transient_failure_is_not_cached(hook, monkeypatch, capsys):
    calls = []

    def scan(t, force=False):
        calls.append(t["id"])
        raise TimeoutError

    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    assert _run(hook, monkeypatch, capsys, targets, scan) == ""
    assert _run(hook, monkeypatch, capsys, targets, scan) == ""
    assert len(calls) == 2


def test_same_coordinate_under_two_names_scans_once(hook, monkeypatch, capsys):
    calls = []

    def scan(t, force=False):
        calls.append(t["id"])
        return _ok(70, "needs review", 1)

    url = "https://mcp.example.com/mcp"
    out = _run(hook, monkeypatch, capsys, [_mcp("a", url), _mcp("b", url)], scan)
    assert len(calls) == 1
    assert "'a'" in out and "'b'" in out


def test_run_stops_scanning_when_the_time_budget_is_spent(hook, monkeypatch, capsys):
    monkeypatch.setattr(hook, "BUDGET", -1)
    calls = []
    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    assert _run(hook, monkeypatch, capsys, targets,
                lambda t, force=False: calls.append(t) or _ok(90, "safe", 0)) == ""
    assert calls == []


@pytest.mark.parametrize("code,unscannable", [
    (400, True), (404, True), (422, True), (429, False), (408, False), (503, False),
])
def test_only_a_definite_refusal_counts_as_unscannable(hook, monkeypatch, code, unscannable):
    def boom(*_a, **_k):
        raise urllib.error.HTTPError("https://x", code, "err", {}, None)

    monkeypatch.setattr(hook.urllib.request, "urlopen", boom)
    expected = hook._UnscannableError if unscannable else urllib.error.HTTPError
    with pytest.raises(expected) as exc:
        hook._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    assert (exc.type is hook._UnscannableError) == unscannable


def test_bare_id_from_a_pre_gate_version_is_graded_once_more(hook, monkeypatch, capsys):
    """Before 0.1.5 a graded server was cached as its id string, with no verdict for
    the gate to act on. It is graded once more, then cached as a record."""
    url = "https://mcp.example.com/mcp"
    hook.CACHE.write_text(json.dumps({"a": url}))
    calls = []

    def scan(t, force=False):
        calls.append(force)
        return _ok(92, "safe", 0)

    assert "92/100" in _run(hook, monkeypatch, capsys, [_mcp("a", url)], scan)
    assert _run(hook, monkeypatch, capsys, [_mcp("a", url)], scan) == ""
    assert calls == [False]


def test_withheld_string_entry_from_the_previous_version_still_counts(hook, monkeypatch, capsys):
    target = hook._resolve_target(
        "zap", {"url": "https://mcp.example.com/s/QmFzZTY0VG9rZW5Mb29raW5nU2VnbWVudEZvclRlc3Rz/mcp"})
    hook.CACHE.write_text(json.dumps({"zap": target["id"]}))
    assert _run(hook, monkeypatch, capsys, [target], lambda t, force=False: None) == ""


def test_cache_is_written_atomically(hook, monkeypatch, capsys):
    _run(hook, monkeypatch, capsys, [_mcp("a", "https://mcp.example.com/mcp")],
         lambda t, force=False: _ok(92, "safe", 0))
    assert [p.name for p in hook.CACHE.parent.iterdir()] == ["scanned.json"]


def test_nothing_to_scan_shows_the_intro_once_and_makes_no_request(hook, monkeypatch, capsys):
    calls = []
    first = _run_raw(hook, monkeypatch, capsys, [], lambda t, force=False: calls.append(t))
    second = _run_raw(hook, monkeypatch, capsys, [], lambda t, force=False: calls.append(t))
    assert "nothing to grade here yet" in first["systemMessage"]
    assert "/agentavow-trust:scan" in first["systemMessage"]  # the plugin copy names the command
    assert "hookSpecificOutput" not in first  # user-facing only; nothing enters Claude's context
    assert second == {}
    assert calls == []
    assert json.loads(hook.CACHE.read_text())[hook.META_KEY]["intro_shown"] == hook.__version__


def test_manual_copy_intro_points_at_the_site_not_the_plugin_command(tmp_path, monkeypatch):
    manual = _load(MANUAL_COPY)
    msg = manual._intro_message()
    assert "agentavow.com/check" in msg
    assert "/agentavow-trust:scan" not in msg


def test_graded_servers_produce_a_visible_summary_and_a_first_reply_instruction(
        hook, monkeypatch, capsys):
    """Claude Code shows the model, not the person, a SessionStart hook's context. So
    the hook also emits a one-line systemMessage, and the context block tells Claude to
    open its first reply with that same line."""
    targets = [_mcp("a", "https://a.example/mcp"), _mcp("b", "https://b.example/mcp"),
               _mcp("c", "https://c.example/mcp")]
    scores = {"https://a.example/mcp": _ok(92, "safe", 0),
              "https://b.example/mcp": _ok(36, "needs review", 5, decision="do_not_connect",
                                           decision_reason="one critical finding: eval"),
              "https://c.example/mcp": _ok(74, "needs review", 0)}
    out = _run_raw(hook, monkeypatch, capsys, targets, lambda t, force=False: scores[t["id"]])
    msg = out["systemMessage"]
    assert msg.startswith("AgentAvow pre-check: graded 3 MCP servers — 1 Safe, 1 Review, 1 Blocked")
    assert "(needs attention: 'b' Do not connect — one critical finding: eval)" in msg
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "has NOT seen this" in ctx and "first reply" in ctx
    assert msg in ctx  # Claude relays the very line the person may or may not have seen
    assert "MCP 'b'" in ctx and "36/100" in ctx  # the per-server detail stays available
    assert "no remote MCP servers to scan yet" not in msg


def test_summary_wording_for_one_safe_server_and_for_none_graded(hook):
    assert hook._summary([("a", _ok(90, "safe", 0))]).startswith(
        "AgentAvow pre-check: graded 1 MCP server — 1 Safe, 0 Review.")
    assert hook._summary([("a", _ok(70, "needs review", 0))]) == (
        "AgentAvow pre-check: graded 1 MCP server — 0 Safe, 1 Review "
        "(needs attention: 'a' Review before you connect). Ask for the AgentAvow pre-check "
        "for details.")
    cert = _ok(98, "safe", 0, decision="safe", certified=True,
               decision_reason="nothing found in 40 files")
    assert hook._answer(cert) == (
        "Safe to connect · Certified — nothing found in 40 files · AgentAvow 98/100")
    assert "could not be scanned" in hook._summary([])


def test_unscannable_only_run_still_tells_the_person(hook, monkeypatch, capsys):
    def refuse(t, force=False):
        raise hook._UnscannableError("422")
    out = _run_raw(hook, monkeypatch, capsys, [_mcp("figma", "https://mcp.figma.com/mcp")], refuse)
    assert "could not be scanned" in out["systemMessage"]
    assert "couldn't read it" in out["hookSpecificOutput"]["additionalContext"]


def test_intro_is_not_shown_when_there_are_targets(hook, monkeypatch, capsys):
    out = _run_raw(hook, monkeypatch, capsys,
                   [_mcp("a", "https://mcp.example.com/mcp")],
                   lambda t, force=False: _ok(92, "safe", 0))
    assert "nothing to grade here yet" not in out.get("systemMessage", "")
    assert "92/100" in out["hookSpecificOutput"]["additionalContext"]


def test_intro_is_skipped_rather_than_repeated_when_the_cache_is_unwritable(
        hook, monkeypatch, capsys, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(hook, "CACHE", blocker / "scanned.json")  # parent is a file
    assert _run_raw(hook, monkeypatch, capsys, [], lambda t, force=False: None) == {}
    assert _run_raw(hook, monkeypatch, capsys, [], lambda t, force=False: None) == {}


def _claude_json(tmp_path, monkeypatch, user=None, projects=None):
    monkeypatch.setattr(hook_pathlib_home_target(), "home", lambda: tmp_path)
    (tmp_path / ".claude.json").write_text(json.dumps(
        {"mcpServers": user or {}, "projects": projects or {}}))


def hook_pathlib_home_target():
    import pathlib as _pl
    return _pl.Path


def test_targets_are_scoped_to_this_session(hook, monkeypatch, tmp_path):
    here = tmp_path / "proj"
    here.mkdir()
    monkeypatch.chdir(here)
    _claude_json(tmp_path, monkeypatch,
                 user={"u": {"url": "https://u.example/mcp"}},
                 projects={str(here): {"mcpServers": {"local1": {"url": "https://l1.example/mcp"}}},
                           str(tmp_path / "other"): {"mcpServers": {
                               "taskmaster": {"command": "npx", "args": ["-y", "task-master-ai"]},
                               "u": {"url": "https://u.example/mcp"}}}})
    (here / ".mcp.json").write_text(json.dumps({"mcpServers": {"p": {"url": "https://p.example/mcp"}}}))
    names = sorted(t["name"] for t in hook._targets())
    assert names == ["local1", "p", "u"]  # user + this project's local + .mcp.json; not 'taskmaster'
    # The other project's distinct server is counted, the shared one is not double-counted.
    assert hook._servers_elsewhere(hook._targets()) == 1


def test_elsewhere_is_zero_without_projects_or_on_error(hook, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _claude_json(tmp_path, monkeypatch, user={"u": {"url": "https://u.example/mcp"}})
    assert hook._servers_elsewhere(hook._targets()) == 0
    (tmp_path / ".claude.json").write_text("{ not json")
    assert hook._targets() == [] and hook._servers_elsewhere([]) == 0


def test_summary_mentions_servers_in_other_projects(hook):
    s = hook._summary([("a", _ok(90, "safe", 0))], elsewhere=2)
    assert s.endswith("2 more MCP servers configured for other projects, graded when you open them.")
    assert "graded 1 MCP server — 1 Safe" in s
    assert "other projects" not in hook._summary([("a", _ok(90, "safe", 0))])


def test_meta_cache_entry_is_never_treated_as_a_server(hook, monkeypatch, tmp_path):
    cfg = {"mcpServers": {hook.META_KEY: {"url": "https://mcp.example.com/mcp"},
                          "real": {"url": "https://mcp.example.com/mcp"}}}
    monkeypatch.setattr(hook.pathlib.Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude.json").write_text(json.dumps(cfg))
    assert [t["name"] for t in hook._targets()] == ["real"]


@pytest.mark.parametrize("behavioral, expected", [
    (None, ""),
    ({"ran": False, "reason": "off"}, ""),
    ({"ran": False, "pending": True}, "sandbox: running now, results in about a minute"),
    ({"ran": True, "findings": [], "plan": "npm-mcp",
      "egress_hosts": ["registry.npmjs.org", "api.x.com"],
      "exercise": {"launch_ok": True, "calls": [{"tool": f"t{i}"} for i in range(9)]
                   + [{"tool": "t0"}]}},
     "sandbox: called 9 tools, network only api.x.com"),
    ({"ran": True, "findings": [], "egress_hosts": ["registry.npmjs.org"],
      "exercise": {"launch_ok": True, "calls": [{"tool": "a"}]}},
     "sandbox: called 1 tool, no network beyond the registry"),
    ({"ran": True, "findings": [], "egress_hosts": ["a.io", "b.io", "c.io"],
      "exercise": {"launch_ok": True, "calls": []}},
     "sandbox: called 0 tools, network only a.io, b.io +1"),
    ({"ran": True, "findings": [{"severity": "high", "rule": "annotation_readonly_violated"}],
      "exercise": None},
     "sandbox: CAUGHT a read-only tool writing files (high)"),
    ({"ran": True, "findings": [{"severity": "medium", "rule": "x_new", "name": "Odd thing"},
                                {"severity": "critical",
                                 "rule": "behavioral_undeclared_egress"}]},
     "sandbox: CAUGHT undeclared network egress (critical) +1 more"),
    ({"ran": True, "findings": [], "canary_exfil": [{"via": "dns", "host": "evil.net"}]},
     "sandbox: CAUGHT a planted credential leaving the sandbox (critical)"),
    ({"ran": True, "findings": [{"severity": "high", "rule": "behavioral_undeclared_egress"}],
      "canary_exfil": [{"via": "dns", "host": "evil.net"}]},
     "sandbox: CAUGHT a planted credential leaving the sandbox (critical) +1 more"),
    ({"ran": True, "findings": [], "exercise": {"launch_ok": False},
      "grade_summary": {"start_reason": "needs_credentials"}},
     "sandbox: not started (needs credentials)"),
    ({"ran": True, "findings": [], "plan": "npm-mcp", "exercise": {"launch_ok": False},
      "grade_summary": {"start_reason": "needs_arguments", "start_reason_detail":
                        "server_exited: Please provide a database URL as a command-line "
                        "argument"}},
     "sandbox: not started (needs a database URL)"),
    ({"ran": True, "findings": [], "exercise": {"launch_ok": False},
      "grade_summary": {"start_reason": "crashed"}},
     "sandbox: not started (crashed on start)"),
    ({"ran": True, "findings": [], "exercise": {"launch_ok": False}},
     "sandbox: not started"),
    ({"ran": True, "findings": [], "exercise": None, "egress_hosts": ["registry.npmjs.org"]},
     "sandbox: installed, no network beyond the registry"),
])
def test_sandbox_summary_in_the_verdict(behavioral, expected):
    mod = _load(PLUGIN_COPY)
    assert mod._sandbox_summary(behavioral) == expected
    v = mod._verdict({"trust_score": 90, "findings": {"items": []}, "behavioral": behavioral})
    assert v["sandbox"] == expected


def test_verdict_line_carries_the_sandbox_clause(hook, monkeypatch, capsys):
    def scan(t, force=False):
        return {"score": 92, "verdict": "safe", "blocking": 0, "tier": "", "grade": "",
                "tool_digests": {}, "tool_manifest_digest": None,
                "sandbox": "sandbox: called 9 tools, network only api.x.com"}
    out = _run(hook, monkeypatch, capsys, [_mcp("a", "https://mcp.example.com/mcp")], scan)
    assert ("Safe to connect · AgentAvow 92/100; sandbox: called 9 tools, network only "
            "api.x.com.") in out


def test_verdict_line_flags_a_deprecated_package(hook, monkeypatch, capsys):
    v = _load(PLUGIN_COPY)._verdict({"trust_score": 70, "findings": {"items": []},
                                      "deprecation": "no longer supported"})
    assert v["deprecated"] is True

    assert (v["decision"], v["decision_reason"]) == (
        "review", "the maintainer has deprecated this package")

    def scan(t, force=False):
        return dict(v)
    out = _run(hook, monkeypatch, capsys, [_mcp("a", "https://mcp.example.com/mcp")], scan)
    assert ("⚠️ MCP 'a' (https://mcp.example.com/mcp): Review before you connect — the "
            "maintainer has deprecated this package · AgentAvow 70/100") in out
