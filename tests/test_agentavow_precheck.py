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
    return mod


def _run(hook, monkeypatch, capsys, targets, scan):
    monkeypatch.setattr(hook, "_targets", lambda: targets)
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    if not out:
        return ""
    return json.loads(out).get("hookSpecificOutput", {}).get("additionalContext", "")


def _run_raw(hook, monkeypatch, capsys, targets, scan) -> dict:
    monkeypatch.setattr(hook, "_targets", lambda: targets)
    monkeypatch.setattr(hook, "_scan", scan)
    hook.main()
    out = capsys.readouterr().out
    return json.loads(out) if out else {}


def _mcp(name: str, url: str) -> dict:
    return {"name": name, "kind": "mcp", "id": url, "url": url}


def test_both_copies_are_identical():
    assert PLUGIN_COPY.read_text() == MANUAL_COPY.read_text()


def test_versions_agree():
    hook = _load(PLUGIN_COPY)
    plugin = json.loads((PLUGIN_DIR / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert hook.__version__ == plugin["version"] == market["plugins"][0]["version"]


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

    def scan(t):
        calls.append(t["id"])
        return 92, "safe", 0

    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    first = _run(hook, monkeypatch, capsys, targets, scan)
    second = _run(hook, monkeypatch, capsys, targets, scan)
    assert "92/100 — safe" in first
    assert second == ""
    assert len(calls) == 1


def test_unscannable_target_is_cached_not_retried_every_session(hook, monkeypatch, capsys):
    calls = []

    def scan(t):
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
    out = _run(hook, monkeypatch, capsys, [_mcp("figma", url)], lambda t: (88, "safe", 0))
    assert "88/100 — safe" in out


def test_transient_failure_is_not_cached(hook, monkeypatch, capsys):
    calls = []

    def scan(t):
        calls.append(t["id"])
        raise TimeoutError

    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    assert _run(hook, monkeypatch, capsys, targets, scan) == ""
    assert _run(hook, monkeypatch, capsys, targets, scan) == ""
    assert len(calls) == 2


def test_same_coordinate_under_two_names_scans_once(hook, monkeypatch, capsys):
    calls = []

    def scan(t):
        calls.append(t["id"])
        return 70, "needs review", 1

    url = "https://mcp.example.com/mcp"
    out = _run(hook, monkeypatch, capsys, [_mcp("a", url), _mcp("b", url)], scan)
    assert len(calls) == 1
    assert "'a'" in out and "'b'" in out


def test_run_stops_scanning_when_the_time_budget_is_spent(hook, monkeypatch, capsys):
    monkeypatch.setattr(hook, "BUDGET", -1)
    calls = []
    targets = [_mcp("a", "https://mcp.example.com/mcp")]
    assert _run(hook, monkeypatch, capsys, targets, lambda t: calls.append(t) or (90, "safe", 0)) == ""
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


def test_cache_written_by_the_previous_version_still_counts(hook, monkeypatch, capsys):
    url = "https://mcp.example.com/mcp"
    hook.CACHE.write_text(json.dumps({"a": url}))
    calls = []
    assert _run(hook, monkeypatch, capsys, [_mcp("a", url)], lambda t: calls.append(t)) == ""
    assert calls == []


def test_nothing_to_scan_shows_the_intro_once_and_makes_no_request(hook, monkeypatch, capsys):
    calls = []
    first = _run_raw(hook, monkeypatch, capsys, [], lambda t: calls.append(t))
    second = _run_raw(hook, monkeypatch, capsys, [], lambda t: calls.append(t))
    assert "no remote MCP servers to scan yet" in first["systemMessage"]
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


def test_intro_is_not_shown_when_there_are_targets(hook, monkeypatch, capsys):
    out = _run_raw(hook, monkeypatch, capsys,
                   [_mcp("a", "https://mcp.example.com/mcp")], lambda t: (92, "safe", 0))
    assert "systemMessage" not in out
    assert "92/100" in out["hookSpecificOutput"]["additionalContext"]


def test_intro_is_skipped_rather_than_repeated_when_the_cache_is_unwritable(
        hook, monkeypatch, capsys, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(hook, "CACHE", blocker / "scanned.json")  # parent is a file
    assert _run_raw(hook, monkeypatch, capsys, [], lambda t: None) == {}
    assert _run_raw(hook, monkeypatch, capsys, [], lambda t: None) == {}


def test_meta_cache_entry_is_never_treated_as_a_server(hook, monkeypatch, tmp_path):
    cfg = {"mcpServers": {hook.META_KEY: {"url": "https://mcp.example.com/mcp"},
                          "real": {"url": "https://mcp.example.com/mcp"}}}
    monkeypatch.setattr(hook.pathlib.Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude.json").write_text(json.dumps(cfg))
    assert [t["name"] for t in hook._targets()] == ["real"]
