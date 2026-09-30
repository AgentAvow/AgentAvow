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
    return json.loads(out)["hookSpecificOutput"]["additionalContext"] if out else ""


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
