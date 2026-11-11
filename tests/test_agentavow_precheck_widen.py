"""Plugin 0.1.37: what the session-start hook can grade (installed plugins' servers,
devDependencies, Cargo.toml, a workspace root's sub-folders), the "your N tools are
fine" line, the sh launcher, and the tagged connector URL. Run with --noconftest."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN_DIR = ROOT / "plugins" / "agentavow-trust"
PRECHECK = PLUGIN_DIR / "scripts" / "agentavow_precheck.py"
GATE = PLUGIN_DIR / "scripts" / "agentavow_pretool_gate.py"
LAUNCHER = PLUGIN_DIR / "scripts" / "run_hook.sh"


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(pathlib.Path, "home", lambda: h)
    return h


@pytest.fixture
def hook(tmp_path, home, monkeypatch):
    mod = _load(PRECHECK, "precheck_widen")
    monkeypatch.setattr(mod, "CACHE", home / ".cache" / "agentavow" / "scanned.json")
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.delenv(mod.DEPS_ENV, raising=False)
    return mod


def _write(path: pathlib.Path, data) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def _plugin(root: pathlib.Path, name: str, mcp=None, manifest_extra=None) -> pathlib.Path:
    _write(root / ".claude-plugin" / "plugin.json", {"name": name, **(manifest_extra or {})})
    if mcp is not None:
        _write(root / ".mcp.json", mcp)
    return root


def _installed(home: pathlib.Path, entries: dict) -> None:
    _write(home / ".claude" / "plugins" / "installed_plugins.json",
           {"version": 2, "plugins": entries})


# ── MCP servers from installed plugins ───────────────────────────────────────


def test_installed_plugin_servers_are_graded(hook, home, tmp_path):
    cache = home / ".claude" / "plugins" / "cache" / "mkt"
    fb = _plugin(cache / "firebase" / "1.0", "firebase",
                 {"firebase": {"command": "npx", "args": ["-y", "firebase-tools@latest", "mcp"]}})
    gh = _plugin(cache / "github" / "1.0", "github",
                 {"mcpServers": {"github": {"type": "http",
                                            "url": "https://api.githubcopilot.com/mcp/"}}})
    off = _plugin(cache / "off" / "1.0", "off", {"off": {"url": "https://off.example/mcp"}})
    other = _plugin(cache / "other" / "1.0", "other",
                    {"other": {"url": "https://other.example/mcp"}})
    ours = _plugin(cache / "agentavow-trust" / "0.1.37", "agentavow-trust",
                   {"mcpServers": {"agentavow": {"url": "https://agentavow.com/mcp?via=plugin"}}})
    # A marketplace checkout that is not installed is never read.
    _plugin(home / ".claude" / "plugins" / "marketplaces" / "mkt" / "x", "x",
            {"x": {"url": "https://not-installed.example/mcp"}})
    _installed(home, {
        "firebase@mkt": [{"scope": "user", "installPath": str(fb)}],
        "github@mkt": [{"scope": "user", "installPath": str(gh)}],
        "off@mkt": [{"scope": "user", "installPath": str(off)}],
        "other@mkt": [{"scope": "project", "projectPath": str(tmp_path / "elsewhere"),
                       "installPath": str(other)}],
        "agentavow-trust@agentavow": [{"scope": "user", "installPath": str(ours)}],
    })
    _write(home / ".claude" / "settings.json", {"enabledPlugins": {"off@mkt": False}})
    got = {t["name"]: t for t in hook._targets()}
    assert set(got) == {"firebase", "github"}
    assert got["firebase"]["id"] == "npm:firebase-tools"
    assert got["github"]["id"] == "https://api.githubcopilot.com/mcp/"
    assert {t["scope"] for t in got.values()} == {"plugin"}


def test_project_scoped_plugin_counts_in_its_own_project(hook, home):
    p = _plugin(home / "p", "tools", {"tools": {"url": "https://tools.example/mcp"}})
    _installed(home, {"tools@m": [{"scope": "project", "projectPath": str(pathlib.Path.cwd()),
                                   "installPath": str(p)}]})
    assert [t["name"] for t in hook._targets()] == ["tools"]


def test_synced_plugins_and_inline_manifest_servers(hook, home):
    synced = home / ".claude" / "plugins" / "synced" / "acct" / "uuid-1"
    _plugin(synced, "docs-helper", manifest_extra={
        "mcpServers": {"docs": {"url": "https://docs.example/mcp"}}})
    _plugin(home / ".claude" / "plugins" / "synced" / "acct" / "uuid-2", "agentavow-trust",
            {"mcpServers": {"agentavow": {"url": "https://agentavow.com/mcp"}}})
    assert [(t["name"], t["id"]) for t in hook._targets()] == [
        ("docs", "https://docs.example/mcp")]


def test_plugin_manifest_path_outside_the_plugin_is_not_read(hook, home, tmp_path):
    _write(tmp_path / "secret.json", {"leak": {"url": "https://leak.example/mcp"}})
    p = _plugin(home / "p", "p", manifest_extra={"mcpServers": "../../secret.json"})
    _installed(home, {"p@m": [{"installPath": str(p)}]})
    assert hook._targets() == []


def test_plugin_server_name_clash_gets_the_gate_s_plugin_key(hook, home):
    _write(home / ".claude.json", {"mcpServers": {"github": {"url": "https://mine.example/mcp"}}})
    p = _plugin(home / "p", "gh-plugin",
                {"github": {"url": "https://api.githubcopilot.com/mcp/"},
                 "same": {"url": "https://mine.example/mcp"}})
    _write(home / ".claude.json", {"mcpServers": {
        "github": {"url": "https://mine.example/mcp"},
        "same": {"url": "https://mine.example/mcp"}}})
    _installed(home, {"gh-plugin@m": [{"installPath": str(p)}]})
    got = {t["name"]: t for t in hook._targets()}
    assert got["github"]["scope"] == "user"
    assert got["plugin_gh-plugin_github"]["id"] == "https://api.githubcopilot.com/mcp/"
    assert "plugin_gh-plugin_same" not in got  # the same server as yours: listed once

    # The per-call gate finds that record from the tool name Claude Code gives it.
    gate = _load(GATE, "gate_widen")
    cache = {"plugin_gh-plugin_github": {"id": "x", "approved_at": 1}}
    assert gate.find_record(cache, "plugin_gh-plugin_github")[0] == "plugin_gh-plugin_github"
    cache = {"github": {"id": "x", "approved_at": 1}}
    assert gate.find_record(cache, "plugin_gh-plugin_github")[0] == "github"


def test_broken_plugin_files_never_break_the_list(hook, home):
    _write(home / ".claude" / "plugins" / "installed_plugins.json", "{ not json")
    _write(home / ".claude.json", {"mcpServers": {"u": {"url": "https://u.example/mcp"}}})
    assert [t["name"] for t in hook._targets()] == ["u"]


def test_url_with_an_unexpanded_placeholder_is_not_sent(hook):
    assert hook._resolve_target("a", {"url": "https://${HOST}/mcp"}) is None
    assert hook._resolve_target("a", {"url": "https://api.example.com/${TOKEN}/mcp"}) is None


# ── dependencies ─────────────────────────────────────────────────────────────


def test_dev_dependencies_when_there_are_no_runtime_dependencies(hook):
    _write(pathlib.Path.cwd() / "package.json",
           {"devDependencies": {"typescript": "^5", "local": "file:../x"}})
    assert [(d["pkg"], d["spec"]) for d in hook._dependency_targets()] == [("typescript", "^5")]
    _write(pathlib.Path.cwd() / "package.json",
           {"dependencies": {"chalk": "5"}, "devDependencies": {"typescript": "^5"}})
    assert [d["pkg"] for d in hook._dependency_targets()] == ["chalk"]


CARGO = """
[package]
name = "demo"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = "1"
local = { path = "../local" }
fromgit = { git = "https://example.com/x.git" }
renamed = { package = "real-crate", version = "0.3" }

[dev-dependencies]
proptest = "1"
"""


def test_cargo_dependencies_with_tomllib_and_with_the_fallback(hook, monkeypatch):
    want = [("serde", "1.0"), ("tokio", "1"), ("real-crate", "0.3")]
    got = hook._cargo_deps(CARGO)
    assert [(d["pkg"], d["spec"]) for d in got] == want
    assert {d["registry"] for d in got} == {"crates"}
    monkeypatch.setitem(sys.modules, "tomllib", None)  # python3 < 3.11
    assert [(d["pkg"], d["spec"]) for d in hook._cargo_deps(CARGO)] == want


def test_cargo_workspace_root_reads_workspace_dependencies(hook):
    text = '[workspace]\nmembers = ["a"]\n\n[workspace.dependencies]\nanyhow = "1"\n'
    assert [d["pkg"] for d in hook._cargo_deps(text)] == ["anyhow"]
    _write(pathlib.Path.cwd() / "Cargo.toml", CARGO)
    assert [d["id"] for d in hook._dependency_targets()][:1] == ["dep:crates:serde@1.0"]


def test_workspace_root_reads_manifests_one_level_down(hook, monkeypatch):
    cwd = pathlib.Path.cwd()
    _write(cwd / "api" / "requirements.txt", "fastapi\n")
    _write(cwd / "web" / "package.json", {"dependencies": {"react": "19"}})
    _write(cwd / "node_modules" / "x" / "package.json", {"dependencies": {"evil": "1"}})
    _write(cwd / ".hidden" / "package.json", {"dependencies": {"hidden": "1"}})
    _write(cwd / "web" / "deeper" / "package.json", {"dependencies": {"deep": "1"}})
    assert [d["pkg"] for d in hook._dependency_targets()] == ["fastapi", "react"]
    monkeypatch.setattr(hook, "SUBPROJECTS_CAP", 1)
    assert [d["pkg"] for d in hook._dependency_targets()] == ["fastapi"]


def test_a_root_with_its_own_manifest_does_not_read_sub_folders(hook):
    cwd = pathlib.Path.cwd()
    _write(cwd / "requirements.txt", "requests\n")
    _write(cwd / "web" / "package.json", {"dependencies": {"react": "19"}})
    assert [d["pkg"] for d in hook._dependency_targets()] == ["requests"]


def test_home_folder_sub_folders_are_never_read(hook, home, monkeypatch):
    _write(home / "someproject" / "package.json", {"dependencies": {"react": "19"}})
    monkeypatch.chdir(home)
    assert hook._dependency_targets() == []


# ── "your N tools are fine" ──────────────────────────────────────────────────


def _user_target(name, url):
    return {"name": name, "kind": "mcp", "id": url, "url": url, "scope": "user"}


def _graded(hook, decision="safe", score=90, reason="nothing found"):
    return {"id": None, "kind": "mcp", "approved_at": time.time(), "epoch": hook.GRADE_EPOCH,
            "score": score, "decision": decision, "decision_reason": reason, "tier": "trusted"}


def _seed(hook, targets, decisions):
    cache = {}
    for t, d in zip(targets, decisions):
        rec = _graded(hook, *d)
        rec["id"] = t["id"]
        cache[t["name"]] = rec
    cache[hook.META_KEY] = {"intro_shown": hook.__version__}
    _write(hook.CACHE, cache)


def _main(hook, monkeypatch, capsys, targets) -> dict:
    monkeypatch.setattr(hook, "_targets", lambda: targets)
    monkeypatch.setattr(hook, "_scan", lambda *a, **k: pytest.fail("no request expected"))
    hook.main()
    out = capsys.readouterr().out
    return json.loads(out) if out else {}


def test_empty_folder_says_your_tools_are_fine_once_a_day(hook, monkeypatch, capsys):
    targets = [_user_target("a", "https://a.example/mcp"), _user_target("b", "https://b.example/mcp")]
    _seed(hook, targets, [("safe",), ("safe",)])
    first = _main(hook, monkeypatch, capsys, targets)
    assert first["systemMessage"].startswith(
        "AgentAvow: your 2 tools are fine — all Safe to connect.")
    assert "MCP 'a'" in first["hookSpecificOutput"]["additionalContext"]
    second = _main(hook, monkeypatch, capsys, targets)
    assert "systemMessage" not in second  # once a day; Claude still has the list
    assert "nothing new" in second["hookSpecificOutput"]["additionalContext"]


def test_your_tools_line_names_the_one_needing_attention(hook, monkeypatch, capsys):
    targets = [_user_target("a", "https://a.example/mcp"), _user_target("bad", "https://b.example/mcp")]
    _seed(hook, targets, [("safe",), ("do_not_connect", 20, "one critical finding")])
    msg = _main(hook, monkeypatch, capsys, targets)["systemMessage"]
    assert msg.startswith("AgentAvow: your 2 tools: 1 Safe, 0 Review, 1 Don't connect")
    assert "'bad' Do not connect — one critical finding" in msg


def test_no_tools_line_in_a_project_or_with_dependencies(hook, monkeypatch, capsys):
    targets = [dict(_user_target("a", "https://a.example/mcp"), scope="project")]
    _seed(hook, targets, [("safe",)])
    assert "systemMessage" not in _main(hook, monkeypatch, capsys, targets)
    # A project with dependencies (all graded already): the usual quiet start.
    targets = [_user_target("a", "https://a.example/mcp")]
    _seed(hook, targets, [("safe",)])
    _write(pathlib.Path.cwd() / "requirements.txt", "requests\n")
    cache = json.loads(hook.CACHE.read_text())
    cache["dep:pypi:requests"] = dict(_graded(hook), id="dep:pypi:requests@")
    _write(hook.CACHE, cache)
    assert "systemMessage" not in _main(hook, monkeypatch, capsys, targets)
    one = hook._fine_message(json.loads(hook.CACHE.read_text()), targets)
    assert one.startswith("AgentAvow: your 1 tool is fine — Safe to connect.")


def test_first_session_with_nothing_still_shows_the_intro(hook, monkeypatch, capsys):
    out = _main(hook, monkeypatch, capsys, [])
    assert "nothing to grade here yet" in out["systemMessage"]


# ── launcher, connector tag ──────────────────────────────────────────────────


def test_hooks_launch_through_the_sh_wrapper():
    hooks = json.loads((PLUGIN_DIR / "hooks" / "hooks.json").read_text())["hooks"]
    commands = [h["command"] for group in hooks.values() for m in group for h in m["hooks"]]
    assert len(commands) == 3
    for c in commands:
        assert c.startswith('sh "${CLAUDE_PLUGIN_ROOT}/scripts/run_hook.sh" "${CLAUDE_PLUGIN_ROOT}/')
    assert "os.environ" not in LAUNCHER.read_text()


def _shim(bindir: pathlib.Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


def _launch(bindir: pathlib.Path, script: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", str(LAUNCHER), str(script)], input="{}",
                          capture_output=True, text=True, timeout=30,
                          env={"PATH": str(bindir), "HOME": str(bindir)})


@pytest.fixture
def probe(tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("import sys; print('ran', sys.stdin.read())\n")
    return script


def test_launcher_skips_a_broken_python3_and_uses_python(tmp_path, probe):
    real = shutil.which("python3") or sys.executable
    bindir = tmp_path / "bin1"
    bindir.mkdir()
    _shim(bindir, "python3", "echo 'Python was not found; run without arguments' >&2; exit 9009")
    _shim(bindir, "python", f'exec "{real}" "$@"')
    r = _launch(bindir, probe)
    assert (r.returncode, r.stdout.strip()) == (0, "ran {}")


def test_launcher_falls_back_to_py_dash_3(tmp_path, probe):
    real = shutil.which("python3") or sys.executable
    bindir = tmp_path / "bin2"
    bindir.mkdir()
    _shim(bindir, "py", f'[ "$1" = "-3" ] || exit 1\nshift\nexec "{real}" "$@"')
    r = _launch(bindir, probe)
    assert (r.returncode, r.stdout.strip()) == (0, "ran {}")


def test_launcher_without_python_is_silent_and_exits_0(tmp_path, probe):
    bindir = tmp_path / "bin3"
    bindir.mkdir()
    r = _launch(bindir, probe)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    r = _launch(bindir, tmp_path / "missing.py")
    assert (r.returncode, r.stdout) == (0, "")


def test_connector_url_is_tagged_and_the_tag_never_reaches_a_scan(hook):
    mcp = json.loads((PLUGIN_DIR / ".mcp.json").read_text())["mcpServers"]
    assert mcp["agentavow"]["url"] == "https://agentavow.com/mcp?via=plugin"
    # Ours is never graded from the plugin list, and a scan URL never carries a query.
    assert hook._sanitize_url(mcp["agentavow"]["url"]) == "https://agentavow.com/mcp"
