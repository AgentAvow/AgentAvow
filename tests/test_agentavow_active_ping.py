"""The plugin's once-a-day active request (0.1.41): sent by the session-start hook at
most once per UTC day, carrying only the install ID header, the plugin version and the
app type; never with AGENTAVOW_ANON_ID=off; fail-open and silent; recorded in the hook
state (the cache's META_KEY entry) so it never goes twice in a day.

Runs with --noconftest (no app, no database)."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import time
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "agentavow-trust" / "scripts"
HEADER = "X-agentavow-install"  # urllib capitalizes header names this way

SCAN = {"trust_score": 92, "decision": "safe", "decision_reason": "no findings",
        "findings": {"items": []}, "tool_digests": {}, "report_url": "https://agentavow.com/r"}


def _load():
    spec = importlib.util.spec_from_file_location("active_ping", SCRIPTS / "agentavow_precheck.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Resp:
    status = 200

    def __init__(self, body: dict | None = None) -> None:
        self._body = json.dumps(body or {}).encode()

    def read(self, *_a):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


@pytest.fixture
def pc(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "CACHE", tmp_path / "cache" / "scanned.json")
    monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    monkeypatch.setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    monkeypatch.chdir(tmp_path)  # no manifests: nothing to grade
    monkeypatch.setattr(mod, "_targets", lambda: [])
    monkeypatch.setattr(mod, "_dependency_targets", lambda: [])
    sent: list = []

    def urlopen(req, timeout=None):
        sent.append((req, timeout))
        return _Resp(SCAN)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    mod._sent = sent
    return mod


def _active(mod) -> list:
    return [r for r, _ in mod._sent if r.full_url == mod.ACTIVE_URL]


def _meta(mod) -> dict:
    return json.loads(mod.CACHE.read_text()).get(mod.META_KEY, {})


def test_sends_one_request_with_only_id_version_and_app(pc, capsys):
    pc.main()
    reqs = _active(pc)
    assert len(reqs) == 1
    req = reqs[0]
    assert req.get_method() == "POST"
    assert req.full_url == "https://agentavow.com/api/v1/public/plugin/active"
    assert json.loads(req.data) == {"version": pc.__version__, "app": "desktop"}
    iid = pc.CACHE.with_name("install_id").read_text().strip()
    assert req.get_header(HEADER) == iid
    assert req.get_header("User-agent") == f"agentavow-active/{pc.__version__}"
    assert {k.lower() for k, _ in req.header_items()} == {
        "user-agent", "content-type", "x-agentavow-install"}
    assert [t for r, t in pc._sent if r is req] == [2]
    assert _meta(pc)[pc.ACTIVE_DAY_KEY] == time.strftime("%Y-%m-%d", time.gmtime())


def test_payload_never_names_tools_servers_paths_or_repos(pc, monkeypatch, tmp_path):
    url = "https://secret-tool.example.com/mcp"
    monkeypatch.setattr(pc, "_targets",
                        lambda: [{"name": "my-private-server", "kind": "mcp", "id": url,
                                  "url": url}])
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"chalk": "5"}}))
    pc.main()
    req = _active(pc)[0]
    blob = (req.full_url + repr(req.data) + repr(req.header_items())).lower()
    for word in ("secret-tool", "my-private-server", "chalk", "mcp.", str(tmp_path).lower(),
                 "package.json"):
        assert word not in blob, word


def test_at_most_once_per_utc_day(pc):
    pc.main()
    pc.main()
    pc.main()
    assert len(_active(pc)) == 1


def test_sends_again_on_a_new_utc_day(pc, monkeypatch):
    pc.main()
    meta = _meta(pc)
    cache = json.loads(pc.CACHE.read_text())
    cache[pc.META_KEY] = dict(meta, **{pc.ACTIVE_DAY_KEY: "2000-01-01"})
    pc.CACHE.write_text(json.dumps(cache))
    pc.main()
    assert len(_active(pc)) == 2


def test_keeps_other_hook_state(pc):
    pc.CACHE.parent.mkdir(parents=True, exist_ok=True)
    pc.CACHE.write_text(json.dumps({pc.META_KEY: {"intro_shown": "0.1.39",
                                                  "fine_shown_day": "2026-11-12"}}))
    pc.main()
    meta = _meta(pc)
    assert meta["intro_shown"] == "0.1.39" and meta["fine_shown_day"] == "2026-11-12"
    assert pc.ACTIVE_DAY_KEY in meta


def test_intro_line_keeps_the_day_so_it_does_not_resend(pc, capsys):
    pc.main()  # nothing to grade: shows the intro once and writes intro_shown
    out = capsys.readouterr().out
    assert "nothing to grade" in out
    meta = _meta(pc)
    assert meta.get("intro_shown") and meta.get(pc.ACTIVE_DAY_KEY)
    pc.main()
    assert len(_active(pc)) == 1


@pytest.mark.parametrize("value", ["off", "OFF", " off ", "0", "false", "no"])
def test_opt_out_sends_nothing_and_makes_no_id(pc, monkeypatch, value):
    monkeypatch.setenv("AGENTAVOW_ANON_ID", value)
    pc.main()
    assert _active(pc) == []
    assert not pc.CACHE.with_name("install_id").exists()


def test_unreadable_id_sends_nothing(pc):
    pc.CACHE.parent.mkdir(parents=True, exist_ok=True)
    pc.CACHE.with_name("install_id").write_text("not-a-uuid\n")
    pc.main()
    assert _active(pc) == []


def test_cache_that_cannot_be_written_sends_nothing(pc, monkeypatch):
    monkeypatch.setattr(pc, "_save_cache", lambda cache: False)
    pc.main()
    assert _active(pc) == []


@pytest.mark.parametrize("exc", [urllib.error.URLError("down"), TimeoutError("slow"),
                                 OSError("refused"), RuntimeError("anything")])
def test_network_error_is_silent_and_the_hook_output_is_unchanged(pc, monkeypatch, capsys,
                                                                   tmp_path, exc):
    baseline = _load()
    monkeypatch.setattr(baseline, "CACHE", tmp_path / "base" / "scanned.json")
    monkeypatch.setattr(baseline, "_targets", lambda: [])
    monkeypatch.setattr(baseline, "_dependency_targets", lambda: [])
    monkeypatch.setattr(baseline, "_start_active", lambda: None)
    baseline.main()
    expected = capsys.readouterr()

    def urlopen(req, timeout=None):
        if req.full_url == pc.ACTIVE_URL:
            raise exc
        return _Resp(SCAN)

    monkeypatch.setattr(pc.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    pc.main()
    got = capsys.readouterr()
    assert got.out == expected.out and got.err == expected.err == ""
    assert _meta(pc)[pc.ACTIVE_DAY_KEY]  # recorded: not retried until tomorrow


def test_output_with_a_graded_server_is_unchanged_and_names_no_id(pc, monkeypatch, capsys,
                                                                  tmp_path):
    url = "https://mcp.example.com/mcp"
    target = [{"name": "a", "kind": "mcp", "id": url, "url": url}]
    baseline = _load()
    monkeypatch.setattr(baseline, "CACHE", tmp_path / "base" / "scanned.json")
    monkeypatch.setattr(baseline, "_targets", lambda: target)
    monkeypatch.setattr(baseline, "_dependency_targets", lambda: [])
    monkeypatch.setattr(baseline, "_start_active", lambda: None)
    monkeypatch.setattr(baseline.urllib.request, "urlopen", lambda req, timeout=None: _Resp(SCAN))
    baseline.main()
    expected = capsys.readouterr()
    monkeypatch.setattr(pc, "_targets", lambda: target)
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    pc.main()
    got = capsys.readouterr()
    assert got.out == expected.out and got.out
    iid = pc.CACHE.with_name("install_id").read_text().strip()
    for text in (got.out, got.err):
        low = text.lower()
        assert iid not in text and "plugin/active" not in low and "active_day" not in low
        assert "anon_id" not in low and "install id" not in low


def test_a_slow_request_never_holds_the_session_up_past_two_seconds(pc, monkeypatch):
    def urlopen(req, timeout=None):
        if req.full_url == pc.ACTIVE_URL:
            time.sleep(5)  # a server that never answers in time
        return _Resp(SCAN)

    monkeypatch.setattr(pc.urllib.request, "urlopen", urlopen)
    started = time.monotonic()
    pc.main()
    assert time.monotonic() - started < 2.8


@pytest.mark.parametrize("entrypoint,app", [
    ("claude-desktop", "desktop"), ("local-agent", "desktop"), ("desktop-app", "desktop"),
    ("cli", "cli"), ("claude-vscode", "cli"), ("claude-jetbrains", "cli"),
    ("sdk-ts", "sdk"), ("sdk-py", "sdk"), ("sdk-cli", "sdk"),
    ("remote", "cloud"), ("remote_mobile", "cloud"),
    ("", "other"), ("something-new", "other"),
])
def test_app_type_groups_the_entrypoint(pc, monkeypatch, entrypoint, app):
    monkeypatch.setenv("CLAUDE_CODE_ENTRYPOINT", entrypoint)
    assert pc._app_type() == app
    assert app in pc.APP_TYPES


def test_unset_entrypoint_is_other(pc, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_ENTRYPOINT", raising=False)
    assert pc._app_type() == "other"


def test_install_time_hook_never_sends_it(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("active_pre_install",
                                                  SCRIPTS / "agentavow_pre_install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pc = mod._precheck()
    monkeypatch.setattr(pc, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(mod, "_precheck", lambda: pc)
    monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    sent: list = []
    monkeypatch.setattr(pc.urllib.request, "urlopen",
                        lambda req, timeout=None: sent.append(req) or _Resp(SCAN))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "claude mcp add x https://mcp.example.com/mcp"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    mod.main()
    assert sent and all(r.full_url != pc.ACTIVE_URL for r in sent)


def test_plugin_and_manual_copies_are_identical():
    for name in ("agentavow_precheck.py", "agentavow_pre_install.py",
                 "agentavow_pretool_gate.py"):
        assert (SCRIPTS / name).read_bytes() == (
            ROOT / "integrations" / "claude-code" / name).read_bytes(), name
