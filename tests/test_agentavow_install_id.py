"""The plugin's random install ID (0.1.40): made once (UUIDv4, 0600), sent as
``X-AgentAvow-Install`` on the session-start and install-time hooks' requests to
agentavow.com, never by the gate, never when AGENTAVOW_ANON_ID=off, never when the file
can't be read, and never visible: every hook prints exactly what it printed without it.

Runs with --noconftest (no app, no database)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import stat
import uuid

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "agentavow-trust" / "scripts"
HEADER = "X-agentavow-install"  # urllib.request.Request capitalizes header names so


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"iid_{name}", SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Resp:
    status = 200

    def __init__(self, body: dict) -> None:
        self._body = json.dumps(body).encode()

    def read(self, *_a):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


SCAN = {"trust_score": 92, "decision": "safe", "decision_reason": "no findings",
        "findings": {"items": []}, "tool_digests": {}, "report_url": "https://agentavow.com/r"}


@pytest.fixture
def pc(tmp_path, monkeypatch):
    mod = _load("agentavow_precheck")
    monkeypatch.setattr(mod, "CACHE", tmp_path / "cache" / "scanned.json")
    monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    sent: list = []

    def urlopen(req, timeout=None):
        sent.append(req)
        return _Resp(SCAN)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    mod._sent = sent
    return mod


def _id_file(mod) -> pathlib.Path:
    return mod.CACHE.with_name("install_id")


# --- the ID itself ------------------------------------------------------------------

def test_made_once_as_uuid4_with_mode_0600_and_reused(pc):
    pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    path = _id_file(pc)
    text = path.read_text().strip()
    assert uuid.UUID(text).version == 4 and str(uuid.UUID(text)) == text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert pc._sent[0].get_header(HEADER) == text
    # no temp file left behind
    assert sorted(p.name for p in path.parent.iterdir()) == ["install_id"]
    # a later run (fresh module) reads the same file, never makes a new one
    again = _load("agentavow_precheck")
    again.CACHE = pc.CACHE
    assert again._install_id() == text
    assert path.read_text().strip() == text


def test_two_runs_at_once_agree_on_one_id(pc, monkeypatch):
    other = _load("agentavow_precheck")
    other.CACHE = pc.CACHE
    first = other._install_id()
    # this run saw no file, then lost the race: its link fails and it reads the winner's
    real_exists = pathlib.Path.exists
    monkeypatch.setattr(pathlib.Path, "exists",
                        lambda self: False if self.name == "install_id" else real_exists(self))
    assert pc._install_id() == first
    assert sorted(p.name for p in pc.CACHE.parent.iterdir()) == ["install_id"]


def test_header_rides_on_package_requests_too_with_the_hook_user_agent(pc):
    pc._fetch("/package/npm/chalk", {"stored": "true"})
    req = pc._sent[0]
    assert req.full_url.startswith("https://agentavow.com/api/v1/public/scan/package/npm/chalk")
    assert req.get_header(HEADER) == _id_file(pc).read_text().strip()
    assert req.get_header("User-agent").startswith(f"agentavow-precheck/{pc.__version__}")


@pytest.mark.parametrize("value", ["off", "OFF", " off "])
def test_opt_out_makes_no_file_and_sends_no_header(pc, monkeypatch, value):
    monkeypatch.setenv("AGENTAVOW_ANON_ID", value)
    pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    assert pc._sent[0].get_header(HEADER) is None
    assert not _id_file(pc).exists()


def test_opt_out_also_stops_an_existing_id_being_sent(pc, monkeypatch):
    _id_file(pc).parent.mkdir(parents=True)
    _id_file(pc).write_text(str(uuid.uuid4()) + "\n")
    monkeypatch.setenv("AGENTAVOW_ANON_ID", "off")
    pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    assert pc._sent[0].get_header(HEADER) is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_unreadable_file_sends_nothing_and_the_request_still_goes(pc):
    path = _id_file(pc)
    path.parent.mkdir(parents=True)
    path.write_text(str(uuid.uuid4()) + "\n")
    path.chmod(0)
    try:
        data = pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    finally:
        path.chmod(0o600)
    assert data["trust_score"] == 92
    assert pc._sent[0].get_header(HEADER) is None


@pytest.mark.parametrize("junk", ["", "not-a-uuid", "../../etc/passwd",
                                  "123e4567-e89b-12d3-a456-426614174000"])  # v1, not v4
def test_garbled_file_sends_nothing_and_is_left_alone(pc, junk):
    path = _id_file(pc)
    path.parent.mkdir(parents=True)
    path.write_text(junk)
    pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    assert pc._sent[0].get_header(HEADER) is None
    assert path.read_text() == junk


def test_cache_folder_that_cannot_be_made_sends_nothing(pc, monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a folder")
    monkeypatch.setattr(pc, "CACHE", blocker / "scanned.json")
    data = pc._fetch("/mcp", {"endpoint": "https://mcp.example.com/mcp"})
    assert data["trust_score"] == 92
    assert pc._sent[0].get_header(HEADER) is None


# --- nothing visible: the hooks print exactly the same thing ---------------------------

def _session_start(tmp_path, monkeypatch, capsys, anon: str | None) -> tuple[str, str, list]:
    mod = _load("agentavow_precheck")
    monkeypatch.setattr(mod, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(mod, "_start_active", lambda: None)  # no daily active request
    if anon is None:
        monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    else:
        monkeypatch.setenv("AGENTAVOW_ANON_ID", anon)
    sent: list = []
    monkeypatch.setattr(mod.urllib.request, "urlopen",
                        lambda req, timeout=None: sent.append(req) or _Resp(SCAN))
    url = "https://mcp.example.com/mcp"
    monkeypatch.setattr(mod, "_targets",
                        lambda: [{"name": "a", "kind": "mcp", "id": url, "url": url}])
    monkeypatch.setattr(mod, "_dependency_targets", lambda: [])
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    capsys.readouterr()
    mod.main()
    out = capsys.readouterr()
    return out.out, out.err, sent


def test_session_start_output_is_unchanged_by_the_install_id(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "on", tmp_path / "off"
    a.mkdir()
    b.mkdir()
    on_out, on_err, on_sent = _session_start(a, monkeypatch, capsys, None)
    off_out, off_err, off_sent = _session_start(b, monkeypatch, capsys, "off")
    assert on_sent and on_sent[0].get_header(HEADER)
    assert off_sent and off_sent[0].get_header(HEADER) is None
    assert on_out == off_out and on_out  # the same line, and there is one
    assert on_err == off_err == ""
    for text in (on_out, on_err):
        low = text.lower()
        assert "install id" not in low and "install_id" not in low
        assert "anon_id" not in low and on_sent[0].get_header(HEADER) not in text


def _install_time(tmp_path, monkeypatch, capsys, anon: str | None) -> tuple[str, str, list]:
    mod = _load("agentavow_pre_install")
    pc_mod = mod._precheck()
    monkeypatch.setattr(pc_mod, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(mod, "_precheck", lambda: pc_mod)
    if anon is None:
        monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    else:
        monkeypatch.setenv("AGENTAVOW_ANON_ID", anon)
    sent: list = []
    review = dict(SCAN, trust_score=60, decision="review",
                  decision_reason="one high finding: shell exec",
                  findings={"items": [{"severity": "high"}]})
    monkeypatch.setattr(pc_mod.urllib.request, "urlopen",
                        lambda req, timeout=None: sent.append(req) or _Resp(review))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "claude mcp add x https://mcp.example.com/mcp"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    capsys.readouterr()
    mod.main()
    out = capsys.readouterr()
    return out.out, out.err, sent


def test_install_time_output_is_unchanged_and_carries_the_header(tmp_path, monkeypatch, capsys):
    a, b = tmp_path / "on", tmp_path / "off"
    a.mkdir()
    b.mkdir()
    on_out, on_err, on_sent = _install_time(a, monkeypatch, capsys, None)
    off_out, off_err, off_sent = _install_time(b, monkeypatch, capsys, "off")
    assert on_sent and off_sent
    iid = (a / "install_id").read_text().strip()
    assert on_sent[0].get_header(HEADER) == iid
    assert on_sent[0].get_header("User-agent").startswith("agentavow-preinstall/")
    assert off_sent[0].get_header(HEADER) is None and not (b / "install_id").exists()
    assert on_out == off_out and on_out
    assert on_err == off_err == ""
    assert iid not in on_out and "install id" not in on_out.lower()


# --- the gate never sends it ------------------------------------------------------------

def test_gate_never_sends_the_install_id_and_never_makes_the_file(tmp_path, monkeypatch):
    gate = _load("agentavow_pretool_gate")
    monkeypatch.setattr(gate, "CACHE", tmp_path / "scanned.json")
    monkeypatch.delenv("AGENTAVOW_ANON_ID", raising=False)
    (tmp_path / "install_id").write_text(str(uuid.uuid4()) + "\n")
    sent: list = []

    def urlopen(req, timeout=None):
        sent.append(req)
        raise OSError("offline")

    monkeypatch.setattr(gate.urllib.request, "urlopen", urlopen)
    import time

    gate.fetch_tools("https://mcp.example.com/mcp", None, time.monotonic() + 2)
    assert sent  # it did try the user's server
    assert all(r.get_header(HEADER) is None for r in sent)
    assert "agentavow_anon_id" not in (SCRIPTS / "agentavow_pretool_gate.py").read_text().lower()


def test_gate_leaves_no_install_id_behind(tmp_path, monkeypatch):
    gate = _load("agentavow_pretool_gate")
    monkeypatch.setattr(gate, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(gate.urllib.request, "urlopen",
                        lambda req, timeout=None: (_ for _ in ()).throw(OSError("x")))
    import time

    gate.fetch_tools("https://mcp.example.com/mcp", None, time.monotonic() + 1)
    assert not (tmp_path / "install_id").exists()


def test_tamper_guard_message_is_unchanged():
    """The own-folder guard still covers the folder; its message does not mention the ID."""
    text = (SCRIPTS / "agentavow_pre_install.py").read_text()
    assert "install_id" not in text and "install ID" not in text
