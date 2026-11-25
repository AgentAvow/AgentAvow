"""Tests for the activity log's per-session store: chain, lock, caps and cleanup."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import multiprocessing
import os
import pathlib
import stat
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_activity.py"


def _load():
    spec = importlib.util.spec_from_file_location("agentavow_activity_t", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = _load()
T0 = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def _worker(activity_dir: str, sid: str, n: int) -> None:
    mod = _load()
    mod.ACTIVITY_DIR = pathlib.Path(activity_dir)
    for i in range(n):
        mod.append_event(sid, {"tool": "Bash", "i": i}, now=T0)


def _lines(path: pathlib.Path) -> list[bytes]:
    return path.read_bytes().split(b"\n")[:-1]


def test_first_line_has_seq_1_and_null_prev(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    line = A.append_event("s1", {"tool": "Read"}, now=T0)
    assert line["seq"] == 1 and line["prev"] is None and line["v"] == 0
    log, state = A.session_paths("s1", T0)
    assert log == tmp_path / "act" / "2026-11-25" / "s1.jsonl"
    assert state == tmp_path / "act" / "sessions" / "s1.json"
    assert json.loads(_lines(log)[0]) == line


def test_chain_links_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(3):
        A.append_event("s1", {"i": i}, now=T0)
    log, _ = A.session_paths("s1", T0)
    lines = _lines(log)
    assert json.loads(lines[1])["prev"] == hashlib.sha256(lines[0]).hexdigest()
    assert A.verify_chain(log) == []


def test_edited_line_breaks_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(3):
        A.append_event("s1", {"i": i}, now=T0)
    log, _ = A.session_paths("s1", T0)
    lines = _lines(log)
    lines[1] = lines[1].replace(b'"i":1', b'"i":9')
    log.write_bytes(b"\n".join(lines) + b"\n")
    assert A.verify_chain(log) == [3]


def test_deleted_line_breaks_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(3):
        A.append_event("s1", {"i": i}, now=T0)
    log, _ = A.session_paths("s1", T0)
    lines = _lines(log)
    del lines[1]
    log.write_bytes(b"\n".join(lines) + b"\n")
    assert A.verify_chain(log) == [2]


def test_verify_missing_file_is_empty(tmp_path):
    assert A.verify_chain(tmp_path / "nope.jsonl") == []


def test_load_state_missing_is_fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    st = A.load_state("nobody")
    assert st["seq"] == 0 and st["prev"] is None and st["dropped"] == 0
    assert st["day"] is None and st["cred_read_ts"] is None
    assert st["shown_rules"] == []


def test_parallel_writers_keep_one_chain(tmp_path):
    act = str(tmp_path / "act")
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_worker, args=(act, "par", 50)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
        assert p.exitcode == 0
    log = pathlib.Path(act) / "2026-11-25" / "par.jsonl"
    seqs = [json.loads(line)["seq"] for line in _lines(log)]
    assert seqs == list(range(1, 401))
    assert A.verify_chain(log) == []


def test_session_spanning_midnight_stays_in_first_day(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    late = datetime(2026, 11, 25, 23, 59, 0, tzinfo=timezone.utc)
    A.append_event("s1", {"i": 1}, now=late)
    A.append_event("s1", {"i": 2}, now=late + timedelta(minutes=5))
    log, _ = A.session_paths("s1", late + timedelta(minutes=5))
    assert log.parent.name == "2026-11-25"
    assert len(_lines(log)) == 2
    assert not (tmp_path / "act" / "2026-11-26").exists()


def test_file_modes(tmp_path, monkeypatch):
    act = tmp_path / "act"
    monkeypatch.setattr(A, "ACTIVITY_DIR", act)
    A.append_event("s1", {"i": 1}, now=T0)
    log, state = A.session_paths("s1", T0)
    for d in (act, log.parent, state.parent):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
    for f in (log, state):
        assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_cap_keeps_flagged_only(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    monkeypatch.setattr(A, "SESSION_CAP", 100)
    assert A.append_event("s1", {"pad": "x" * 200}, now=T0) is not None
    assert A.append_event("s1", {"i": 2}, now=T0) is None
    assert A.load_state("s1")["dropped"] == 1
    flagged = A.append_event("s1", {"i": 3}, flagged=True, now=T0)
    assert flagged is not None and flagged["seq"] == 2
    log, _ = A.session_paths("s1", T0)
    assert A.verify_chain(log) == []


def test_total_cap_drops_unflagged(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    monkeypatch.setattr(A, "TOTAL_CAP", 100)
    assert A.append_event("a", {"pad": "x" * 200}, now=T0) is not None
    assert A.append_event("b", {"i": 1}, now=T0) is None
    assert A.append_event("b", {"i": 2}, flagged=True, now=T0) is not None


def test_cleanup_deletes_whole_old_days(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    old = T0 - timedelta(days=31)
    recent = T0 - timedelta(days=29)
    A.append_event("old1", {"i": 1}, now=old)
    A.append_event("old2", {"i": 1}, now=old)
    A.append_event("new1", {"i": 1}, now=recent)
    A.cleanup(T0)
    act = tmp_path / "act"
    assert not (act / old.strftime("%Y-%m-%d")).exists()
    assert not (act / "sessions" / "old1.json").exists()
    assert not (act / "sessions" / "old2.json").exists()
    assert (act / recent.strftime("%Y-%m-%d") / "new1.jsonl").exists()
    assert (act / "sessions" / "new1.json").exists()


def test_cleanup_without_folder_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "missing")
    A.cleanup(T0)


def test_odd_session_id_is_hashed(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    odd = "../../etc/passwd"
    log, state = A.session_paths(odd, T0)
    sid = hashlib.sha256(odd.encode()).hexdigest()[:32]
    assert log.name == sid + ".jsonl" and state.name == sid + ".json"
    assert A.session_paths("ok_id-1", T0)[0].name == "ok_id-1.jsonl"
    assert A.session_paths("x" * 129, T0)[0].name != "x" * 129 + ".jsonl"
    assert A.append_event(odd, {"i": 1}, now=T0) is not None
    assert os.path.isfile(log)


def test_append_fails_open(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(A, "ACTIVITY_DIR", blocker / "act")
    assert A.append_event("s1", {"i": 1}, now=T0) is None
