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


# --- fix round 1: the log is the source of truth; verify_session ---


def _seqs(log):
    return [json.loads(line)["seq"] for line in _lines(log)]


def _three(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(3):
        A.append_event("s1", {"i": i}, now=T0)
    return A.session_paths("s1", T0)


def test_deleted_state_keeps_chain(tmp_path, monkeypatch):
    log, state = _three(monkeypatch, tmp_path)
    state.unlink()
    assert A.append_event("s1", {"i": 3}, now=T0 + timedelta(days=1))["seq"] == 4
    assert _seqs(log) == [1, 2, 3, 4]
    assert A.verify_chain(log) == []
    assert not (tmp_path / "act" / "2026-11-26").exists()


def test_stale_state_keeps_chain(tmp_path, monkeypatch):
    log, state = _three(monkeypatch, tmp_path)
    st = A.load_state("s1")
    lines = _lines(log)
    st["seq"] = 2
    st["prev"] = hashlib.sha256(lines[1]).hexdigest()
    A.save_state("s1", st)
    assert A.verify_session("s1") == []
    A.append_event("s1", {"i": 3}, now=T0)
    assert _seqs(log) == [1, 2, 3, 4]
    assert A.verify_chain(log) == []
    assert A.verify_session("s1") == []


def test_empty_state_file_keeps_chain(tmp_path, monkeypatch):
    log, state = _three(monkeypatch, tmp_path)
    state.write_bytes(b"")
    A.append_event("s1", {"i": 3}, now=T0)
    assert _seqs(log) == [1, 2, 3, 4]
    assert A.verify_chain(log) == []


def test_torn_tail_flags_only_the_torn_line(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    with open(log, "ab") as f:
        f.write(b'{"seq":4,"pre')
    assert A.append_event("s1", {"i": 4}, now=T0)["seq"] == 4
    assert A.verify_chain(log) == [4]
    lines = _lines(log)
    assert len(lines) == 5 and lines[3] == b'{"seq":4,"pre'
    assert json.loads(lines[4])["seq"] == 4


def test_tail_cut_is_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(4):
        A.append_event("s1", {"i": i}, now=T0)
    log, _ = A.session_paths("s1", T0)
    log.write_bytes(b"\n".join(_lines(log)[:2]) + b"\n")
    assert A.verify_chain(log) == []
    assert A.verify_session("s1") == [3]


def test_edited_last_line_is_detected(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    lines = _lines(log)
    lines[2] = lines[2].replace(b'"i":2', b'"i":7')
    log.write_bytes(b"\n".join(lines) + b"\n")
    assert A.verify_session("s1") == [4]


def test_clean_session_and_state_one_behind(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    assert A.verify_session("s1") == []
    assert A.verify_session("never-seen") == []


# --- fix round 2: breaks survive the next append; session_lock; write guards ---


def _four(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    for i in range(4):
        A.append_event("s1", {"i": i}, now=T0)
    return A.session_paths("s1", T0)


def test_cut_then_append_keeps_the_break(tmp_path, monkeypatch):
    log, _ = _four(monkeypatch, tmp_path)
    log.write_bytes(b"\n".join(_lines(log)[:2]) + b"\n")
    assert A.append_event("s1", {"i": 9}, now=T0)["seq"] == 5
    assert _seqs(log) == [1, 2, 5]
    assert 3 in A.verify_chain(log)
    assert 3 in A.verify_session("s1")
    assert A.load_state("s1")["breaks"][0]["line"] == 3


def test_edited_last_then_append_keeps_the_break(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    lines = _lines(log)
    lines[2] = lines[2].replace(b'"i":2', b'"i":7')
    log.write_bytes(b"\n".join(lines) + b"\n")
    A.append_event("s1", {"i": 3}, now=T0)
    assert 4 in A.verify_session("s1")


def test_emptied_then_append_keeps_the_break(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    log.write_bytes(b"")
    A.append_event("s1", {"i": 3}, now=T0)
    assert 1 in A.verify_session("s1")


def test_break_survives_lost_state(tmp_path, monkeypatch):
    log, state = _four(monkeypatch, tmp_path)
    log.write_bytes(b"\n".join(_lines(log)[:2]) + b"\n")
    A.append_event("s1", {"i": 9}, now=T0)
    state.unlink()
    assert 3 in A.verify_session("s1")


def test_state_two_behind_is_clean(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    st = A.load_state("s1")
    st["seq"] = 1
    st["prev"] = hashlib.sha256(_lines(log)[0]).hexdigest()
    A.save_state("s1", st)
    assert A.verify_session("s1") == []
    A.append_event("s1", {"i": 3}, now=T0)
    assert _seqs(log) == [1, 2, 3, 4]
    assert A.verify_session("s1") == []
    assert A.load_state("s1")["breaks"] == []


def test_breaks_keep_newest_100(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    for _ in range(105):
        st = A.load_state("s1")
        st["seq"] = st["seq"] + 5  # state ahead of the log
        A.save_state("s1", st)
        A.append_event("s1", {"i": 0}, now=T0)
    assert len(A.load_state("s1")["breaks"]) == 100


def test_session_lock_is_reentrant_for_append(tmp_path, monkeypatch):
    import threading

    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    result = []

    def run():
        with A.session_lock("s1"):
            st = A.load_state("s1")
            st["shown_rules"] = ["r1"]
            A.save_state("s1", st)
            result.append(A.append_event("s1", {"i": 1}, now=T0))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(10)
    assert not t.is_alive(), "append_event deadlocked under session_lock"
    assert result[0]["seq"] == 1
    assert A.load_state("s1")["shown_rules"] == ["r1"]


def test_session_lock_excludes_other_processes(tmp_path):
    act = tmp_path / "act"
    ctx = multiprocessing.get_context("fork")
    ready, go = ctx.Event(), ctx.Event()

    def holder():
        mod = _load()
        mod.ACTIVITY_DIR = act
        with mod.session_lock("s1"):
            ready.set()
            go.wait(10)

    p = ctx.Process(target=holder)
    p.start()
    assert ready.wait(10)
    q = ctx.Process(target=_worker, args=(str(act), "s1", 1))
    q.start()
    q.join(0.5)
    assert q.is_alive()  # blocked on the lock
    go.set()
    q.join(10)
    p.join(10)
    assert q.exitcode == 0
    assert A.verify_chain(act / "2026-11-25" / "s1.jsonl") == []


def test_short_write_still_yields_whole_line(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    real = os.write
    calls = []

    def fake(fd, data):
        calls.append(1)
        return real(fd, bytes(data)[:5]) if len(calls) == 1 else real(fd, data)

    with monkeypatch.context() as m:
        m.setattr(A.os, "write", fake)
        assert A.append_event("s1", {"i": 1}, now=T0) is not None
    log, _ = A.session_paths("s1", T0)
    assert A.verify_chain(log) == [] and len(_lines(log)) == 1
    json.loads(_lines(log)[0])


def test_save_state_leaves_no_tmp_and_cleanup_removes_stale_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    A.append_event("s1", {"i": 1}, now=T0)
    sess = tmp_path / "act" / "sessions"
    assert list(sess.glob("*.tmp")) == []
    stale, fresh = sess / "a.json.1.tmp", sess / "b.json.2.tmp"
    stale.write_text("x")
    fresh.write_text("x")
    old = T0.timestamp() - 7200
    os.utime(stale, (old, old))
    os.utime(fresh, (T0.timestamp() - 60, T0.timestamp() - 60))
    A.cleanup(T0)
    assert not stale.exists() and fresh.exists()


def test_torn_write_then_lost_state_save_is_not_a_false_break(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    with open(log, "ab") as f:
        f.write(b'{"seq":4,"pre')  # torn line 4, state not saved
    real = A.save_state
    monkeypatch.setattr(A, "save_state", lambda *a, **k: (_ for _ in ()).throw(OSError("full")))
    assert A.append_event("s1", {"i": 4}, now=T0) is None  # log written, state save lost
    monkeypatch.setattr(A, "save_state", real)
    assert len(_lines(log)) == 5
    assert A.append_event("s1", {"i": 5}, now=T0)["seq"] == 5
    assert A.verify_session("s1") == [4]
    assert A.load_state("s1")["breaks"] == []


# --- fix round 4: a line that lost only its trailing newline is healed, not flagged ---


def _strip_last_newline(log):
    data = log.read_bytes()
    assert data.endswith(b"\n")
    log.write_bytes(data[:-1])


def test_line_missing_only_its_newline_is_not_flagged(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    A.append_event("s1", {"i": 3}, now=T0)
    _strip_last_newline(log)  # line 4 complete but unterminated (state saved)
    assert A.verify_session("s1") == []
    assert A.append_event("s1", {"i": 4}, now=T0)["seq"] == 5
    A.append_event("s1", {"i": 5}, now=T0)
    assert _seqs(log) == [1, 2, 3, 4, 5, 6]
    assert A.verify_session("s1") == []


def test_newline_only_tear_then_killed_recovery_is_clean(tmp_path, monkeypatch):
    log, state = _three(monkeypatch, tmp_path)
    snap = state.read_bytes()
    A.append_event("s1", {"i": 3}, now=T0)
    state.write_bytes(snap)  # the write was killed before the state save ...
    _strip_last_newline(log)  # ... and before its newline reached the disk
    real = A.save_state
    monkeypatch.setattr(A, "save_state", lambda *a, **k: (_ for _ in ()).throw(OSError("full")))
    assert A.append_event("s1", {"i": 4}, now=T0) is None  # log written, state save lost
    monkeypatch.setattr(A, "save_state", real)
    assert A.append_event("s1", {"i": 5}, now=T0)["seq"] == 6
    assert _seqs(log) == [1, 2, 3, 4, 5, 6]
    assert A.verify_session("s1") == []
    assert A.load_state("s1")["breaks"] == []


def test_first_line_missing_only_its_newline_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    A.append_event("s1", {"i": 0}, now=T0)
    log, state = A.session_paths("s1", T0)
    state.unlink()  # killed before the first state save
    _strip_last_newline(log)
    assert A.append_event("s1", {"i": 1}, now=T0)["seq"] == 2
    assert _seqs(log) == [1, 2]
    assert A.verify_session("s1") == []


def test_dropping_last_line_with_the_newline_before_it_is_flagged(tmp_path, monkeypatch):
    log, _ = _four(monkeypatch, tmp_path)
    log.write_bytes(b"\n".join(_lines(log)[:3]))  # line 3 now unterminated
    assert A.verify_session("s1") != []
    A.append_event("s1", {"i": 9}, now=T0)
    assert A.verify_session("s1") != []


def test_editing_last_line_and_stripping_its_newline_is_flagged(tmp_path, monkeypatch):
    log, _ = _three(monkeypatch, tmp_path)
    log.write_bytes(log.read_bytes()[:-1].replace(b'"i":2', b'"i":9'))
    assert A.verify_session("s1") != []
    A.append_event("s1", {"i": 3}, now=T0)
    assert A.verify_session("s1") != []


# --- Task 4 fix round 1: the lock wait is bounded (Codex runs async hooks inline) -----


def test_append_gives_up_on_a_held_lock_within_a_second(tmp_path, monkeypatch):
    import subprocess
    import sys
    import time

    monkeypatch.setattr(A, "ACTIVITY_DIR", tmp_path / "act")
    first = A.append_event("s1", {"i": 1}, now=T0)
    assert first["seq"] == 1
    lock = A._lock_path("s1")
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import fcntl, os, sys, time\n"
         "fd = os.open(sys.argv[1], os.O_RDWR)\n"
         "fcntl.flock(fd, fcntl.LOCK_EX)\n"
         "print('held', flush=True)\n"
         "time.sleep(30)\n",
         str(lock)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        start = time.monotonic()
        assert A.append_event("s1", {"i": 2}, now=T0) is None
        assert time.monotonic() - start < 1.5
        assert issubclass(A.LockTimeoutError, OSError)
        try:
            with A.session_lock("s1"):
                raise AssertionError("the lock was taken while another process held it")
        except A.LockTimeoutError:
            pass
    finally:
        holder.kill()
        holder.wait(10)
    # The dropped event is not a break: the next append continues the chain.
    assert A.append_event("s1", {"i": 3}, now=T0)["seq"] == 2
    assert A.verify_session("s1") == []
