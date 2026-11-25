#!/usr/bin/env python3
"""AgentAvow local activity log: what the agent did in a session, kept on this machine.

Entry-point module. This part holds the storage layer: one append-only JSON Lines
file per session with a SHA-256 hash chain (tamper evidence), a per-session state
file guarded by an flock, size caps and 30-day cleanup. Standard library only.

Fail-open: ``append_event`` never raises. A full disk or a read-only folder means
the event is simply not recorded.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import time
from datetime import datetime, timedelta, timezone

__version__ = "0.1.46"

ACTIVITY_DIR = pathlib.Path.home() / ".cache" / "agentavow" / "activity"

# ---------------------------------------------------------------------------
# Store: hash chain, lock, caps, cleanup
# ---------------------------------------------------------------------------

SESSION_CAP = 20 * 2**20  # bytes per session log; past it only flagged events are kept
TOTAL_CAP = 200 * 2**20  # bytes across all day folders
RETENTION_DAYS = 30
TOTAL_CHECK_SECONDS = 60

_SID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _sid(session_id: str) -> str:
    if _SID_RE.fullmatch(session_id or ""):
        return session_id
    return hashlib.sha256(str(session_id).encode("utf-8")).hexdigest()[:32]


def _state_path(session_id: str) -> pathlib.Path:
    return ACTIVITY_DIR / "sessions" / (_sid(session_id) + ".json")


def _lock_path(session_id: str) -> pathlib.Path:
    return ACTIVITY_DIR / "sessions" / (_sid(session_id) + ".lock")


def _fresh_state() -> dict:
    return {
        "day": None,
        "seq": 0,
        "prev": None,
        "dropped": 0,
        "cred_read_ts": None,
        "shown_rules": [],
        "agent": None,
        "cwd": None,
        "total_checked_ts": None,
        "total_over": False,
        "breaks": [],
    }


def load_state(session_id: str) -> dict:
    """Read the session state; a missing or unreadable file gives a fresh state."""
    state = _fresh_state()
    try:
        data = json.loads(_state_path(session_id).read_text("utf-8"))
        if isinstance(data, dict):
            state.update(data)
    except (OSError, ValueError):
        pass
    return state


def save_state(session_id: str, state: dict) -> None:
    """Write the state atomically (temp file plus replace); the lock is a separate file."""
    data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = _state_path(session_id)
    tmp = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        _write_all(fd, data)
    except BaseException:
        os.close(fd)
        _unlink(tmp)
        raise
    os.close(fd)
    os.replace(tmp, path)


def _unlink(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError("short write")
        view = view[n:]


def _find_day(session_id: str) -> str | None:
    """Earliest day folder that already holds this session's log, if any."""
    name = _sid(session_id) + ".jsonl"
    try:
        days = sorted(d.name for d in os.scandir(ACTIVITY_DIR) if d.is_dir(follow_symlinks=False))
    except OSError:
        return None
    for day in days:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day) and (ACTIVITY_DIR / day / name).is_file():
            return day
    return None


def session_paths(session_id: str, now: datetime) -> tuple[pathlib.Path, pathlib.Path]:
    """Return (log_file, state_file). The day is the session's first event's day."""
    sid = _sid(session_id)
    day = load_state(session_id).get("day") or _find_day(session_id) or now.strftime("%Y-%m-%d")
    return ACTIVITY_DIR / day / (sid + ".jsonl"), _state_path(session_id)


def _tail(log_file: pathlib.Path) -> dict:
    """Describe the end of the log.

    Keys: ``torn`` (non-empty file not ending in a newline), ``last_line`` (the
    torn bytes when torn, else the last complete line, else None), and for the
    last complete line ``seq``, ``prev`` and ``hash`` (None when there is none
    or it does not parse).
    """
    info = _tail_empty()
    size = log_file.stat().st_size
    if size == 0:
        return info
    chunk = 65536
    with open(log_file, "rb") as f:
        while True:
            start = max(0, size - chunk)
            f.seek(start)
            data = f.read(size - start)
            if start == 0 or data.count(b"\n") >= 5:
                break
            chunk *= 4
    if start > 0:
        data = data[data.index(b"\n") + 1:]
    parts = data.split(b"\n")
    info["torn"] = parts[-1] != b""
    complete = parts[:-1]
    info["last_line"] = parts[-1] if info["torn"] else (complete[-1] if complete else None)
    if len(complete) >= 2:
        # Torn-line recovery: the line before the last is unparseable, and its
        # nearest parseable predecessor is the anchor the state may still hold.
        info["before_hash"] = hashlib.sha256(complete[-2]).hexdigest()
        for raw in reversed(complete[:-1]):
            try:
                json.loads(raw)
            except ValueError:
                continue
            info["anchor_hash"] = hashlib.sha256(raw).hexdigest()
            break
        else:
            info["anchor_hash"] = None
        try:
            json.loads(complete[-2])
            info["before_torn"] = False
        except ValueError:
            info["before_torn"] = True
    if complete:
        info["hash"] = hashlib.sha256(complete[-1]).hexdigest()
        try:
            obj = json.loads(complete[-1])
            info["seq"], info["prev"] = int(obj["seq"]), obj.get("prev")
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
    return info


def _tail_mismatch(state: dict, tail: dict) -> bool:
    """True when the log's last complete line contradicts the state.

    The log is written before the state, so the state may lag the log (a kill
    between the two writes, or two in a row) but is never legitimately ahead.
    """
    s = int(state.get("seq") or 0)
    if s == 0:
        return False
    if tail["hash"] is None:
        return tail["last_line"] is None  # empty or missing log, state says otherwise
    if tail["seq"] is None:
        return False  # unparseable last line: verify_chain flags it
    if tail["seq"] < s:
        return True
    if tail["seq"] == s:
        return tail["hash"] != state.get("prev")
    if tail["seq"] == s + 1:
        if tail["prev"] == state.get("prev"):
            return False
        # A torn line, then a recovery append whose state save was lost.
        torn_recovery = (
            tail.get("before_torn")
            and tail["prev"] == tail.get("before_hash")
            and tail.get("anchor_hash") == state.get("prev")
        )
        return not torn_recovery
    return False


def _count_lines(log_file: pathlib.Path) -> int:
    try:
        data = log_file.read_bytes()
    except OSError:
        return 0
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


_held: dict[str, int] = {}


@contextlib.contextmanager
def session_lock(session_id: str):
    """Hold the session's flock. Re-entrant in-process: append_event inside it is safe."""
    sid = _sid(session_id)
    if _held.get(sid):
        _held[sid] += 1
        try:
            yield
        finally:
            _held[sid] -= 1
        return
    _mkdir(ACTIVITY_DIR)
    _mkdir(ACTIVITY_DIR / "sessions")
    fd = os.open(_lock_path(session_id), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _held[sid] = 1
        try:
            yield
        finally:
            _held.pop(sid, None)
    finally:
        os.close(fd)


def _mkdir(path: pathlib.Path) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)


def _total_size() -> int:
    total = 0
    try:
        days = list(os.scandir(ACTIVITY_DIR))
    except OSError:
        return 0
    for d in days:
        if not d.is_dir(follow_symlinks=False) or d.name == "sessions":
            continue
        try:
            for f in os.scandir(d.path):
                try:
                    total += f.stat(follow_symlinks=False).st_size
                except OSError:
                    pass
        except OSError:
            pass
    return total


def append_event(
    session_id: str,
    event: dict,
    *,
    flagged: bool = False,
    now: datetime | None = None,
) -> dict | None:
    """Append one chained line. Returns the line as written, or None (dropped or failed)."""
    try:
        return _append_event(session_id, event, flagged, now)
    except Exception:  # fail open: logging must never break the agent
        return None


def _append_event(session_id: str, event: dict, flagged: bool, now: datetime | None) -> dict | None:
    now = now or datetime.now(timezone.utc)
    with session_lock(session_id):
        state = load_state(session_id)
        if not state.get("day"):
            state["day"] = _find_day(session_id) or now.strftime("%Y-%m-%d")
        log_dir = ACTIVITY_DIR / state["day"]
        _mkdir(log_dir)
        log_file = log_dir / (_sid(session_id) + ".jsonl")

        # The log is the source of truth for seq and prev (the state may be lost or stale).
        tail = _tail(log_file) if log_file.exists() else _tail_empty()
        seq_base = tail["seq"]
        if seq_base is None and tail["last_line"] is not None:
            seq_base = int(state.get("seq") or 0)
        seq_base = seq_base or 0
        if _tail_mismatch(state, tail):
            breaks = list(state.get("breaks") or [])
            breaks.append(
                {
                    "line": _count_lines(log_file) + 1,
                    "state_seq": int(state.get("seq") or 0),
                    "log_seq": tail["seq"] or 0,
                    "ts": now.isoformat(),
                }
            )
            state["breaks"] = breaks[-100:]
            seq_base = max(seq_base, int(state.get("seq") or 0))

        # Caps: past either one, only flagged events are still written.
        over = False
        try:
            over = log_file.stat().st_size >= SESSION_CAP
        except OSError:
            pass
        ts = time.time()
        checked = state.get("total_checked_ts")
        if checked is None or ts - checked >= TOTAL_CHECK_SECONDS or ts < checked:
            state["total_over"] = _total_size() >= TOTAL_CAP
            state["total_checked_ts"] = ts
        over = over or bool(state.get("total_over"))
        if over and not flagged:
            state["dropped"] = int(state.get("dropped") or 0) + 1
            save_state(session_id, state)
            return None

        prev = hashlib.sha256(tail["last_line"]).hexdigest() if tail["last_line"] else None
        line = dict(event)
        line["v"] = 0
        line["seq"] = seq_base + 1
        line["prev"] = prev
        raw = json.dumps(
            line, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            _write_all(fd, (b"\n" if tail["torn"] else b"") + raw + b"\n")
        finally:
            os.close(fd)
        state["seq"] = line["seq"]
        state["prev"] = hashlib.sha256(raw).hexdigest()
        save_state(session_id, state)
        return line


def _tail_empty() -> dict:
    return {"torn": False, "last_line": None, "seq": None, "prev": None, "hash": None}


def verify_chain(log_file: pathlib.Path) -> list[int]:
    """Return the 1-based line numbers that break the chain.

    A line breaks it when its ``prev`` is not the hash of the line before, or its
    ``seq`` is not the previous line's ``seq`` + 1 (the first line must be 1).
    """
    try:
        data = pathlib.Path(log_file).read_bytes()
    except OSError:
        return []
    broken: list[int] = []
    prev_hash = None
    prev_seq: int | None = 0
    lines = data.split(b"\n")
    if data.endswith(b"\n") or not data:
        lines.pop()
    for n, raw in enumerate(lines, 1):
        bad = False
        seq = None
        try:
            obj = json.loads(raw)
            bad = obj.get("prev") != prev_hash
            seq = obj.get("seq")
            seq = seq if isinstance(seq, int) else None
        except (ValueError, AttributeError):
            bad = True
        if prev_seq is not None and seq != prev_seq + 1:
            bad = True
        if bad:
            broken.append(n)
        prev_hash = hashlib.sha256(raw).hexdigest()
        prev_seq = seq
    return broken


def verify_session(session_id: str) -> list[int]:
    """Every break in a session's log, as sorted unique line numbers.

    The union of the chain check, the breaks recorded in the state when an append
    found the log contradicting it, and a live check of the log's tail against the
    state (which catches a cut or edited tail). The state may lag the log by any
    number of events (kills between the log write and the state write). A tail
    break is reported at ``len(lines) + 1``.
    """
    log_file, _ = session_paths(session_id, datetime.now(timezone.utc))
    broken = set(verify_chain(log_file))
    state = load_state(session_id)
    for b in state.get("breaks") or []:
        try:
            broken.add(int(b["line"]))
        except (KeyError, TypeError, ValueError):
            pass
    if int(state.get("seq") or 0) > 0:
        tail = _tail(log_file) if log_file.exists() else _tail_empty()
        if _tail_mismatch(state, tail):
            broken.add(_count_lines(log_file) + 1)
    return sorted(broken)


def cleanup(now: datetime) -> None:
    """Delete day folders older than 30 days, with the state files of their sessions."""
    cutoff = (now - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%d")
    try:
        for f in os.scandir(ACTIVITY_DIR / "sessions"):
            if f.name.endswith(".tmp") and f.stat().st_mtime < now.timestamp() - 3600:
                _unlink(f.path)
    except OSError:
        pass
    try:
        entries = list(os.scandir(ACTIVITY_DIR))
    except OSError:
        return
    for d in entries:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.name) or d.name >= cutoff:
            continue
        if not d.is_dir(follow_symlinks=False):
            continue
        try:
            for f in os.scandir(d.path):
                if f.name.endswith(".jsonl"):
                    stem = f.name[: -len(".jsonl")]
                    for ext in (".json", ".lock"):
                        _unlink(ACTIVITY_DIR / "sessions" / (stem + ext))
                try:
                    os.unlink(f.path)
                except OSError:
                    pass
            os.rmdir(d.path)
        except OSError:
            pass
