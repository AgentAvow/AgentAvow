#!/usr/bin/env python3
"""AgentAvow local activity log: what the agent did in a session, kept on this machine.

Entry-point module. This part holds the storage layer: one append-only JSON Lines
file per session with a SHA-256 hash chain (tamper evidence), a per-session state
file guarded by an flock, size caps and 30-day cleanup. Standard library only.

Fail-open: ``append_event`` never raises. A full disk or a read-only folder means
the event is simply not recorded.
"""
from __future__ import annotations

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
    """Write the state in place (same inode, so the flock holders stay valid)."""
    data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(_state_path(session_id), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def session_paths(session_id: str, now: datetime) -> tuple[pathlib.Path, pathlib.Path]:
    """Return (log_file, state_file). The day is the session's first event's day."""
    sid = _sid(session_id)
    day = load_state(session_id).get("day") or now.strftime("%Y-%m-%d")
    return ACTIVITY_DIR / day / (sid + ".jsonl"), _state_path(session_id)


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
    _mkdir(ACTIVITY_DIR)
    _mkdir(ACTIVITY_DIR / "sessions")
    lock_fd = os.open(_state_path(session_id), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = load_state(session_id)
        if not state.get("day"):
            state["day"] = now.strftime("%Y-%m-%d")
        log_dir = ACTIVITY_DIR / state["day"]
        _mkdir(log_dir)
        log_file = log_dir / (_sid(session_id) + ".jsonl")

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

        line = dict(event)
        line["v"] = 0
        line["seq"] = int(state.get("seq") or 0) + 1
        line["prev"] = state.get("prev")
        raw = json.dumps(
            line, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, raw + b"\n")
        finally:
            os.close(fd)
        state["seq"] = line["seq"]
        state["prev"] = hashlib.sha256(raw).hexdigest()
        save_state(session_id, state)
        return line
    finally:
        os.close(lock_fd)


def verify_chain(log_file: pathlib.Path) -> list[int]:
    """Return the 1-based line numbers whose ``prev`` does not match the line before."""
    try:
        data = pathlib.Path(log_file).read_bytes()
    except OSError:
        return []
    broken: list[int] = []
    prev_hash = None
    lines = data.split(b"\n")
    if data.endswith(b"\n"):
        lines.pop()
    for n, raw in enumerate(lines, 1):
        try:
            prev = json.loads(raw).get("prev")
        except (ValueError, AttributeError):
            prev = object()
        if prev != prev_hash:
            broken.append(n)
        prev_hash = hashlib.sha256(raw).hexdigest()
    return broken


def cleanup(now: datetime) -> None:
    """Delete day folders older than 30 days, with the state files of their sessions."""
    cutoff = (now - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%d")
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
                    try:
                        os.unlink(ACTIVITY_DIR / "sessions" / (f.name[: -len(".jsonl")] + ".json"))
                    except OSError:
                        pass
                try:
                    os.unlink(f.path)
                except OSError:
                    pass
            os.rmdir(d.path)
        except OSError:
            pass
