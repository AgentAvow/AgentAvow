#!/usr/bin/env python3
"""AgentAvow local activity log: what the agent did in a session, kept on this machine.

Entry-point module, run by hooks/hooks.json through run_hook.sh:

    agentavow_activity.py                  record one event from the stdin payload (async)
    agentavow_activity.py --session-start  record SessionStart, then 30-day cleanup (while
                                           off: cleanup only, if the folder exists)
    agentavow_activity.py --session-end    record SessionEnd (append only, nothing else)
    agentavow_activity.py --notes          not built yet: exit 0, print nothing
    agentavow_activity.py --report         print the report (plain text); the person runs it
                                           themselves, on or off, and it reads no stdin

It is off unless AGENTAVOW_ACTIVITY=on, and off on Windows. The recorder never prints
anything: no decision, no message. Only a summary of each event is kept (see
agentavow_activity_redact.py), never prompts, assistant messages or tool output.

The storage layer: one append-only JSON Lines file per session with a SHA-256 hash
chain (tamper evidence), a per-session state file guarded by an flock, size caps and
30-day cleanup. Standard library only.

Fail-open: ``main`` and ``append_event`` never raise. A full disk, a read-only folder
or a bad payload means the event is simply not recorded.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import re
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import fcntl
except ImportError:  # Windows: the log is off there, and main() returns first
    fcntl = None

# Sibling modules: the script's folder is sys.path[0] when run as a hook, but not when
# this file is loaded by path (tests), so make sure it is there.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:  # fail-open: a broken sibling must not print a traceback; main() then does nothing
    import agentavow_activity_redact as _redact
except Exception:
    _redact = None

__version__ = "0.1.47"

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
    return hashlib.sha256(str(session_id).encode("utf-8", "surrogatepass")).hexdigest()[:32]


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
    or it does not parse). Unterminated bytes that are exactly the next chained
    line (only the newline was lost) count as the last complete line, with
    ``torn`` still set.
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
    if info["torn"] and _lost_only_newline(parts[-1], complete):
        complete = parts  # a whole line; ``torn`` stays set so the writer adds the newline
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


def _lost_only_newline(raw: bytes, complete: list[bytes]) -> bool:
    """True when unterminated bytes are exactly the next chained line, minus its newline.

    Their ``prev`` must be the hash of the last complete line and their ``seq``
    that line's seq + 1 (None and 1 when there is no complete line).
    """
    want_seq, want_prev = 1, None
    try:
        obj = json.loads(raw)
        if complete:
            before = json.loads(complete[-1])
            want_seq = before["seq"] + 1 if type(before["seq"]) is int else None
            want_prev = hashlib.sha256(complete[-1]).hexdigest()
    except (ValueError, KeyError, TypeError):
        return False
    return (
        isinstance(obj, dict)
        and want_seq is not None
        and type(obj.get("seq")) is int
        and obj["seq"] == want_seq
        and obj.get("prev") == want_prev
    )


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

# Codex runs async hooks inline, so a tool call can wait on the recorder: the lock wait
# is bounded, and on timeout the event is dropped (not a chain break).
LOCK_WAIT_SECONDS = 1.0


class LockTimeout(OSError):
    """The session lock stayed held by another process for LOCK_WAIT_SECONDS."""


def _flock_bounded(fd: int) -> None:
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    pause = 0.001
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            pass
        left = deadline - time.monotonic()
        if left <= 0:
            raise LockTimeout("session lock busy")
        time.sleep(min(pause, left))
        pause = min(pause * 2, 0.02)


@contextlib.contextmanager
def session_lock(session_id: str):
    """Hold the session's flock. Re-entrant in-process: append_event inside it is safe.

    Waits at most LOCK_WAIT_SECONDS for another process, then raises LockTimeout.
    """
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
        _flock_bounded(fd)
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
        try:
            raw = _dump_line(line)
        except UnicodeEncodeError:  # a lone surrogate: keep it as a visible \udcXX
            raw = _dump_line(_no_surrogates(line))
        fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            _write_all(fd, (b"\n" if tail["torn"] else b"") + raw + b"\n")
        finally:
            os.close(fd)
        state["seq"] = line["seq"]
        state["prev"] = hashlib.sha256(raw).hexdigest()
        save_state(session_id, state)
        return line


def _dump_line(line: dict) -> bytes:
    return json.dumps(line, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8")


def _no_surrogates(value: object) -> object:
    """A copy with each lone surrogate in a string (key or value) spelled as ``\\udcXX``.

    A payload's JSON can carry one (``"\\udc80"``); UTF-8 cannot, so without this the
    line would not be written and the call would be missing from the log.
    """
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {_no_surrogates(k): _no_surrogates(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_no_surrogates(v) for v in value]
    return value


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


# ---------------------------------------------------------------------------
# Recorder: payload -> event line
# ---------------------------------------------------------------------------

# PostToolUseFailure is handled (ok=False) but not registered in hooks/hooks.json yet:
# Codex reads the same file, and Codex 0.166 does not list that event. An event it does
# not know could make it reject the whole file, which would switch off the gate and the
# install check for every Codex user. Registering it later is a one-entry change there.
EVENTS = frozenset({
    "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "SessionStart", "SessionEnd", "SubagentStart", "SubagentStop",
})
TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure"})


def _enabled() -> bool:
    """Release 1: on only when AGENTAVOW_ACTIVITY is ``on`` (any case).

    run_hook.sh applies the same rule before starting Python, so a log that is off
    costs no process per tool call. Release 2 flips the rule (off only for ``off``)
    in both places; tests pin that they agree.
    """
    return os.environ.get("AGENTAVOW_ACTIVITY", "").lower() == "on"


def _text(value: object) -> str | None:
    return _redact.cut(value, _redact.TEXT_LIMIT) if isinstance(value, str) else None


def _gate():
    """The pre-tool gate module (same folder), for its MCP name split and cache lookup."""
    import agentavow_pretool_gate

    return agentavow_pretool_gate


def _answer(server: str) -> str | None:
    """The server's AgentAvow answer (safe, review or do_not_connect) from scanned.json.

    Read-only; any failure means no answer.
    """
    try:
        gate = _gate()
        cache = json.loads(gate.CACHE.read_text("utf-8"))
        found = gate.find_record(cache, server) if isinstance(cache, dict) else None
        if found:
            decision = found[1].get("decision")
            if decision in gate.DECISION_PHRASES:
                return decision
    except Exception:
        pass
    return None


def build_event(payload: dict, *, now: datetime | None = None) -> dict | None:
    """The fields to record for one hook payload, or None when it is not one to record.

    Only named fields are copied. Prompts, assistant messages, tool output and
    transcript paths are never read into the event.
    """
    if not isinstance(payload, dict):
        return None
    event = payload.get("hook_event_name")
    session = payload.get("session_id")
    if event not in EVENTS or not isinstance(session, str) or not session:
        return None
    now = now or datetime.now(timezone.utc)
    out: dict = {
        "ts": now.isoformat(timespec="milliseconds"),
        "agent": "codex" if "turn_id" in payload else "claude-code",
        "event": event,
        "session": _text(session),
        "cwd": _text(payload.get("cwd")),
    }
    if payload.get("agent_id") is not None:
        out["subagent"] = {"id": _text(str(payload["agent_id"])),
                           "type": _text(payload.get("agent_type"))}
    duration = payload.get("duration_ms")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool):
        out["duration_ms"] = duration
    if event == "SessionStart" and isinstance(payload.get("source"), str):
        out["source"] = _text(payload["source"])
    if event == "SessionEnd" and isinstance(payload.get("reason"), str):
        out["reason"] = _text(payload["reason"])
    if event in TOOL_EVENTS:
        tool = payload.get("tool_name")
        tool = tool if isinstance(tool, str) else ""
        out["tool"] = _text(tool)
        out["input"] = _redact.summarize_input(tool, payload.get("tool_input"), out["cwd"])
        if tool.startswith("mcp__"):
            try:
                parts = _gate().parse_tool_name(tool)
            except Exception:  # the gate failed to import: record the call without them
                parts = None
            if parts:
                out["mcp_server"], out["mcp_tool"] = _text(parts[0]), _text(parts[1])
                answer = _answer(parts[0])
                if answer:
                    out["answer"] = answer
        if event != "PreToolUse":
            out["ok"] = event == "PostToolUse"
            if "tool_response" in payload:
                out["out_bytes"] = _redact.summarize_output(payload["tool_response"])["out_bytes"]
    return out


def _record(payload: object, now: datetime) -> None:
    event = build_event(payload, now=now)
    if event is not None:
        append_event(payload["session_id"], event, now=now)


# ---------------------------------------------------------------------------
# The trusted report (--report): run by the person, read-only, plain text
# ---------------------------------------------------------------------------

_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_SEVERITY = {"high": (0, "HIGH"), "medium": (1, "MED"), "med": (1, "MED"), "low": (2, "LOW")}
_ANSWER_WORDS = {"safe": "Safe to connect", "review": "Review before you connect",
                 "do_not_connect": "Do not connect"}
_SUMMARY_LIMIT = 100
_MAX_WARN_LINES = 10


def _parse_ts(value: object) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _read_log(path: pathlib.Path) -> list[tuple[dict, str, datetime]]:
    """Valid event lines of one log as (event, raw line, time); anything else is skipped."""
    out = []
    try:
        data = path.read_bytes()
    except OSError:
        return out
    for raw in data.split(b"\n"):
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        ts = _parse_ts(obj.get("ts")) if isinstance(obj, dict) else None
        if ts is not None:
            out.append((obj, raw.decode("utf-8", "replace"), ts))
    return out


def _log_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    try:
        days = sorted(d.name for d in os.scandir(ACTIVITY_DIR)
                      if _DAY_RE.fullmatch(d.name) and d.is_dir(follow_symlinks=False))
        for day in days:
            for f in sorted(os.scandir(ACTIVITY_DIR / day), key=lambda e: e.name):
                if f.name.endswith(".jsonl") and f.is_file(follow_symlinks=False):
                    files.append(pathlib.Path(f.path))
    except OSError:
        pass
    return files


def _clean(value: object) -> str:
    """Printable text only: ESC, CR, BEL, bidi overrides and the like become ``?``.

    Everything the plain-text report prints passes through here, so a logged string
    cannot move the cursor, overwrite a line or hide a flag on the person's terminal.
    """
    return "".join(c if c.isprintable() else "?" for c in str(value))


def _short(value: object, limit: int = _SUMMARY_LIMIT) -> str:
    text = " ".join(_clean(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _summary(ev: dict) -> str:
    try:
        return _summary_of(ev)
    except Exception:
        return ""


def _summary_of(ev: dict) -> str:
    """One short line for an event, from the redacted summary the log already holds."""
    data = ev.get("input")
    if isinstance(data, dict):
        for key in ("command", "path", "url", "query"):
            if data.get(key):
                return _short(data[key])
        if isinstance(data.get("paths"), (list, tuple)) and data["paths"]:
            return _short(", ".join(str(p) for p in data["paths"]))
        if data.get("pattern") and isinstance(data["pattern"], str):
            where = f" in {data['path']}" if data.get("path") else ""
            return _short(f"{data['pattern']}{where}")
        if isinstance(data.get("args"), dict) and data["args"]:
            return _short(" ".join(f"{k}={v}" for k, v in data["args"].items()))
        if isinstance(data.get("arg_names"), (list, tuple)) and data["arg_names"]:
            return _short("args: " + ", ".join(str(n) for n in data["arg_names"]))
    for key in ("source", "reason"):
        if ev.get(key):
            return _short(ev[key])
    sub = ev.get("subagent")
    if isinstance(sub, dict) and sub.get("type"):
        return _short(f"subagent {sub['type']}")
    return ""


def _group(tool: str) -> str:
    """mcp__server__tool counts under mcp__server."""
    if tool.startswith("mcp__"):
        return "mcp__" + tool[5:].split("__", 1)[0]
    return tool


def _day_text(ts: datetime) -> str:
    return f"{_MONTHS[ts.month - 1]} {ts.day}"


def _range_text(first: datetime, last: datetime) -> str:
    a, b = _day_text(first), _day_text(last)
    if a == b:
        return a
    return f"{a}-{b.split(' ', 1)[1]}" if first.month == last.month else f"{a}-{b}"


def _flag_of(ev: dict) -> dict | None:
    flag = ev.get("flag")
    return flag if isinstance(flag, dict) else None


def _warnings(stems: list[str]) -> list[str]:
    out = []
    for stem in stems:
        try:
            broken = verify_session(stem)
        except Exception:
            continue
        if broken:
            shown = ", ".join(str(n) for n in broken[:_MAX_WARN_LINES])
            more = ", …" if len(broken) > _MAX_WARN_LINES else ""
            out.append(f"Warning: the log for session {_clean(stem)} was changed or cut "
                       f"(lines {shown}{more}).")
    return out


def report(days: int = 7, session: str | None = None, rule: str | None = None,
           export: bool = False, now: datetime | None = None) -> str:
    """The report as plain text (raw JSON lines for ``export``). Never raises on bad logs."""
    now = now or datetime.now(timezone.utc)
    days = min(days, 3650) if isinstance(days, int) and days > 0 else 7
    cutoff = now - timedelta(days=days)
    wanted = _sid(session) if session else None
    rows: list[tuple[dict, str, datetime, str]] = []  # event, raw, time, session stem
    stems_seen: list[str] = []
    for path in _log_files():
        stem = path.name[: -len(".jsonl")]
        if wanted is not None and stem != wanted:
            continue
        found = _read_log(path)
        keep = [r for r in found if wanted is not None or r[2] >= cutoff]
        if keep or not found:
            stems_seen.append(stem)
        rows.extend((*r, stem) for r in keep)
    rows.sort(key=lambda r: r[2])
    warnings = _warnings(list(dict.fromkeys(stems_seen)))

    if export:
        return "\n".join(r[1] for r in rows)

    if not rows:
        what = f"session {_clean(session)}" if session else f"the last {days} days"
        text = (f"AgentAvow activity: no events for {what}." if session
                else f"AgentAvow activity: nothing recorded in {what}.")
        if not session and not _enabled():
            text += "\nIt is off; set AGENTAVOW_ACTIVITY=on to turn it on."
        return "\n".join([*warnings, text])

    if session:
        head = f"AgentAvow activity, session {_clean(session)} · {len(rows)} events"
        lines = []
        for ev, _raw, ts, _stem in rows:
            try:
                name = _short(ev.get("tool") or ev.get("event") or "?", 80)
                line = f"{ts.astimezone(timezone.utc):%H:%M:%S}  {name}  {_summary(ev)}".rstrip()
                flag = _flag_of(ev)
                if flag:
                    line += (f"  [{_short(flag.get('severity', 'flag'), 20)}: "
                             f"{_short(flag.get('note', ''), 160)}]")
            except Exception:
                line = f"{ts:%H:%M:%S}  ?"
            lines.append(line)
        return "\n".join([*warnings, head, *lines])

    flags = []
    for ev, _raw, ts, stem in rows:
        flag = _flag_of(ev)
        if flag and (rule is None or flag.get("rule") == rule):
            flags.append((ev, flag, ts, stem))
    flags.sort(key=lambda f: (_SEVERITY.get(str(f[1].get("severity")).lower(), (3, ""))[0],
                              -f[2].timestamp()))
    head = (f"AgentAvow activity, {_range_text(rows[0][2], rows[-1][2])} · "
            f"{len(rows):,} events · {len(set(r[3] for r in rows))} sessions · "
            f"{len(flags)} flags")
    out = [*warnings, head, ""]
    for ev, flag, ts, stem in flags:
        try:
            label = _SEVERITY.get(str(flag.get("severity")).lower(),
                                  (3, _short(flag.get("severity", "?"), 12).upper()))[1]
            agent = "Codex" if ev.get("agent") == "codex" else "Claude Code"
            out.append(f"{label:<5} {_day_text(ts)} {ts:%H:%M}  {_short(flag.get('note', ''), 160)}")
            out.append(f"      session {_clean(stem)} ({agent}, {_short(ev.get('cwd') or '?', 60)})")
        except Exception:
            out.append(f"?     {_day_text(ts)} {ts:%H:%M}  (flag could not be shown)")
    if flags:
        out.append("")
    counts: dict[str, int] = {}
    servers: dict[str, str | None] = {}
    for ev, _raw, _ts, _stem in rows:
        tool = ev.get("tool")
        if ev.get("event") == "PreToolUse" and isinstance(tool, str) and tool:
            counts[_group(tool)] = counts.get(_group(tool), 0) + 1
        server = ev.get("mcp_server")
        if isinstance(server, str) and server:
            answer = ev.get("answer")
            answer = answer if isinstance(answer, str) and answer in _ANSWER_WORDS else None
            servers[server] = answer or servers.get(server)
    if counts:
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        out.append("Most active: " + " · ".join(f"{_short(n, 60)} {c:,}" for n, c in top))
    if servers:
        answers = set(servers.values())
        if len(answers) == 1 and None not in answers:
            out.append(f"MCP servers called: {', '.join(_short(n, 60) for n in servers)} "
                       f"(all {_ANSWER_WORDS[answers.pop()]})")
        else:
            out.append("MCP servers called: " + ", ".join(
                f"{_short(n, 60)} ({_ANSWER_WORDS.get(a, 'not scanned')})"
                for n, a in servers.items()))
    return "\n".join(out).rstrip()


def _report_args(argv: list[str]) -> dict:
    kwargs: dict = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--export":
            kwargs["export"] = True
        elif arg in ("--days", "--session", "--rule") and i + 1 < len(argv):
            i += 1
            if arg == "--days":
                try:
                    kwargs["days"] = int(argv[i])
                except ValueError:
                    pass
            else:
                kwargs[arg[2:]] = argv[i]
        i += 1
    return kwargs


def _read_stdin() -> str:
    """The payload text. Bytes that are not UTF-8 become U+FFFD whatever the locale, so
    they cannot keep a call out of the log."""
    buf = getattr(sys.stdin, "buffer", None)
    if buf is None:
        return sys.stdin.read()
    return buf.read().decode("utf-8", "replace")


def main(argv: list[str]) -> int:
    """Hook entry point. Always returns 0 and prints nothing (fail-open)."""
    try:
        if os.name == "nt":
            return 0
        mode = argv[0] if argv else None
        if mode == "--report":  # the person's own view: on or off, no stdin, no recording
            try:
                text = report(**_report_args(argv[1:]))
            except Exception as exc:
                text = ("AgentAvow activity: the report could not be built "
                        f"({type(exc).__name__}).")
            print(text)
            return 0
        if mode not in (None, "--session-start", "--session-end"):
            return 0  # --notes comes in a later release; unknown flags are ignored
        if not _enabled():
            if mode == "--session-start" and ACTIVITY_DIR.is_dir():
                _read_stdin()  # read to the end; nothing from it is kept
                cleanup(datetime.now(timezone.utc))  # logs from when it was on still age out
            return 0
        if _redact is None:
            return 0
        payload = json.loads(_read_stdin())
        now = datetime.now(timezone.utc)
        _record(payload, now)
        if mode == "--session-start":
            cleanup(now)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
