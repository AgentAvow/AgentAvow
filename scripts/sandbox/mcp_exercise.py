#!/usr/bin/env python3
"""In-sandbox MCP exerciser (Python 3.12, stdlib only; ``mcp_exercise.js`` is the Node twin).

Runs INSIDE the gVisor container: spawns an MCP server over stdio, does ``initialize`` +
``tools/list``, calls every tool (up to ``--max-tools``) with deterministic synthetic
arguments, diffs the writable mounts around each call, and prints ONE transcript between
``AGENTAVOW_TRANSCRIPT_BEGIN`` / ``AGENTAVOW_TRANSCRIPT_END`` on stdout. The JSON shape is
the contract in ``src/scanner/behavioral/transcript.py``. Always exits 0 and always
prints a transcript — a launch failure, timeout, or crash is recorded, not raised.

    python mcp_exercise.py [--timeout S] [--per-call-timeout S] [--max-tools N]
        [--readme PATH] [--canary-env A,B] [--canary-value V] [--mounts /tmp,/work,/run]
        -- <server command and args...>
    python mcp_exercise.py --gen-args schema.json     # debug: print generated args
"""
from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True  # no __pycache__ in the mount diff
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(1, os.path.join(_HERE, "..", "..", "src", "scanner", "behavioral"))
try:
    from synthetic_args import args_for_tool, generate_args, mine_examples
except ImportError:  # the copy next to us is missing; still exercise with empty args
    def generate_args(schema):
        return {}

    def mine_examples(text, names):
        return {}

    def args_for_tool(name, schema, mined):
        return {}

BEGIN, END = "AGENTAVOW_TRANSCRIPT_BEGIN", "AGENTAVOW_TRANSCRIPT_END"
INIT_WAIT_MAX = 15.0  # seconds to wait for `initialize` before giving up on a candidate
PROTOCOLS = ("2025-06-18", "2024-11-05")
CLIENT_INFO = {"name": "agentavow-exerciser", "version": "1.0"}
DEFAULT_MOUNTS = "/tmp,/work,/run"
MAX_WALK_ENTRIES = 50_000
MAX_WRITES_PER_CALL = 50
SAMPLE_CHARS = 300
STDERR_TAIL = 500


class Options:
    def __init__(self) -> None:
        self.timeout = 60.0
        self.per_call_timeout = 8.0
        self.max_tools = 25
        self.readme: str | None = None
        self.canary_env: list[str] = []
        self.canary_value = ""
        self.mounts = DEFAULT_MOUNTS.split(",")
        self.gen_args: str | None = None
        self.command: list[str] = []


def parse_cli(argv: list[str]) -> Options:
    o = Options()
    if "--" in argv:
        split = argv.index("--")
        argv, o.command = argv[:split], argv[split + 1:]
    i = 0
    while i < len(argv):
        flag, val = argv[i], argv[i + 1] if i + 1 < len(argv) else ""
        if flag == "--timeout":
            o.timeout = float(val)
        elif flag == "--per-call-timeout":
            o.per_call_timeout = float(val)
        elif flag == "--max-tools":
            o.max_tools = int(val)
        elif flag == "--readme":
            o.readme = val
        elif flag == "--canary-env":
            o.canary_env = [n.strip() for n in val.split(",") if n.strip()]
        elif flag == "--canary-value":
            o.canary_value = val
        elif flag == "--mounts":
            o.mounts = [m.strip() for m in val.split(",") if m.strip()]
        elif flag == "--gen-args":
            o.gen_args = val
        else:
            i -= 1  # unknown flag: skip just the flag
        i += 2
    return o


def empty_transcript(command: list[str], canary_env: list[str]) -> dict:
    return {
        "version": 1,
        "launch": {"command": command, "ok": False, "error": None, "startup_ms": 0},
        "server_info": {"name": "", "version": ""},
        "protocol_version": "",
        "tools": [],
        "calls": [],
        "canary": {"env_names": list(canary_env), "seen_in_result": []},
        "timed_out": False,
        "error": None,
    }


def walk_mounts(mounts: list[str], exclude: set[str]) -> set[str]:
    """Every path (files and dirs) under the writable mounts; bounded, no symlink follow."""
    seen: set[str] = set()
    for mount in mounts:
        stack = [mount]
        while stack and len(seen) < MAX_WALK_ENTRIES:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        p = e.path
                        if p in exclude or any(p.startswith(x + os.sep) for x in exclude):
                            continue
                        seen.add(p)
                        try:
                            if e.is_dir(follow_symlinks=False):
                                stack.append(p)
                        except OSError:
                            pass
            except OSError:
                continue
    return seen


class StdioClient:
    """Newline-delimited JSON-RPC 2.0 over a child's stdin/stdout (MCP stdio transport)."""

    def __init__(self, command: list[str], env: dict) -> None:
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True, bufsize=0,
        )
        self.inbox: queue.Queue = queue.Queue()
        self.stderr_tail = ""
        self.next_id = 1
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self) -> None:
        for raw in self.proc.stdout:  # type: ignore[union-attr]
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("{"):
                continue  # servers log to stdout sometimes
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict):
                self.inbox.put(msg)

    def _pump_stderr(self) -> None:
        for raw in self.proc.stderr:  # type: ignore[union-attr]
            self.stderr_tail = (self.stderr_tail + raw.decode("utf-8", "replace"))[-STDERR_TAIL:]

    def alive(self) -> bool:
        return self.proc.poll() is None

    def send(self, msg: dict) -> bool:
        try:
            self.proc.stdin.write((json.dumps(msg, separators=(",", ":")) + "\n").encode())  # type: ignore[union-attr]
            self.proc.stdin.flush()  # type: ignore[union-attr]
            return True
        except (OSError, ValueError):
            return False

    def request(self, method: str, params: dict, timeout: float) -> tuple[dict | None, str | None]:
        """(result, None) on success; (None, error_code) on JSON-RPC error / timeout / exit."""
        rid = self.next_id
        self.next_id += 1
        if not self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}):
            return None, "server_exited"
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, "timeout"
            try:
                msg = self.inbox.get(timeout=min(0.1, remaining))
            except queue.Empty:
                if not self.alive() and self.inbox.empty():
                    return None, "server_exited"
                continue
            if "method" in msg:
                if msg.get("id") is not None:  # a server→client request we don't serve
                    self.send({"jsonrpc": "2.0", "id": msg["id"],
                               "error": {"code": -32601, "message": "not supported"}})
                continue
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                err = msg["error"]
                text = err.get("message") if isinstance(err, dict) else str(err)
                return None, f"rpc_error: {str(text)[:200]}"
            result = msg.get("result")
            return (result if isinstance(result, dict) else {}), None

    def kill(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        try:
            self.proc.kill()
        except OSError:
            pass


def result_text(result: dict) -> str:
    parts = [c.get("text") for c in (result.get("content") or [])
             if isinstance(c, dict) and isinstance(c.get("text"), str)]
    if parts:
        return "\n".join(parts)
    structured = result.get("structuredContent")
    return json.dumps(structured, sort_keys=True) if structured is not None else ""


def list_tools(client: StdioClient, deadline: float, per_call: float) -> tuple[list[dict], str | None]:
    tools: list[dict] = []
    cursor = None
    for _ in range(20):
        params = {"cursor": cursor} if cursor else {}
        result, err = client.request("tools/list", params,
                                     min(per_call, max(0.05, deadline - time.monotonic())))
        if err:
            return tools, err
        for t in result.get("tools") or []:
            if isinstance(t, dict) and isinstance(t.get("name"), str):
                tools.append(t)
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return tools, None


def exercise(o: Options, out: dict) -> None:
    """Fill ``out`` in place so a watchdog can print whatever was observed so far."""
    env = dict(os.environ)
    for name in o.canary_env:
        env[name] = o.canary_value
    started = time.monotonic()
    deadline = started + o.timeout
    try:
        client = StdioClient(o.command, env)
    except (OSError, ValueError) as e:
        out["launch"]["error"] = f"spawn_failed: {type(e).__name__}: {str(e)[:200]}"
        return
    out["_client"] = client
    try:
        # A server that will not initialize should fail fast: the in-container launcher may
        # try up to 3 candidate commands inside one wall clock.
        init_wait = min(max(o.timeout - 0.5, 0.5), INIT_WAIT_MAX)
        result = err = None
        for proto in PROTOCOLS:
            result, err = client.request("initialize", {
                "protocolVersion": proto, "capabilities": {}, "clientInfo": CLIENT_INFO,
            }, init_wait)
            if err is None or not err.startswith("rpc_error"):
                break
        if err:
            code = {"timeout": "initialize_timeout", "server_exited": "server_exited"}.get(
                err, f"initialize_error: {err}")
            tail = client.stderr_tail.strip()
            out["launch"]["error"] = f"{code}: {tail}" if tail else code
            out["timed_out"] = err == "timeout" and time.monotonic() >= deadline
            return
        out["launch"]["ok"] = True
        out["launch"]["startup_ms"] = int((time.monotonic() - started) * 1000)
        info = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
        out["server_info"] = {"name": str(info.get("name", ""))[:120],
                              "version": str(info.get("version", ""))[:40]}
        out["protocol_version"] = str(result.get("protocolVersion") or proto)[:40]
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        tools, err = list_tools(client, deadline, max(o.per_call_timeout, 5.0))
        out["tools"] = [{
            "name": t["name"], "description": str(t.get("description") or "")[:2000],
            "annotations": t.get("annotations") if isinstance(t.get("annotations"), dict) else None,
            "input_schema": t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else None,
        } for t in tools]
        if err:
            out["error"] = f"tools_list_failed: {err}"
            return

        mined: dict = {}
        if o.readme:
            try:
                with open(o.readme, encoding="utf-8", errors="replace") as fh:
                    mined = mine_examples(fh.read(400_000), [t["name"] for t in tools])
            except OSError:
                mined = {}
        exclude = {os.path.abspath(__file__), os.path.join(_HERE, "synthetic_args.py"),
                   os.path.join(_HERE, "__pycache__")}
        if o.readme:
            exclude.add(os.path.abspath(o.readme))
        for spec in out["tools"][:o.max_tools]:
            if time.monotonic() >= deadline:
                out["timed_out"] = True
                break
            if not client.alive():
                out["error"] = "server_exited"
                break
            call = call_tool(client, spec, o, mined, exclude, deadline,
                             out["canary"]["seen_in_result"])
            out["calls"].append(call)
            if call["error"] == "server_exited":
                out["error"] = "server_exited"
                break
    finally:
        out.pop("_client", None)
        client.kill()


def call_tool(client: StdioClient, spec: dict, o: Options, mined: dict,
              exclude: set[str], deadline: float, canary_seen: list[str]) -> dict:
    args = args_for_tool(spec["name"], spec.get("input_schema"), mined)
    before = walk_mounts(o.mounts, exclude)
    budget = min(o.per_call_timeout, max(0.05, deadline - time.monotonic()))
    t0 = time.monotonic()
    result, err = client.request("tools/call", {"name": spec["name"], "arguments": args}, budget)
    duration = int((time.monotonic() - t0) * 1000)
    writes = sorted(walk_mounts(o.mounts, exclude) - before)[:MAX_WRITES_PER_CALL]
    call = {"tool": spec["name"], "args": args, "ok": err is None, "error": None,
            "is_error": False, "duration_ms": duration, "fs_writes": writes,
            "result_sample": ""}
    if err:
        call["error"] = "call_timeout" if err == "timeout" else err
        return call
    text = result_text(result)
    call["is_error"] = bool(result.get("isError"))
    call["result_sample"] = text[:SAMPLE_CHARS]
    if o.canary_value and o.canary_value in text:
        # One canary value is shared by every name, so a sighting implicates all of them.
        for name in o.canary_env:
            if name not in canary_seen:
                canary_seen.append(name)
    return call


def emit(out: dict) -> None:
    doc = {k: v for k, v in out.items() if not k.startswith("_")}
    sys.stdout.write(f"\n{BEGIN}\n{json.dumps(doc)}\n{END}\n")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    o = parse_cli(argv)
    if o.gen_args:
        with open(o.gen_args, encoding="utf-8") as fh:
            print(json.dumps(generate_args(json.load(fh)), sort_keys=True))
        return 0
    out = empty_transcript(o.command, o.canary_env)
    emitted = threading.Event()

    def _watchdog() -> None:  # a blocking read or a stuck thread must not hang the run
        if not emitted.is_set():
            out["timed_out"] = True
            out["error"] = out.get("error") or "exerciser_watchdog"
            emit(out)
            client = out.get("_client")
            if client:
                client.kill()
            os._exit(0)

    threading.Timer(o.timeout + 10.0, _watchdog).start()
    try:
        if not o.command:
            out["launch"]["error"] = "no_command"
        else:
            exercise(o, out)
    except BaseException as e:  # noqa: BLE001 — the transcript is the only output that matters
        out["error"] = f"exerciser_crash: {type(e).__name__}: {str(e)[:200]}"
    emitted.set()
    emit(out)
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
