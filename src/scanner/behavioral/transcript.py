"""Exercise transcript — the contract between the in-sandbox MCP exerciser and the graders.

The exerciser (``scripts/sandbox/mcp_exercise.py`` / ``mcp_exercise.js``) runs INSIDE the
gVisor container, launches the target MCP server over stdio, sends ``initialize`` +
``tools/list``, calls every tool with deterministic synthetic arguments, and prints ONE
JSON document between the markers below on stdout. The sandbox runner script forwards
that document verbatim in its ``exercise`` field; ``runner.py`` parses it into
:class:`ExerciseTranscript`; ``graders.py`` turns it into findings.

Everything here is observed fact, never judgement: graders are the only place that
decides what a transcript means, and they are deterministic so a verdict is
recomputable from the transcript alone.

Markers (exact, on their own line):
    AGENTAVOW_TRANSCRIPT_BEGIN
    {...one JSON object...}
    AGENTAVOW_TRANSCRIPT_END

JSON shape (version 1):
    {
      "version": 1,
      "launch": {"command": ["npx", "-y", "pkg"], "ok": true, "error": null,
                 "startup_ms": 812},
      "server_info": {"name": "...", "version": "..."},          # from initialize
      "protocol_version": "2025-06-18",
      "tools": [ {"name": "...", "description": "...",
                  "annotations": {"readOnlyHint": true, ...} | null,
                  "input_schema": {...} | null} ],
      "calls": [ {"tool": "...", "args": {...}, "ok": true, "error": null,
                  "is_error": false,                               # MCP isError flag
                  "duration_ms": 120,
                  "fs_writes": ["/tmp/x"],                         # NEW paths under the
                                                                  # writable mounts, per call
                  "result_sample": "first 300 chars of text content"} ],
      "canary": {"env_names": ["GITHUB_TOKEN"], "seen_in_result": ["GITHUB_TOKEN"]},
      "timed_out": false,                                            # global wall clock hit
      "error": null
    }

Value vocabularies (set by the exerciser, matched by the graders):
  call.ok          a JSON-RPC *result* arrived (transport level), independent of is_error
  call.error       "call_timeout" | "server_exited" | "rpc_error: <msg>"
  error            "server_exited" | "tools_list_failed: …" | "exerciser_crash: …"
                   | "exerciser_watchdog"
  launch.error     "spawn_failed: …" | "initialize_timeout" | "server_exited"
                   | "initialize_error: …" | "no_command"   (each may end ": <stderr tail>")
                   | "no_entrypoint_found"  (synthetic transcript from the in-container
                   launcher mcp_launch.sh: the installed package exposes no runnable bin /
                   console script; error is set to the same value — "no bin", not "crashed")
  canary.seen_in_result lists EVERY injected name on a sighting (one shared canary value),
                   so read it as "a canary leaked", not "this exact variable leaked".
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

TRANSCRIPT_BEGIN = "AGENTAVOW_TRANSCRIPT_BEGIN"
TRANSCRIPT_END = "AGENTAVOW_TRANSCRIPT_END"
TRANSCRIPT_VERSION = 1

# Env var names the exerciser fills with a canary value when a tool reads them (names
# come from the static scan of the package: process.env.X / os.environ["X"]). The value
# is ``agentavow-canary-<run id>``; a DNS query or plaintext HTTP body carrying it is
# credential exfiltration, graded critical.
CANARY_PREFIX = "agentavow-canary-"

# Writable mounts inside the sandbox container (root is read-only). The exerciser diffs
# these before/after each call to attribute filesystem writes per tool.
WRITABLE_MOUNTS = ("/tmp", "/work", "/run")


@dataclass
class ToolSpec:
    name: str
    description: str = ""
    annotations: dict | None = None
    input_schema: dict | None = None

    def hint(self, key: str) -> bool | None:
        """A declared annotation hint (``readOnlyHint`` …) or None when not declared."""
        if not isinstance(self.annotations, dict):
            return None
        v = self.annotations.get(key)
        return v if isinstance(v, bool) else None


@dataclass
class ToolCall:
    tool: str
    args: dict = field(default_factory=dict)
    ok: bool = False
    is_error: bool = False
    error: str | None = None
    duration_ms: int = 0
    fs_writes: list[str] = field(default_factory=list)
    result_sample: str = ""


@dataclass
class ExerciseTranscript:
    launch_ok: bool = False
    launch_command: list[str] = field(default_factory=list)
    launch_error: str | None = None
    startup_ms: int = 0
    server_name: str = ""
    server_version: str = ""
    protocol_version: str = ""
    tools: list[ToolSpec] = field(default_factory=list)
    calls: list[ToolCall] = field(default_factory=list)
    canary_env_names: list[str] = field(default_factory=list)
    canary_seen_in_result: list[str] = field(default_factory=list)
    timed_out: bool = False
    error: str | None = None

    @property
    def present(self) -> bool:
        """True when the exerciser actually ran and reported something — a launch that
        failed (``launch_error`` set) is still a present, meaningful transcript."""
        return (self.launch_ok or bool(self.tools) or bool(self.error)
                or bool(self.launch_error))

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)

    def calls_for(self, name: str) -> list[ToolCall]:
        return [c for c in self.calls if c.tool == name]

    def to_public_dict(self) -> dict:
        return {
            "launch_ok": self.launch_ok,
            "server": {"name": self.server_name, "version": self.server_version},
            "protocol_version": self.protocol_version,
            "tools": [
                {"name": t.name, "annotations": t.annotations or {}} for t in self.tools
            ],
            "calls": [
                {"tool": c.tool, "ok": c.ok, "is_error": c.is_error,
                 "duration_ms": c.duration_ms, "fs_writes": c.fs_writes[:10],
                 "error": c.error}
                for c in self.calls
            ],
            "canary": {"env_names": self.canary_env_names,
                       "seen_in_result": self.canary_seen_in_result},
            "timed_out": self.timed_out,
            "error": self.error,
        }


def extract_transcript_json(stdout_text: str | None) -> str | None:
    """The JSON document between the markers, or None if absent/unterminated."""
    if not stdout_text:
        return None
    start = stdout_text.find(TRANSCRIPT_BEGIN)
    end = stdout_text.find(TRANSCRIPT_END, start + len(TRANSCRIPT_BEGIN)) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    return stdout_text[start + len(TRANSCRIPT_BEGIN):end].strip()


def parse_transcript(doc: str | dict | None) -> ExerciseTranscript:
    """Parse the exerciser's JSON (string or already-decoded). Malformed → an empty
    transcript with ``error`` set; never raises, so a broken exerciser fails open."""
    if doc is None:
        return ExerciseTranscript()
    try:
        data = json.loads(doc) if isinstance(doc, str) else doc
    except Exception as e:  # noqa: BLE001
        return ExerciseTranscript(error=f"transcript_unparseable: {e.__class__.__name__}")
    if not isinstance(data, dict):
        return ExerciseTranscript(error="transcript_not_an_object")

    def _s(v: object, limit: int = 300) -> str:
        return str(v)[:limit] if isinstance(v, (str, int, float)) else ""

    def _d(v: object) -> dict | None:
        return v if isinstance(v, dict) else None

    def _i(v: object) -> int:
        return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0

    def _strs(v: object, limit: int = 200) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x) for x in v if isinstance(x, str)][:limit]

    launch = _d(data.get("launch")) or {}
    info = _d(data.get("server_info")) or {}
    canary = _d(data.get("canary")) or {}
    tools: list[ToolSpec] = []
    for t in data.get("tools") or []:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            tools.append(ToolSpec(
                name=t["name"], description=_s(t.get("description"), 2000),
                annotations=_d(t.get("annotations")), input_schema=_d(t.get("input_schema")),
            ))
    calls: list[ToolCall] = []
    for c in data.get("calls") or []:
        if isinstance(c, dict) and isinstance(c.get("tool"), str):
            calls.append(ToolCall(
                tool=c["tool"], args=_d(c.get("args")) or {},
                ok=bool(c.get("ok")), is_error=bool(c.get("is_error")),
                error=_s(c.get("error")) or None, duration_ms=_i(c.get("duration_ms")),
                fs_writes=_strs(c.get("fs_writes")), result_sample=_s(c.get("result_sample")),
            ))
    return ExerciseTranscript(
        launch_ok=bool(launch.get("ok")),
        launch_command=_strs(launch.get("command"), 32),
        launch_error=_s(launch.get("error")) or None,
        startup_ms=_i(launch.get("startup_ms")),
        server_name=_s(info.get("name"), 120), server_version=_s(info.get("version"), 40),
        protocol_version=_s(data.get("protocol_version"), 40),
        tools=tools, calls=calls,
        canary_env_names=_strs(canary.get("env_names"), 64),
        canary_seen_in_result=_strs(canary.get("seen_in_result"), 64),
        timed_out=bool(data.get("timed_out")),
        error=_s(data.get("error")) or None,
    )
