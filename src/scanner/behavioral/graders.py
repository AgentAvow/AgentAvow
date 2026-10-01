"""Deterministic graders: (BehavioralResult, ExerciseTranscript) → findings.

A grader is a pure function of the sandbox observation. Two runs with the same
BehavioralResult produce the same findings, in the same order — so a verdict is
recomputable from the stored result alone. Nothing here looks at the network, the clock,
or settings.

Rules (id → severity):
  behavioral_undeclared_egress   egress outside registries + declared hosts   high / critical
  annotation_readonly_violated   readOnlyHint=true tool wrote files           high
  annotation_open_world_violated every tool says openWorldHint=false, egress  medium
  credential_canary_exfiltrated  canary seen in DNS / plaintext HTTP          critical
  canary_echoed_in_result        canary env value returned in a tool result   medium
  tool_call_crashed_server       a tool call took the server down             low
  server_failed_to_start         no finding — surfaced via launch_ok/launch_error
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.scanner.behavioral.transcript import ExerciseTranscript
from src.scanner.scan import Finding

# Paths a read-only tool may legitimately touch (caches, bytecode) without "writing".
_CACHE_LIKE = ("/tmp/npm-", "__pycache__", "/.cache", "/.npm/", "/node_modules/.cache")
_CRASH_MARKERS = ("server exited", "broken pipe", "epipe", "connection reset")
_BEHAVIORAL_PATH = "<behavioral>"


@dataclass
class BehavioralFinding(Finding):
    """A :class:`Finding` that also names the grader rule that produced it."""
    rule: str = ""


def _finding(rule: str, *, category: str, name: str, severity: str, evidence: str,
             remediation: str) -> BehavioralFinding:
    return BehavioralFinding(
        category=category, name=name, severity=severity, file_path=_BEHAVIORAL_PATH,
        line_number=0, snippet=evidence[:300], remediation=remediation,
        reachability="direct", rule=rule,
    )


def _is_cache_like(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    return any(marker in p for marker in _CACHE_LIKE)


_SCRATCH_PREFIXES = ("/tmp/tmp", "/tmp/npm-", "/tmp/pip-", "/tmp/.", "/tmp/node-")


def _is_scratch(path: str) -> bool:
    """A tool's own throw-away temp area, not a modification of the user's environment:
    a randomly-suffixed directory under /tmp (``/tmp/playwright-artifacts-cFaHfA``), or a
    well-known temp/cache prefix. A NAMED file (``/tmp/agentavow-lie.txt``) is never scratch:
    the last segment has an extension or no random tail."""
    p = (path or "").replace("\\", "/").rstrip("/")
    if not p.startswith("/tmp/"):
        return False
    if p.startswith(_SCRATCH_PREFIXES):
        return True
    last = p.rsplit("/", 1)[-1]
    if "." in last:
        return False
    tail = last.rsplit("-", 1)[-1] if "-" in last else last.rsplit("_", 1)[-1]
    if len(tail) < 6 or not tail.isalnum() or tail == last:
        return False
    has_digit = any(c.isdigit() for c in tail)
    mixed = tail.lower() != tail and tail.upper() != tail
    return has_digit or mixed


# ── individual graders ──────────────────────────────────────────────────────────

def grade_undeclared_egress(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    hosts = sorted(set(h for h in (result.unexpected_egress or []) if h))
    if not hosts:
        return []
    shown = ", ".join(hosts[:8])
    return [_finding(
        "behavioral_undeclared_egress", category="exfiltration",
        name="Unexpected network egress during install/run",
        severity="high" if len(hosts) < 3 else "critical",
        evidence=f"egress to {shown}",
        remediation=(
            "The tool contacted host(s) outside the package registry and its declared "
            "endpoints while installing/running in isolation. Review why it phones home; "
            "unexpected egress at install time is a common exfiltration pattern. Declare "
            "legitimate hosts in .agentavow.yml."
        ),
    )]


def grade_readonly_violated(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    """ONE finding per server naming every read-only-declared tool that wrote a real file.
    Scratch dirs and caches (a browser's per-call temp profile) are not modifications."""
    violators: list[tuple[str, list[str]]] = []
    for tool in transcript.tools:
        if tool.hint("readOnlyHint") is not True:
            continue
        writes: list[str] = []
        for call in transcript.calls_for(tool.name):
            writes += [w for w in call.fs_writes
                       if w and not _is_cache_like(w) and not _is_scratch(w)]
        if writes:
            violators.append((tool.name, sorted(set(writes))))
    if not violators:
        return []
    names = [v[0] for v in violators]
    def _one(t: str, w: list[str]) -> str:
        more = f" (+{len(w) - 3} more)" if len(w) > 3 else ""
        return f"{t} wrote {', '.join(w[:3])}{more}"

    evidence = "; ".join(_one(t, w) for t, w in violators[:6])
    if len(violators) > 6:
        evidence += f"; +{len(violators) - 6} more tools"
    return [_finding(
        "annotation_readonly_violated", category="annotation_lie",
        name=(f"Tool '{names[0]}' declares readOnlyHint but wrote files" if len(names) == 1
              else f"{len(names)} tools declare readOnlyHint but wrote files: "
                   + ", ".join(names[:5]) + (", …" if len(names) > 5 else "")),
        severity="high",
        evidence=evidence,
        remediation=(
            "The tool's annotations promise it does not modify its environment, yet a "
            "call produced filesystem writes. Either drop readOnlyHint or stop writing; "
            "agents and gateways rely on this hint to skip confirmation prompts."
        ),
    )]


def grade_open_world_violated(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    if not transcript.tools or not result.unexpected_egress:
        return []
    if not all(t.hint("openWorldHint") is False for t in transcript.tools):
        return []
    hosts = ", ".join(sorted(set(result.unexpected_egress))[:8])
    return [_finding(
        "annotation_open_world_violated", category="annotation_lie",
        name="Every tool declares openWorldHint=false, yet the server reached the network",
        severity="medium",
        evidence=f"openWorldHint=false on {len(transcript.tools)} tool(s); egress to {hosts}",
        remediation=(
            "The server's tools all claim to be closed-world (no external entities), but "
            "the sandbox observed undeclared network egress. Set openWorldHint truthfully "
            "or declare the hosts in .agentavow.yml."
        ),
    )]


def grade_canary_exfiltrated(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    hits = [h for h in (getattr(result, "canary_exfil", None) or []) if isinstance(h, dict)]
    if not hits:
        return []
    seen: list[str] = []
    for h in hits:
        via = str(h.get("via") or "?")
        host = str(h.get("host") or "?")
        tag = f"{via}:{host}"
        if tag not in seen:
            seen.append(tag)
    return [_finding(
        "credential_canary_exfiltrated", category="exfiltration",
        name="Credential canary exfiltrated over the network",
        severity="critical",
        evidence="canary left the sandbox via " + ", ".join(seen[:6]),
        remediation=(
            "A secret placed in the server's environment was transmitted off-box over DNS "
            "or plaintext HTTP during the run. Treat as credential theft: do not connect "
            "this tool; revoke any secret it was ever given."
        ),
    )]


def grade_canary_echoed(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    names = [n for n in transcript.canary_seen_in_result if n]
    if not names:
        return []
    return [_finding(
        "canary_echoed_in_result", category="secret",
        name="Environment secret returned in tool output",
        severity="medium",
        evidence="tool result contained the value of " + ", ".join(sorted(set(names))[:6]),
        remediation=(
            "A tool result included the value of an environment variable the server reads. "
            "Model context is shared with every participant in a session; never echo "
            "secrets back in tool output."
        ),
    )]


def grade_crashed_server(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    crashed: list[str] = []
    for c in transcript.calls:
        err = (c.error or "").lower()
        if err and any(m in err for m in _CRASH_MARKERS):
            crashed.append(c.tool)
    if (transcript.error or "").lower() == "server_exited" and transcript.calls:
        last = transcript.calls[-1].tool
        if last not in crashed:
            crashed.append(last)
    if not crashed:
        return []
    uniq = sorted(set(crashed))
    return [_finding(
        "tool_call_crashed_server", category="robustness",
        name="A tool call crashed the server",
        severity="low",
        evidence="server exited during call(s) to " + ", ".join(uniq[:6]),
        remediation=(
            "Calling the tool with ordinary synthetic input took the whole server down. "
            "Validate inputs and return an MCP error (isError) instead of crashing; a crash "
            "drops every other tool in the session."
        ),
    )]


GRADERS: tuple[tuple[str, Callable[..., list[BehavioralFinding]]], ...] = (
    ("behavioral_undeclared_egress", grade_undeclared_egress),
    ("annotation_readonly_violated", grade_readonly_violated),
    ("annotation_open_world_violated", grade_open_world_violated),
    ("credential_canary_exfiltrated", grade_canary_exfiltrated),
    ("canary_echoed_in_result", grade_canary_echoed),
    ("tool_call_crashed_server", grade_crashed_server),
)


def _transcript_of(result) -> ExerciseTranscript:
    t = getattr(result, "transcript", None)
    return t if isinstance(t, ExerciseTranscript) else ExerciseTranscript()


def grade(result) -> list[BehavioralFinding]:
    """All findings for a sandbox result, in rule order. Empty when it didn't run."""
    if not getattr(result, "ran", False):
        return []
    transcript = _transcript_of(result)
    out: list[BehavioralFinding] = []
    for _rule, fn in GRADERS:
        try:
            out.extend(fn(result, transcript))
        except Exception:  # noqa: BLE001 — one broken grader must not hide the others
            continue
    return out


def grade_summary(result) -> dict:
    """Counts for the UI: what ran, what was called, what was found."""
    findings = grade(result)
    transcript = _transcript_of(result)
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in by_sev:
            by_sev[f.severity] += 1
    calls = transcript.calls
    # ``present`` (contract) ignores a launch that failed with only launch_error set;
    # a transcript that names a launch command or error was still an exercise attempt.
    exercised = (transcript.present or bool(transcript.launch_error)
                 or bool(transcript.launch_command))
    return {
        "ran": bool(getattr(result, "ran", False)),
        "plan": getattr(result, "plan", "") or "",
        "exercised": exercised,
        "launch_ok": transcript.launch_ok,
        "launch_error": transcript.launch_error,
        "server_failed_to_start": exercised and not transcript.launch_ok,
        "tools_listed": len(transcript.tools),
        "tools_called": len({c.tool for c in calls}),
        "calls_total": len(calls),
        "calls_failed": sum(1 for c in calls if not c.ok or c.is_error),
        "egress_hosts": len(getattr(result, "egress_hosts", None) or []),
        "unexpected_egress": len(getattr(result, "unexpected_egress", None) or []),
        "canary_exfil": len(getattr(result, "canary_exfil", None) or []),
        "findings": dict(by_sev, total=len(findings)),
        "rules": [f.rule for f in findings],
    }
