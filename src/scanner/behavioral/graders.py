"""Deterministic graders: (BehavioralResult, ExerciseTranscript) → findings.

A grader is a pure function of the sandbox observation. Two runs with the same
BehavioralResult produce the same findings, in the same order — so a verdict is
recomputable from the stored result alone. Nothing here looks at the network, the clock,
or settings.

Rules (id → severity):
  ssrf_internal_fetch            followed a caller-supplied URL to a link-local  high
                                 sentinel (no target-IP validation; SSRF)
  behavioral_undeclared_egress   egress outside registries + declared hosts   high / critical
  annotation_readonly_violated   readOnlyHint=true tool wrote files           high
  annotation_open_world_violated every tool says openWorldHint=false, egress  medium
  credential_canary_exfiltrated  canary seen in DNS / plaintext HTTP          critical
  canary_echoed_in_result        canary env value returned in a tool result   medium
  tool_call_crashed_server       a tool call took the server down             low
  skill_script_egress            (skill plan) the ONE hook/script that ran    medium
                                 reached an undeclared host — named
  server_failed_to_start         no finding — surfaced via launch_ok/launch_error and
                                 classify_start() → (start_reason, start_reason_detail)
"""
from __future__ import annotations

import re
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
    """A cache write, not a modification: known cache paths, or any path under a
    directory whose NAME says cache (tiktoken's /tmp/data-gym-cache/<sha>, *-cache,
    .cache, cache_dir…). Validated 2026-10-02 on nia-mcp-server."""
    p = (path or "").replace("\\", "/")
    if any(marker in p for marker in _CACHE_LIKE):
        return True
    segments = [seg.lower() for seg in p.split("/") if seg]
    if not segments:
        return False
    *parents, last = segments
    # under a cache dir, or the cache dir itself (no extension); a FILE named 'cached…'
    # elsewhere is a real write
    return any("cache" in seg for seg in parents) or ("cache" in last and "." not in last)


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

# Cloud instance-metadata endpoints. Cloud SDKs (AWS, GCP, Azure) query them on their
# own when looking for credentials, so reaching one is normal for a cloud-backed tool;
# it is ALSO the classic credential-theft target. Reported as its own LOW, labelled
# note (no score effect), never as "undeclared egress".
CLOUD_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "169.254.170.2",
                        "metadata.google.internal", "metadata.goog", "metadata"}


def _is_cloud_metadata(host: str) -> bool:
    return (host or "").strip().lower().rstrip(".") in CLOUD_METADATA_HOSTS


def grade_cloud_metadata(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    hosts = sorted({h for h in (result.unexpected_egress or []) if _is_cloud_metadata(h)})
    if not hosts:
        return []
    return [_finding(
        "cloud_metadata_probe", category="data_handling",
        name="Contacted the cloud instance-metadata service",
        severity="low", evidence=f"egress to {', '.join(hosts)}",
        remediation=(
            "Normal for tools built on a cloud SDK (AWS/GCP/Azure look for credentials "
            "there by default). If this tool is not meant to use a cloud SDK, treat it as "
            "a red flag: metadata services hand out cloud credentials."
        ),
    )]


def grade_ssrf_internal_fetch(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    """A tool followed a caller-supplied URL to a link-local sentinel address: the server
    builds an outbound request from a URL the caller controls and does not validate where
    it resolves (CVE-2026-14540 and the JPMorgan/DINUM class). ``result.ssrf_hits`` is set
    only by the sandbox, which hands URL-taking tools the sentinel and watches the host-side
    capture for a connection to it. Attributed to a single tool when exactly one SSRF probe
    call ran; otherwise the tool is named only if unambiguous."""
    hits = [h for h in (getattr(result, "ssrf_hits", None) or []) if h]
    if not hits:
        return []
    probed = sorted({c.tool for c in transcript.calls if getattr(c, "ssrf_probe", False)})
    who = f"Tool '{probed[0]}'" if len(probed) == 1 else "A tool"
    where = ", ".join(sorted(set(hits))[:4])
    return [_finding(
        "ssrf_internal_fetch", category="data_handling",
        name=f"{who} followed a caller-supplied URL to an internal address",
        severity="high",
        evidence=f"the server connected to the link-local sentinel {where} after being "
                 f"handed it as a URL argument",
        remediation=(
            "The tool takes a URL from the caller and makes the request without checking "
            "where the address resolves, so an agent can steer it at cloud-metadata or "
            "internal services (server-side request forgery). Resolve the host first and "
            "reject private, link-local and metadata ranges; disable automatic redirects; "
            "and allowlist the destinations the tool legitimately needs."
        ),
    )]


def grade_undeclared_egress(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    hosts = sorted(set(h for h in (result.unexpected_egress or [])
                       if h and not _is_cloud_metadata(h)))
    if not hosts:
        return []
    shown = ", ".join(hosts[:8])
    return [_finding(
        "behavioral_undeclared_egress", category="exfiltration",
        name="Unexpected network egress during install/run",
        # Never critical by host COUNT: many undeclared hosts is not exfiltration (that is
        # what the canary detects). Validated 2026-10-02: nia-mcp-server hit 3 hosts
        # (its vendor, a tokenizer download, an API) and was capped at 45.
        severity="high",
        evidence=f"egress to {shown}",
        remediation=(
            "The tool contacted host(s) outside the package registry and its declared "
            "endpoints while installing/running in isolation. Review why it phones home; "
            "unexpected egress at install time is a common exfiltration pattern. Declare "
            "legitimate hosts in .agentavow.yml."
        ),
    )]


def _generated_name_prefixes(transcript: ExerciseTranscript) -> set[str]:
    """Prefixes of generated temp names seen across the whole run: when two or more writes
    share ``<prefix>-<tail>`` with different equal-length alnum tails (``/tmp/playwright-
    artifacts-cFaHfA``, ``…-bgcdef``), the name is generated, whatever one tail looks like.
    Deterministic over the transcript; complements the per-path test in ``_is_scratch``."""
    seen: dict[str, set[tuple[int, str]]] = {}
    for call in transcript.calls:
        for w in call.fs_writes:
            p = (w or "").replace("\\", "/").rstrip("/")
            if not p.startswith("/tmp/"):
                continue
            last = p.rsplit("/", 1)[-1]
            if "." in last:
                continue
            for sep in ("-", "_"):
                if sep in last:
                    prefix, tail = last.rsplit(sep, 1)
                    if len(tail) >= 4 and tail.isalnum():
                        key = p[: -len(last)] + prefix + sep
                        seen.setdefault(key, set()).add((len(tail), tail))
                    break
    out = set()
    for prefix, tails in seen.items():
        lengths = {n for n, _ in tails}
        if len(tails) >= 2 and len(lengths) == 1:
            out.add(prefix)
    return out


def grade_readonly_violated(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    """ONE finding per server naming every read-only-declared tool that wrote a real file.
    Scratch dirs and caches (a browser's per-call temp profile) are not modifications."""
    generated = _generated_name_prefixes(transcript)

    def _is_generated(path: str) -> bool:
        p = (path or "").replace("\\", "/").rstrip("/")
        return any(p.startswith(g) and "/" not in p[len(g):] for g in generated)

    violators: list[tuple[str, list[str]]] = []
    for tool in transcript.tools:
        if tool.hint("readOnlyHint") is not True:
            continue
        writes: list[str] = []
        for call in transcript.calls_for(tool.name):
            writes += [w for w in call.fs_writes
                       if w and not _is_cache_like(w) and not _is_scratch(w)
                       and not _is_generated(w)]
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


def _call_spawned(call) -> bool:
    """Did this entrypoint actually start a process? A call that never spawned (missing
    interpreter, spawn failure) cannot have produced egress."""
    err = (call.error or "")
    return bool(call.ok) or bool(err and not err.startswith(("spawn_failed", "missing_binary")))


def grade_skill_script_egress(result, transcript: ExerciseTranscript) -> list[BehavioralFinding]:
    """Skill plan only: name the bundled script / hook / server behind undeclared egress.
    Egress is captured run-wide (passively, on the host side of the bridge), so it is
    attributed ONLY when exactly one entrypoint ran — then it is that one's. With two or
    more, this grader stays silent (``behavioral_undeclared_egress`` still covers the run)
    rather than guess; the per-call attribution is a documented gap."""
    if str(getattr(result, "plan", "") or "") != "skill":
        return []
    hosts = sorted({h for h in (result.unexpected_egress or [])
                    if h and not _is_cloud_metadata(h)})
    if not hosts:
        return []
    ran = [c for c in transcript.calls if _call_spawned(c)]
    if len(ran) != 1:
        return []
    call = ran[0]
    kind = str((call.args or {}).get("kind") or "script")
    noun = {"hook": "lifecycle hook", "mcp": "bundled MCP server"}.get(kind, "bundled script")
    return [_finding(
        "skill_script_egress", category="exfiltration",
        name=f"{noun[0].upper() + noun[1:]} '{call.tool}' contacted undeclared host(s)",
        severity="medium",
        evidence=f"{call.tool} was the only entrypoint that ran; egress to "
                 + ", ".join(hosts[:8]),
        remediation=(
            "This skill entrypoint reached a host outside GitHub and the skill's declared "
            "scope while running with no arguments and canary credentials. A hook runs on "
            "every session without asking; review why it phones home, or declare the host "
            "in .agentavow.yml."
        ),
    )]


GRADERS: tuple[tuple[str, Callable[..., list[BehavioralFinding]]], ...] = (
    ("ssrf_internal_fetch", grade_ssrf_internal_fetch),
    ("behavioral_undeclared_egress", grade_undeclared_egress),
    ("annotation_readonly_violated", grade_readonly_violated),
    ("annotation_open_world_violated", grade_open_world_violated),
    ("credential_canary_exfiltrated", grade_canary_exfiltrated),
    ("canary_echoed_in_result", grade_canary_echoed),
    ("tool_call_crashed_server", grade_crashed_server),
    ("cloud_metadata_probe", grade_cloud_metadata),
    ("skill_script_egress", grade_skill_script_egress),
)


def _transcript_of(result) -> ExerciseTranscript:
    t = getattr(result, "transcript", None)
    return t if isinstance(t, ExerciseTranscript) else ExerciseTranscript()


# ── start-reason classifier ─────────────────────────────────────────────────────
#
# WHY a server did not start, as a fixed vocabulary the UI can render and the eval can
# count. Deterministic over (result, transcript); the order of the checks below IS the
# precedence. A non-started server never yields a finding — this only explains it.

START_REASONS = (
    "started", "needs_credentials", "needs_arguments", "missing_binary", "install_failed",
    "resource_limit", "no_entrypoint", "timeout", "crashed", "unknown",
)
_RESOURCE_LIMIT_EXIT = 137  # SIGKILL from the cgroup OOM killer / pids cap
_DETAIL_LIMIT = 160
# Plans that always exercise something (a transcript is expected), besides the MCP plans.
_EXERCISE_PLANS = ("docker", "skill")
# Strong credential vocabulary. "PAT" is case-sensitive and whole-word (it is inside
# "path" and "compatible"); "environment variable" alone is NOT enough — GitPython's
# missing-binary message mentions one — it only counts next to a credential-looking name.
_CRED_RE = re.compile(
    r"api[ _-]?key|token|secret|credential|password|passwd|(?<![A-Za-z])PAT(?![A-Za-z])",
)
_CRED_CI_RE = re.compile(_CRED_RE.pattern, re.IGNORECASE)
_ENV_VAR_RE = re.compile(r"env(ironment)?[ _-]?var(iable)?s?", re.IGNORECASE)
# A server that exits asking for a launch argument (a URL, path, connection string …).
# Searched anywhere in the error, not only at its start: the launcher prefixes it with
# ``server_exited:`` and stderr may carry a banner first. Real strings:
#   server-postgres  "Please provide a database URL as a command-line argument"
#   mcp-remote       "Usage: mcp-remote <https://server-url> [callback-port] [--debug]"
_ARGS_RE = re.compile(
    r"usage:|expected \d+ (positional )?arguments?|missing (required )?argument|"
    r"missing required|<[a-z:/_. -]*url[^>]*>|<url>|required argument|too few arguments|"
    r"the following arguments are required|as an? command[- ]line argument|"
    r"provide an? [\w ./-]{0,40}?(url|uri|path|argument|connection string|dsn|directory)\b|"
    r"requires? (a|an) [\w ./-]{0,40}?argument",
    re.IGNORECASE,
)
_BINARY_RE = re.compile(
    r"not found|executable|ENOENT|No such file|command not found|cannot find module|"
    r"cannot execute|not recognized as", re.IGNORECASE,
)
_PATH_RE = re.compile(r"(?<![\w:/])/[\w.@~-]+(?:/[\w.@~-]+)+")
_FRAME_PREFIXES = ("File \"", "at ", "Traceback (most recent call last)", "^")
_EXCEPTION_LINE_RE = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception|Warning|Exit|Interrupt)\b")


def _clean_detail(text: str, limit: int = _DETAIL_LIMIT) -> str:
    """A short, human excerpt of an error: stack frames and the traceback header dropped,
    absolute paths replaced by ``<path>``, whitespace collapsed, cut to ``limit``. For a
    Python traceback the last line (the exception) is the excerpt."""
    raw = (text or "").replace("\r", "\n")
    lines = [ln.strip() for ln in raw.split("\n")]
    lines = [ln for ln in lines if ln and not ln.startswith(_FRAME_PREFIXES)
             and not re.fullmatch(r"[~^|\s]+", ln)]
    if "Traceback (most recent call last)" in raw and lines:
        # keep the exerciser's own code prefix ("server_exited: ") in front of the
        # exception line; the transcript caps the error text, so the exception line may
        # be gone — then say so rather than quote a random frame.
        head = lines[0].split(":", 1)[0] if lines[0] and ":" in lines[0] else ""
        exc = [ln for ln in lines if _EXCEPTION_LINE_RE.match(ln)]
        last = exc[-1] if exc else "Python traceback (exception line truncated)"
        if head and head.replace("_", "").isalnum() and not last.startswith(head):
            lines = [head + ": " + last]
        else:
            lines = [last]
    out = " ".join(lines)
    out = _PATH_RE.sub("<path>", out)
    out = re.sub(r"\s+", " ", out).strip()
    if len(out) > limit:
        out = out[: limit - 1].rstrip() + "…"
    return out


def _looks_like_credential_error(text: str) -> bool:
    if not text:
        return False
    if _CRED_CI_RE.search(text):
        return True
    if _ENV_VAR_RE.search(text):
        from src.scanner.behavioral.env_reads import env_names_from_text
        return bool(env_names_from_text(text))
    return False


def classify_start(result, transcript: ExerciseTranscript | None = None) -> tuple[str, str]:
    """(reason, detail) for why the server did or did not start — see START_REASONS.

    Precedence: started → resource_limit (exit 137 / ``killed_resource_limit`` note) →
    timeout (wall clock hit with no transcript) → install_failed (no transcript, exit≠0)
    → no_entrypoint → needs_credentials → needs_arguments → missing_binary → timeout
    (initialize_timeout) → crashed (server_exited / spawn_failed / exerciser error) →
    unknown. ``detail`` is a ≤160-char cleaned excerpt of the underlying error."""
    t = transcript if isinstance(transcript, ExerciseTranscript) else _transcript_of(result)
    if t.launch_ok:
        return "started", ""
    plan = str(getattr(result, "plan", "") or "")
    if plan and not plan.endswith("-mcp") and plan not in _EXERCISE_PLANS and not t.present:
        # install/import plans never launch a server; "did it start" does not apply
        return "not_applicable", "install/import plan: no server is launched"
    exit_code = getattr(result, "exit_code", None)
    notes = [str(n) for n in (getattr(result, "notes", None) or [])]
    present = (t.present or bool(t.launch_error) or bool(t.launch_command))
    if exit_code == _RESOURCE_LIMIT_EXIT or "killed_resource_limit" in notes:
        return "resource_limit", (
            "container killed by the sandbox resource cap (memory / pids) before the "
            "server could be exercised")
    if not present:
        if getattr(result, "timed_out", False):
            return "timeout", "the run hit the sandbox wall clock before the server started"
        if isinstance(exit_code, int) and exit_code != 0:
            if plan == "skill":
                return "install_failed", f"clone step exited {exit_code}; nothing ran"
            return "install_failed", f"install step exited {exit_code}; no exercise ran"
        return "unknown", _clean_detail(getattr(result, "error", None) or "")
    err = t.launch_error or t.error or ""
    low = err.lower()
    if "no_entrypoint_found" in low:
        if plan == "skill":
            return "no_entrypoint", "the skill ships no lifecycle hook or runnable script"
        return "no_entrypoint", "the installed package exposes no runnable bin / console script"
    detail = _clean_detail(err)
    if _looks_like_credential_error(err):
        return "needs_credentials", detail
    if _ARGS_RE.search(err):
        return "needs_arguments", detail
    if _BINARY_RE.search(err):
        return "missing_binary", detail
    if low.startswith("initialize_timeout") or (t.timed_out and not t.launch_ok):
        return "timeout", detail
    if low.startswith(("server_exited", "spawn_failed", "initialize_error")) or t.error:
        return "crashed", detail
    return "unknown", detail


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
    reason, detail = classify_start(result, transcript)
    return {
        "ran": bool(getattr(result, "ran", False)),
        "plan": getattr(result, "plan", "") or "",
        "exercised": exercised,
        "launch_ok": transcript.launch_ok,
        "launch_error": transcript.launch_error,
        "server_failed_to_start": exercised and not transcript.launch_ok,
        "start_reason": reason,
        "start_reason_detail": detail,
        "tools_listed": len(transcript.tools),
        "tools_called": len({c.tool for c in calls}),
        "calls_total": len(calls),
        "calls_failed": sum(1 for c in calls if not c.ok or c.is_error),
        "egress_hosts": len(getattr(result, "egress_hosts", None) or []),
        "unexpected_egress": len(getattr(result, "unexpected_egress", None) or []),
        "canary_exfil": len(getattr(result, "canary_exfil", None) or []),
        "ssrf_hits": len(getattr(result, "ssrf_hits", None) or []),
        "findings": dict(by_sev, total=len(findings)),
        "rules": [f.rule for f in findings],
    }
