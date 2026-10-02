"""Opt-in live probe of an MCP server reached by URL — advisory, never scored.

A remote server is someone else's running system, so the static scan never calls its
tools. When a user explicitly asks (``?probe=true`` on the public scan, or the button on
the score page), this module calls **only** the tools whose annotations declare
``readOnlyHint: true`` (and not ``destructiveHint: true``), at most :data:`MAX_TOOLS` of
them, once each, with the same deterministic synthetic arguments the sandbox exerciser
uses, over the same Streamable-HTTP client (same headers, no credentials, SSRF-pinned).

What comes back is a block in the public ``behavioral`` shape with ``plan =
"live-probe"``. It is NOT a sandbox observation: nobody can reproduce a live server's
answers, so the block carries no attestation, every finding is tagged ``advisory``, and
``src.scanner.verdict`` / the MCP connector exclude it from the safe/needs-review call.

Graders (deterministic over the recorded responses):
  tool_result_injection         a tool RESULT carries prompt-injection text      high
  tool_result_secret_like       a tool RESULT carries a credential-looking value medium
  readonly_tool_errors_on_read  a read-only-annotated tool errored on synthetic  low
                                input (informational)
  needs_auth                    no finding — ``start_reason = needs_credentials``
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

PLAN = "live-probe"
MAX_TOOLS = 10
PER_CALL_TIMEOUT = 8.0
TOTAL_BUDGET = 55.0  # the router wraps the whole probe at 60 s; stop calling before that
_HANDSHAKE_TIMEOUT = 12.0
_SAMPLE_CHARS = 300
_SNIPPET_CHARS = 120
_NOTE = "live probe: only read-only-annotated tools were called; not reproducible; not scored"

_AUTH_STATUSES = (401, 403)


# ── tool selection ──────────────────────────────────────────────────────────────

def is_probe_eligible(tool: dict) -> bool:
    """Only a tool that declares itself read-only, and does not declare itself
    destructive, is ever called. A missing annotation is a "no"."""
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
        return False
    ann = tool.get("annotations")
    if not isinstance(ann, dict):
        return False
    return ann.get("readOnlyHint") is True and ann.get("destructiveHint") is not True


def select_tools(tools: list, max_tools: int = MAX_TOOLS) -> list[dict]:
    """The first ``max_tools`` eligible tools in listed order (deterministic)."""
    out: list[dict] = []
    seen: set[str] = set()
    for t in tools or []:
        if not is_probe_eligible(t) or t["name"] in seen:
            continue
        seen.add(t["name"])
        out.append(t)
        if len(out) >= max_tools:
            break
    return out


# ── graders ─────────────────────────────────────────────────────────────────────

def _finding(rule: str, *, category: str, name: str, severity: str, evidence: str,
             remediation: str, tool: str | None = None) -> dict:
    return {
        "rule": rule, "category": category, "name": name, "severity": severity,
        "evidence": evidence[:300], "remediation": remediation, "advisory": True,
        "tool": tool,
    }


def _snippet(text: str, limit: int = _SNIPPET_CHARS) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def _redact(value: str) -> str:
    v = str(value or "")
    return v[:4] + "…[redacted]" if len(v) > 4 else "[redacted]"


def grade_result_injection(calls: list[dict]) -> list[dict]:
    """A tool result containing prompt-injection / hidden-unicode text — the same
    detector the static scan runs over tool descriptions. One finding per tool."""
    from src.scanner.mcp_scan import _scan_text_for_injection
    out: list[dict] = []
    for c in calls:
        text = c.get("_result_text") or ""
        if not text:
            continue
        hits = _scan_text_for_injection(text, f"tool:{c['tool']}:result")
        if not hits:
            continue
        first = hits[0]
        snippet = _snippet(getattr(first, "snippet", "") or first.name)
        out.append(_finding(
            "tool_result_injection", category="prompt_injection",
            name=f"Tool '{c['tool']}' returned prompt-injection text ({first.name})",
            severity="high", tool=c["tool"],
            evidence=f"{c['tool']} result: \"{snippet}\"",
            remediation=(
                "The server's live output carried text addressed to the model rather than "
                "the user. An agent that reads this result can be steered; treat the "
                "server as untrusted input and keep its output out of the system prompt."
            ),
        ))
    return out


def grade_result_secret_like(calls: list[dict]) -> list[dict]:
    """A tool result containing something shaped like a credential (the static scan's
    secret patterns): the server hands config to any anonymous caller."""
    from src.scanner.patterns import SECRET_PATTERNS
    out: list[dict] = []
    for c in calls:
        text = c.get("_result_text") or ""
        if not text:
            continue
        for pname, pattern, _sev in SECRET_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            val = m.group(1) if m.groups() else m.group()
            out.append(_finding(
                "tool_result_secret_like", category="secret",
                name=f"Tool '{c['tool']}' returned a credential-looking value ({pname})",
                severity="medium", tool=c["tool"],
                evidence=f"{c['tool']} result contained {pname}: {_redact(val)}",
                remediation=(
                    "A synthetic, unauthenticated call got back a value that looks like a "
                    "secret. Scope tool output to the caller and never echo configuration "
                    "or tokens in results; model context is shared with every participant."
                ),
            ))
            break
    return out


def grade_readonly_errors(calls: list[dict]) -> list[dict]:
    """Read-only-annotated tools that answered synthetic input with ``isError``.
    Informational: it usually means the input did not fit, not that the tool is unsafe."""
    errored = sorted({c["tool"] for c in calls if c.get("ok") and c.get("is_error")})
    if not errored:
        return []
    return [_finding(
        "readonly_tool_errors_on_read", category="robustness",
        name=(f"{len(errored)} read-only tool{'' if len(errored) == 1 else 's'} returned "
              "an error for synthetic input"),
        severity="low",
        evidence="isError from " + ", ".join(errored[:8]),
        remediation=(
            "Informational. The tool rejected a generated argument set; check that its "
            "inputSchema describes what it actually needs so agents can call it."
        ),
    )]


def grade_probe(calls: list[dict]) -> list[dict]:
    """All advisory findings for a probe, in rule order. Pure over the recorded calls."""
    out: list[dict] = []
    for fn in (grade_result_injection, grade_result_secret_like, grade_readonly_errors):
        try:
            out.extend(fn(calls))
        except Exception:  # noqa: BLE001 — one broken grader must not hide the others
            continue
    return out


# ── block assembly ──────────────────────────────────────────────────────────────

def _public_call(c: dict) -> dict:
    return {
        "tool": c["tool"], "ok": bool(c.get("ok")), "is_error": bool(c.get("is_error")),
        "duration_ms": int(c.get("duration_ms") or 0), "error": c.get("error"),
        "result_sample": (c.get("_result_text") or "")[:_SAMPLE_CHARS],
        "fs_writes": [],
    }


def _summary(findings: list[dict], *, launch_ok: bool, start_reason: str, detail: str,
             tools_listed: int, eligible: int, calls: list[dict], timed_out: bool) -> dict:
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.get("severity") in by_sev:
            by_sev[f["severity"]] += 1
    return {
        "ran": True, "plan": PLAN, "advisory": True,
        "exercised": launch_ok,
        "launch_ok": launch_ok,
        "launch_error": None if launch_ok else (detail or start_reason),
        "server_failed_to_start": not launch_ok,
        "start_reason": start_reason, "start_reason_detail": detail,
        "tools_listed": tools_listed, "tools_eligible": eligible,
        "tools_called": len({c["tool"] for c in calls}),
        "calls_total": len(calls),
        "calls_failed": sum(1 for c in calls if not c.get("ok") or c.get("is_error")),
        "timed_out": timed_out,
        "egress_hosts": 0, "unexpected_egress": 0, "canary_exfil": 0,
        "findings": dict(by_sev, total=len(findings)),
        "rules": [f["rule"] for f in findings],
    }


def build_block(*, server_info: dict, tools: list, eligible: list[dict], calls: list[dict],
                launch_ok: bool, start_reason: str, detail: str = "",
                timed_out: bool = False, notes: list[str] | None = None) -> dict:
    """The public ``behavioral`` block for a probe (pure; used by the tests too)."""
    findings = grade_probe(calls) if launch_ok else []
    listed = [t for t in (tools or []) if isinstance(t, dict)]
    return {
        "ran": True, "plan": PLAN, "pending": False, "advisory": True,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "exercise": {
            "launch_ok": launch_ok,
            "server": {"name": str((server_info or {}).get("name") or ""),
                       "version": str((server_info or {}).get("version") or "")},
            "tools": [{"name": str(t.get("name") or ""),
                       "annotations": t.get("annotations") if isinstance(
                           t.get("annotations"), dict) else {}} for t in listed],
            "eligible": [t["name"] for t in eligible],
            "calls": [_public_call(c) for c in calls],
            "canary": {"env_names": [], "seen_in_result": []},
            "timed_out": timed_out,
            "error": None if launch_ok else (detail or start_reason),
        },
        "findings": findings,
        "grade_summary": _summary(
            findings, launch_ok=launch_ok, start_reason=start_reason, detail=detail,
            tools_listed=len(listed), eligible=len(eligible), calls=calls,
            timed_out=timed_out),
        "notes": [_NOTE] + list(notes or []),
        "egress_hosts": [], "unexpected_egress": [], "vendor_egress": [],
        "declared_egress": [], "fs_writes_sample": [], "canary_exfil": [],
        "timed_out": timed_out, "error": None,
        "attestation": None,
    }


def not_run(reason: str) -> dict:
    return {"ran": False, "plan": PLAN, "pending": False, "advisory": True,
            "reason": reason, "findings": [], "notes": [_NOTE], "attestation": None}


# ── the probe ───────────────────────────────────────────────────────────────────

async def probe_live_mcp(
    endpoint_url: str, *, max_tools: int = MAX_TOOLS, per_call_timeout: float = PER_CALL_TIMEOUT,
    total_budget: float = TOTAL_BUDGET,
) -> dict:
    """Handshake ``endpoint_url`` and call its read-only-annotated tools once each.
    Fail-open: every failure is reported inside the block; never raises."""
    try:
        return await _probe(endpoint_url, max_tools=max_tools,
                            per_call_timeout=per_call_timeout, total_budget=total_budget)
    except Exception as exc:  # noqa: BLE001 — a probe must never take the scan down
        return not_run(f"live probe error: {exc.__class__.__name__}")


async def _probe(endpoint_url: str, *, max_tools: int, per_call_timeout: float,
                 total_budget: float) -> dict:
    from src.scanner.behavioral.synthetic_args import args_for_tool
    from src.scanner.mcp_scan import McpSession, mcp_result_text
    from src.ssrf import ssrf_safe_async_client, validate_url_https

    try:
        url = validate_url_https(endpoint_url, field_name="endpoint")
    except Exception:
        return not_run("endpoint must be a valid https:// URL")

    t_start = time.monotonic()
    async with ssrf_safe_async_client(timeout=_HANDSHAKE_TIMEOUT,
                                      follow_redirects=False) as client:
        session = McpSession(client, url)
        try:
            status = await asyncio.wait_for(session.initialize(), timeout=_HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            return build_block(server_info={}, tools=[], eligible=[], calls=[],
                               launch_ok=False, start_reason="timeout",
                               detail="initialize did not answer in time")
        if status in _AUTH_STATUSES:
            return build_block(
                server_info={}, tools=[], eligible=[], calls=[], launch_ok=False,
                start_reason="needs_credentials",
                detail=f"initialize answered HTTP {status}; nothing was called",
                notes=["needs_auth: the server requires credentials; no tool was called"])
        if status == 0 or status >= 400:
            detail = f"initialize answered HTTP {status}" if status else "transport error"
            return build_block(server_info={}, tools=[], eligible=[], calls=[],
                               launch_ok=False, start_reason="unknown", detail=detail)

        tools = [t for t in await session.list("tools/list", "tools") if isinstance(t, dict)]
        eligible = select_tools(tools, max_tools)
        calls: list[dict] = []
        timed_out = False
        for t in eligible:
            if time.monotonic() - t_start > total_budget:
                timed_out = True
                break
            name = t["name"]
            schema = t.get("inputSchema") or t.get("input_schema") or {}
            args = args_for_tool(name, schema if isinstance(schema, dict) else None, None)
            t0 = time.monotonic()
            res = await session.call_tool(name, args, timeout=per_call_timeout)
            call = {
                "tool": name, "args": args, "ok": res["ok"], "is_error": res["is_error"],
                "error": res["error"], "duration_ms": int((time.monotonic() - t0) * 1000),
                "_result_text": mcp_result_text(res.get("result")) if res["ok"] else "",
            }
            calls.append(call)
        return build_block(server_info=session.server_info, tools=tools, eligible=eligible,
                           calls=calls, launch_ok=True, start_reason="started",
                           timed_out=timed_out)


def cache_key(endpoint_url: str) -> str:
    """``behavioral:mcp:<sha256(endpoint)>:live-probe``."""
    import hashlib
    digest = hashlib.sha256(str(endpoint_url).encode("utf-8")).hexdigest()
    return f"behavioral:mcp:{digest}:{PLAN}"
