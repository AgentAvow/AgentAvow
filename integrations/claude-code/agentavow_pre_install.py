#!/usr/bin/env python3
"""AgentAvow install-time check — grades an MCP server BEFORE it is added. Warn-only,
fail-open, deterministic.

The scan-before-connect skill asks Claude to scan a tool before installing it, but a
skill fires on intent and can be skipped. This PreToolUse hook does not depend on
intent: it watches the two ways an MCP server actually gets added in Claude Code —
a ``claude mcp add`` / ``claude mcp add-json`` command (Bash) and a write to a
``.mcp.json`` file (Write / Edit / MultiEdit) — grades the server through the public
scan API, and puts the verdict where the person sees it:

  • blocking findings (critical/high), or a blocked / restricted tier
                    -> permissionDecision "ask": Claude Code shows the verdict as the
                       reason and the person decides. The install is never denied.
  • everything else (safe; needs review with no blocking finding, e.g. thin
    coverage on a small server; not scannable)
                    -> a one-line systemMessage and the command proceeds as normal (the
                       hook never grants permission, so Claude Code's own prompt, if
                       any, still runs). A legitimate server with little to inspect
                       must not get the same prompt a poisoned one gets.
  • anything else   -> silent, exit 0 (fail-open). A hook bug can never block a command.

The graded server is written to the same cache the session-start hook reads, so it is
not reported a second time at the next session start. Reuses the precheck's target
resolution and scan code (same file, same directory) so the two never disagree.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import shlex
import sys
import time

__version__ = "0.1.18"

TIMEOUT = 12  # seconds per scan: an install is rare, so a slower fresh scan is fine
_HERE = pathlib.Path(__file__).resolve().parent


def _precheck():
    """The session-start hook's module (same directory), loaded by path so this works
    both as a plugin (scripts/) and as the manual copy (~/.claude/hooks/)."""
    spec = importlib.util.spec_from_file_location(
        "agentavow_precheck", _HERE / "agentavow_precheck.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    mod.TIMEOUT = TIMEOUT
    return mod


# --------------------------------------------------------------------------- #
# What is being added?
# --------------------------------------------------------------------------- #
_MCP_ADD = re.compile(r"\bclaude\s+mcp\s+add(?:-json)?\b")


def _server_from_mcp_add(command: str) -> tuple[str, dict] | None:
    """``claude mcp add [flags] <name> <url-or-command> [args…]`` or
    ``claude mcp add-json <name> '<json>'`` -> (name, config) in the mcpServers shape
    the precheck already understands. None when the command is something else."""
    m = _MCP_ADD.search(command)
    if not m:
        return None
    try:
        argv = shlex.split(command[m.start():])
    except ValueError:
        return None
    # argv = ['claude', 'mcp', 'add' | 'add-json', ...]
    rest = argv[3:]
    if argv[2] == "add-json":
        if len(rest) < 2:
            return None
        try:
            cfg = json.loads(rest[1])
        except ValueError:
            return None
        return (rest[0], cfg) if isinstance(cfg, dict) else None
    positional: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            positional.extend(rest[i + 1:])
            break
        if a.startswith("-"):
            # flags with a value: -s/--scope, -t/--transport, -e/--env, -H/--header
            if a in ("-s", "--scope", "-t", "--transport", "-e", "--env", "-H", "--header"):
                i += 2
                continue
            i += 1
            continue
        positional.append(a)
        i += 1
    if len(positional) < 2:
        return None
    name, head, *args = positional
    if head.startswith("http://") or head.startswith("https://"):
        return name, {"url": head}
    return name, {"command": head, "args": args}


def _servers_from_mcp_json(text: str) -> list[tuple[str, dict]]:
    """Every mcpServers entry in a (possibly partial) .mcp.json write. A partial edit
    that is not valid JSON on its own is wrapped and retried; unparseable -> []."""
    for candidate in (text, "{" + text + "}", "{" + text.rstrip().rstrip(",") + "}"):
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = data if all(isinstance(v, dict) and ("url" in v or "command" in v)
                                  for v in data.values()) and data else {}
        return [(k, v) for k, v in servers.items() if isinstance(v, dict)]
    return []


def _targets_for(payload: dict, pc) -> list[dict]:
    tool = str(payload.get("tool_name") or "")
    inp = payload.get("tool_input") or {}
    if not isinstance(inp, dict):
        return []
    found: list[tuple[str, dict]] = []
    if tool == "Bash":
        hit = _server_from_mcp_add(str(inp.get("command") or ""))
        if hit:
            found.append(hit)
    elif tool in ("Write", "Edit", "MultiEdit"):
        path = str(inp.get("file_path") or "")
        if not path.endswith(".mcp.json"):
            return []
        texts = [str(inp.get("content") or ""), str(inp.get("new_string") or "")]
        for e in inp.get("edits") or []:
            if isinstance(e, dict):
                texts.append(str(e.get("new_string") or ""))
        for t in texts:
            if t:
                found.extend(_servers_from_mcp_json(t))
    out: list[dict] = []
    for name, cfg in found:
        t = pc._resolve_target(name, cfg)
        if t and t.get("kind") in ("mcp", "package"):
            out.append(t)
    return out


# --------------------------------------------------------------------------- #
# Verdict -> what the person sees
# --------------------------------------------------------------------------- #
def _coord(t: dict) -> str:
    return t["url"] if t["kind"] == "mcp" else f"{t['registry']}:{t['pkg']}"


def _report_url(t: dict, pc) -> str:
    return pc._record(t, {"score": 0, "verdict": "", "blocking": 0, "tier": "", "grade": "",
                          "tool_digests": {}, "tool_manifest_digest": None, "sandbox": "",
                          "deprecated": False}, 0)["report_url"]


_ASK_TIERS = frozenset({"blocked", "restricted"})
_RESTRICTED_FLOOR = 31  # src/trust_tiers: restricted is 11-30, blocked 0-10


def _needs_decision(r: dict | None) -> bool:
    """Ask the person only when the grade carries real risk: a critical/high finding,
    or a blocked/restricted tier. A soft needs-review (no findings) and an
    unscannable target are reported, not prompted."""
    if r is None:
        return False
    if int(r.get("blocking") or 0) > 0:
        return True
    tier = str(r.get("tier") or "")
    if tier:
        return tier in _ASK_TIERS
    return int(r.get("score") or 0) < _RESTRICTED_FLOOR


def _line(t: dict, r: dict | None, pc) -> str:
    coord = _coord(t)
    if r is None:
        return (f"➖ MCP '{t['name']}' ({coord}): not scanned — AgentAvow couldn't read it "
                "(it may need sign-in). That is neither safe nor unsafe.")
    flag = "✅" if r["verdict"] == "safe" else "⚠️"
    extra = f", {r['blocking']} blocking finding(s)" if r["blocking"] else (
        "" if r["verdict"] == "safe" else ", no blocking findings")
    dep = "; DEPRECATED by its maintainer" if r.get("deprecated") else ""
    sandbox = f"; {r['sandbox']}" if r.get("sandbox") else ""
    return (f"{flag} MCP '{t['name']}' ({coord}): AgentAvow {r['score']}/100 — "
            f"{r['verdict']}{extra}{dep}{sandbox}. Report: {_report_url(t, pc)}")


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    if not isinstance(payload, dict) or payload.get("hook_event_name") not in (None, "PreToolUse"):
        return
    try:
        pc = _precheck()
        targets = _targets_for(payload, pc)
    except Exception:
        return
    if not targets:
        return

    cache = pc._load_cache()
    now = time.time()
    lines: list[str] = []
    needs_decision = False
    for t in targets[:3]:  # an install adds one server; cap the odd bulk edit
        try:
            r: dict | None = pc._scan(t)
        except pc._UnscannableError:
            r = None
        except Exception:
            continue  # transient: say nothing about this one (fail-open)
        lines.append(_line(t, r, pc))
        if r is None:
            cache[t["name"]] = {"id": t["id"], "retry_after": now + pc.RETRY_UNSCANNABLE}
        else:
            cache[t["name"]] = pc._record(t, r, now)
        needs_decision = needs_decision or _needs_decision(r)
    if not lines:
        return
    pc._save_cache(cache)

    body = "AgentAvow checked this before it is added:\n" + "\n".join(lines)
    out: dict = {
        "systemMessage": body,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": body + "\nTell the user this verdict in one line before "
                                        "you continue; they decide whether to proceed.",
        },
    }
    if needs_decision:
        out["hookSpecificOutput"]["permissionDecision"] = "ask"
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            body + "\nThis grade carries real risk. Continue anyway?")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
