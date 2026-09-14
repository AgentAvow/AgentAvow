#!/usr/bin/env python3
"""AgentAvow SessionStart pre-check — OPT-IN, warn-only, fail-open.

Scans any HTTP(S) MCP server configured for Claude Code that hasn't been scanned
yet, and injects a one-line AgentAvow trust verdict into the session so you see it
BEFORE you rely on a newly added tool.

Design guarantees (deliberate):
  • OPT-IN — nothing runs unless YOU install this hook. AgentAvow's MCP server never
    forces a scan; that would be an injection vector and is not how this works.
  • WARN, never BLOCK — it only adds context. A low score never stops your session.
  • FAIL-OPEN — a network hiccup, an unknown config shape, anything unexpected: the
    hook stays silent and exits 0. It can never break session startup.

Install: see README.md in this directory.
"""
from __future__ import annotations

import json
import pathlib
import sys
import urllib.parse
import urllib.request

API = "https://agentavow.com/api/v1/public/scan/mcp"
CACHE = pathlib.Path.home() / ".cache" / "agentavow" / "scanned.json"
TIMEOUT = 8  # seconds per scan; short so startup is never held up


def _configured_http_mcp_endpoints() -> dict[str, str]:
    """Best-effort {name: url} of HTTP(S) MCP servers from Claude Code config.
    Config paths/shape vary by version, so this walks each file defensively and
    skips anything it doesn't recognize rather than raising."""
    endpoints: dict[str, str] = {}
    candidates = [
        pathlib.Path.home() / ".claude.json",
        pathlib.Path.cwd() / ".mcp.json",
        pathlib.Path.cwd() / ".claude" / "settings.json",
    ]
    for path in candidates:
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                servers = node.get("mcpServers")
                if isinstance(servers, dict):
                    for name, cfg in servers.items():
                        url = (cfg or {}).get("url") or (cfg or {}).get("endpoint")
                        if isinstance(url, str) and url.startswith("http"):
                            endpoints[name] = url
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, (dict, list)))
    return endpoints


def _load_cache() -> dict[str, str]:
    try:
        return json.loads(CACHE.read_text())
    except Exception:
        return {}


def _save_cache(cache: dict[str, str]) -> None:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(cache))
    except Exception:
        pass


def _scan(url: str) -> tuple[int, str, int]:
    """(score, verdict, blocking_count) for an MCP endpoint. Raises on failure."""
    query = urllib.parse.urlencode({"endpoint": url})
    req = urllib.request.Request(
        f"{API}?{query}", headers={"User-Agent": "agentavow-precheck"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https only)
        data = json.load(resp)
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    blocking = sum(1 for i in items if i.get("severity") in ("critical", "high"))
    verdict = "safe" if (score >= 81 and blocking == 0) else "needs review"
    return score, verdict, blocking


def main() -> None:
    try:
        json.load(sys.stdin)  # consume the SessionStart payload (unused); ignore errors
    except Exception:
        pass

    try:
        endpoints = _configured_http_mcp_endpoints()
    except Exception:
        return
    if not endpoints:
        return

    cache = _load_cache()
    lines: list[str] = []
    for name, url in endpoints.items():
        if cache.get(name) == url:  # already scanned this exact endpoint
            continue
        try:
            score, verdict, blocking = _scan(url)
        except Exception:
            continue  # fail-open: skip on any error
        cache[name] = url
        flag = "✅" if verdict == "safe" else "⚠️"
        extra = f", {blocking} blocking finding(s)" if blocking else ""
        lines.append(f"{flag} MCP '{name}' ({url}): AgentAvow {score}/100 — {verdict}{extra}.")

    _save_cache(cache)
    if not lines:
        return

    context = (
        "AgentAvow pre-check — new MCP servers scanned before you rely on them:\n"
        + "\n".join(lines)
        + "\nReview any ⚠️ before trusting it. Full reports: https://agentavow.com/check"
    )
    # SessionStart injects `additionalContext` into the session.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))


if __name__ == "__main__":
    main()
