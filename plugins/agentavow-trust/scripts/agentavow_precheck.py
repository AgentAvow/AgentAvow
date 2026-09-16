#!/usr/bin/env python3
"""AgentAvow SessionStart pre-check — OPT-IN, warn-only, fail-open.

Scans MCP servers configured for Claude Code that haven't been scanned yet and
injects a one-line AgentAvow trust verdict into the session, so you see it BEFORE
you rely on a newly added tool. Covers both:
  • Remote HTTP(S) MCP servers  -> scan_mcp_server (the live tool definitions).
  • Local stdio servers run from an npm or PyPI package (npx / uvx / pipx / bunx)
    -> scan_package on the resolved package coordinate.
Local servers that run a hand-written script (node foo.js, python foo.py) have no
published package to grade and are skipped.

Design guarantees (deliberate):
  • OPT-IN — nothing runs unless YOU install this hook. AgentAvow's MCP server never
    forces a scan; that would be an injection vector and is not how this works.
  • WARN, never BLOCK — it only adds context. A low score never stops your session.
  • FAIL-OPEN — a network hiccup, an unknown config shape, anything unexpected: the
    hook stays silent and exits 0. It can never break session startup.

Install / test: see README.md in this directory.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import urllib.parse
import urllib.request

API = "https://agentavow.com/api/v1/public/scan"
CACHE = pathlib.Path.home() / ".cache" / "agentavow" / "scanned.json"
TIMEOUT = 8  # seconds per scan; short so startup is never held up

# stdio runners we can map to a package registry. node/python/etc. are hand-written
# scripts with no published package to grade, so they're intentionally absent.
_NPM_RUNNERS = {"npx", "bunx", "pnpm-dlx"}
_PYPI_RUNNERS = {"uvx", "pipx"}


def _strip_npm_version(spec: str) -> str:
    """'@scope/name@1.2' -> '@scope/name'; 'name@1.2' -> 'name'."""
    if spec.startswith("@"):
        parts = spec.split("@")  # ['', 'scope/name', '1.2']
        return "@" + parts[1] if len(parts) >= 2 else spec
    return spec.split("@", 1)[0]


def _strip_pypi_version(spec: str) -> str:
    """'mcp-server-git==0.1' / 'pkg[extra]>=1' -> 'mcp-server-git' / 'pkg'."""
    return re.split(r"[=<>!~\[]", spec, 1)[0].strip()


def _pkg_from_args(args: list[str], flag_takes_pkg: tuple[str, ...]) -> str | None:
    """First real package token in a runner's args, honoring a 'flag then package'
    form (npx -p PKG, uvx --from PKG)."""
    want_next = False
    for a in args:
        if want_next:
            return a
        if a in flag_takes_pkg:
            want_next = True
            continue
        if a.startswith("-") or a in ("run", "--"):
            continue
        return a
    return None


def _resolve_target(name: str, cfg: dict) -> dict | None:
    """Classify one MCP server config into a scannable target, or None to skip."""
    url = cfg.get("url") or cfg.get("endpoint")
    if isinstance(url, str) and url.startswith("http"):
        return {"name": name, "kind": "mcp", "id": url, "url": url}

    cmd = cfg.get("command")
    if not isinstance(cmd, str):
        return None
    args = [a for a in (cfg.get("args") or []) if isinstance(a, str)]
    runner = os.path.basename(cmd)
    # `pnpm dlx x` arrives as command=pnpm, args=[dlx, x]
    if runner == "pnpm" and args[:1] == ["dlx"]:
        runner, args = "pnpm-dlx", args[1:]

    if runner in _NPM_RUNNERS:
        spec = _pkg_from_args(args, ("-p", "--package"))
        if spec:
            pkg = _strip_npm_version(spec)
            return {"name": name, "kind": "package", "registry": "npm",
                    "pkg": pkg, "id": f"npm:{pkg}"}
    elif runner in _PYPI_RUNNERS:
        spec = _pkg_from_args(args, ("--from",))
        if spec:
            pkg = _strip_pypi_version(spec)
            return {"name": name, "kind": "package", "registry": "pypi",
                    "pkg": pkg, "id": f"pypi:{pkg}"}
    return None


def _targets() -> list[dict]:
    """Best-effort scannable targets from Claude Code config files. Paths/shape vary
    by version, so each file is walked defensively and unknown shapes are skipped."""
    seen: dict[str, dict] = {}
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
                    for sname, cfg in servers.items():
                        if sname in seen or not isinstance(cfg, dict):
                            continue
                        t = _resolve_target(sname, cfg)
                        if t:
                            seen[sname] = t
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, (dict, list)))
    return list(seen.values())


def _verdict(data: dict) -> tuple[int, str, int]:
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    blocking = sum(1 for i in items if i.get("severity") in ("critical", "high"))
    return score, ("safe" if (score >= 81 and blocking == 0) else "needs review"), blocking


def _fetch(path: str, params: dict) -> dict:
    url = f"{API}{path}?{urllib.parse.urlencode(params)}" if params else f"{API}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "agentavow-precheck"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https only)
        return json.load(resp)


def _scan(target: dict) -> tuple[int, str, int]:
    if target["kind"] == "mcp":
        return _verdict(_fetch("/mcp", {"endpoint": target["url"]}))
    return _verdict(_fetch(f"/package/{target['registry']}/{target['pkg']}", {}))


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


def main() -> None:
    try:
        json.load(sys.stdin)  # consume the SessionStart payload (unused); ignore errors
    except Exception:
        pass

    try:
        targets = _targets()
    except Exception:
        return
    if not targets:
        return

    cache = _load_cache()
    lines: list[str] = []
    for t in targets:
        if cache.get(t["name"]) == t["id"]:  # already scanned this exact coordinate
            continue
        try:
            score, verdict, blocking = _scan(t)
        except Exception:
            continue  # fail-open
        cache[t["name"]] = t["id"]
        flag = "✅" if verdict == "safe" else "⚠️"
        extra = f", {blocking} blocking finding(s)" if blocking else ""
        coord = t["url"] if t["kind"] == "mcp" else f"{t['registry']}:{t['pkg']}"
        lines.append(f"{flag} MCP '{t['name']}' ({coord}): AgentAvow {score}/100 — "
                     f"{verdict}{extra}.")

    _save_cache(cache)
    if not lines:
        return

    context = (
        "AgentAvow pre-check — new MCP servers scanned before you rely on them:\n"
        + "\n".join(lines)
        + "\nReview any ⚠️ before trusting it. Full reports: https://agentavow.com/check"
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))


if __name__ == "__main__":
    main()
