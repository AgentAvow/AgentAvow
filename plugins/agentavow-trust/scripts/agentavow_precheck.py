#!/usr/bin/env python3
"""AgentAvow SessionStart pre-check — OPT-IN, warn-only, fail-open.

Scans MCP servers configured for Claude Code that haven't been scanned yet and
injects a one-line AgentAvow trust verdict into the session, so you see it BEFORE
you rely on a newly added tool. Covers both:
  • Remote HTTP(S) MCP servers  -> scan_mcp_server (the live tool definitions).
  • Local stdio servers run from an npm or PyPI package (npx / uvx / pipx / bunx)
    -> scan_package on the resolved package coordinate.
Local servers that run a hand-written script (node foo.js, python foo.py) have no
published package to grade and are skipped. So are MCP URLs on localhost or a
private network: AgentAvow can't reach them, so they never leave your machine.
A URL whose path looks like it carries a secret (a long token or a UUID) is not
sent either; it is reported as not scanned.
The first time there is nothing to scan at all, the hook shows one line saying so
(and how to scan a tool on demand), then never repeats it. That line makes no request.
Each verdict (score, tier, grade, the signed per-tool digests) is kept in the cache
file so the per-call gate (agentavow_pretool_gate.py) can act on it without a request.
A server whose tool definitions the gate saw change since the grade is re-graded here
at the next session start, and reported again.

Design guarantees (deliberate):
  • OPT-IN — nothing runs unless YOU install this hook. AgentAvow's MCP server never
    forces a scan; that would be an injection vector and is not how this works.
  • WARN, never BLOCK — it only adds context. A low score never stops your session.
  • FAIL-OPEN — a network hiccup, an unknown config shape, anything unexpected: the
    hook stays silent and exits 0. It can never break session startup.

Install / test: https://agentavow.com/docs/auto-scan-claude-code
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.6"

API = "https://agentavow.com/api/v1/public/scan"
WEB = "https://agentavow.com"
CACHE = pathlib.Path.home() / ".cache" / "agentavow" / "scanned.json"
TIMEOUT = 8  # seconds per scan; short so startup is never held up
BUDGET = 20  # seconds for the whole run; stays inside the hook's 30s timeout
RETRY_UNSCANNABLE = 7 * 24 * 3600  # re-try a server the API refused after a week
META_KEY = "_agentavow"  # cache entry holding hook state; never treated as a server name

# stdio runners we can map to a package registry. node/python/etc. are hand-written
# scripts with no published package to grade, so they're intentionally absent.
_NPM_RUNNERS = {"npx", "bunx", "pnpm-dlx"}
_PYPI_RUNNERS = {"uvx", "pipx"}


class _UnscannableError(Exception):
    """The API refused this target (needs sign-in, not publicly reachable, unknown
    coordinate). Retrying every session can't change that, so it is cached."""


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


def _sanitize_url(url: str) -> str:
    """Strip any embedded credential (user:pass@) and the query/fragment before a URL
    leaves the machine. A scan needs only scheme+host+path, never a '?token=' or a
    'user:pass@' a server config might carry, so the precheck can't forward a secret
    to the scan API."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        return urllib.parse.urlunsplit((p.scheme, host, p.path, "", ""))
    except Exception:
        return url.split("?", 1)[0].split("#", 1)[0]


def _is_local_host(url: str) -> bool:
    """True for a URL AgentAvow could never reach from outside: localhost, a
    single-label or .local/.internal name, or a loopback/private/link-local IP.
    Unparseable URLs count as local, so they are skipped rather than sent."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except Exception:
        return True
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return (
            "." not in host
            or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa"))
        )
    return not ip.is_global


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _has_secret_path(url: str) -> bool:
    """True when a URL path segment looks like a credential rather than a route: a
    UUID, a 32+ character unbroken run, or a 16+ character run mixing letters with
    several digits. Some hosted MCP servers put the user's key in the path, and a
    path is sent as-is, so these are withheld. Words, versions and dates (split on
    - _ . ~) pass."""
    try:
        path = urllib.parse.unquote(urllib.parse.urlsplit(url).path)
    except Exception:
        return True
    for segment in path.split("/"):
        if _UUID.search(segment):
            return True
        for run in re.split(r"[-_.~]", segment):
            if len(run) >= 32 and run.isalnum():
                return True
            if (len(run) >= 16 and re.search(r"[A-Za-z]", run)
                    and len(re.findall(r"\d", run)) >= 3):
                return True
    return False


def _resolve_target(name: str, cfg: dict) -> dict | None:
    """Classify one MCP server config into a scannable target, or None to skip."""
    url = cfg.get("url") or cfg.get("endpoint")
    if isinstance(url, str) and url.startswith("http"):
        if _is_local_host(url):
            return None
        safe = _sanitize_url(url)
        if _has_secret_path(safe):
            host = urllib.parse.urlsplit(safe).hostname or ""
            return {"name": name, "kind": "withheld", "id": f"withheld:{host}", "host": host}
        return {"name": name, "kind": "mcp", "id": safe, "url": safe}

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
                        if sname in seen or sname == META_KEY or not isinstance(cfg, dict):
                            continue
                        t = _resolve_target(sname, cfg)
                        if t:
                            seen[sname] = t
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, (dict, list)))
    return list(seen.values())


def _verdict(data: dict) -> dict:
    """The parts of a scan response the hook reports and the gate acts on."""
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    blocking = sum(1 for i in items if i.get("severity") in ("critical", "high"))
    digests = data.get("tool_digests")
    return {
        "score": score,
        "verdict": "safe" if (score >= 81 and blocking == 0) else "needs review",
        "blocking": blocking,
        "tier": str(data.get("trust_tier") or ""),
        "grade": str(data.get("grade") or ""),
        "tool_digests": digests if isinstance(digests, dict) else {},
        "tool_manifest_digest": data.get("tool_manifest_digest") or None,
        "sandbox": _sandbox_summary(data.get("behavioral")),
    }


def _sandbox_summary(b: object) -> str:
    """One clause about the behavioral sandbox run AgentAvow did on the package (it runs
    automatically on the first scan and is cached for a day): what it found, or that it
    is still running. Empty when there is nothing to say. Read-only; no extra request."""
    if not isinstance(b, dict):
        return ""
    if b.get("pending"):
        return "sandbox run pending"
    if not b.get("ran"):
        return ""
    findings = [f for f in (b.get("findings") or []) if isinstance(f, dict)]
    ex = b.get("exercise") if isinstance(b.get("exercise"), dict) else {}
    called = len(ex.get("calls") or []) if ex else 0
    exfil = b.get("canary_exfil") or []
    if exfil:
        return "sandbox: LEAKED a canary credential"
    if findings:
        worst = "critical" if any(f.get("severity") == "critical" for f in findings) else (
            "high" if any(f.get("severity") == "high" for f in findings) else "")
        sev = f" ({worst})" if worst else ""
        return f"sandbox: {len(findings)} behavioral finding(s){sev}"
    if ex and ex.get("launch_ok"):
        return f"sandbox: clean, {called} tool(s) exercised"
    reason = str((b.get("grade_summary") or {}).get("start_reason") or "")
    if reason and reason not in ("started", "not_applicable", "unknown"):
        return f"sandbox: install clean; server not exercised ({reason.replace('_', ' ')})"
    return "sandbox: clean"


def _record(target: dict, result: dict, now: float) -> dict:
    """The cache entry for a graded server: the target's identity (name is the key,
    id is the sanitized URL or package coordinate), the verdict, the signed per-tool
    digests, the report link, and when it was approved. The gate reads this."""
    rec = {"id": target["id"], "kind": target["kind"], "approved_at": now}
    if target["kind"] == "mcp":
        rec["url"] = target["url"]
        rec["report_url"] = (
            f"{WEB}/check/mcp?endpoint={urllib.parse.quote(target['url'], safe='')}")
    else:
        rec["registry"] = target["registry"]
        rec["pkg"] = target["pkg"]
        rec["report_url"] = f"{WEB}/check/pkg/{target['registry']}/{target['pkg']}"
        result = dict(result, tool_digests={}, tool_manifest_digest=None)  # not live-served
    rec.update(result)
    return rec


def _drifted(entry: dict) -> bool:
    """True when the gate saw this server serve tool definitions that differ from
    the ones its grade signed. Tools the gate could not hash are left out."""
    seen = entry.get("last_seen")
    approved = entry.get("tool_digests")
    if not isinstance(seen, dict) or not isinstance(approved, dict) or not approved:
        return False
    live = seen.get("tool_digests")
    if not isinstance(live, dict) or not live:
        return False
    skip = set(seen.get("unhashable") or [])
    return {k: v for k, v in approved.items() if k not in skip} != {
        k: v for k, v in live.items() if k not in skip}


def _install_source() -> str:
    # Installed as a plugin, this file sits at <plugin>/scripts/ beside .claude-plugin/.
    plugin_root = pathlib.Path(__file__).resolve().parent.parent
    return "plugin" if (plugin_root / ".claude-plugin").is_dir() else "manual"


def _user_agent() -> str:
    return f"agentavow-precheck/{__version__} ({_install_source()})"


def _fetch(path: str, params: dict) -> dict:
    url = f"{API}{path}?{urllib.parse.urlencode(params)}" if params else f"{API}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": _user_agent()})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https only)
            return json.load(resp)
    except urllib.error.HTTPError as e:
        # 4xx (bar rate limiting) is the API's answer about the target, not a hiccup.
        if 400 <= e.code < 500 and e.code not in (408, 429):
            raise _UnscannableError(str(e.code)) from e
        raise


def _scan(target: dict, force: bool = False) -> dict:
    if target["kind"] == "mcp":
        params = {"endpoint": target["url"]}
        if force:
            params["force"] = "true"  # the definitions changed; a cached grade is stale
        return _verdict(_fetch("/mcp", params))
    return _verdict(_fetch(f"/package/{target['registry']}/{target['pkg']}", {}))


def _load_cache() -> dict:
    try:
        data = json.loads(CACHE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(cache: dict) -> bool:
    """Write the whole file at once (temp file + rename) so a gate call running at
    the same moment never reads a half-written file."""
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE.with_name(f"{CACHE.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(cache))
        os.replace(tmp, CACHE)
        return True
    except Exception:
        return False


def _intro_message() -> str:
    how = (
        "run /agentavow-trust:scan <MCP URL | npm or pypi package | owner/repo>"
        if _install_source() == "plugin"
        else 'ask Claude "is <tool> safe?" or open https://agentavow.com/check'
    )
    return ("AgentAvow: no remote MCP servers to scan yet; new ones are graded at your next "
            f"session start. To check a tool before you connect it, {how}.")


def _show_intro_once() -> None:
    """On the first session with nothing to scan, tell the user so (a silent hook
    looks broken) and how to scan on demand. Shown once per machine, recorded in
    the cache; if the cache can't be written it is not shown, so it can never nag.
    No request is made."""
    cache = _load_cache()
    meta = cache.get(META_KEY)
    if isinstance(meta, dict) and meta.get("intro_shown"):
        return
    cache[META_KEY] = {"intro_shown": __version__}
    if _save_cache(cache):
        print(json.dumps({"systemMessage": _intro_message()}))


def _is_cached(entry: object, target_id: str, now: float) -> bool:
    """A graded target is cached as a record ({"id", "approved_at", verdict, ...})
    and stays cached until the gate reports its definitions drifted. An unscannable
    one is cached as {"id", "retry_after"} until that time passes. A withheld URL is
    cached as its id string. A bare id string for a graded target was written by a
    version before the gate existed and carries no verdict, so it is graded once more."""
    if isinstance(entry, str):
        return entry == target_id and target_id.startswith("withheld:")
    if not isinstance(entry, dict) or entry.get("id") != target_id:
        return False
    if "approved_at" in entry:
        return not _drifted(entry)
    try:
        return now < float(entry.get("retry_after") or 0)
    except (TypeError, ValueError):
        return False


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
        _show_intro_once()
        return

    cache = _load_cache()
    started = time.monotonic()
    now = time.time()
    results: dict[str, dict | None] = {}  # id -> verdict, None = unscannable
    lines: list[str] = []
    for t in targets:
        entry = cache.get(t["name"])
        if _is_cached(entry, t["id"], now):
            continue
        regraded = isinstance(entry, dict) and _drifted(entry)
        if t["kind"] == "withheld":
            cache[t["name"]] = t["id"]
            lines.append(f"➖ MCP '{t['name']}' ({t['host']}): not scanned — its URL looks "
                         "like it contains a secret, so it was not sent to AgentAvow.")
            continue
        if t["id"] not in results:  # the same coordinate under two names scans once
            if time.monotonic() - started > BUDGET:
                break  # out of time; the rest are picked up next session
            try:
                results[t["id"]] = _scan(t, force=regraded)
            except _UnscannableError:
                results[t["id"]] = None
            except Exception:
                continue  # fail-open; transient, so not cached
        coord = t["url"] if t["kind"] == "mcp" else f"{t['registry']}:{t['pkg']}"
        result = results[t["id"]]
        if result is None:
            cache[t["name"]] = {"id": t["id"], "retry_after": now + RETRY_UNSCANNABLE}
            lines.append(f"➖ MCP '{t['name']}' ({coord}): not scanned — AgentAvow "
                         "couldn't read it (it may need sign-in).")
            continue
        cache[t["name"]] = _record(t, result, now)
        score, verdict, blocking = result["score"], result["verdict"], result["blocking"]
        flag = "✅" if verdict == "safe" else "⚠️"
        extra = f", {blocking} blocking finding(s)" if blocking else ""
        changed = ("its tool definitions changed since the last grade; re-graded: "
                   if regraded else "")
        sandbox = f"; {result['sandbox']}" if result.get("sandbox") else ""
        lines.append(f"{flag} MCP '{t['name']}' ({coord}): {changed}AgentAvow {score}/100 — "
                     f"{verdict}{extra}{sandbox}.")

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
