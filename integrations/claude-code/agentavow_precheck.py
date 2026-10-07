#!/usr/bin/env python3
"""AgentAvow SessionStart pre-check — OPT-IN, warn-only, fail-open.

Scans the MCP servers THIS session can use (user scope, this project's local
scope, and the project's .mcp.json / settings) that haven't been scanned yet and
injects a one-line AgentAvow trust verdict into the session, so you see it BEFORE
you rely on a newly added tool. Servers configured for other projects are counted
in the summary and graded when those projects are opened.
It also grades the project's DIRECT dependencies (package.json "dependencies";
requirements.txt / pyproject [project].dependencies), up to DEPS_CAP per session
start in manifest order, the rest on later starts, re-graded only when the declared
version changes. Most projects have no MCP servers but every project has
dependencies, so this is what gives a first session something to say. Dependencies
are already installed, so a low grade is advice ("needs a look"), never a stop.
AGENTAVOW_PRECHECK_DEPS=off turns the pass off. "This project" is the ``cwd`` Claude Code
passes in the hook payload (the session's folder), so a session moved into a project
and then cleared (/clear) is graded for that project. Covers both:
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
How the result reaches the person: Claude Code never displays a SessionStart hook's
``additionalContext`` (it goes to the model only), and ``systemMessage`` is not rendered
by every client. So the hook does both, and the context block asks Claude to open its
first reply with the one-line summary — the one channel every surface shows.
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

__version__ = "0.1.16"

API = "https://agentavow.com/api/v1/public/scan"
WEB = "https://agentavow.com"
CACHE = pathlib.Path.home() / ".cache" / "agentavow" / "scanned.json"
TIMEOUT = 8  # seconds per scan; short so startup is never held up
BUDGET = 20  # seconds for the whole run; stays inside the hook's 30s timeout
RETRY_UNSCANNABLE = 7 * 24 * 3600  # re-try a server the API refused after a week
META_KEY = "_agentavow"  # cache entry holding hook state; never treated as a server name
# Direct dependencies graded per session start; the rest follow next time. The public
# scan routes allow 20 requests/min per IP, and the server pass runs first, so 8 keeps
# a normal start (a handful of servers + 8) under the limit.
DEPS_CAP = 8
DEPS_ENV = "AGENTAVOW_PRECHECK_DEPS"  # set to "off" to skip the dependency pass
DEP_PREFIX = "dep:"  # cache keys for dependencies, so they never collide with server names

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


def _take(servers: object, seen: dict[str, dict]) -> None:
    if not isinstance(servers, dict):
        return
    for sname, cfg in servers.items():
        if sname in seen or sname == META_KEY or not isinstance(cfg, dict):
            continue
        t = _resolve_target(sname, cfg)
        if t:
            seen[sname] = t


def _walk_for_servers(data: object, seen: dict[str, dict]) -> None:
    """Defensive walk of a project-level config file: every ``mcpServers`` map, at
    any depth (shapes vary by Claude Code version)."""
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            _take(node.get("mcpServers"), seen)
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))


def _read_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


# The folder the SESSION is in. Claude Code passes it as ``cwd`` in the hook payload;
# that is what "this project" means, and it differs from the process directory when
# the session was moved (Claude Desktop's Code tab starts in a scratch workspace and
# the person cd's into the project). Set by main() from stdin; falls back to the
# process cwd.
_SESSION_CWD: pathlib.Path | None = None


def _cwd() -> pathlib.Path:
    return _SESSION_CWD or pathlib.Path.cwd()


def _set_session_cwd(payload: object) -> None:
    global _SESSION_CWD
    _SESSION_CWD = None
    if isinstance(payload, dict):
        raw = payload.get("cwd")
        if isinstance(raw, str) and raw.strip():
            try:
                cand = pathlib.Path(raw).expanduser()
                if cand.is_dir():
                    _SESSION_CWD = cand
            except Exception:
                _SESSION_CWD = None


def _cwd_keys() -> set[str]:
    cwd = _cwd()
    keys = {str(cwd)}
    try:
        keys.add(str(cwd.resolve()))
    except Exception:
        pass
    return keys


def _targets() -> list[dict]:
    """The servers THIS session can connect to — what ``claude mcp list`` shows here:
    user scope (``~/.claude.json`` top-level ``mcpServers``), this project's local
    scope (``~/.claude.json`` → ``projects[cwd].mcpServers``), and project scope
    (``./.mcp.json``, ``./.claude/settings*.json``). Servers configured for other
    projects are graded when those projects are opened (see _servers_elsewhere), so
    the summary matches the list the person can see."""
    seen: dict[str, dict] = {}
    data = _read_json(pathlib.Path.home() / ".claude.json")
    if isinstance(data, dict):
        _take(data.get("mcpServers"), seen)
        projects = data.get("projects")
        if isinstance(projects, dict):
            for key in _cwd_keys():
                proj = projects.get(key)
                if isinstance(proj, dict):
                    _take(proj.get("mcpServers"), seen)
    for path in (_cwd() / ".mcp.json",
                 _cwd() / ".claude" / "settings.json",
                 _cwd() / ".claude" / "settings.local.json"):
        node = _read_json(path)
        if node is not None:
            _walk_for_servers(node, seen)
    return list(seen.values())


# --------------------------------------------------------------------------- #
# Direct dependencies of the project in cwd
# --------------------------------------------------------------------------- #
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _deps_enabled() -> bool:
    return os.environ.get(DEPS_ENV, "").strip().lower() not in ("off", "0", "false", "no")


def _dep(registry: str, pkg: str, spec: str) -> dict:
    spec = (spec or "").strip()
    return {"name": f"{DEP_PREFIX}{registry}:{pkg}", "kind": "package", "registry": registry,
            "pkg": pkg, "spec": spec, "id": f"{DEP_PREFIX}{registry}:{pkg}@{spec}"}


def _npm_deps(data: object) -> list[dict]:
    """package.json → direct runtime dependencies only (not devDependencies, not
    transitive). Local / git / URL specs have no registry grade and are skipped."""
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), dict):
        return []
    out = []
    for name, spec in data["dependencies"].items():
        if not isinstance(name, str) or not isinstance(spec, str):
            continue
        low = spec.strip().lower()
        if low.startswith(("file:", "link:", "git", "http", "workspace:", "npm:", ".", "/")):
            continue
        out.append(_dep("npm", name, spec))
    return out


def _pypi_name_spec(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-") or "://" in line or line.startswith((".", "/")):
        return None
    m = _PY_NAME.match(line)
    if not m:
        return None
    name = m.group(0)
    rest = line[m.end():].split(";", 1)[0].strip()  # drop environment markers
    if rest.startswith("["):  # extras: requests[security]>=2
        rest = rest.split("]", 1)[1].strip() if "]" in rest else ""
    return name, rest


def _requirements_deps(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        hit = _pypi_name_spec(raw)
        if hit:
            out.append(_dep("pypi", hit[0], hit[1]))
    return out


def _toml_string_list(text: str, start: int) -> list[str]:
    """The quoted strings of a TOML array that opens at ``text[start] == '['``, read
    with quote awareness so a ']' inside an entry ("uvicorn[standard]>=0.24") does
    not end the list. Stops at the matching close bracket; comments are skipped."""
    out: list[str] = []
    i, n = start + 1, len(text)
    while i < n:
        c = text[i]
        if c == "]":
            break
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c in "\"'":
            j = text.find(c, i + 1)
            if j < 0:
                break
            out.append(text[i + 1:j])
            i = j + 1
            continue
        i += 1
    return out


def _pyproject_deps(text: str) -> list[dict]:
    """[project].dependencies from pyproject.toml. tomllib when available (3.11+),
    else a fallback that finds the [project] table's ``dependencies = [`` and reads
    the list quote-aware (the system python3 on many Macs is 3.9)."""
    deps: list[str] = []
    try:
        import tomllib  # type: ignore[import-not-found]
        data = tomllib.loads(text)
        raw = (data.get("project") or {}).get("dependencies") or []
        deps = [d for d in raw if isinstance(d, str)]
    except Exception:
        m = re.search(r"^\[project\][ \t]*\n(.*?)(?=^\[|\Z)", text, re.S | re.M)
        if m:
            body = m.group(1)
            m2 = re.search(r"^dependencies\s*=\s*\[", body, re.M)
            if m2:
                deps = _toml_string_list(body, m2.end() - 1)
    out = []
    for d in deps:
        hit = _pypi_name_spec(d)
        if hit:
            out.append(_dep("pypi", hit[0], hit[1]))
    return out


def _dependency_targets() -> list[dict]:
    """Direct dependencies declared by the project in cwd, in manifest order; [] when
    there is no manifest or the pass is off. Same package under two manifests → once."""
    if not _deps_enabled():
        return []
    cwd = _cwd()
    found: list[dict] = []
    pj = _read_json(cwd / "package.json")
    if pj is not None:
        found += _npm_deps(pj)
    try:
        found += _requirements_deps((cwd / "requirements.txt").read_text())
    except Exception:
        pass
    try:
        found += _pyproject_deps((cwd / "pyproject.toml").read_text())
    except Exception:
        pass
    seen: dict[str, dict] = {}
    for t in found:
        seen.setdefault(t["name"], t)
    return list(seen.values())


_DEP_RISK_TIERS = frozenset({"blocked", "restricted"})


def _dep_needs_look(r: dict) -> bool:
    """A dependency is already installed, so its grade is advice; and the static
    scanner's high-severity PATTERN hits (exec / fs / deserialization regexes) fire
    all over large, legitimate frameworks (fastapi: 30 highs, 0 critical). So a
    dependency 'needs a look' only on evidence that is not a pattern hit: a critical
    finding, a published advisory for the installed version, a deprecation, a known
    incident, or a blocked / restricted tier. Everything else is reported with its
    score and counted OK."""
    if r.get("verdict") == "safe":
        return False
    return bool(
        int(r.get("critical") or 0) > 0
        or int(r.get("advisories") or 0) > 0
        or r.get("deprecated")
        or r.get("incident")
        or str(r.get("tier") or "") in _DEP_RISK_TIERS
    )


def _dep_coord(t: dict) -> str:
    return f"{t['registry']}:{t['pkg']}" + (f"@{t['spec']}" if t.get("spec") else "")


def _dep_lines_and_graded(cache: dict, deps: list[dict], now: float, started: float
                          ) -> tuple[list[str], list[tuple[str, dict]], bool]:
    """Grade up to DEPS_CAP not-yet-graded dependencies within the shared time budget.
    Returns (report lines for the newly graded ones, (name, verdict) for EVERY graded
    dependency of this manifest incl. cached ones, whether the API throttled us). A
    429 or a 5xx stops the pass for this session: burning the budget on refused
    requests helps nobody, and the rest are picked up next time."""
    lines: list[str] = []
    new = 0
    throttled = False
    for t in deps:
        entry = cache.get(t["name"])
        if _is_cached(entry, t["id"], now):
            continue
        if new >= DEPS_CAP or time.monotonic() - started > BUDGET:
            break
        new += 1
        try:
            r: dict | None = _scan(t)
        except _UnscannableError:
            r = None
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                throttled = True
                break
            continue
        except Exception:
            continue  # transient; next session
        if r is None:
            cache[t["name"]] = {"id": t["id"], "retry_after": now + RETRY_UNSCANNABLE}
            lines.append(f"➖ dependency '{t['pkg']}' ({_dep_coord(t)}): not scanned — "
                         "AgentAvow couldn't read it.")
            continue
        rec = _record(t, r, now)
        rec["spec"] = t.get("spec", "")
        cache[t["name"]] = rec
        sandbox = f"; {r['sandbox']}" if r.get("sandbox") else ""
        coord = _dep_coord(t)
        if r["verdict"] == "safe":
            lines.append(f"✅ dependency '{t['pkg']}' ({coord}): AgentAvow {r['score']}/100 — "
                         f"safe{sandbox}.")
        elif _dep_needs_look(r):
            why = []
            if r.get("critical"):
                why.append(f"{r['critical']} critical finding(s)")
            if r.get("advisories"):
                why.append(f"{r['advisories']} advisory(ies) for this version")
            if r.get("deprecated"):
                why.append("DEPRECATED by its maintainer (no more security fixes)")
            if r.get("incident"):
                why.append("a known incident")
            if not why:
                why.append(f"{r.get('tier') or 'low'} tier")
            lines.append(f"📦 dependency '{t['pkg']}' ({coord}): AgentAvow {r['score']}/100 — "
                         f"needs a look: {'; '.join(why)}{sandbox}.")
        else:
            lines.append(f"ℹ️ dependency '{t['pkg']}' ({coord}): AgentAvow {r['score']}/100 — "
                         f"no critical findings, no advisories; {r['blocking']} high-severity "
                         f"pattern hit(s) (common in large frameworks), see the report{sandbox}.")
    graded: list[tuple[str, dict]] = []
    for t in deps:
        e = cache.get(t["name"])
        if isinstance(e, dict) and e.get("id") == t["id"] and "score" in e:
            graded.append((t["pkg"], e))
    return lines, graded, throttled


def _deps_clause(graded: list[tuple[str, dict]], total: int, throttled: bool = False) -> str:
    """' Dependencies: graded 12 of 38 — 11 safe, 1 needs a look (lowest: ...).'"""
    if not total:
        return ""
    paused = " (paused: rate limited; continues next session)" if throttled else ""
    done = len(graded)
    if not done:
        return f" Dependencies: 0 of {total} graded yet{paused}."
    risky = [(n, r) for n, r in graded if _dep_needs_look(r)]
    look = len(risky)
    ok = done - look
    of = f"{done} of {total}" if done < total else f"all {total}"
    out = f" Dependencies: graded {of} — {ok} OK, {look} need{'s' if look == 1 else ''} a look"
    if look:
        name, worst = min(risky, key=lambda g: int(g[1].get("score") or 0))
        tag = (", deprecated" if worst.get("deprecated") else
               f", {worst['critical']} critical" if worst.get("critical") else
               ", advisory" if worst.get("advisories") else
               ", incident" if worst.get("incident") else "")
        out += f" (lowest: '{name}' {worst.get('score')}/100{tag})"
    return out + paused + "."


def _servers_elsewhere(here: list[dict]) -> int:
    """How many scannable servers are configured for OTHER projects on this machine
    (not in this session's list). Reported as a count only; they are graded when
    those projects are opened. 0 on any error."""
    try:
        data = _read_json(pathlib.Path.home() / ".claude.json")
        if not isinstance(data, dict) or not isinstance(data.get("projects"), dict):
            return 0
        skip = _cwd_keys()
        have = {t["id"] for t in here}
        elsewhere: dict[str, dict] = {}
        for key, proj in data["projects"].items():
            if key in skip or not isinstance(proj, dict):
                continue
            _take(proj.get("mcpServers"), elsewhere)
        return len({t["id"] for t in elsewhere.values()} - have)
    except Exception:
        return 0


def _advisory_applies(a: object) -> bool:
    """Does a raw advisory entry apply to the installed version? An explicit flag wins;
    otherwise only an advisory with no fix counts. A fixed one with no version match
    is history, not evidence against this version."""
    if not isinstance(a, dict):
        return False
    for key in ("affects_current_version", "current_version_affected"):
        if key in a:
            return bool(a[key])
    return not (a.get("fixed_in") or a.get("fixed") or a.get("fixed_version"))


def _verdict(data: dict) -> dict:
    """The parts of a scan response the hook reports and the gate acts on."""
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    blocking = sum(1 for i in items if i.get("severity") in ("critical", "high"))
    critical = sum(1 for i in items if i.get("severity") == "critical")
    # Advisories for the installed version. ``advisories_affecting_version`` (MCP shape)
    # is already filtered: count it all. The raw ``advisories`` list is the package's
    # HISTORY (fastapi: a CSRF fixed in 0.65.2, current 0.142.2), so an entry counts
    # only if it says it affects the current version, or has no fix at all.
    adv = data.get("advisories_affecting_version")
    if isinstance(adv, list):
        advisories = len(adv)
    else:
        raw = data.get("advisories") if isinstance(data.get("advisories"), list) else []
        advisories = sum(1 for a in raw if _advisory_applies(a))
    # A past incident (chalk, Sep 2025) only matters if the installed version is affected.
    ih = data.get("incident_history") if isinstance(data.get("incident_history"), dict) else {}
    incident = bool(data.get("incident")) or bool(ih.get("current_version_affected"))
    digests = data.get("tool_digests")
    return {
        "score": score,
        "verdict": "safe" if (score >= 81 and blocking == 0) else "needs review",
        "blocking": blocking,
        "critical": critical,
        "advisories": advisories,
        "incident": incident,
        "tier": str(data.get("trust_tier") or ""),
        "grade": str(data.get("grade") or ""),
        "tool_digests": digests if isinstance(digests, dict) else {},
        "tool_manifest_digest": data.get("tool_manifest_digest") or None,
        "sandbox": _sandbox_summary(data.get("behavioral")),
        "deprecated": bool(data.get("deprecation")),
    }


# Package-registry hosts an install always reaches; left out of the one-line network
# clause so it names the hosts the tool itself contacted.
_REGISTRY_HOSTS = frozenset({
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "github.com", "codeload.github.com", "objects.githubusercontent.com",
    "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
})
# A behavioral rule in a few words, for "sandbox: CAUGHT <...>".
_RULE_SHORT = {
    "credential_canary_exfiltrated": "a planted credential leaving the sandbox",
    "ssrf_internal_fetch": "following a caller-supplied URL to an internal address",
    "behavioral_undeclared_egress": "undeclared network egress",
    "annotation_readonly_violated": "a read-only tool writing files",
    "annotation_open_world_violated": "closed-world tools reaching the network",
    "canary_echoed_in_result": "a secret echoed in tool output",
    "tool_call_crashed_server": "a tool call crashing the server",
}
_START_SHORT = {
    "needs_credentials": "needs credentials", "missing_binary": "missing a program",
    "no_entrypoint": "no entry point", "resource_limit": "hit the resource limit",
    "install_failed": "install failed", "timeout": "timed out", "crashed": "crashed on start",
}
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _needs_what(detail: str) -> str:
    low = (detail or "").lower()
    if any(k in low for k in ("database url", "connection string", "dsn", "postgres")):
        return "needs a database URL"
    if "url" in low:
        return "needs a URL argument"
    if "path" in low or "directory" in low:
        return "needs a path argument"
    return "needs a startup argument"


def _hosts(hosts: list, limit: int = 2) -> str:
    return ", ".join(hosts[:limit]) + (f" +{len(hosts) - limit}" if len(hosts) > limit else "")


def _sandbox_summary(b: object) -> str:
    """One clause about the behavioral sandbox run AgentAvow did on the package (it runs
    automatically on the first scan and is cached for a day): what it caught, what it
    called and where it connected, why the server did not start, or that it is still
    running. Empty when there is nothing to say. Read-only; no extra request."""
    if not isinstance(b, dict):
        return ""
    if b.get("pending"):
        return "sandbox: running now, results in about a minute"
    if not b.get("ran"):
        return ""
    findings = [f for f in (b.get("findings") or []) if isinstance(f, dict)]
    if b.get("canary_exfil") and not any(
            f.get("rule") == "credential_canary_exfiltrated" for f in findings):
        findings.append({"rule": "credential_canary_exfiltrated", "severity": "critical"})
    if findings:
        findings.sort(key=lambda f: (f.get("rule") != "credential_canary_exfiltrated",
                                     _SEV.get(str(f.get("severity")), 4)))
        top = findings[0]
        what = _RULE_SHORT.get(str(top.get("rule") or ""),
                               str(top.get("name") or top.get("rule") or "a behavior"))
        sev = str(top.get("severity") or "")
        more = f" +{len(findings) - 1} more" if len(findings) > 1 else ""
        return f"sandbox: CAUGHT {what}" + (f" ({sev})" if sev else "") + more
    ex = b.get("exercise") if isinstance(b.get("exercise"), dict) else None
    hosts = sorted({str(h) for h in (b.get("egress_hosts") or []) if h} - _REGISTRY_HOSTS)
    net = f"network only {_hosts(hosts)}" if hosts else "no network beyond the registry"
    if ex and ex.get("launch_ok"):
        called = len({c.get("tool") for c in (ex.get("calls") or [])
                      if isinstance(c, dict) and c.get("tool")})
        return f"sandbox: called {called} tool{'' if called == 1 else 's'}, {net}"
    plan = str(b.get("plan") or "")
    if ex is not None or plan.endswith("-mcp"):
        gs = b.get("grade_summary") if isinstance(b.get("grade_summary"), dict) else {}
        reason = str(gs.get("start_reason") or "")
        if reason == "needs_arguments":
            why = _needs_what(str(gs.get("start_reason_detail") or ""))
        else:
            why = _START_SHORT.get(reason, "")
        return "sandbox: not started" + (f" ({why})" if why else "")
    return f"sandbox: installed, {net}"


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
    return ("AgentAvow: nothing to grade here yet — no remote MCP servers and no "
            "package.json / requirements.txt in this folder. Add a server (for example "
            "`claude mcp add <name> <https url>` or `claude mcp add <name> -- npx <package>`) "
            "and it is graded before it is added and again at your next session start; open "
            "a project and its direct dependencies are graded too. To check any tool right "
            f"now, {how}.")


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


def _summary(graded: list[tuple[str, dict]], elsewhere: int = 0, deps: str = "",
             servers_present: bool = True) -> str:
    """One line a person can act on: how many servers were graded, how many are safe,
    and the one that needs attention most, then the dependency clause. Shown as the
    hook's systemMessage and relayed by Claude at the top of its first reply.
    ``elsewhere`` = servers configured for other projects, mentioned so nothing looks
    silently skipped. ``servers_present`` False = this project has no MCP servers and
    the line is about dependencies only."""
    n = len(graded)
    tail = (f" {elsewhere} more configured for other projects, graded when you open them."
            if elsewhere else "")
    if not servers_present:
        return ("AgentAvow pre-check: no MCP servers in this project." + deps
                + " Ask for the AgentAvow pre-check for details." + tail)
    if not n:
        return ("AgentAvow pre-check: a configured MCP server could not be scanned; "
                "ask for the AgentAvow pre-check for details." + deps + tail)
    safe = sum(1 for _, r in graded if r["verdict"] == "safe")
    review = n - safe
    parts = [f"AgentAvow pre-check: graded {n} MCP server{'' if n == 1 else 's'} — "
             f"{safe} safe, {review} need{'s' if review == 1 else ''} review"]
    if review:
        name, worst = min(graded, key=lambda g: g[1]["score"])
        extra = f", {worst['blocking']} blocking" if worst["blocking"] else ""
        parts.append(f" (lowest: '{name}' {worst['score']}/100{extra})")
    parts.append("." + deps + " Ask for the AgentAvow pre-check for details." + tail)
    return "".join(parts)


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
    payload = None
    try:
        payload = json.load(sys.stdin)  # the SessionStart payload: ``cwd`` is the session folder
    except Exception:
        payload = None
    try:
        _set_session_cwd(payload)
    except Exception:
        pass

    try:
        targets = _targets()
    except Exception:
        return
    try:
        deps = _dependency_targets()
    except Exception:
        deps = []
    if not targets and not deps:
        _show_intro_once()
        return

    cache = _load_cache()
    started = time.monotonic()
    now = time.time()
    results: dict[str, dict | None] = {}  # id -> verdict, None = unscannable
    lines: list[str] = []
    graded: list[tuple[str, dict]] = []  # (server name, verdict) for the summary line
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
        graded.append((t["name"], result))
        score, verdict, blocking = result["score"], result["verdict"], result["blocking"]
        flag = "✅" if verdict == "safe" else "⚠️"
        extra = f", {blocking} blocking finding(s)" if blocking else ""
        changed = ("its tool definitions changed since the last grade; re-graded: "
                   if regraded else "")
        sandbox = f"; {result['sandbox']}" if result.get("sandbox") else ""
        if result.get("deprecated"):
            sandbox = "; DEPRECATED by its maintainer (no more security fixes)" + sandbox
        lines.append(f"{flag} MCP '{t['name']}' ({coord}): {changed}AgentAvow {score}/100 — "
                     f"{verdict}{extra}{sandbox}.")

    dep_clause = ""
    if deps:
        try:
            dep_lines, dep_graded, throttled = _dep_lines_and_graded(cache, deps, now, started)
            lines += dep_lines
            dep_clause = _deps_clause(dep_graded, len(deps), throttled)
            if throttled and not lines:
                lines.append("➖ dependencies: the AgentAvow API rate-limited this session start; "
                             "grading continues next session.")
        except Exception:
            pass  # fail-open: the dependency pass can never break the server report

    _save_cache(cache)
    if not lines:
        return

    try:
        elsewhere = _servers_elsewhere(targets)
    except Exception:
        elsewhere = 0
    summary = _summary(graded, elsewhere, dep_clause, servers_present=bool(targets))
    context = (
        "AgentAvow pre-check — new MCP servers and direct dependencies graded before you "
        "rely on them.\n"
        "The user has NOT seen this (hook output is not displayed to them). At the very "
        "start of your first reply in this session, before anything else, tell them in one "
        f"or two lines: \"{summary}\" Then carry on with whatever they asked. If they want "
        "details, use the lines below; do not repeat the summary in later replies.\n"
        + "\n".join(lines)
        + "\nReview any ⚠️ before trusting it. A 📦 dependency is already installed: its grade "
          "is advice, not a stop; an ℹ️ dependency has only pattern hits, no critical finding "
          "or advisory. Full reports: https://agentavow.com/check"
    )
    print(json.dumps({
        "systemMessage": summary,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))


if __name__ == "__main__":
    main()
