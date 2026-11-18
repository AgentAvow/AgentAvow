#!/usr/bin/env python3
"""AgentAvow install-time check — grades an MCP server BEFORE it is added. Warn-only,
fail-open, deterministic.

The scan-before-connect skill asks Claude to scan a tool before installing it, but a
skill fires on intent and can be skipped. This PreToolUse hook does not depend on
intent: it watches the two ways an MCP server actually gets added in Claude Code —
a ``claude mcp add`` / ``claude mcp add-json`` command (Bash) and a write to a
``.mcp.json`` file (Write / Edit / MultiEdit) — grades the server through the public
scan API, and puts the answer where the person sees it. Each line leads with one of
three answers and its reason — "Safe to connect", "Review before you connect" or "Do
not connect" — then the 0-100 score (" · Certified" when the tool carries the mark):

  • Do not connect  -> permissionDecision "ask": Claude Code shows the answer as the
                       reason and the person decides. The install is never denied.
  • everything else (Safe to connect; Review before you connect, including thin
    coverage on a small server; not scannable)
                    -> a one-line systemMessage and the command proceeds as normal (the
                       hook never grants permission, so Claude Code's own prompt, if
                       any, still runs). Review is a note, never a prompt: a legitimate
                       server with little to inspect must not get the prompt a poisoned
                       one gets.
  • anything else   -> silent, exit 0 (fail-open). A hook bug can never block a command.

A command that names AgentAvow's own folder (~/.cache/agentavow: the grades, the
per-call gate's allow list and the key behind its confirmation codes), or a write into
that folder, always asks the person first. That is a second line of defence: an allow
line only counts with a code the gate shows the person alone, so a line Claude writes
allows nothing however it reaches the file.

The graded server is written to the same cache the session-start hook reads, so it is
not reported a second time at the next session start. Reuses the precheck's target
resolution and scan code (same file, same directory) so the two never disagree.

In Codex (which runs this same plugin's hooks): servers are added with
``codex mcp add <name> --url <url>`` or ``codex mcp add <name> -- <command…>`` (its shell
tool reaches hooks as "Bash"), or written into a config.toml ``[mcp_servers.<name>]``
table (its apply_patch tool, which the Write|Edit matcher selects). A Codex hook cannot
ask, so Do not connect is a deny whose reason says what was found, links the report and
says how to go ahead anyway; a step that names AgentAvow's own files is a deny too.
Review, Safe and not-scannable stay notes, exactly as in Claude Code. Claude Code's
output is unchanged (tests/test_agentavow_claude_pins.py).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import shlex
import sys
import time
import urllib.error

__version__ = "0.1.44"

TIMEOUT = 12  # seconds per scan: an install is rare, so a slower fresh scan is fine
_HERE = pathlib.Path(__file__).resolve().parent

# Package installs (npm / pnpm / yarn / bun / pip / uv / pipx / poetry). Quiet by design:
# Safe is silent, a deprecated package gets a plain "deprecated" note (not a security
# finding), Review is a one-line note and the install goes ahead, Do not connect asks.
# Stored grades first so an install is not held up; one bounded fresh scan at most;
# anything slow, unknown or unscannable stays silent (fail-open).
INSTALL_ENV = "AGENTAVOW_INSTALL_CHECKS"  # "off" disables package-install checks
PKG_CAP = 5            # packages checked per command
PKG_BUDGET = 14.0      # seconds for all package lookups in one command (hook timeout 20)
FRESH_MAX = 1          # fresh scans per command for a package with no stored grade
STATS_KEY = "install_checks"  # counter in the cache's meta entry, read at session start


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
_CODEX_MCP_ADD = re.compile(r"\bcodex\s+mcp\s+add\b")
# `codex mcp add` flags whose NEXT token is their value (codex-cli 0.169).
_CODEX_VALUE_FLAGS = {"--env", "--url", "--bearer-token-env-var", "--oauth-client-id",
                      "--oauth-client-secret", "--oauth-client-registration",
                      "--oauth-resource", "-c", "--config", "--enable", "--disable"}


def _server_from_codex_mcp_add(command: str) -> tuple[str, dict] | None:
    """``codex mcp add [flags] <name> --url <url>`` or ``codex mcp add [flags] <name> --
    <command> [args…]`` -> (name, config) in the shape the precheck reads. None when the
    command is something else."""
    m = _CODEX_MCP_ADD.search(command)
    if not m:
        return None
    try:
        argv = shlex.split(_strip_redirections(command[m.start():]))
    except ValueError:
        return None
    rest = argv[3:]
    name: str | None = None
    url: str | None = None
    stdio: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("&&", "||", ";", "|", "&"):
            break
        if a == "--":
            stdio = rest[i + 1:]
            break
        if a.startswith("--url="):
            url = a.split("=", 1)[1]
        elif a == "--url":
            url = rest[i + 1] if i + 1 < len(rest) else None
            i += 2
            continue
        elif a in _CODEX_VALUE_FLAGS:
            i += 2
            continue
        elif a.startswith("-"):
            pass
        elif name is None:
            name = a
        i += 1
    for j, a in enumerate(stdio):  # the command ends where the next one starts
        if a in ("&&", "||", ";", "|", "&"):
            stdio = stdio[:j]
            break
    if not name:
        return None
    if url:
        return name, {"url": url}
    if stdio:
        return name, {"command": stdio[0], "args": stdio[1:]}
    return None


# An apply_patch body: "*** Add File: <path>" / "*** Update File: <path>", then lines
# that start with "+" (added), "-" (removed) or " " (kept).
_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update) File: (.+?)\s*$")


def _servers_from_codex_patch(patch: str, pc) -> list[tuple[str, dict]]:
    """MCP servers a Codex apply_patch adds or changes in a ``config.toml`` (Codex's
    own config, user or project): every ``[mcp_servers.<name>]`` table in the patched
    text whose lines the patch adds. Best effort; unreadable -> []."""
    out: list[tuple[str, dict]] = []
    path: str | None = None
    new_lines: list[str] = []
    added: list[str] = []

    def flush() -> None:
        if not path or not path.replace("\\", "/").endswith("config.toml"):
            return
        servers = pc._codex_server_map(pc._toml_load("\n".join(new_lines)))
        if not servers:  # a hunk that cut a table in two: read the added lines alone
            servers = pc._codex_server_map(pc._mini_toml("\n".join(new_lines)))
        touched = "\n".join(added)
        for name, cfg in servers.items():
            values = [cfg.get("url"), cfg.get("command")]
            if name in touched or any(isinstance(v, str) and v and v in touched
                                      for v in values):
                out.append((name, cfg))

    for line in (patch or "").splitlines():
        m = _PATCH_FILE.match(line)
        if m or line.startswith("*** End Patch") or line.startswith("*** Delete File:"):
            flush()
            path, new_lines, added = (m.group(1) if m else None), [], []
            continue
        if path is None or line.startswith(("@@", "*** ")):
            continue
        if line.startswith("+"):
            new_lines.append(line[1:])
            added.append(line[1:])
        elif line.startswith(" "):
            new_lines.append(line[1:])
    flush()
    return out[:3]


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


def _install_checks_enabled() -> bool:
    import os
    return os.environ.get(INSTALL_ENV, "").strip().lower() not in ("off", "0", "false", "no")


_SEGMENTS = re.compile(r"&&|\|\||;|\n|\||&")  # run after _strip_redirections


def _strip_redirections(command: str) -> str:
    """The command with every shell redirection removed, operator and target both
    (``2>&1``, ``>/dev/null``, ``>file``, ``>>log``, ``&>out``, ``<in``, ``2>err``), so
    ``pip install requests 2>&1`` is not read as a package named '2'. Quoted text is
    left alone (``"requests>=2"`` is a version spec, not a redirection)."""
    out: list[str] = []
    i, n, quote = 0, len(command), ""
    while i < n:
        c = command[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(command[i + 1])
                i += 1
            elif c == quote:
                quote = ""
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            continue
        if c in "<>" or (c == "&" and command[i + 1:i + 2] == ">"):
            j = len(out)
            while j and out[j - 1].isdigit():
                j -= 1
            if j < len(out) and (j == 0 or out[j - 1].isspace()):
                del out[j:]  # the file-descriptor number in front: the 2 of 2>
            while i < n and command[i] in "<>&|":
                i += 1  # the operator: > >> >& &> >| < << <&
            while i < n and command[i] in " \t":
                i += 1
            target_quote = ""
            while i < n and (target_quote or not command[i].isspace()):
                ch = command[i]
                if target_quote:
                    target_quote = "" if ch == target_quote else target_quote
                elif ch in "'\"":
                    target_quote = ch
                elif ch in ";|&\n":
                    break  # the target ends where the next command starts
                i += 1
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_JS_VERBS = {"npm": {"install", "i", "add", "in"}, "pnpm": {"add", "install", "i"},
             "yarn": {"add"}, "bun": {"add", "install", "i"}}
# Flags whose NEXT token is a value, never a package (a requirements file, an index URL,
# a workspace, an editable path …).
_VALUE_FLAGS = {
    "--registry", "--prefix", "-w", "--workspace", "--filter", "-C", "--dir", "--cwd",
    "-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url",
    "-t", "--target", "--python", "-p", "--project", "--group", "-f", "--find-links",
    "--root", "--src", "--platform", "--python-version", "--implementation", "--abi",
    "--trusted-host", "--cache-dir", "--log", "--proxy", "--timeout", "--retries",
    "-e", "--editable", "--extra", "--optional", "-G", "--with", "--tag", "--save-prefix",
}
_NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")


def _install_argv(argv: list[str]) -> tuple[str, list[str]] | None:
    """(registry, the args after the install verb) when ``argv`` installs packages."""
    while argv and (_ENV_ASSIGN.match(argv[0]) or argv[0] in ("sudo", "env", "time",
                                                               "command", "exec")):
        argv = argv[1:]
    if len(argv) < 2:
        return None
    tool = argv[0].rsplit("/", 1)[-1]
    if tool in _JS_VERBS and argv[1] in _JS_VERBS[tool]:
        return "npm", argv[2:]
    if tool in ("pip", "pip3") and argv[1] == "install":
        return "pypi", argv[2:]
    if tool.startswith("python") and argv[1:4] == ["-m", "pip", "install"]:
        return "pypi", argv[4:]
    if tool == "uv" and argv[1:3] == ["pip", "install"]:
        return "pypi", argv[3:]
    if tool in ("uv", "poetry") and argv[1] == "add":
        return "pypi", argv[2:]
    if tool == "pipx" and argv[1] == "install":
        return "pypi", argv[2:]
    return None


def _npm_spec(token: str) -> tuple[str, str] | None:
    low = token.strip()
    if not low or low.startswith(("file:", "link:", "git", "http", ".", "/", "~", "npm:",
                                  "workspace:", "github:")) or low.endswith((".tgz", ".tar.gz")):
        return None
    if "/" in low and not low.startswith("@"):
        return None  # owner/repo GitHub shorthand: no registry grade
    if low.startswith("@"):
        parts = low.split("@")  # ['', 'scope/name', 'ver']
        pkg, spec = "@" + parts[1], (parts[2] if len(parts) > 2 else "")
    else:
        pkg, _, spec = low.partition("@")
    pkg = pkg.lower()
    return (pkg, spec) if _NPM_NAME.match(pkg) else None


def _pypi_spec(token: str, pc) -> tuple[str, str] | None:
    t = token.strip()
    if not t or "/" in t or "\\" in t or t.endswith((".whl", ".zip", ".tar.gz")):
        return None
    return pc._pypi_name_spec(t)


def _package_installs(command: str, pc) -> list[tuple[str, str, str]]:
    """Every (registry, package, version spec) a shell command installs, in order,
    de-duplicated, capped at PKG_CAP. A bare ``npm install`` (lockfile), a requirements
    file, local paths, git URLs and tarballs are not registry packages and are skipped."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for seg in _SEGMENTS.split(_strip_redirections(command or "")):
        try:
            argv = shlex.split(seg)
        except ValueError:
            continue
        hit = _install_argv(argv)
        if not hit:
            continue
        registry, args = hit
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a == "--":
                continue
            if a in _VALUE_FLAGS:
                skip_next = True
                continue
            if a.startswith("-"):
                continue
            parsed = _npm_spec(a) if registry == "npm" else _pypi_spec(a, pc)
            if not parsed:
                continue
            key = (registry, parsed[0].lower())
            if key in seen:
                continue
            seen.add(key)
            out.append((registry, parsed[0], parsed[1]))
    return out[:PKG_CAP]


def _is_deprecation_only(r: dict) -> bool:
    """Review only because the maintainer deprecated it — a maintenance signal, not a
    security finding (Kenne, 2026-10-14): worded as "deprecated" at install time."""
    return (r.get("decision") == "review" and bool(r.get("deprecated"))
            and not int(r.get("blocking") or 0) and not int(r.get("advisories") or 0)
            and "deprecat" in str(r.get("decision_reason") or "").lower())


# Coverage gaps a package author can cause on purpose (pad a file past the read cap, ship
# thousands of files so the payload falls past the unpack budget): a Safe answer with one
# of these says, in one quiet line, that part of the package was not read.
_CHEAP_GAPS = frozenset({"oversized_files", "package_skipped"})


def _package_line(t: dict, r: dict, pc) -> str | None:
    """The one line for a package install, or None when there is nothing to say (Safe,
    with everything read)."""
    coord = f"{t['registry']} package '{t['pkg']}'"
    url = f"{pc.WEB}/check/pkg/{t['registry']}/{t['pkg']}"
    d = pc._dval(r)
    if d == "safe":
        if _CHEAP_GAPS & set(r.get("gaps") or []):
            return (f"ℹ️ {coord}: {pc._answer(r)}. Part of the package could not be read, "
                    f"so that part is unchecked. The install goes ahead. Report: {url}")
        return None
    if _is_deprecation_only(r):
        return (f"📦 {coord}: deprecated by its maintainer — not a security finding, but "
                f"consider a maintained alternative. {url}")
    if d == "review":
        return f"⚠️ {coord}: {pc._answer(r)}. The install goes ahead. Report: {url}"
    return f"⛔ {coord}: {pc._answer(r)}. Report: {url}"


def _not_graded_line(t: dict, reason: str, pc, busy: bool = False) -> str:
    """A package AgentAvow could not grade: said once, so silence never reads as clean."""
    coord = f"{t['registry']} package '{t['pkg']}'"
    if busy:
        return (f"❔ {coord}: not checked (AgentAvow is busy right now). "
                "The install goes ahead.")
    why = " ".join(reason.split())[:120]
    why = "" if why.isdigit() else why
    return (f"❔ {coord}: not checked — AgentAvow couldn't grade it"
            f"{f' ({why})' if why else ''}. The install goes ahead.")


def _check_packages(command: str, pc, cache: dict, now: float
                    ) -> tuple[list[str], bool, int]:
    """(lines, needs_decision, packages checked) for the package installs in
    ``command``. Never raises; anything uncertain is left silent."""
    if not _install_checks_enabled():
        return [], False, 0
    try:
        pkgs = _package_installs(command, pc)
    except Exception:
        return [], False, 0
    lines: list[str] = []
    needs = False
    checked = 0
    fresh = 0
    started = time.monotonic()
    for registry, pkg, spec in pkgs:
        t = pc._dep(registry, pkg, spec)
        entry = cache.get(t["name"])
        r: dict | None = None
        if pc._is_cached(entry, t["id"], now) and isinstance(entry, dict) and "score" in entry:
            r = entry
        else:
            left = PKG_BUDGET - (time.monotonic() - started)
            if left <= 1:
                break
            pc.TIMEOUT = min(TIMEOUT, max(1.0, left))
            try:
                r = pc._scan(t, stored=True)
            except pc._QueuedError:
                # never graded: one bounded fresh scan, else stay silent
                left = PKG_BUDGET - (time.monotonic() - started)
                if fresh >= FRESH_MAX or left <= 3:
                    continue
                fresh += 1
                pc.TIMEOUT = min(TIMEOUT, left)
                try:
                    r = pc._scan(t)
                except Exception:
                    continue
            except pc._UnscannableError as e:
                # The API's answer about the target (not found, not scannable): say it was
                # not checked rather than stay silent beside an install that goes ahead.
                lines.append(_not_graded_line(t, str(e), pc))
                continue
            except urllib.error.HTTPError as e:
                if e.code == 429 or e.code >= 500:
                    lines.append(_not_graded_line(t, "", pc, busy=True))
                continue
            except Exception:
                continue  # offline / timeout: nothing to say
            rec = pc._record(t, r, now)
            rec["spec"] = spec
            cache[t["name"]] = rec
        checked += 1
        line = _package_line(t, r, pc)
        if line:
            lines.append(line)
        needs = needs or pc._dval(r) == "do_not_connect"
    return lines, needs, checked


def _bump_stats(cache: dict, pc, checked: int, flagged: int, now: float) -> None:
    """Count install-time checks for the quiet session-start line."""
    if not checked:
        return
    meta = cache.get(pc.META_KEY)
    meta = dict(meta) if isinstance(meta, dict) else {}
    st = meta.get(STATS_KEY) if isinstance(meta.get(STATS_KEY), dict) else {}
    meta[STATS_KEY] = {"count": int(st.get("count") or 0) + checked,
                       "flagged": int(st.get("flagged") or 0) + flagged,
                       "since": st.get("since") or now}
    cache[pc.META_KEY] = meta


def _targets_for(payload: dict, pc) -> list[dict]:
    tool = str(payload.get("tool_name") or "")
    inp = payload.get("tool_input") or {}
    if not isinstance(inp, dict):
        return []
    found: list[tuple[str, dict]] = []
    if pc._in_codex():
        if tool == "Bash":
            hit = _server_from_codex_mcp_add(_command_text(inp))
            if hit:
                found.append(hit)
        elif tool == "apply_patch":
            found.extend(_servers_from_codex_patch(_command_text(inp), pc))
    elif tool == "Bash":
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


# The three headline phrases (src/trust_tiers.py DECISIONS; pinned by tests).
DECISION_PHRASES = {
    "safe": "Safe to connect",
    "review": "Review before you connect",
    "do_not_connect": "Do not connect",
}


def _needs_decision(r: dict | None) -> bool:
    """Ask the person only on "Do not connect". Review before you connect (a high
    finding, an advisory, …) and an unscannable target are reported, not prompted."""
    return r is not None and r.get("decision") == "do_not_connect"


def _line(t: dict, r: dict | None, pc) -> str:
    coord = _coord(t)
    if r is None:
        return (f"➖ MCP '{t['name']}' ({coord}): not scanned — AgentAvow couldn't read it "
                "(it may need sign-in). That is neither safe nor unsafe.")
    sandbox = f"; {r['sandbox']}" if r.get("sandbox") else ""
    return (f"{pc._flag(r)} MCP '{t['name']}' ({coord}): {pc._answer(r)}{sandbox}. "
            f"Report: {_report_url(t, pc)}")


ALLOW_FILE_NAME = "allowed-servers.txt"  # the per-call gate's allow list (same name there)
ALLOW_KEY_NAME = "allow.key"             # the key its confirmation codes come from


def _own_dir() -> pathlib.Path:
    return pathlib.Path.home() / ".cache" / "agentavow"


# A second line of defence only: an allow line Claude writes does not count anyway (it
# lacks the code the gate shows the person alone). These catch the plain and the common
# disguised spellings of AgentAvow's folder in a shell command, so reading the key or
# changing the files is put to the person; no string match can catch every disguise.
_NAMED_FILE = re.compile(r"allowed[-_]?servers|allow\.key|allow[-_]line")
_STANDALONE = re.compile(r"(?<![\w.@-])agentavow(?![\w.-])")
# The GitHub org and repo (AgentAvow/AgentAvow, github.com/AgentAvow/...), not the folder.
_REPO_SLUG = re.compile(r"agentavow/agentavow|(?:github(?:usercontent)?|gitlab)\.com/+agentavow")
_PATH_PART = re.compile(r"/agentavow(?![\w.-])")
_CACHE_DIR = re.compile(r"\.cache\b|xdg_cache_home")
# "allow" starting a word (allowed, allow.key, allow-list), not inside one (shallow, swallow).
_ALLOW_WORD = re.compile(r"(?<![a-z])allow")
_GLOB_AFTER_CACHE = re.compile(r"\.cache/+[^\s/]*[*?\[]")
# `cd` into a folder named agentavow (the whole name: a checkout at AgentAvow-wt-x is not).
_CD_INTO = re.compile(r"\b(?:cd|pushd|chdir)\b[\s(]+[^;&|\n]*(?<![\w.@-])agentavow(?![\w.-])")
# An `agentavow` path segment and the segment before it. The cache folder is reached
# under `.cache` or $XDG_CACHE_HOME, so a folder named AgentAvow under a plain literal
# parent (a checkout of this repo at ~/projects/AgentAvow, the plugin's install folder
# ~/.claude/plugins/cache/agentavow) is not ours; without this every Edit and every
# absolute path in a checkout of the repo asked the person. A parent that could stand
# for anything (a variable, substitution, glob, `~`, `.` or `..`) still counts.
_SEGMENT = re.compile(r"([^\s/]*)/+agentavow(?![\w.-])", re.IGNORECASE)
_KEEP_PARENT = re.compile(r"\.cache\b|cache_home|[*?\[\]${}()~]|^\.{0,2}$")
_REPO_SLUG_ANY_CASE = re.compile(r"agentavow/agentavow|(?:github(?:usercontent)?|gitlab)"
                                 r"\.com/+agentavow", re.IGNORECASE)
# A command that makes a link can point a plain-looking folder at the cache folder in
# the same breath (`ln -s ~/.cache q && cat q/agentavow/...`): nothing is ruled out.
_MAKES_LINK = re.compile(r"\bln\b|symlink|\bmount\b|\bbindfs\b", re.IGNORECASE)
_UNRESOLVED = re.compile(r"[*?\[\]${}()`]")
_HOME_VAR = re.compile(r"\$(?:home\b|\{home\})", re.IGNORECASE)
_TOKEN_STOP = set(";&|<>=([,")  # `[` and `,` end a token: ["/a/AgentAvow", ...]


def _is_cache_parent(prefix: str, cwd: object, has_cd: bool, sets_home: bool) -> bool:
    """Whether the literal path ``prefix`` (the folder that holds an ``agentavow``
    segment) is, or could be, the cache folder's parent. The real path decides, so a
    symlink to ~/.cache under a plain name still counts. Anything that cannot be
    resolved here (a variable, glob or substitution, a relative path after a `cd` or
    with no known cwd) counts too."""
    p = prefix if sets_home else _HOME_VAR.sub("~", prefix)
    if not p or _UNRESOLVED.search(p):
        return True
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        if has_cd or not isinstance(cwd, str) or not cwd:
            return True
        p = os.path.join(os.path.expanduser(cwd), p)
    try:
        here = os.path.realpath(p).lower()
        return here == os.path.realpath(_own_dir().parent).lower()
    except Exception:
        return True


def _literally_cache_parent(prefix: str, cwd: object, sets_home: bool) -> bool:
    """Whether ``prefix``, the whole word up to the whitespace before an ``agentavow``
    segment, read literally (a `[` or `,` as part of a folder name), resolves to the
    cache folder's parent. The token stops cut ``["/a/AgentAvow"`` down to the path, but
    a real folder can be named ``p,q`` or ``a[b``, and a link under it can point at
    ~/.cache, so the segment is kept when either reading lands there."""
    p = prefix if sets_home else _HOME_VAR.sub("~", prefix)
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        if not isinstance(cwd, str) or not cwd:
            return False
        p = os.path.join(os.path.expanduser(cwd), p)
    try:
        return os.path.realpath(p).lower() == os.path.realpath(_own_dir().parent).lower()
    except Exception:
        return True


def _other_agentavow_dirs(text: str, cwd: object = None) -> str:
    """``text`` with each ``<parent>/agentavow`` segment blanked out when that parent is
    a plain folder whose real path is not the cache folder's parent (a checkout of this
    repo at ~/projects/AgentAvow, the plugin's install folder), so it counts neither as
    a path into AgentAvow's folder nor as a standalone name. Case is kept so the real
    path can be resolved."""
    if _MAKES_LINK.search(text):
        return text
    has_cd = bool(_CD_WORD.search(text.lower()))
    sets_home = bool(re.search(r"\bhome=", text, re.IGNORECASE))

    def blank(m: re.Match) -> str:
        parent = m.group(1)
        if _KEEP_PARENT.search(parent.lower()):
            return m.group(0)
        start = m.start(1)
        while start > 0 and not text[start - 1].isspace() and text[start - 1] not in _TOKEN_STOP:
            start -= 1
        if _is_cache_parent(text[start:m.end(1)], cwd, has_cd, sets_home):
            return m.group(0)
        whole = m.start(1)
        while whole > 0 and not text[whole - 1].isspace():
            whole -= 1
        if whole < start and _literally_cache_parent(text[whole:m.end(1)], cwd, sets_home):
            return m.group(0)
        return parent + "/_"
    return _SEGMENT.sub(blank, text)


_CD_WORD = re.compile(r"\b(?:cd|pushd|chdir)\b")


def _cd_cannot_reach_own_dir(s: str, cwd: object) -> bool:
    """A command with a single `cd` into a bare relative `agentavow`, run from a folder
    that is not the cache folder, cannot land in AgentAvow's folder (a checkout named
    AgentAvow, entered from its parent). Unknown cwd, or a second `cd` that could move
    first: not ruled out."""
    if not isinstance(cwd, str) or not cwd or len(_CD_WORD.findall(s)) != 1:
        return False
    try:
        here = os.path.realpath(os.path.expanduser(cwd))
        return here != os.path.realpath(_own_dir().parent)
    except Exception:
        return False


def _shell_names_own_files(command: str, cwd: object = None) -> bool:
    """Whether a shell command names AgentAvow's cache folder or one of its files, in
    any of the spellings a person or a script would use: ~ / $HOME / ${HOME} /
    expanduser, quotes or backslashes inside a word, path pieces joined in Python,
    `cd` into the folder, a glob over ~/.cache. Our own repo and package names
    (AgentAvow/AgentAvow, agentavow-trust, agentavow_precheck) do not count, and
    neither does a folder named AgentAvow anywhere but the cache folder: the test is
    where a folder sits (its parent, or the working directory for a relative `cd`),
    never what a checkout or worktree is called."""
    raw = re.sub(r"[\"'`\\]", "", command)
    s = raw.lower()
    if _NAMED_FILE.search(s):
        return True
    t = _other_agentavow_dirs(_REPO_SLUG_ANY_CASE.sub("", raw), cwd).lower()
    if _PATH_PART.search(t):  # .../agentavow as a folder, however the rest is spelled
        return True
    standalone = bool(_STANDALONE.search(t))
    if _CACHE_DIR.search(s) and (standalone or _GLOB_AFTER_CACHE.search(s)
                                 or _ALLOW_WORD.search(s)):
        return True
    cd_in = bool(_CD_INTO.search(t)) and not _cd_cannot_reach_own_dir(s, cwd)
    return standalone and (cd_in or bool(re.search(r"\b(?:allow|scanned)", s)))


def _path_in_own_dir(raw: str, cwd: object) -> bool:
    """Whether a file path lands in AgentAvow's folder, symlinks resolved."""
    if not raw:
        return False
    if _shell_names_own_files(raw):
        return True
    try:
        base = pathlib.Path(str(cwd)) if isinstance(cwd, str) and cwd else pathlib.Path.cwd()
        path = pathlib.Path(raw).expanduser()
        path = path if path.is_absolute() else base / path
        real = pathlib.Path(os.path.realpath(path))
        own = pathlib.Path(os.path.realpath(_own_dir()))
        return real == own or own in real.parents
    except Exception:
        return False


def _command_text(inp: dict) -> str:
    """A shell command or patch as text. Codex sends a string; a list of words (an
    older shell tool) is joined back into one command."""
    cmd = inp.get("command")
    if isinstance(cmd, list):
        return shlex.join(str(a) for a in cmd)
    return str(cmd or "")


def _touches_own_files(payload: dict) -> bool:
    """Whether Claude is about to run something that names AgentAvow's own files, or to
    write or edit a file in its folder. Only the person may allow a Do not connect
    server, so such a step is always put to them, whatever Claude's own permissions say."""
    inp = payload.get("tool_input")
    if not isinstance(inp, dict):
        return False
    tool = str(payload.get("tool_name") or "")
    if tool == "apply_patch":  # Codex: a patch names the files it writes
        return any(_path_in_own_dir(m.group(1), payload.get("cwd"))
                   for m in map(_PATCH_FILE.match, _command_text(inp).splitlines()) if m)
    if tool == "Bash" and isinstance(inp.get("command"), list):
        return _shell_names_own_files(_command_text(inp), payload.get("cwd"))
    if tool == "Bash":
        return _shell_names_own_files(str(inp.get("command") or ""), payload.get("cwd"))
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        raw = inp.get("file_path") or inp.get("notebook_path") or ""
        return _path_in_own_dir(str(raw), payload.get("cwd"))
    return False


def _ask_about_allow_list(codex: bool = False) -> None:
    reason = ("AgentAvow: this reads or changes AgentAvow's own files (~/.cache/agentavow: "
              "the grades, the list of servers you allowed past a Do not connect answer, "
              "and the key behind its confirmation codes). Only approve it if you asked "
              "for this yourself.")
    if codex:  # Codex cannot ask: stop it, and say how the person does it themselves
        reason = ("AgentAvow: this reads or changes AgentAvow's own files (~/.cache/agentavow: "
                  "the grades, the list of servers you allowed past a Do not connect answer, "
                  "and the key behind its confirmation codes). Codex cannot ask you first, "
                  "so AgentAvow stopped it. If you asked for this yourself, do it in your "
                  "own terminal outside Codex, or switch AgentAvow's hooks off in Codex "
                  "(/hooks) for this session.")
    print(json.dumps({"systemMessage": reason, "hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny" if codex else "ask",
        "permissionDecisionReason": reason}}))


def codex_deny_reason(body: str, targets: list[dict], pkg_lines: list[str]) -> str:
    """Why a Codex step was stopped and how to go ahead anyway. Codex has no "ask", so
    a Do not connect answer is a deny (owner's call, 2026-11-17); the person can still
    do it themselves outside Codex."""
    what = "add this server" if targets and not pkg_lines else "install this"
    return (body + f"\nAgentAvow says: {DECISION_PHRASES['do_not_connect']}, so it stopped this "
            f"step (Codex cannot ask you first). If you reviewed the report and still want to "
            f"{what}, run the same command yourself in your own terminal outside Codex, or "
            "switch AgentAvow's hooks off in Codex (/hooks) for this session. Do not retry "
            "it another way from here.")


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    if not isinstance(payload, dict) or payload.get("hook_event_name") not in (None, "PreToolUse"):
        return
    try:
        codex = _precheck().detect_host(payload) == "codex"
    except Exception:
        codex = False
    try:
        if _touches_own_files(payload):
            _ask_about_allow_list(codex)
            return
    except Exception:
        pass
    try:
        pc = _precheck()
        pc.UA_PRODUCT = "agentavow-preinstall"  # count install-time checks separately
        if codex:
            pc._set_host(payload)
            pc._set_session_cwd(payload)
        targets = _targets_for(payload, pc)
    except Exception:
        return
    command = ""
    if payload.get("tool_name") == "Bash" and isinstance(payload.get("tool_input"), dict):
        command = (_command_text(payload["tool_input"]) if codex
                   else str(payload["tool_input"].get("command") or ""))
    if not targets and not (command and _install_checks_enabled()
                            and _package_installs(command, pc)):
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

    pkg_lines: list[str] = []
    if command:
        pkg_lines, pkg_needs, checked = _check_packages(command, pc, cache, now)
        needs_decision = needs_decision or pkg_needs
        # A partial-read note (ℹ️) or a "not checked" line (❔) is not a flagged package.
        _bump_stats(cache, pc, checked,
                    sum(1 for ln in pkg_lines if not ln.startswith(("ℹ️", "❔"))), now)
        if checked:
            pc._save_cache(cache)
    if not lines and not pkg_lines:
        return  # Safe packages and nothing else: silent by design
    lines += pkg_lines
    pc._save_cache(cache)

    head = ("AgentAvow checked this before it is added:" if not pkg_lines else
            "AgentAvow checked this before it is installed:")
    body = head + "\n" + "\n".join(lines)
    out: dict = {
        "systemMessage": body,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": body + "\nTell the user this verdict in one line before "
                                        "you continue; they decide whether to proceed.",
        },
    }
    if needs_decision and codex:
        reason = codex_deny_reason(body, targets, pkg_lines)
        out["hookSpecificOutput"]["permissionDecision"] = "deny"
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
        out["hookSpecificOutput"]["additionalContext"] = (
            reason + "\nTell the user this in one line; do not try to add or install it "
                     "another way.")
        out["systemMessage"] = reason
    elif needs_decision:
        out["hookSpecificOutput"]["permissionDecision"] = "ask"
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            body + f"\nAgentAvow says: {DECISION_PHRASES['do_not_connect']}. Continue anyway?")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
