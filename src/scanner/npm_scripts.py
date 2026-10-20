"""Which package.json ``scripts`` can run on a consumer's machine.

npm runs a fixed set of lifecycle scripts when a package is installed as a dependency
(``preinstall`` / ``install`` / ``postinstall``; for a git dependency also the
``prepare`` / ``prepack`` / ``postpack`` family, since npm installs and packs the clone).
Everything else under ``scripts`` (``test:e2e:docker``, ``update-lock:docker``,
``release``) is the maintainer's: it runs only when someone types ``npm run <name>`` in
a checkout. A ``curl … | sh`` in such a script is a build recipe, not something the
package does to the people who install it.

A maintainer script stops being maintainer-only when a consumer script reaches it.
:func:`reachable_scripts` is a deliberately over-approximate closure:

* every script whose name appears as a word in a reachable script's command
  (``npm run X``, ``npm run-script X``, ``yarn X``, ``pnpm X``, ``bun run X``,
  ``node --run X``, ``npm --prefix . run X``, ``cross-env A=1 npm run X``,
  ``run-s X``, ``npm-run-all X``, ``concurrently "npm:X"`` …), glob words
  (``run-p "build:*"``) matched against every name;
* the npm pre/post hooks of every reachable script (``preX`` / ``postX``);
* the scripts npm runs for ``npm pack`` / ``publish`` / ``version`` / ``restart``
  when a reachable script calls one of those;
* every ``<name>:<suffix>`` script of a reached name (run-script-os conventions);
* EVERYTHING, when a reachable script does anything the closure cannot follow. The
  followable set is an allowlist: script runners (``npm run`` …), an interpreter
  running a local file, and build / lint / filesystem tools that cannot run a
  package script. A dependency's bin, ``make``, ``xargs``, a pipe or stdin
  redirect, a subshell, ``sh -c``, inline code (``node -e``), a shell variable or
  command substitution, ``eval``, bash sequence braces, or a read of package.json /
  ``npm_package_*`` all count as "could run any script".

:func:`restore_externally_invoked` then checks the rest of the tree: a local file a
reachable script runs must be present, and if it is, no file in the tree may spawn a
process (or reach one by a computed name); no code or config file may name the
script, match it with a glob, or spawn a package manager with a built name.

Unparseable input (invalid JSON, a duplicate key, a non-string script) answers
``None``: the caller keeps its finding as it was.
"""

from __future__ import annotations

import bisect
import fnmatch
import json
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field

# The scripts npm (or yarn / pnpm) can run for someone who installs the package: as a
# registry dependency (install trio), or as a git dependency (npm installs the clone's
# dev deps and packs it: prepare, prepack, postpack, the npm 6 ``prepublish``, and the
# npm 8+ ``dependencies`` hook of the clone's own install).
CONSUMER_ROOTS = frozenset({
    "preinstall", "install", "postinstall",
    "preprepare", "prepare", "postprepare",
    "prepack", "postpack", "prepublish", "dependencies",
})

# npm subcommands that run named lifecycle scripts beyond the one they are named after.
_VERB_SCRIPTS = {
    "pack": ("prepack", "prepare", "postpack"),
    "publish": ("prepublishOnly", "prepack", "prepare", "postpack", "prepublish",
                "publish", "postpublish"),
    "version": ("preversion", "version", "postversion"),
    "restart": ("prestop", "stop", "poststop", "prerestart", "restart", "postrestart",
                "prestart", "start", "poststart"),
    "start": ("start",),
    "stop": ("stop",),
    "test": ("test",),
    "t": ("test",),
    "tst": ("test",),
    "install": tuple(CONSUMER_ROOTS),
    "i": tuple(CONSUMER_ROOTS),
    "add": tuple(CONSUMER_ROOTS),
    "ci": tuple(CONSUMER_ROOTS),
    "clean-install": tuple(CONSUMER_ROOTS),
    "rebuild": tuple(CONSUMER_ROOTS),
    "rb": tuple(CONSUMER_ROOTS),
}
for _v in ("it", "cit", "sit", "install-test", "install-ci-test", "clean-install-test"):
    _VERB_SCRIPTS[_v] = (*CONSUMER_ROOTS, "test")
# Lifecycle names a verb reaches even when package.json has no script by that name
# (their pre/post hooks still run around npm's default).
_VERB_TARGET_NAMES = frozenset(n for v in _VERB_SCRIPTS.values() for n in v)

# Words are split on shell syntax, quotes and `=` / `,` (``A=x``, ``--scripts=a,b``).
_WORD_SPLIT_RE = re.compile(r"[\s;&|()<>'\"`=,{}\[\]\\]+")
# Something the closure cannot follow: inline code, eval, a shell variable / command
# substitution (``npm run $X``), or a read of package.json / its env projection.
_OPAQUE_RE = re.compile(
    r"\$(?!npm_execpath\b|npm_node_execpath\b)[\w{(]|`|\beval\b|"
    r"\bnode\b[^&|;]*\s(?:-e|--eval|-p|--print)\b|"
    r"\b(?:python3?|perl|ruby|php)\b[^&|;]*\s-[ce]\b|"
    r"\b(?:deno|bun)\s+(?:eval|-e|--eval)\b|"
    r"package\.json|npm_package_|\bnpm\s+pkg\b",
    re.IGNORECASE,
)
_RUNNER_PREFIX_RE = re.compile(r"^(?:npm|yarn|pnpm|bun):")


@dataclass
class ScriptsInfo:
    scripts: dict[str, str]
    # (0-based line, column start, column end) of each script's VALUE string token,
    # quotes included, in the raw text.
    spans: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    _reachable: set[str] | None = None

    @property
    def reachable(self) -> set[str]:
        if self._reachable is None:
            self._reachable = reachable_scripts(self.scripts)
        return self._reachable


class _MalformedError(Exception):
    pass


def _no_dupes(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _MalformedError("duplicate key")
    return dict(pairs)


class _Locator:
    """A JSON reader that records where each top-level ``scripts.<name>`` value
    string sits in the raw text."""

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.spans: dict[str, tuple[int, int]] = {}

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t\r\n﻿":
            self.i += 1

    def string(self) -> str:
        if self.s[self.i] != '"':
            raise _MalformedError("string")
        start = self.i
        self.i += 1
        while True:
            if self.i >= len(self.s):
                raise _MalformedError("eof")
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
                continue
            if ch == "\n":
                raise _MalformedError("newline in string")
            self.i += 1
            if ch == '"':
                break
        return json.loads(self.s[start:self.i])

    def value(self, path: tuple[str, ...]) -> None:
        self.ws()
        if self.i >= len(self.s):
            raise _MalformedError("eof")
        ch = self.s[self.i]
        if ch == "{":
            self.i += 1
            self.ws()
            if self.s[self.i:self.i + 1] == "}":
                self.i += 1
                return
            while True:
                self.ws()
                key = self.string()
                self.ws()
                if self.s[self.i:self.i + 1] != ":":
                    raise _MalformedError("colon")
                self.i += 1
                self.ws()
                start = self.i
                self.value((*path, key))
                if len(path) == 1 and path[0] == "scripts":
                    self.spans[key] = (start, self.i)
                self.ws()
                c = self.s[self.i:self.i + 1]
                self.i += 1
                if c == "}":
                    return
                if c != ",":
                    raise _MalformedError("comma")
        elif ch == "[":
            self.i += 1
            self.ws()
            if self.s[self.i:self.i + 1] == "]":
                self.i += 1
                return
            while True:
                self.value((*path, "[]"))
                self.ws()
                c = self.s[self.i:self.i + 1]
                self.i += 1
                if c == "]":
                    return
                if c != ",":
                    raise _MalformedError("comma")
        elif ch == '"':
            self.string()
        else:
            m = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null").match(
                self.s, self.i)
            if not m:
                raise _MalformedError("literal")
            self.i = m.end()


def parse_scripts(text: str) -> ScriptsInfo | None:
    """The ``scripts`` of a package.json and where each value sits, or ``None`` when
    the file is not plain, unambiguous JSON with a string-valued ``scripts`` object."""
    try:
        data = json.loads(text.lstrip("﻿"), object_pairs_hook=_no_dupes)
        loc = _Locator(text)
        loc.value(())
        loc.ws()
        if loc.i != len(text):
            return None
    except (ValueError, _MalformedError, IndexError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in scripts.items()):
        return None
    line_starts = [0]
    line_starts.extend(m.end() for m in re.finditer("\n", text))
    spans: dict[str, tuple[int, int, int]] = {}
    for name, (a, b) in loc.spans.items():
        ln = bisect.bisect_right(line_starts, a) - 1
        if bisect.bisect_right(line_starts, b - 1) - 1 != ln:
            return None
        spans[name] = (ln, a - line_starts[ln], b - line_starts[ln])
    if set(spans) != set(scripts):
        return None
    return ScriptsInfo(scripts=scripts, spans=spans)


def _brace_expand(word: str, depth: int = 0) -> list[str]:
    """Shell / minimatch brace expansion (``f:{a,b}`` → ``f:a``, ``f:b``)."""
    m = re.search(r"\{([^{}]*)\}", word)
    if not m or depth > 4:
        return [word]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out.extend(_brace_expand(word[:m.start()] + alt + word[m.end():], depth + 1))
        if len(out) > 256:
            break
    return out


def shell_words(cmd: str) -> list[str] | None:
    """The command's words as the shell joins them (``fe"tch"`` / ``fe''tch`` /
    ``fe\\tch`` are one word ``fetch``), or ``None`` when it cannot be tokenized."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace = " \t\r\n"  # not NBSP: the shell does not split on it
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return None


# Commands a reachable script may run without making the closure give up: script
# runners (analysed word by word below), interpreters running a local file (the
# caller checks the tree for that file and for process spawning), and build / lint /
# filesystem tools that cannot run a package script. Anything else (a dependency's
# bin, make, awk, xargs, task, nx, wireit, turbo …) could run any script.
_RUNNERS = frozenset({"npm", "yarn", "pnpm", "bun", "run-s", "run-p", "npm-run-all",
                      "npm-run-all2", "$npm_execpath"})
_RUNNER_SUBCOMMANDS = frozenset({
    "run", "run-script", "rum", "urn", "start", "stop", "test", "t", "tst", "restart",
    "install", "i", "add", "ci", "clean-install", "rebuild", "rb", "pack", "publish",
    "version", "it", "cit", "sit", "install-test", "install-ci-test",
    "clean-install-test",
})
_INERT_TOOLS = frozenset({
    "tsc", "tsup", "tsc-alias", "vite", "rollup", "webpack", "esbuild", "swc", "babel",
    "prettier", "eslint", "biome", "husky", "rimraf", "del-cli", "mkdirp", "copyfiles",
    "cpy", "echo", "true", "false", "exit", "cp", "mv", "rm", "mkdir", "touch", "chmod",
    "ln", "cd", "typedoc", "api-extractor", "ncc", "terser", "uglifyjs", "jest",
    "vitest", "mocha", "playwright", "svelte-kit", "svelte-package", "changeset",
    "is-ci", "node-gyp-build", "tshy", "unbuild", "pkgroll", "microbundle",
})
_SEGMENT_OPS = frozenset({"&&", "||", ";", "&"})
# Of those, the ones that load the package's own JS (a vite / webpack / jest / eslint /
# prettier / babel config, plugins, a binding.gyp build): they run local code, so the
# caller applies the same tree check as for `node file.js`.
_TRULY_INERT = frozenset({"tsc", "echo", "true", "false", "exit", "cp", "mv", "rm",
                          "mkdir", "touch", "chmod", "ln", "cd", "rimraf", "del-cli",
                          "mkdirp", "copyfiles", "cpy", "is-ci", "husky"})
RUNS_PACKAGE_CODE = "\0runs-package-code"


def _segment_ok(seg: list[str], names: list[str]) -> bool:
    """Can the closure follow this simple command (no pipe / redirect-in / subshell)?"""
    i = 0
    while i < len(seg) and re.match(r"^[A-Za-z_]\w*=", seg[i]):
        i += 1  # leading env assignments
    while i < len(seg) and seg[i] in ("cross-env", "env"):
        i += 1
        while i < len(seg) and (re.match(r"^[A-Za-z_]\w*=", seg[i]) or seg[i] == "--"):
            i += 1
    if i >= len(seg):
        return True
    if "/" in seg[i] and not re.match(r"^(?:\./)?node_modules/\.bin/[^/]+$", seg[i]):
        return False  # `./bin/tsc` runs a package file, not the tool its name suggests
    cmd = seg[i].rsplit("/", 1)[-1] if not seg[i].startswith("$") else seg[i]
    rest = [w for w in seg[i + 1:] if not w.startswith("-")]
    if cmd in _INERT_TOOLS:
        return True
    if cmd in ("node", "tsx", "ts-node", "sh", "bash", "zsh", "dash"):
        # Runs a local file (the caller checks the tree for it); `sh -c "<cmd>"` and
        # `sh -s` (commands on stdin) are not followable.
        return not any(w in ("-c", "-s") or re.fullmatch(r"-[a-z]*c[a-z]*", w)
                       for w in seg[i + 1:])
    if cmd in _RUNNERS:
        if cmd in ("run-s", "run-p", "npm-run-all", "npm-run-all2"):
            return True
        if not rest:
            return cmd in ("yarn", "bun", "pnpm")  # bare `yarn` = install
        if rest[0] in _RUNNER_SUBCOMMANDS:
            return True
        # `yarn x` / `pnpm x` / `bun x`: a script name (or glob of one) only.
        return cmd in ("yarn", "pnpm", "bun") and (
            rest[0] in names or "/" in rest[0] or rest[0].endswith(
                (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")))
    if cmd == "concurrently":
        return all(w.startswith(("npm:", "yarn:", "pnpm:", "bun:")) for w in rest)
    return False


def _followable(words: list[str], names: list[str]) -> bool:
    if any(w in ("|", "|&", "<", "<<", "<<<", "(", ")", "<(") for w in words):
        return False
    seg: list[str] = []
    ws = [*words, ";"]
    i = 0
    while i < len(ws):
        w = ws[i]
        if re.fullmatch(r">>?|>&", w) or (re.fullmatch(r"\d", w) and i + 1 < len(ws)
                                          and re.fullmatch(r">>?|>&", ws[i + 1])):
            # an output redirect and its target (`> /dev/null`, `2>&1`)
            i += 1 if re.fullmatch(r"\d", w) else 0
            i += 2
            continue
        if w in _SEGMENT_OPS or re.fullmatch(r"[;&|<>()]+", w):
            if w not in _SEGMENT_OPS:
                return False
            if seg and not _segment_ok(seg, names):
                return False
            seg = []
        else:
            seg.append(w)
        i += 1
    return True


def _referenced(cmd: str, names: list[str]) -> set[str] | None:
    """Script names a command can run, or ``None`` for "any of them"."""
    if _OPAQUE_RE.search(cmd) or re.search(r"\{[^{}]*\.\.[^{}]*\}", cmd):
        return None  # (bash sequence braces `{h..h}` too)
    words = shell_words(cmd)
    if words is None or not _followable(words, names):
        return None
    out: set[str] = set()
    for word in words:
        cands = {word}
        cands.update(p for p in re.split(r"[=,]", word) if p)
        for c in list(cands):
            cands.update(_brace_expand(c))
        for w in cands:
            w = _RUNNER_PREFIX_RE.sub("", w)
            if w in _VERB_SCRIPTS:
                out.update(_VERB_SCRIPTS[w])
            if any(ch in w for ch in "*?["):
                out.update(n for n in names if fnmatch.fnmatchcase(n, w))
            elif w in names:
                out.add(w)
    # Backstop: a name anywhere in the command once quotes and escapes are gone
    # (names with spaces, `=`, `,`, or anything the word split above misses).
    flat = re.sub(r"[\"'\\]", "", cmd)
    out.update(n for n in names if script_word_re(n).search(flat))
    return out


def reachable_scripts(scripts: dict[str, str],
                      roots: frozenset[str] = CONSUMER_ROOTS) -> set[str]:
    """Every script name that can run when a consumer installs the package (see the
    module docstring). Over-approximate by design: a reached name also reaches its
    npm pre/post hooks (even when the name itself has no script: `npm start` runs
    `prestart` around its default `node server.js`) and every `<name>:<suffix>`
    script (run-script-os picks `postinstall:linux` by convention)."""
    names = list(scripts)
    todo = [n for n in names if n in roots]
    seen: set[str] = set()
    touched: set[str] = set()
    while todo:
        n = todo.pop()
        if n in touched:
            continue
        touched.add(n)
        refs = {f"pre{n}", f"post{n}"}
        refs.update(s for s in names if s.startswith(n + ":"))
        if n in scripts:
            seen.add(n)
            more = _referenced(scripts[n], names)
            if more is None:
                return set(names)
            refs |= more
        todo.extend(r for r in refs if r not in touched and (
            r in scripts or r in _VERB_TARGET_NAMES))
    return seen


def maintainer_scripts_at(info: ScriptsInfo, line_idx: int,
                          spans: list[tuple[int, int]]) -> set[str] | None:
    """The unreachable scripts holding every ``[start, end)`` match span on raw line
    ``line_idx``, or ``None`` when any span is not wholly inside the value of a
    script no consumer path reaches."""
    if not spans:
        return None
    reach = info.reachable
    hit: set[str] = set()
    for a, b in spans:
        owner = None
        for name, (ln, c0, c1) in info.spans.items():
            if ln == line_idx and c0 < a and b < c1:
                owner = name
                break
        if owner is None or owner in reach:
            return None
        hit.add(owner)
    return hit


def script_word_re(name: str) -> re.Pattern[str]:
    """A script name as a whole word (names carry ``:`` ``-`` ``.``)."""
    return re.compile(r"(?<![\w:.\-/@])" + re.escape(name) + r"(?![\w:.\-/])")


PIPE_TO_SHELL = "curl/wget piped to shell"
MAINTAINER_WHY = (
    "Maintainer-only package.json script: npm never runs it when the package is "
    "installed (it is not an install lifecycle script and none of those reaches it). "
    "It runs only when someone types `npm run` for it in a checkout.")

# Code that builds a script name at runtime, or reads package.json's scripts table.
_DYNAMIC_RUN_RE = re.compile(
    r"\b(?:npm|yarn|pnpm|bun|npm_execpath)\b[^\n]{0,60}?\brun(?:-script)?\b\s*"
    r"(?:['\"`]\s*(?:\+|,\s*[A-Za-z_$])|\$\{|\+)|"
    r"\.scripts\s*(?:\[|\.\s*[A-Za-z_$])|npm_package_scripts_|"
    r"\b(?:run-s|run-p|npm-run-all|concurrently)\b[^\n]{0,80}?(?:\+|\$\{)",
)
_RUNNER_LINE_RE = re.compile(
    r"\b(?:npm|yarn|pnpm|bun|node|npx|run-s|run-p|run-all|npm-run-all2?|concurrently|"
    r"wireit|turbo|lerna|nx|npm_execpath)\b|\bnpm:")
_GLOB_WORD_RE = re.compile(r"""['"`\s]((?:npm:|yarn:|pnpm:)?[\w:.\-]*\*[\w:.\-*]*)['"`\s]""")


def mark_maintainer(finding: object, scripts: set[str]) -> None:
    """Downgrade a pipe-to-shell finding that sits in maintainer-only scripts to low,
    remembering what :func:`restore_externally_invoked` puts back."""
    finding._maintainer_restore = (  # type: ignore[attr-defined]
        finding.severity, finding.payload, frozenset(scripts))  # type: ignore[attr-defined]
    finding.severity = "low"  # type: ignore[attr-defined]
    finding.payload = False  # type: ignore[attr-defined]
    finding.remediation = MAINTAINER_WHY  # type: ignore[attr-defined]


# What a registry install runs (no prepare / pack: those run for a git dependency,
# whose tree is the repo, not the published tarball).
REGISTRY_ROOTS = frozenset({"preinstall", "install", "postinstall"})
_LOCAL_FILE_WORD_RE = re.compile(
    r"^(?:\./|\.\./)?[\w@.\-]+(?:/[\w@.\-]+)*\.(?:[cm]?[jt]sx?|sh|bash|zsh|py|rb|pl|ps1)$")


# Programs that run the file named after them (`node scripts/setup`, `sh install`).
_INTERPRETERS = frozenset({
    "node", "nodejs", "sh", "bash", "zsh", "dash", "ksh", "source", ".", "tsx", "ts-node",
    "ts-node-esm", "esno", "esr", "jiti", "bun", "deno", "python", "python3", "ruby",
    "perl", "php", "pwsh", "powershell", "zx", "babel-node", "coffee",
})
# An interpreter's first word that is a subcommand (`bun run x`), not a file.
_SUBCOMMANDS = frozenset({"run", "x", "exec", "test", "install", "i", "add", "build",
                          "eval", "repl", "upgrade", "create", "init", "pm", "link",
                          "task", "-"})
_RESOLVE_SUFFIXES = ("", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".py",
                     "/index.js", "/index.mjs", "/index.cjs", "/index.ts")


def _norm(base: str, w: str) -> str | None:
    parts: list[str] = []
    for seg in (base + w).split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def _script_file_refs(cmd: str, main: str) -> list[str]:
    """Local files a command runs: a word shaped like a script path, or the argument
    of an interpreter (`node scripts/setup`, `node .` = the package's main)."""
    words = shell_words(cmd) or [w for w in _WORD_SPLIT_RE.split(cmd) if w]
    refs: list[str] = []
    for i, w in enumerate(words):
        if not w or w.startswith("-"):
            continue
        if w.rsplit("/", 1)[-1] in _INERT_TOOLS - _TRULY_INERT:
            refs.append(RUNS_PACKAGE_CODE)
            continue
        prev = next((p for p in reversed(words[:i]) if not p.startswith("-")), "")
        if _LOCAL_FILE_WORD_RE.match(w):
            refs.append(w)
        elif prev.rsplit("/", 1)[-1] in _INTERPRETERS and w not in _SUBCOMMANDS:
            refs.append(main or "index.js" if w in (".", "./") else w)
    return refs


def _named_files(info: ScriptsInfo, pkg_path: str, roots: frozenset[str],
                 texts: dict[str, str]) -> tuple[set[str], bool]:
    """``(files a reachable script runs that the tree holds, whether one is missing)``.
    A missing one (a sampled repo scan, a file the fetch skipped, a dependency path)
    is unseen code that could run any script, so the downgrade cannot stand."""
    base = pkg_path.rsplit("/", 1)[0] + "/" if "/" in pkg_path else ""
    have = {p[2:] if p.startswith("./") else p: p for p in texts}
    try:
        main = str(json.loads(texts.get(pkg_path) or "{}").get("main") or "")
    except (ValueError, AttributeError):
        main = ""
    found: set[str] = set()
    missing = False
    for name in reachable_scripts(info.scripts, roots):
        for w in _script_file_refs(info.scripts[name], main):
            if w == RUNS_PACKAGE_CODE:
                found.add(w)
                continue
            p = _norm(base, w)
            hit = next((have[p + s] for s in _RESOLVE_SUFFIXES
                        if p is not None and p + s in have), None)
            if hit is None:
                missing = True
            else:
                found.add(hit)
    return found, missing


# Never executed at install / run time: docs, lockfiles, CI recipes, type
# declarations, media. Everything else (JSON / YAML configs included: wireit, nx
# project.json and Taskfile.yml all name scripts) can run a script.
_DOC_EXTS = frozenset({
    ".md", ".markdown", ".mdx", ".rst", ".txt", ".map", ".css", ".scss", ".svg", ".png",
    ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".csv",
    ".license",
})
_LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                        "pnpm-lock.yaml", "bun.lock", "bun.lockb"})
_CI_PARTS = frozenset({".github", ".gitlab", ".circleci", ".buildkite"})
_CI_NAMES = frozenset({".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml",
                       "appveyor.yml", "bitbucket-pipelines.yml"})


def _is_code_file(path: str) -> bool:
    parts = path.lower().split("/")
    low = parts[-1]
    dot = low.rfind(".")
    ext = low[dot:] if dot != -1 else ""
    if (low in _LOCKFILES or low in _CI_NAMES or re.search(r"\.d\.[cm]?ts$", low)
            or (ext in (".yml", ".yaml") and any(p in _CI_PARTS for p in parts[:-1]))
            or (ext in ("", *_DOC_EXTS) and re.match(
                r"(?:license|licence|copying|changelog|history|authors|notice)\b", low))):
        return False
    return ext not in _DOC_EXTS


# A process spawn: code that could run `npm run <anything>` however the name is built.
_SPAWN_RE = re.compile(
    r"child_process|\bexec(?:Sync|File|FileSync)?\s*\(|\bspawn(?:Sync)?\s*\(|\bfork\s*\(|"
    r"\bexeca\b|\bshelljs\b|\bzx\b|\$`|Bun\.(?:spawn|\$)|Deno\.(?:run|Command)|"
    r"\bsubprocess\b|\bos\.(?:system|popen|exec\w*|spawn\w*)|\bsystem\s*\(|\bpopen\b|"
    r"\bProcessBuilder\b|\bRuntime\.getRuntime|"
    # ...or code that could reach one by a computed name
    r"process\.(?:binding|_linkedBinding|dlopen)|\brequire\s*\(\s*[^'\"`\s)]|"
    r"\bimport\s*\(\s*[^'\"`\s)]|\bFunction\s*\(|\beval\s*\(|\bvm\.\w+|"
    r"__import__|\bimportlib\b|\bgetattr\s*\(")
# A string naming a package manager.
_PM_STRING_RE = re.compile(r"""['"`](?:npm|yarn|pnpm|bun|npx)(?:\.cmd)?(?:['"`]|\s)|"""
                           r"npm_execpath|npm_node_execpath")


ALLOWLIST_WHY = (
    "A tunnel / webhook host listed in a host or origin allowlist (Vite allowedHosts, "
    "Django ALLOWED_HOSTS, CORS origins): the server ACCEPTS requests for it; nothing "
    "here sends data there.")


# ── Files a consumer can run (shared by the dev-tooling and dataset restores) ──
# A shell running a file: `sh x`, `bash -e x`, `zsh x`, `source x`, `. x`, `exec x`.
_SHELL_RUN_RE = re.compile(
    r"""(?:^|[\s;&|(`'"\[,@])(?:(?:ba|z|da|k)?sh|source|exec|\.)\s+(?:-[\w-]+\s+)*"""
    r"""['"]?([^\s;&|)'"`\],]+)""",
    re.MULTILINE)
# A path to a shell script used as a command word. In a shell script every such word
# counts; in a config only on a line that runs something (`command:`, `run:`, `exec`
# …), so a YAML list of paths (vllm's tools/agent/domains.yaml) is not a run.
_SCRIPT_WORD_RE = re.compile(
    r"""(?:^|[\s;&|(`'"\[,@])((?:\.{0,2}/)?[\w.\-/]+\.(?:sh|bash|zsh|ps1)(?![\w.\-/])"""
    r"""|\.{1,2}/[\w.\-/]+)""",
    re.MULTILINE)
_RUN_KEY_LINE_RE = re.compile(
    r"""(?:command|cmd|entrypoint|run|exec|script|start\w*|args)['"]?\s*[:=]""",
    re.IGNORECASE)
_SHELL_FILE_EXTS = frozenset({"", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"})
_NON_RUNTIME_DIRS = frozenset({
    "test", "tests", "__tests__", "spec", "docs", "doc", "example", "examples",
    "fixture", "fixtures",
})
_MCP_CONFIG_NAMES = frozenset({"mcp.json", ".mcp.json", "server.json", "smithery.yaml",
                               "smithery.yml"})
_MAKEFILES = frozenset({"makefile", "gnumakefile"})
_MAKE_TARGET_RE = re.compile(r"^([\w.\-]+(?:\s+[\w.\-]+)*)\s*::?(?!=)(.*)$")
_DOCKER_RUN_RE = re.compile(r"^\s*(?:RUN|CMD|ENTRYPOINT)\b", re.IGNORECASE)
_COMPOSE_NAME_RE = re.compile(r"(?:docker-)?compose[\w.\-]*\.ya?ml$")


def _pkg_run_strings(text: str, path: str, texts: dict[str, str],
                     roots: frozenset[str] | None) -> list[str]:
    """package.json: the scripts that run (``roots`` None: every script) and the
    bin / main / module / exports / browser entry points."""
    try:
        data = json.loads(text.lstrip("﻿"))
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[str] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        table = {k: v for k, v in scripts.items() if isinstance(v, str)}
        names = set(table) if roots is None else reachable_scripts(table, roots)
        out += [table[n] for n in sorted(names) if n in table]
    info = parse_scripts(text) if roots is not None else None
    if info is not None:
        out += sorted(f for f in _named_files(info, path, roots, texts)[0]
                      if f != RUNS_PACKAGE_CODE)

    def walk(v: object) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    for key in ("bin", "main", "module", "exports", "browser"):
        walk(data.get(key))
    return out


def _make_recipes(text: str, targets: frozenset[str]) -> list[str]:
    """The target lines and recipe lines of the named Makefile targets."""
    out: list[str] = []
    take = False
    for ln in text.split("\n"):
        if ln.startswith("\t"):
            if take:
                out.append(ln)
            continue
        m = _MAKE_TARGET_RE.match(ln)
        if m:
            take = bool(set(m.group(1).split()) & targets)
            if take:
                out.append(ln)
        elif ln.strip() and not ln.lstrip().startswith("#"):
            take = False
    return out


def _docker_run_lines(text: str) -> list[str]:
    """RUN / CMD / ENTRYPOINT instructions, continuation lines joined."""
    out: list[str] = []
    cur: list[str] | None = None
    for ln in text.split("\n"):
        if cur is not None:
            cur.append(ln)
        elif _DOCKER_RUN_RE.match(ln):
            cur = [ln]
        if cur is not None and not ln.rstrip().endswith("\\"):
            out.append(" ".join(cur))
            cur = None
    if cur:
        out.append(" ".join(cur))
    return out


def _run_key_lines(text: str) -> list[str]:
    """Config lines that run something: a run-key line (``_RUN_KEY_LINE_RE``) plus,
    when its value is a block list, the items that follow: YAML ``- item`` lines
    (more indented, or ``-`` at the key's indent) until a dedent, or JSON array
    elements until the closing ``]``."""
    out: list[str] = []
    carry: tuple[int, bool] | None = None   # (key indent, JSON array)
    for ln in text.split("\n"):
        ind = len(ln) - len(ln.lstrip())
        if carry is not None:
            key_ind, js = carry
            if js:
                out.append(ln)
                if "]" in ln:
                    carry = None
                continue
            if not ln.strip():
                continue
            if ind > key_ind or (ind == key_ind and ln.lstrip().startswith("- ")):
                out.append(ln)
                continue
            carry = None
        m = _RUN_KEY_LINE_RE.search(ln)
        if m:
            out.append(ln)
            rest = ln[m.end():].strip()
            if not rest or rest in ("|", ">", "|-", ">-"):
                carry = (ind, False)
            elif rest.startswith("[") and "]" not in rest:
                carry = (ind, True)
    return out


def consumer_run_strings(texts: dict[str, str], *, roots: frozenset[str] | None,
                         skip: Callable[[str], bool] = lambda p: False) -> list[str]:
    """Text naming what a consumer of the tree can run, for "is this file run?":
    package.json scripts (``roots``: those reachable from these roots; None: every
    script) and bin / main / exports; a shell running a file in any script or config
    (``sh x``, ``bash x``, ``source x``, ``. x``, ``exec x``, ``./x.sh``); Dockerfile /
    Containerfile RUN / CMD / ENTRYPOINT and compose files; MCP / smithery configs
    (``command`` + ``args``, ``startCommand``); Procfile; the ``install`` / ``all``
    targets of a Makefile; a VS Code task that runs on folder open. Not docs, CI
    recipes, test / example dirs, or files ``skip`` names (the candidates themselves).
    Callers check ``_SPAWN_RE`` code that names a file separately."""
    out: list[str] = []
    for p, t in texts.items():
        if not t or skip(p):
            continue
        parts = p.lower().split("/")
        low = parts[-1]
        if any(x in _NON_RUNTIME_DIRS or x in _CI_PARTS for x in parts[:-1]) \
                or low in _CI_NAMES:
            continue
        if low == "package.json":
            out += _pkg_run_strings(t, p, texts, roots)
            continue
        if low in _MAKEFILES:
            out += _make_recipes(t, frozenset({"install", "all"}))
            continue
        if low == "tasks.json" and ".vscode" in parts[:-1]:
            if "folderOpen" in t:
                out.append(t)
            continue
        if low.startswith(("dockerfile", "containerfile")) or low.endswith(
                (".dockerfile", ".containerfile")):
            out += _docker_run_lines(t)
            continue
        if (low in _MCP_CONFIG_NAMES or low.startswith("claude_desktop_config")
                or _COMPOSE_NAME_RE.match(low) or low == "procfile"):
            out.append(t)
            continue
        dot = low.rfind(".")
        ext = low[dot:] if dot > 0 else ""
        if ext in _DOC_EXTS:
            continue
        if ext == ".mk":
            # An included make fragment: its targets are maintainer targets unless
            # they are install / all.
            out += _make_recipes(t, frozenset({"install", "all"}))
            continue
        out += [m.group(1) for m in _SHELL_RUN_RE.finditer(t)]
        if ext in _SHELL_FILE_EXTS:
            out += [m.group(1) for m in _SCRIPT_WORD_RE.finditer(t)]
        else:
            out += [m.group(1) for ln in _run_key_lines(t)
                    for m in _SCRIPT_WORD_RE.finditer(ln)]
    return out


def _names_file(path: str, strings: list[str]) -> bool:
    """A string names the file: its tree path, or its file name as a word."""
    rx = re.compile(r"(?<![\w.\-])" + re.escape(path.rsplit("/", 1)[-1]) + r"(?![\w\-])")
    return any(path in t or rx.search(t) for t in strings)


DATASET_WHY = (
    "Text in a dataset file (an attack-prompt or evaluation corpus): data the code "
    "reads, not an instruction file and not run by the code found. An agent that reads "
    "the file still sees it, so it is reported as high.")


def _restore_datasets(findings: list, texts: dict[str, str]) -> None:
    """A dataset finding capped at high (``scan._is_dataset_file``) gets its severity
    back when code that can execute something (``_SPAWN_RE``) names the file by path or
    file name, when anything a consumer can run names it (``consumer_run_strings``,
    every package.json script included), or when the file is not in ``texts``
    (unseen).

    Policy (accepted 2026-10-19): an MCP tool or agent that READS a dataset file and
    returns its text to the model is an injection path this check does not follow.
    Such a file stays capped at high (Review), never Safe; it is not restored to
    critical."""
    from src.scanner.scan import _is_dataset_file

    marked = [f for f in findings if getattr(f, "_dataset_restore", None)
              and f.severity == "high" and f.remediation == DATASET_WHY]
    if not marked:
        return
    spawners = [t for p, t in texts.items()
                if t and _is_code_file(p) and not _is_dataset_file(p) and _SPAWN_RE.search(t)]
    runs = consumer_run_strings(texts, roots=None, skip=_is_dataset_file)
    for f in marked:
        path = f.file_path
        if path not in texts or _names_file(path, spawners) or _names_file(path, runs):
            f.severity, f.remediation = f._dataset_restore, ""
            f._dataset_restore = None


def mark_allowlist(finding: object, severity: str, keys: set[str]) -> None:
    """A webhook/tunnel-host match that is an allowlist element (scan.py
    ``_host_allowlist_entry``), reported low until the rest of the tree is checked."""
    finding._allowlist_restore = (severity, frozenset(keys))  # type: ignore[attr-defined]
    finding.remediation = ALLOWLIST_WHY  # type: ignore[attr-defined]


def _restore_allowlist_hosts(findings: list, texts: dict[str, str]) -> None:
    """Another file of the tree that reads the allowlist (``settings.ALLOWED_HOSTS``,
    an import of the config) may send to it: restore the finding's severity."""
    marked = [f for f in findings if getattr(f, "_allowlist_restore", None)
              and f.severity == "low" and f.remediation == ALLOWLIST_WHY]
    for f in marked:
        sev, keys = f._allowlist_restore
        # The file's import name: `vite.config` (vite.config.ts), `settings`.
        stem = re.escape(f.file_path.rsplit("/", 1)[-1].rsplit(".", 1)[0])
        key_alt = "|".join(re.escape(k) for k in keys)
        # Reading THIS allowlist from elsewhere: an import of the file (any line that
        # imports / requires and names it), or the key as a property / index /
        # imported name (`settings.ALLOWED_HOSTS`, `cfg["allowedHosts"]`,
        # `import { allowedHosts }`). Another file's own local `const allowedHosts`
        # is a different variable.
        rx = re.compile(
            r"(?:\bimport\b|\brequire\s*\(|\bfrom\b)[^\n]*(?<![\w$])" + stem + r"(?![\w$])|"
            r"[.\[]\s*['\"]?(?:" + key_alt + r")(?![\w$])|"
            r"(?:\bimport\b|\bfrom\b)[^\n]*(?<![\w$])(?:" + key_alt + r")(?![\w$])|"
            r"\{[^}\n]*(?<![\w$])(?:" + key_alt + r")(?![\w$])[^}\n]*\}\s*=\s*require")
        if f.file_path not in texts or any(
                p != f.file_path and t and _is_code_file(p) and rx.search(t)
                for p, t in texts.items()):
            f.severity, f.remediation = sev, ""
            f._allowlist_restore = None


def _restore_dev_tooling(findings: list, texts: dict[str, str],
                         roots: frozenset[str]) -> None:
    """A dev-tooling script (``scan._is_dev_tooling_script``: ``tools/dev/``,
    ``dev/``, ``hack/`` …) is graded like CI tooling only while nothing a consumer runs
    starts it: anything a consumer can run that names the file
    (``consumer_run_strings``: install-reachable npm scripts, bin / main / exports,
    shell lines, Dockerfile / compose, MCP / smithery configs, Procfile, Makefile
    install / all, VS Code folder-open tasks), or code that spawns processes and names
    it, puts it back on the shipped surface. Its findings are then scanned again without the
    downgrade and graded as shipped code (``Finding.payload``)."""
    from src.scanner.scan import _is_dev_tooling_script, _scan_content

    dev = sorted({f.file_path for f in findings
                  if f.file_path and _is_dev_tooling_script(f.file_path)})
    if not dev:
        return
    runs = consumer_run_strings(texts, roots=roots, skip=_is_dev_tooling_script)
    spawners = [t for p, t in texts.items()
                if t and p.rsplit("/", 1)[-1].lower() != "package.json"
                and not _is_dev_tooling_script(p) and _is_code_file(p)
                and _SPAWN_RE.search(t)]
    for path in dev:
        if path not in texts:
            continue
        if not (_names_file(path, runs) or _names_file(path, spawners)):
            continue
        fresh, _p, _s = _scan_content(texts[path], path, dev_tooling_runs=True)
        for f in fresh:
            if f.kind == "defect":
                f.payload = True
        findings[:] = [f for f in findings if f.file_path != path] + fresh


def restore_externally_invoked(findings: list, texts: dict[str, str], *,
                               registry_artifact: bool = False) -> None:
    """Undo the maintainer-script downgrade of a pipe-to-shell finding when the
    package.json closure alone cannot rule a consumer path out: another file of the
    tree can run the script (a postinstall's ``node setup.js`` calling ``npm run
    fetch``), or a reachable install script runs a local file the tree does not hold.
    Over-approximate: any code file naming the script as a word, matching it with a
    glob word, or building a script name at runtime restores the finding.

    ``registry_artifact``: ``texts`` is a published tarball, where npm runs only the
    install trio; elsewhere (a repo / local tree) the git-dependency roots count too.
    Every caller of ``_scan_content`` that can see a package.json must call this."""
    _restore_allowlist_hosts(findings, texts)
    _restore_datasets(findings, texts)
    _restore_dev_tooling(findings, texts,
                         REGISTRY_ROOTS if registry_artifact else CONSUMER_ROOTS)
    # (A finding a later pass already capped further, e.g. to info in an uninstalled
    # or test-dir file, keeps that cap.)
    marked = [f for f in findings if getattr(f, "_maintainer_restore", None)
              and f.severity == "low" and f.remediation == MAINTAINER_WHY]
    if not marked:
        return
    roots = REGISTRY_ROOTS if registry_artifact else CONSUMER_ROOTS
    missing: dict[str, bool] = {}
    named: set[str] = set()
    for path in {f.file_path for f in marked}:
        info = parse_scripts(texts[path]) if texts.get(path) else None
        if info is None:
            missing[path] = True
            continue
        found, missing[path] = _named_files(info, path, roots, texts)
        named |= found
    code: list[str] = []
    for p, t in texts.items():
        if not t or not (p in named or _is_code_file(p)):
            continue
        if p in missing and p.rsplit("/", 1)[-1].lower() == "package.json":
            # The file's own scripts table was the closure's input; the rest of it
            # (a wireit block, a config) can still name a script.
            try:
                data = json.loads(t.lstrip("﻿"))
                data.pop("scripts", None)
                t = json.dumps(data)
            except (ValueError, AttributeError):
                pass
        code.append(t)
    spawners = [t for t in code if _SPAWN_RE.search(t)]
    # Code that spawns a package manager can build any script name at runtime
    # (`'fe' + 'tch'`, `['run'].concat(...)`), and a reachable script that runs a
    # local file hands the install to code that, if anything in the tree spawns, may
    # do the same (transitive requires included).
    dynamic = (any(_DYNAMIC_RUN_RE.search(t) for t in code)
               or any(_PM_STRING_RE.search(t) for t in spawners))
    if spawners and named:
        for path in missing:
            missing[path] = True
    # Glob words (`run-p "build:*"`) count anywhere; a bare `*` / `**` (match every
    # script) only on a line that names a script runner, since elsewhere it is a
    # doc-comment margin or a multiplication.
    globs = {_RUNNER_PREFIX_RE.sub("", g) for t in code for g in _GLOB_WORD_RE.findall(t)
             if g.strip("*")}
    globs |= {_RUNNER_PREFIX_RE.sub("", g) for t in code for ln in t.split("\n")
              if _RUNNER_LINE_RE.search(ln)
              and not ln.lstrip().startswith(("*", "/*", "//", "#"))
              for g in _GLOB_WORD_RE.findall(f" {ln} ")}
    for f in marked:
        sev, payload, owners = f._maintainer_restore
        path = f.file_path
        if (missing[path] or dynamic or any(
                any(script_word_re(n).search(t) for t in code)
                or any(fnmatch.fnmatchcase(n, g) for g in globs) for n in owners)):
            f.severity, f.payload, f.remediation = sev, payload, ""
            f._maintainer_restore = None
