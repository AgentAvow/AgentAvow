"""A ``curl … | sh`` the program SHOWS a person and never runs (DNC sample, round 2,
2026-10-19).

The critical "curl/wget piped to shell" rule matches text. Round 2 found it blocking on
install hints that nothing runs: a script's ``--help`` text (``echo "  curl … | bash"``),
an installer's own error message (``fail "… curl … | bash -s -- --quick"``), a project
web page showing its install command, and a JSON catalog of third-party agents whose
``install`` field a CLI only prints. Each is reported **low** with :data:`WHY_SHOWN`,
never dropped. Every helper here answers conservatively: anything it cannot classify
keeps the critical.

* :func:`shell_shown` (shell scripts): every match on the line sits inside ONE quoted
  argument of ``echo`` / ``printf`` / a function of this file whose body only prints
  (``fail() { printf …; exit 1; }``). It stays critical when the line has a command
  substitution or backtick, a pipe after that command, a redirect to a file, a
  continuation, an unbalanced quote, or runs ``eval`` / ``exec`` / ``source`` / a shell
  / ``xargs`` / ``sudo``; when the string is a variable assignment, not an argument;
  when the function runs its arguments (``"$@"``, ``$1``, ``eval``) or is not defined
  in this file (or the file sources another one); when ``echo`` / ``printf`` is
  redefined or the script's stdout is redirected (``exec > >(sh)``); and when the
  function that holds the line has its output piped, captured or ``eval``-ed anywhere
  in the file (followed through every caller).
* :func:`html_shown` (``.html`` pages): the line is page text or a plain attribute
  (``<span>``, ``data-copy``, ``title``), outside any ``<script>`` element a browser
  runs and with no ``on…=`` handler / ``javascript:`` URL / ``srcdoc`` on the line.
* :func:`json_data_key` (JSON data): the match is the string value of a
  ``"key": "…"`` pair whose key is not command-shaped (``command``, ``run``,
  ``script``, ``args``, ``…Command`` …), in a file that is not a config some tool runs
  (``package.json``, ``devcontainer.json``, ``tasks.json``, ``settings.json`` hooks,
  MCP configs …). It is lowered only with the whole scanned tree in view, and only when
  :func:`json_key_executed` finds no code that hands that key to an exec sink
  (``package_context``).
"""
from __future__ import annotations

import re
from pathlib import Path

WHY_SHOWN = ("Install command shown to a person (help text, an error message, a web "
             "page, or a data field the code only displays); nothing in the scanned "
             "files runs it. Reported for visibility.")

SHELL_EXTS = frozenset({".sh", ".bash", ".zsh", ".ksh"})
HTML_EXTS = frozenset({".html", ".htm", ".xhtml"})
JSON_EXTS = frozenset({".json", ".jsonl", ".ndjson", ".jsonc", ".json5"})

# ---------------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------------

_OPS = ("&&", "||", "|&", ";;", ";", "|", "&", "(", ")")
_REDIR_RE = re.compile(r"(\d*)(>>|>&|<&|<<<|<<-?|>\||&>>|&>|>|<)")
# Redirections that only route output to the terminal or nowhere.
_REDIR_OK = frozenset({">&2", "1>&2", "2>&1", ">&1", ">/dev/null", "2>/dev/null",
                       "1>/dev/null", ">/dev/stderr", ">/dev/tty", "&>/dev/null",
                       ">>/dev/null", "2>>/dev/null"})
# Command words that run (or may run) their arguments or input.
_RUNNERS = frozenset({
    "eval", "exec", "source", ".", "sh", "bash", "zsh", "dash", "ksh", "fish", "xargs",
    "sudo", "su", "doas", "env", "command", "builtin", "nohup", "timeout", "watch",
    "parallel", "ssh", "python", "python3", "perl", "ruby", "node", "trap",
})
# Words that open / continue a compound command before the real command word.
_LEAD_KW = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{",
                      "time", "}", "fi", "done", "esac"})
_PRINTERS = frozenset({"echo", "printf"})
# Statement heads allowed in a print-only function body.
_PRINT_BODY_OK = frozenset({
    "echo", "printf", "exit", "return", "local", "true", "false", ":", "tput", "[",
    "[[", "test", "shift", "declare", "typeset", "readonly",
})
_ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:function\s+([A-Za-z_][\w.:-]*)\s*(?:\(\s*\))?|([A-Za-z_][\w.:-]*)\s*\(\s*\))"
    r"\s*(\{)?")
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")
_SOURCES_RE = re.compile(r"^\s*(?:source|\.)\s+\S", re.M)
_ECHO_REDEFINED_RE = re.compile(
    r"^\s*(?:function\s+)?(?:echo|printf)\s*\(\s*\)|^\s*function\s+(?:echo|printf)\b|"
    r"\balias\s+(?:echo|printf)\s*=|\benable\s+-n\s+(?:echo|printf)\b", re.M)
_STDOUT_REDIRECTED_RE = re.compile(r"\bexec\s+(?:\d*>|&>|>)")


class _Tok:
    __slots__ = ("kind", "text", "start", "end", "quotes")

    def __init__(self, kind: str, text: str, start: int, end: int,
                 quotes: list[tuple[int, int]] | None = None) -> None:
        self.kind = kind          # "word" | "op" | "redir"
        self.text = text
        self.start = start
        self.end = end
        self.quotes = quotes or []  # quoted spans [open quote, close quote] in the line


def _lex(line: str) -> list[_Tok] | None:
    """Tokens of one shell line, or None when the line cannot be read safely: an
    unbalanced quote, a command substitution / backtick / process substitution, a
    heredoc, or a trailing continuation."""
    if "`" in line or "$(" in line or "<(" in line or ">(" in line:
        return None
    toks: list[_Tok] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "#":
            break
        op = next((o for o in _OPS if line.startswith(o, i)), None)
        if op is not None and not (op == "&" and line.startswith("&>", i)):
            toks.append(_Tok("op", op, i, i + len(op)))
            i += len(op)
            continue
        m = _REDIR_RE.match(line, i)
        if m and (m.group(1) or c in "<>&"):
            if m.group(2).startswith("<<") and m.group(2) != "<<<":
                return None  # heredoc
            j = m.end()
            while j < n and line[j] in " \t":
                j += 1
            k = j
            while k < n and line[k] not in " \t;|&()<>":
                k += 1
            toks.append(_Tok("redir", line[i:m.end()] + line[j:k], i, k))
            i = k
            continue
        # A word, with its quoted spans.
        start, quotes = i, []
        while i < n and line[i] not in " \t\r;|&()<>":
            ch = line[i]
            if ch == "\\":
                if i + 1 >= n:
                    return None  # line continuation
                i += 2
                continue
            if ch == "'":
                j = line.find("'", i + 1)
                if j < 0:
                    return None
                quotes.append((i, j))
                i = j + 1
                continue
            if ch == '"':
                j = i + 1
                while j < n and line[j] != '"':
                    j += 2 if line[j] == "\\" else 1
                if j >= n:
                    return None
                quotes.append((i, j))
                i = j + 1
                continue
            if ch == "$" and line.startswith("${", i):
                j = line.find("}", i)
                if j < 0:
                    return None
                i = j + 1
                continue
            i += 1
        toks.append(_Tok("word", line[start:i], start, i, quotes))
    return toks


def _commands(toks: list[_Tok]) -> list[list[_Tok]]:
    """Split tokens into simple commands; each list keeps its trailing op (if any)."""
    out: list[list[_Tok]] = [[]]
    for t in toks:
        out[-1].append(t)
        if t.kind == "op":
            out.append([])
    return [c for c in out if c]


def _head(cmd: list[_Tok]) -> _Tok | None:
    """The command word: past leading keywords and ``VAR=value`` assignments."""
    for t in cmd:
        if t.kind != "word":
            continue
        if t.text in _LEAD_KW or _ASSIGN_RE.match(t.text):
            continue
        return t
    return None


def _line_runs(toks: list[_Tok]) -> bool:
    """A command word on the line runs its arguments / input, or a redirect writes a
    file."""
    for cmd in _commands(toks):
        h = _head(cmd)
        if h is not None and (h.text in _RUNNERS or h.quotes or h.text.startswith("$")):
            return True
        if any(t.kind == "redir" and t.text not in _REDIR_OK for t in cmd):
            return True
    return False


def _code_view(lines: list[str]) -> tuple[list[str], list[bool]] | None:
    """Each line with quoted text, ``${…}`` expansions, comments and heredoc bodies
    blanked, and whether the line STARTS as code (not inside a string or heredoc that
    an earlier line opened). Quotes are followed across lines. None when a quote or
    heredoc never closes."""
    out: list[str] = []
    starts: list[bool] = []
    quote: str | None = None
    heredoc: str | None = None
    pending_doc: str | None = None
    for raw in lines:
        if heredoc is not None:
            out.append("")
            starts.append(False)
            if raw.strip() == heredoc:
                heredoc = None
            continue
        starts.append(quote is None)
        buf: list[str] = []
        i, n = 0, len(raw)
        while i < n:
            c = raw[i]
            if quote == "'":
                if c == "'":
                    quote = None
                buf.append(" ")
                i += 1
                continue
            if quote == '"':
                if c == "\\":
                    buf.append("  "[: min(2, n - i)])
                    i += 2
                    continue
                if c == '"':
                    quote = None
                buf.append(" ")
                i += 1
                continue
            if c == "\\":
                buf.append("  "[: min(2, n - i)])
                i += 2
                continue
            if c in "'\"":
                quote = c
                buf.append(" ")
                i += 1
                continue
            if c == "$" and raw.startswith("${", i):
                j = raw.find("}", i)
                j = n - 1 if j < 0 else j
                buf.append(" " * (j - i + 1))
                i = j + 1
                continue
            if c == "#" and (i == 0 or raw[i - 1] in " \t;&|("):
                break
            if raw.startswith("<<", i) and not raw.startswith("<<<", i):
                hm = _HEREDOC_RE.match(raw, i)
                if hm:
                    pending_doc = hm.group(2)
            buf.append(c)
            i += 1
        out.append("".join(buf))
        if pending_doc is not None and quote is None:
            heredoc, pending_doc = pending_doc, None
    if quote is not None or heredoc is not None:
        return None
    return out, starts


class _ShellFile:
    """Per-file facts for :func:`shell_shown` (functions, bodies, call sites)."""

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.text = "\n".join(lines)
        view = _code_view(lines)
        self.code, self.starts = view if view is not None else ([], [])
        self.funcs: list[tuple[str, int, int]] | None = (
            self._functions() if view is not None else None)
        self._print_only: dict[str, bool] = {}

    def _functions(self) -> list[tuple[str, int, int]] | None:
        """(name, first line, last line) of every function; None when the brace
        structure cannot be followed."""
        funcs: list[tuple[str, int, int]] = []
        stack: list[tuple[str | None, int, int]] = []  # (name, start, depth at open)
        depth = 0
        pending: tuple[str, int] | None = None  # `name()` with `{` on a later line
        for idx, line in enumerate(self.code):
            if not self.starts[idx]:
                # The tail of a string an earlier line opened (its text is blanked).
                pending = None
                depth, stack = self._count(line, idx, depth, stack, funcs)
                if depth < 0:
                    return None
                continue
            fm = _FUNC_DEF_RE.match(line)
            if fm:
                name = fm.group(1) or fm.group(2)
                if fm.group(3):
                    stack.append((name, idx, depth))
                    depth += 1
                    depth, stack = self._count(line[fm.end():], idx, depth, stack, funcs)
                    if depth < 0:
                        return None
                    continue
                pending = (name, idx)
                continue
            if pending is not None and line.strip().startswith("{"):
                stack.append((pending[0], pending[1], depth))
                depth += 1
                pending = None
                depth, stack = self._count(line.strip()[1:], idx, depth, stack, funcs)
            else:
                if line.strip():
                    pending = None
                depth, stack = self._count(line, idx, depth, stack, funcs)
            if depth < 0:
                return None
        if depth != 0:
            return None
        return funcs

    @staticmethod
    def _count(line, idx, depth, stack, funcs):
        for m in re.finditer(r"(?:^|(?<=[\s;&|]))([{}])(?=[\s;&|)]|$)", line):
            if m.group(1) == "{":
                stack.append((None, idx, depth))
                depth += 1
            else:
                depth -= 1
                if not stack:
                    return -1, stack
                name, start, _d = stack.pop()
                if name is not None:
                    funcs.append((name, start, idx))
        return depth, stack

    def enclosing(self, idx: int) -> list[str]:
        """Names of the functions whose body holds line ``idx`` (innermost first)."""
        assert self.funcs is not None
        hits = [(s, name) for name, s, e in self.funcs if s <= idx <= e]
        return [name for _s, name in sorted(hits, reverse=True)]

    def print_only(self, name: str, depth: int = 0) -> bool:
        """Every definition of ``name`` in this file only prints / exits."""
        if name in self._print_only:
            return self._print_only[name]
        self._print_only[name] = False  # a recursive call is not trusted
        defs = [(s, e) for n, s, e in (self.funcs or []) if n == name]
        ok = bool(defs) and depth < 4 and all(self._body_prints(s, e, depth) for s, e in defs)
        self._print_only[name] = ok
        return ok

    def _body_prints(self, s: int, e: int, depth: int) -> bool:
        body = "\n".join(self.lines[s:e + 1])
        o, c = body.find("{"), body.rfind("}")
        if o < 0 or c <= o:
            return False
        for line in body[o + 1:c].split("\n"):
            toks = _lex(line)
            if toks is None:
                return False
            for cmd in _commands(toks):
                if cmd[-1].kind == "op" and cmd[-1].text in ("|", "|&", "&"):
                    return False
                if any(t.kind == "redir" and t.text not in _REDIR_OK for t in cmd):
                    return False
                h = _head(cmd)
                if h is None:
                    continue
                if h.quotes or "$" in h.text:
                    return False  # runs a parameter: "$@", $1, ${cmd}
                if h.text in _PRINT_BODY_OK:
                    if h.text in ("[", "[[", "test", "local", "declare", "typeset",
                                  "readonly") and any(
                            t.kind == "word" and t.text in ("eval", "-c") for t in cmd):
                        return False
                    continue
                if h.text not in _RUNNERS and self.print_only(h.text, depth + 1):
                    continue
                return False
        return True

    def output_plain(self, start: list[str]) -> bool:
        """The output of every function in ``start`` (and of each function that calls
        one of them, transitively) is never piped, captured, ``eval``-ed or written to
        a file anywhere in this file."""
        assert self.funcs is not None
        seen: set[str] = set()
        work = list(start)
        while work:
            name = work.pop()
            if name in seen:
                continue
            seen.add(name)
            if len(seen) > 40:
                return False
            rx = re.compile(r"(?<![\w.:-])" + re.escape(name) + r"(?![\w.:-])")
            own = [(s, e) for n, s, e in self.funcs if n == name]
            for idx, line in enumerate(self.lines):
                if not rx.search(line) or any(s <= idx <= e for s, e in own):
                    continue
                toks = _lex(line)
                if toks is None or _line_runs(toks) or any(
                        t.kind == "op" and t.text in ("|", "|&") for t in toks):
                    return False
                work.extend(self.enclosing(idx))
        return True


def shell_shown(lines: list[str], idx: int, matches: list[tuple[int, int]],
                memo: dict) -> bool:
    """Every pipe-to-shell match (``(start, end)`` on line ``idx``) is text shown by
    ``echo`` / ``printf`` / a print-only function and nothing in the file runs it."""
    line = lines[idx]
    if not matches or (idx > 0 and lines[idx - 1].rstrip().endswith("\\")):
        return False
    toks = _lex(line)
    if toks is None or _line_runs(toks):
        return False
    sf = memo.get("shell")
    if sf is None:
        sf = memo["shell"] = _ShellFile(lines)
    if sf.funcs is None or not sf.starts[idx] or _ECHO_REDEFINED_RE.search(sf.text) \
            or _STDOUT_REDIRECTED_RE.search(sf.text):
        return False  # (a line inside a multi-line string or heredoc is data)
    cmds = _commands(toks)
    for ms, me in matches:
        cmd = next((c for c in cmds for t in c if t.kind == "word" and any(
            qs < ms and me - 1 < qe for qs, qe in t.quotes)), None)
        if cmd is None:
            return False  # not inside one quoted argument
        word = next(t for t in cmd if t.kind == "word" and any(
            qs < ms and me - 1 < qe for qs, qe in t.quotes))
        h = _head(cmd)
        if h is None or h is word or h.quotes:
            return False  # the string is the command or an assignment, not an argument
        if cmd[-1].kind == "op" and cmd[-1].text in ("|", "|&", "&"):
            return False
        if h.text not in _PRINTERS:
            if _SOURCES_RE.search(sf.text) or not sf.print_only(h.text):
                return False
    return sf.output_plain(sf.enclosing(idx))


# ---------------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------------

_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)(?:</script\s*>|\Z)", re.I | re.S)
_TYPE_ATTR_RE = re.compile(r"""\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
# <script type> values a browser does not run (data blocks, templates).
_DATA_SCRIPT_TYPES = frozenset({
    "application/json", "application/ld+json", "importmap", "speculationrules",
    "text/template", "text/x-template", "text/plain", "text/markdown",
    "text/x-handlebars-template", "text/html",
})
_HTML_CODE_ATTR_RE = re.compile(r"\bon[a-z]+\s*=|javascript:|\bsrcdoc\s*=", re.I)


def _html_code_lines(content: str) -> set[int]:
    """0-based lines inside a ``<script>`` element a browser runs."""
    out: set[int] = set()
    for m in _SCRIPT_RE.finditer(content):
        tm = _TYPE_ATTR_RE.search(m.group(1))
        typ = (next((g for g in tm.groups() if g is not None), "") if tm else "")
        if typ.strip().lower() in _DATA_SCRIPT_TYPES:
            continue
        a = content.count("\n", 0, m.start())
        b = content.count("\n", 0, m.end())
        out.update(range(a, b + 1))
    return out


def html_shown(content: str, lines: list[str], idx: int, memo: dict) -> bool:
    """Line ``idx`` of an HTML page is display text: no script a browser runs."""
    code = memo.get("html")
    if code is None:
        code = memo["html"] = _html_code_lines(content)
    return idx not in code and not _HTML_CODE_ATTR_RE.search(lines[idx])


# ---------------------------------------------------------------------------------
# JSON data fields
# ---------------------------------------------------------------------------------

# Config files some tool runs commands from: never data.
_EXECUTED_JSON_NAMES = frozenset({
    "package.json", "composer.json", "deno.json", "deno.jsonc", "devcontainer.json",
    ".devcontainer.json", "tasks.json", "launch.json", "settings.json",
    "settings.local.json", "hooks.json", "plugin.json", "marketplace.json", "mcp.json",
    ".mcp.json", "mcp_config.json", "claude_desktop_config.json", "server.json",
    "smithery.json", "app.json", "vercel.json", "now.json", "turbo.json", "project.json",
    "nx.json", "lerna.json", "renovate.json", ".renovaterc.json", "manifest.json",
    "extension.json", "gemini-extension.json", "devbox.json", "nodemon.json",
    "firebase.json", "netlify.json", "angular.json", "workspace.json", "bower.json",
    "cdk.json", "serverless.json", "jsr.json", "tsconfig.json", ".eslintrc.json",
    "openclaw.json", "agent.json", "tool.json", "tools.json",
})
# Keys whose value a tool runs.
_EXEC_KEY_RE = re.compile(
    r"(?i)^(?:.*(?:command|cmd|script|hook|exec|execute|run|task|shell|args|argv|"
    r"entrypoint|entry_point|steps|action)s?|start|build|test|setup|init|"
    r"(?:pre|post)install|prepare|launch|program)$")
_JSON_STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def json_data_key(file_path: str, line: str, matches: list[tuple[int, int]]) -> str | None:
    """The data key every match on ``line`` sits under, or None (keep the critical)."""
    p = Path(file_path)
    name = p.name.lower()
    if p.suffix.lower() not in JSON_EXTS or name in _EXECUTED_JSON_NAMES or \
            name.endswith(".mcp.json") or not matches:
        return None
    from src.scanner.scan import AGENT_METADATA_FILES
    if name in AGENT_METADATA_FILES:
        return None
    strs = list(_JSON_STR_RE.finditer(line))
    pairs: list[tuple[str, int, int]] = []  # (key, value start, value end)
    for i, m in enumerate(strs[:-1]):
        nxt = strs[i + 1]
        if re.fullmatch(r"\s*:\s*", line[m.end():nxt.start()]):
            pairs.append((m.group(0)[1:-1], nxt.start(), nxt.end()))
    keys: set[str] = set()
    for ms, me in matches:
        hit = next((k for k, vs, ve in pairs if vs < ms and me <= ve), None)
        if hit is None or not re.fullmatch(r"[A-Za-z_][\w.-]{0,63}", hit) or \
                _EXEC_KEY_RE.match(hit):
            return None
        keys.add(hit)
    return next(iter(keys)) if len(keys) == 1 else None


_NOT_CODE_SUFFIXES = (".json", ".jsonl", ".ndjson", ".jsonc", ".json5", ".md",
                      ".markdown", ".mdx", ".txt", ".rst", ".html", ".htm", ".css",
                      ".svg", ".map", ".lock", ".csv", ".tsv", ".xml", ".yaml", ".yml",
                      ".toml", ".ini", ".cfg")
# An exec sink in any language the tree may hold (generous on purpose: a false match
# only keeps the critical).
_ANY_SINK_RE = re.compile(
    # a call: execSync(…), spawn(…), subprocess.run(…), os.system(…), $`…` (zx)
    r"\b(?:exec\w*|spawn\w*|fork|system|popen|Popen|call|check_call|check_output|"
    r"getoutput|getstatusoutput|run\w*|shell_exec|passthru|proc_open|eval|Function|"
    r"ShellExecute|execa\w*|shell)\s*\(|\$\s*`|"
    r"\b(?:subprocess|child_process|shelljs|Invoke-Expression|iex)\b|"
    # shell: a pipe into a shell, sh -c, command substitution, eval / source / exec
    r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:ba|z|da|k)?sh\s+-c\b|\$\(|"
    r"(?:^|[;&|]|\b(?:then|do)\b)\s*(?:eval|source|exec|\.)\s")
# A backtick runs a command in shell / Ruby / Perl / PHP; in JS / TS it is a template
# literal (`Install: ${a.install}`), not a sink.
_BACKTICK_LANG_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".rb", ".pl", ".pm", ".php")
_NEAR_CHARS = 240
_ASSIGN_LHS_RE = re.compile(
    r"^\s*(?:(?:const|let|var|local|export|readonly|declare|my|our)\s+)?\$?"
    r"([A-Za-z_][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?\s*:?=(?!=)")


def json_key_executed(key: str, json_path: str, texts: dict[str, str]) -> bool:
    """Some code file of ``texts`` reads ``key`` next to an exec sink (same or an
    adjacent line), or into a variable a sink line of that file uses."""
    return json_key_exec_site(key, json_path, texts) is not None


def json_key_exec_site(key: str, json_path: str,
                       texts: dict[str, str]) -> tuple[str, int] | None:
    """Where :func:`json_key_executed` saw ``key`` reach a sink: (path, 1-based line)."""
    k = re.escape(key)
    # A read of the field: `a.install` / jq `.install` (not a method call
    # `x.install(`), `a["install"]`, `.get("install")`, `getattr(a, "install")`.
    ref = re.compile(
        r"(?<=[\w\])$?])\." + k + r"(?![\w$-])(?!\s*\()|"
        # jq `'.install'` / `jq -r .install` (a quoted `".install.lock"` is a name)
        r"(?:(?<=['\"\s])|^)\." + k + r"(?![\w$.-])|"
        r"\[\s*['\"`]" + k + r"['\"`]\s*\]|"
        r"\b(?:get|getattr|pick|prop|path|at|lookup|fetch|dig)\s*\([^()\n]{0,80}?['\"`]"
        + k + r"['\"`]")
    for fp, text in texts.items():
        if fp == json_path or not text or key not in text:
            continue
        if fp.lower().endswith(_NOT_CODE_SUFFIXES):
            continue
        lines = text.split("\n")
        low = fp.lower()
        tick = low.endswith(_BACKTICK_LANG_SUFFIXES) or "." not in Path(low).name

        def sink(x: str) -> bool:
            return bool(_ANY_SINK_RE.search(x)) or (tick and "`" in x)

        sink_lines: list[str] | None = None
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith(("#", "//", "*", "/*")):
                continue  # a comment mentions it
            refs = list(ref.finditer(ln))
            if not refs:
                continue
            # Bounded by characters too: on a minified bundle line every sink in
            # the file is "on the same line".
            around = [lines[i - 1][-_NEAR_CHARS:] if i else "",
                      lines[i + 1][:_NEAR_CHARS] if i + 1 < len(lines) else ""]
            around += [ln[max(0, m.start() - _NEAR_CHARS): m.end() + _NEAR_CHARS]
                       for m in refs]
            if any(sink(x) for x in around):
                return fp, i + 1
            am = _ASSIGN_LHS_RE.match(ln)
            if am:
                var = re.compile(r"(?<![\w$])\$?\{?" + re.escape(am.group(1)) + r"(?![\w$])")
                if sink_lines is None:
                    sink_lines = [x for x in lines if sink(x)]
                if any(var.search(x) for x in sink_lines):
                    return fp, i + 1
    return None
