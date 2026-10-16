"""Printed install hints: a `curl … | bash` the code shows a person and never runs.

pm2 prints ``Install NVM: $ curl …/install.sh | bash`` when NVM is missing; the Vercel
CLI tells you how to reinstall it (``To reinstall the CLI manually, run: ${CURL_…}``);
gemini-mcp-tool puts the Antigravity installer in an ENOENT error message. Each matches
the critical "curl/wget piped to shell" rule as text, and none of them runs it.

:func:`hint_only` answers one question for one pipe-to-shell match in a JS / TS or
Python file: does the matched string reach ONLY human-facing output? It follows the
string's value, conservatively, and says yes only when every path ends in

* a print / log call (``console.*``, ``process.stdout|stderr.write``, a logger method
  the package itself defines whose body runs nothing, Python ``print`` / ``logging`` /
  ``click.echo`` …);
* an ``Error`` / exception message, or a ``throw`` (unless some ``catch`` in the
  package hands a caught error to a command runner);
* a discarded expression, a comparison, or an import / export list.

On the way the value may pass through string building (``+``, template / f-string
interpolation, ``.join`` / ``.trim`` …, colour formatters such as chalk), a ternary, an
array that is only pushed to and joined, a ``const`` / ``var`` binding (every read in
scope is followed), an object property of a top-level constant (every read of the
object must be a static ``.prop``), or a function's return value (every call site is
followed). Anything else, including any read the walk cannot classify, a direct
``eval`` in scope, the name mentioned inside a string, a namespace import of the
defining module, or a module that does not tokenize cleanly, keeps the finding as it
was. ``files`` is the whole package for an artifact scan (exported names are followed
into every file that mentions them) or just the one file for a per-file scan, where a
name that leaves the file keeps its severity.

Not applied to shell scripts, package.json lifecycle scripts, Markdown / agent
instruction files or any other format: those are unchanged.
"""
from __future__ import annotations

import ast
import re
from bisect import bisect_right
from pathlib import Path

JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
PY_EXTS = frozenset({".py"})
_DTS_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
# Files that may mention a name without running anything: type declarations, source
# maps, prose. Any OTHER file that mentions a followed name (package.json, a shell
# script, a YAML config …) keeps the finding.
_INERT_SUFFIXES = (".d.ts", ".d.mts", ".d.cts", ".map", ".md", ".markdown", ".txt",
                   ".rst", ".html", ".htm", ".css", ".svg", ".png", ".jpg", ".gif")

WHY = ("Install command shown to a person (printed, logged, or put in an error "
       "message); no code in the package runs it. Reported for visibility.")

_MAX_STEPS = 400  # total climb steps per question (bounded work on a huge bundle)


def is_supported(path: str) -> bool:
    p = path.lower()
    if p.endswith(_DTS_SUFFIXES):
        return False
    return Path(p).suffix in JS_EXTS or Path(p).suffix in PY_EXTS


class _UnclassifiedError(Exception):
    """The walk met something it cannot classify: keep the finding."""


# ---------------------------------------------------------------------------
# JavaScript / TypeScript tokenizer
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"#?[A-Za-z_$\u0080-￿][\w$\u0080-￿]*")
_NUM_RE = re.compile(r"(?:0[xXoObB][\w]+|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?\d+)?n?"
                     r"|\.\d[\d_]*(?:[eE][+-]?\d+)?)")
_WS_RE = re.compile(r"[ \t\r\f\v ﻿  ]+")
_SQ_RE = re.compile(r"'(?:[^'\\\n]|\\[\s\S])*'")
_DQ_RE = re.compile(r'"(?:[^"\\\n]|\\[\s\S])*"')
_TPL_BODY_RE = re.compile(r"(?:[^`\\$]|\\[\s\S]|\$(?!\{))*")
_REGEX_RE = re.compile(r"/(?![*/])(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[A-Za-z]*")
_PUNCTS = sorted("""
>>>= ... === !== **= <<= >>= >>> &&= ||= ??= => == != <= >= && || ?? ?. ++ -- += -= *= /=
%= &= |= ^= ** << >> { } ( ) [ ] ; , < > + - * / % & | ^ ! ~ ? : = . @
""".split(), key=len, reverse=True)
_PUNCT_RE = re.compile("|".join(re.escape(p) for p in _PUNCTS))
_REGEX_AFTER_KW = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
    "case", "do", "else", "yield", "await",
})


class _Toks:
    """Token arrays for one JS file: type, start, end, value, newline-before, match."""

    __slots__ = ("typ", "st", "en", "val", "nl", "match", "head", "clean", "by_val")

    def __init__(self, text: str) -> None:
        typ: list[str] = []
        st: list[int] = []
        en: list[int] = []
        val: list[str] = []
        nl: list[bool] = []
        match: dict[int, int] = {}
        head: dict[int, int] = {}  # template mid/tail → its head
        stack: list[tuple[str, int]] = []  # ("(", i) / ("[", i) / ("{", i) / ("T", head)
        clean = True
        i, n = 0, len(text)
        saw_nl = False
        if text.startswith("#!"):
            j = text.find("\n")
            i = n if j == -1 else j
        prev_sig: tuple[str, str] | None = None

        def emit(t: str, a: int, b: int) -> None:
            nonlocal saw_nl, prev_sig
            typ.append(t)
            st.append(a)
            en.append(b)
            v = text[a:b] if t in ("id", "punct") else ""
            val.append(v)
            nl.append(saw_nl)
            saw_nl = False
            prev_sig = (t, v)

        def template(start: int, opener: str, head_idx: int | None) -> int:
            """Scan template text from ``start``; emit a token; return next pos."""
            nonlocal clean
            m = _TPL_BODY_RE.match(text, start)
            j = m.end()
            if j < n and text[j] == "`":
                if opener == "`":
                    emit("tpl", start - 1, j + 1)
                else:
                    emit("tpl_tail", start - 1, j + 1)
                    k = len(typ) - 1
                    head[k] = head_idx
                    match[head_idx] = k
                    match[k] = head_idx
                return j + 1
            if text.startswith("${", j):
                if opener == "`":
                    emit("tpl_head", start - 1, j + 2)
                    k = len(typ) - 1
                    stack.append(("T", k))
                else:
                    emit("tpl_mid", start - 1, j + 2)
                    head[len(typ) - 1] = head_idx
                    stack.append(("T", head_idx))
                return j + 2
            clean = False  # unterminated template
            return n

        while i < n:
            c = text[i]
            if c == "\n":
                saw_nl = True
                i += 1
                continue
            m = _WS_RE.match(text, i)
            if m:
                i = m.end()
                continue
            if text.startswith("//", i) or text.startswith("<!--", i):
                j = text.find("\n", i)
                i = n if j == -1 else j
                continue
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                if j == -1:
                    clean = False
                    break
                if "\n" in text[i:j]:
                    saw_nl = True
                i = j + 2
                continue
            if c == "'" or c == '"':
                m = (_SQ_RE if c == "'" else _DQ_RE).match(text, i)
                if not m:
                    clean = False
                    emit("punct", i, i + 1)
                    i += 1
                    continue
                emit("str", i, m.end())
                i = m.end()
                continue
            if c == "`":
                i = template(i + 1, "`", None)
                continue
            if c == "}" and stack and stack[-1][0] == "T":
                _, h = stack.pop()
                i = template(i + 1, "}", h)
                continue
            m = _ID_RE.match(text, i)
            if m:
                emit("id", i, m.end())
                i = m.end()
                continue
            m = _NUM_RE.match(text, i)
            if m and m.end() > i:
                emit("num", i, m.end())
                i = m.end()
                continue
            if c == "/":
                regex_ok = (prev_sig is None
                            or prev_sig[0] in ("tpl_head", "tpl_mid")
                            or (prev_sig[0] == "punct" and prev_sig[1] not in (")", "]", "}"))
                            or (prev_sig[0] == "id" and prev_sig[1] in _REGEX_AFTER_KW))
                if regex_ok:
                    m = _REGEX_RE.match(text, i)
                    if m:
                        emit("regex", i, m.end())
                        i = m.end()
                        continue
                else:
                    # Read as division. If it could also open a regex literal that
                    # holds an unpaired quote (`if (a) /'/.test(b)`), the two readings
                    # disagree on what is string and what is code: not clean.
                    m = _REGEX_RE.match(text, i)
                    # (A span through `;` is two statements, not a regex.)
                    if m and prev_sig[1] in (")", "}") and ";" not in m.group(0) and any(
                            m.group(0).count(q) % 2 for q in "'\"`"):
                        clean = False
            m = _PUNCT_RE.match(text, i)
            if m:
                p = m.group(0)
                emit("punct", i, m.end())
                k = len(typ) - 1
                if p in ("(", "[", "{"):
                    stack.append((p, k))
                elif p in (")", "]", "}"):
                    want = {")": "(", "]": "[", "}": "{"}[p]
                    if stack and stack[-1][0] == want:
                        o = stack.pop()[1]
                        match[o] = k
                        match[k] = o
                    else:
                        clean = False
                i = m.end()
                continue
            # Anything else (JSX text, a stray byte): not a clean JS tokenization.
            clean = False
            i += 1
        if stack:
            clean = False
        self.typ, self.st, self.en, self.val, self.nl = typ, st, en, val, nl
        self.match, self.head, self.clean = match, head, clean
        by_val: dict[str, list[int]] = {}
        for k, (t, v) in enumerate(zip(typ, val)):
            if t == "id":
                by_val.setdefault(v, []).append(k)
        self.by_val = by_val

    def __len__(self) -> int:
        return len(self.typ)

    def is_p(self, k: int, *vals: str) -> bool:
        return 0 <= k < len(self.typ) and self.typ[k] == "punct" and self.val[k] in vals

    def is_id(self, k: int, *vals: str) -> bool:
        return 0 <= k < len(self.typ) and self.typ[k] == "id" and (
            not vals or self.val[k] in vals)

    def at(self, pos: int) -> int:
        """Index of the token whose span contains ``pos`` (or -1)."""
        k = bisect_right(self.st, pos) - 1
        if k >= 0 and self.st[k] <= pos < self.en[k]:
            return k
        return -1


_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "with", "return", "typeof", "void",
    "delete", "throw", "new", "in", "of", "instanceof", "case", "do", "else", "var",
    "let", "const", "function", "class", "export", "import", "default", "yield",
    "await", "async", "try", "finally", "extends", "super", "this", "null", "true",
    "false", "undefined", "debugger", "break", "continue", "static", "get", "set",
})
_LEFT_STOP_PUNCT = frozenset({
    "=", "(", "[", "{", ",", ";", "=>", "+=", "-=", "*=", "/=", "%=", "**=", "<<=",
    ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=", "...",
})
_RIGHT_STOP_PUNCT = frozenset({
    ")", "]", "}", ",", ";", "=", "=>", "+=", "-=", "*=", "/=", "%=", "**=", "<<=",
    ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=",
})
_STOP_KW = frozenset({
    "return", "throw", "case", "yield", "else", "do", "var", "let", "const", "export",
    "default", "if", "while", "for", "switch", "with", "catch", "extends", "import",
    "from",
})
_COND_KW = frozenset({"if", "while", "switch", "for"})
# Methods on a string / array that hand back a value derived from it and call nothing.
_SAFE_METHODS = frozenset({
    "join", "trim", "trimStart", "trimEnd", "toString", "slice", "substring", "concat",
    "padStart", "padEnd", "toUpperCase", "toLowerCase", "split", "includes",
    "startsWith", "endsWith", "indexOf", "length", "at", "charAt",
})
_CONSOLE_METHODS = frozenset({"log", "error", "warn", "info", "debug", "trace"})
# Method names a package's own output layer uses. Accepted only when the package defines
# the method and no definition of it runs anything.
_OUTPUT_METHODS = frozenset({
    "log", "error", "warn", "warning", "info", "debug", "trace", "print", "printOut",
    "printError", "fatal", "note", "success", "notice", "verbose", "say", "hint",
})
_STYLE_NAMES = frozenset({
    "default", "bold", "dim", "italic", "underline", "inverse", "strikethrough", "reset",
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white", "gray",
    "grey", "redBright", "greenBright", "yellowBright", "blueBright", "magentaBright",
    "cyanBright", "whiteBright", "blackBright", "bgRed", "bgGreen", "bgYellow",
    "bgBlue", "bgMagenta", "bgCyan", "bgWhite", "bgBlack", "visible", "hidden",
})
# Dependencies a print method may call with the message (formatting / terminal output).
_SAFE_OUTPUT_DEPS = frozenset({
    "util", "node:util", "chalk", "picocolors", "kleur", "colorette", "strip-ansi",
    "ansi-escapes", "wrap-ansi", "string-width", "log-symbols", "figures", "boxen",
    "cli-cursor", "ora", "supports-color", "ansi-styles", "ansis", "colors", "cli-color",
})
_COLOR_LIB_RE = re.compile(r"(?i)chalk|kleur|picocolors|colorette|ansi[_-]?colors")
_BUILTIN_ERRORS = frozenset({
    "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "EvalError",
    "URIError", "AggregateError",
})
# What a definition's body must not contain for a print / format method to be trusted.
_JS_SINK_RE = re.compile(
    r"""child_process|(?<!['"])\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|"""
    r"""fork|execa\w*|eval|system|popen|shell)\b(?!['"])|\bFunction\s*\(|\$\s*`|\bshelljs\b|Reflect\s*\."""
    r"""\s*apply|\bimport\s*\(|\brequire\s*\(\s*[^'"`\s)]|\bvm\s*\.\s*run|writeFile|"""
    r"""\[\s*[\w$.]+\s*\]\s*\(""")
_JS_RUN_CALL = (r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa\w*|eval|"
                r"Function|system|popen|\$)")
# Where a thrown error's message can land: a catch binding, a rejection handler, a
# process-level error handler.
_CATCH_RE = re.compile(
    r"""\bcatch\s*\(\s*([\w$]+)\s*\)|\.catch\s*\(\s*(?:async\s*)?(?:function\s*[\w$]*\s*)?"""
    r"""\(?\s*([\w$]+)|['"](?:uncaughtException|unhandledRejection|error)['"]\s*,\s*"""
    r"""(?:async\s*)?(?:function\s*[\w$]*\s*)?\(?\s*([\w$]+)|\.then\s*\([^,()]*,\s*"""
    r"""(?:async\s*)?(?:function\s*[\w$]*\s*)?\(?\s*([\w$]+)""")
# `console` / the std streams replaced, wrapped or bound to something else.
_CONSOLE_SHADOW_RE = re.compile(
    r"""\bconsole\s*(?:\.\s*[\w$]+\s*|\[[^\]]*\]\s*)?=(?!=)|\b(?:var|let|const|function|"""
    r"""class)\s+console\b|defineProperty\s*\(\s*console\b|assign\s*\(\s*console\b|"""
    r"""[(,]\s*console\s*[,)=]|\{\s*console\s*[,}:]|[,{]\s*console\s*\}|\bConsole\s*\(|"""
    r"""process\s*\.\s*std(?:out|err)\s*(?:\.\s*write\s*)?=(?!=)|"""
    r"""defineProperty\s*\(\s*process\b|setPrototypeOf\s*\(\s*console\b|"""
    r"""['"`]console['"`]\s*\]\s*=|defineProperty\s*\([^,]*,\s*['"`]console['"`]|"""
    r"""\bwith\s*\(""")


def _handler_body(text: str, start: int) -> str:
    """The block (or concise arrow body) of a catch / error handler starting near
    ``start`` (approximate; bounded)."""
    k = start
    while k < len(text) and k < start + 80 and text[k] not in "{\n;":
        k += 1
    if k < len(text) and text[k] == "{":
        depth, j, lim = 0, k, min(len(text), k + 20000)
        while j < lim:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        return text[k:j + 1]
    return text[start:start + 600]


def _binding_spec(text: str, name: str) -> str | None:
    """The module specifier ``name`` is imported / required from in ``text``."""
    r = re.escape(name)
    m = re.search(
        r"""\bimport\s*(?:[\w$]+\s*,\s*)?\{[^}]*(?<![\w$])""" + r
        + r"""(?![\w$])[^}]*\}\s*from\s*['"]([^'"]+)['"]|\bimport\s+""" + r
        + r"""\b[^;'"]*?from\s*['"]([^'"]+)['"]|\bimport\s*\*\s*as\s+""" + r
        + r"""\s+from\s*['"]([^'"]+)['"]|(?<![\w$.])""" + r
        + r"""\s*=\s*(?:__toESM\s*\(\s*)?require\s*\(\s*['"]([^'"]+)['"]|\{[^}]*"""
        + r"""(?<![\w$])""" + r + r"""(?![\w$])[^}]*\}\s*=\s*require\s*\(\s*['"]"""
        + r"""([^'"]+)['"]""", text)
    return next((g for g in m.groups() if g), None) if m else None


def _concise_body(text: str, j: int) -> str:
    """A concise arrow body from ``j``: up to the first top-level ``,`` ``;`` or
    closing bracket (bounded)."""
    depth, k, lim = 0, j, min(len(text), j + 2000)
    while k < lim:
        ch = text[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ",;\n" and depth == 0:
            break
        k += 1
    return text[j:k]


def _def_bodies(text: str, name: str) -> list[str]:
    """Bodies (approximate) of every JS definition of ``name`` in ``text``."""
    n = re.escape(name)
    rx = re.compile(
        r"\bfunction\s*\*?\s*" + n + r"\s*\(|(?<![\w$])" + n
        + r"\s*[:=]\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[\w$]+\s*=>)|"
        r"(?:^|[;{},\s])(?:async\s+|static\s+|get\s+|set\s+)*" + n
        + r"\s*\([^()]*\)\s*(?::\s*[\w$<>\[\]|, ]+\s*)?\{|(?<![\w$])" + n
        + r"\s*[:=]\s*[\w$.]+\s*\.\s*bind\s*\(")
    out = []
    for m in rx.finditer(text):
        j = m.end()
        brace = text.find("{", m.end() - 1, m.end() + 400)
        arrow_end = m.group(0).rstrip().endswith("=>")
        if (arrow_end and not text[j:j + 50].lstrip().startswith("{")) or brace == -1:
            out.append(_concise_body(text, j))
            continue
        depth, k, lim = 0, brace, min(len(text), brace + 30000)
        while k < lim:
            ch = text[k]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(text[brace:k + 1])
    return out


class _JsFlow:
    """Follow one value through JS code (module docstring)."""

    def __init__(self, files: dict[str, str], package: bool) -> None:
        self.files = files
        self.package = package
        self._toks: dict[str, _Toks] = {}
        self.steps = 0
        self.followed: set[tuple] = set()
        self._catch_ok: bool | None = None
        self.uses = 0
        self._console_ok: bool | None = None
        self.code_paths = [p for p in files if Path(p.lower()).suffix in JS_EXTS
                           and not p.lower().endswith(_DTS_SUFFIXES)]

    # -- helpers ---------------------------------------------------------------
    def toks(self, path: str) -> _Toks:
        t = self._toks.get(path)
        if t is None:
            t = _Toks(self.files[path])
            self._toks[path] = t
        if not t.clean:
            raise _UnclassifiedError(f"{path}: does not tokenize cleanly")
        return t

    def tick(self) -> None:
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise _UnclassifiedError("walk too long")

    # -- entry -----------------------------------------------------------------
    def literal(self, path: str, start: int, end: int) -> None:
        """The pipe-to-shell match spans [start, end) of ``path``."""
        t = self.toks(path)
        k = t.at(start)
        if k < 0:
            raise _UnclassifiedError("match not in a token")
        ty = t.typ[k]
        if ty in ("str", "tpl"):
            if end > t.en[k]:
                raise _UnclassifiedError("match spans more than one literal")
            a = b = k
        elif ty in ("tpl_head", "tpl_mid", "tpl_tail"):
            h = k if ty == "tpl_head" else t.head[k]
            tail = t.match[h]
            if end > t.en[tail]:
                raise _UnclassifiedError("match leaves the template")
            a, b = h, tail
        else:
            raise _UnclassifiedError("match is not inside a string literal")
        # `key: "curl … | bash"` in an object literal bound to a top-level constant.
        if t.is_p(a - 1, ":") and a == b and t.is_p(b + 1, ",", "}") \
                and (t.typ[a - 2] in ("id", "str")) and t.is_p(a - 3, "{", ","):
            self.property_value(path, t, a)
            return
        self.value(path, a, b)

    # -- property of a top-level object constant ---------------------------------
    def property_value(self, path: str, t: _Toks, k: int) -> None:
        key = t.val[k - 2] if t.typ[k - 2] == "id" else \
            self.files[path][t.st[k - 2] + 1:t.en[k - 2] - 1]
        if not re.fullmatch(r"[\w$]+", key or ""):
            raise _UnclassifiedError("computed / odd property key")
        # Find the object literal's '{'.
        j = k - 3
        while j >= 0 and not t.is_p(j, "{"):
            if t.is_p(j, ")", "]", "}"):
                j = t.match[j]
            elif t.typ[j] == "tpl_tail":
                j = t.match[j]
            elif t.is_p(j, "(", "["):
                raise _UnclassifiedError("property inside a nested expression")
            j -= 1
        if j < 0:
            raise _UnclassifiedError("no object literal")
        if not (t.is_p(j - 1, "=") and t.is_id(j - 2) and t.is_id(j - 3, "const", "let", "var")):
            raise _UnclassifiedError("object literal is not a constant's initializer")
        if self.depth_of(t, j) != 0:
            raise _UnclassifiedError("object constant is not top-level")
        container = t.val[j - 2]
        exported = t.is_id(j - 4, "export")
        if not t.is_p(t.match[j] + 1, ";") and not (
                t.match[j] + 1 < len(t) and t.nl[t.match[j] + 1]) and t.match[j] + 1 < len(t):
            raise _UnclassifiedError("object literal is part of a larger expression")
        self.check_name_unmentioned(key, path, exclude=(path, k - 2))
        self.check_namespace_imports(path)
        files = self.scope_files(path, exported or self.mentions_exported(path, container))
        used_before = self.uses
        for fp in files:
            if container not in self.files[fp] and key not in self.files[fp]:
                continue
            ft = self.toks(fp)
            for r in ft.by_val.get(container, []):
                if fp == path and r == j - 2:
                    continue
                if ft.is_p(r - 1, ".", "?."):
                    continue  # someone else's `.RETIREMENT`
                if self.specifier(ft, r, fp):
                    continue
                if ft.is_p(r + 1, ".", "?.") and ft.is_id(r + 2):
                    if ft.val[r + 2] == key:
                        self.value(fp, r, r + 2, chain=True)
                    elif ft.is_p(r + 3, "=") or ft.is_p(r + 3, "(") or ft.is_p(r + 3, "["):
                        # Writing / calling another member: not our value, but `C.x = C`
                        # style aliasing is still caught at the read of `C` itself.
                        pass
                    continue
                raise _UnclassifiedError(f"{container} used as a whole")
            # `.key` reads on any object (aliases of the container read it this way).
            for r in ft.by_val.get(key, []):
                if fp == path and r == k - 2:
                    continue
                if ft.is_p(r - 1, ".", "?.") and ft.is_id(r - 2, container):
                    continue  # already followed above
                if ft.is_p(r - 1, ".", "?."):
                    self.value(fp, r - 2 if ft.is_id(r - 2) else r, r, chain=True)
                    continue
                if ft.is_p(r + 1, ":") and ft.is_p(r - 1, "{", ","):
                    raise _UnclassifiedError(f"another object defines {key}")
                if self.specifier(ft, r, fp):
                    continue
                raise _UnclassifiedError(f"bare read of {key}")
        if self.uses == used_before:
            raise _UnclassifiedError("never read: nothing shows it to a person")

    def depth_of(self, t: _Toks, k: int) -> int:
        """Number of brace / paren / bracket groups enclosing token ``k``."""
        d = 0
        j = k - 1
        while j >= 0:
            if t.is_p(j, ")", "]", "}"):
                j = t.match[j] - 1
                continue
            if t.typ[j] == "tpl_tail":
                j = t.match[j] - 1
                continue
            if t.is_p(j, "(", "[", "{") or t.typ[j] in ("tpl_head", "tpl_mid"):
                d += 1
                if t.typ[j] == "tpl_mid":
                    j = t.head[j]
            j -= 1
        return d

    def enclosing_open(self, t: _Toks, k: int) -> int:
        """The nearest unmatched opener left of ``k`` (-1 at top level)."""
        j = k - 1
        while j >= 0:
            if t.is_p(j, ")", "]", "}") or t.typ[j] == "tpl_tail":
                j = t.match[j] - 1
                continue
            if t.is_p(j, "(", "[", "{") or t.typ[j] in ("tpl_head", "tpl_mid"):
                return j
            j -= 1
        return -1

    # -- the value walk ----------------------------------------------------------
    def value(self, path: str, a: int, b: int, chain: bool = False) -> None:
        """Token range [a, b] of ``path`` evaluates to (a string built from) our
        value. Raise _UnclassifiedError unless every place it can go is human output."""
        self.uses += 1
        t = self.toks(path)
        while True:
            self.tick()
            if t.typ[a] in ("tpl", "tpl_head") and a > 0 and (
                    (t.typ[a - 1] == "id" and t.val[a - 1] not in _KEYWORDS)
                    or t.is_p(a - 1, ")", "]") or t.typ[a - 1] == "tpl_tail"):
                raise _UnclassifiedError("tagged template (zx `$`, a custom tag)")
            nb = self.postfix(t, b)
            if nb is None:
                return
            a, b = self.expand(t, a, nb)
            p, nx = a - 1, b + 1
            # template interpolation `${ value }`
            if p >= 0 and t.typ[p] in ("tpl_head", "tpl_mid") and nx < len(t) \
                    and t.typ[nx] in ("tpl_mid", "tpl_tail"):
                h = p if t.typ[p] == "tpl_head" else t.head[p]
                a, b = h, t.match[h]
                continue
            if p < 0:
                return  # program-level expression statement: value discarded
            if t.is_p(p, ","):
                o = self.enclosing_open(t, a)
                if o == -1:
                    return  # top-level sequence expression: discarded
                self.in_open(path, t, o, a, b)
                return
            if t.is_p(p, "(", "[", "{"):
                r = self.in_open(path, t, p, a, b)
                if r is not None:
                    a, b = r
                    continue
                return
            if t.is_p(p, ";", "}"):
                return  # expression statement
            if t.typ[p] == "id":
                kw = t.val[p]
                if kw == "return":
                    self.returned(path, t, p)
                    return
                if kw == "throw":
                    self.require_no_catch_exec()
                    return
                if kw == "case":
                    return
                if kw in ("else", "do"):
                    return  # statement
                raise _UnclassifiedError(f"value after keyword {kw}")
            if t.is_p(p, "=>"):
                self.arrow_returned(path, t, p)
                return
            if t.is_p(p, "="):
                self.assigned(path, t, p)
                return
            if t.is_p(p, "+="):
                self.assigned(path, t, p)
                return
            raise _UnclassifiedError(f"value after {t.val[p] or t.typ[p]}")

    def postfix(self, t: _Toks, b: int) -> int | None:
        """Absorb `.method(...)`, `.prop`, `[i]` applied to the value; each called
        method must be one that calls nothing (``_SAFE_METHODS``). None: the value
        is only appended to (``arr.push(other)``)."""
        a_call = False
        while True:
            nx = b + 1
            if t.is_p(nx, ".", "?.") and t.is_id(nx + 1):
                name = t.val[nx + 1]
                if t.is_p(nx + 2, "(") and name in ("push", "unshift") and not a_call:
                    return None  # something else appended to the value: neutral
                if t.is_p(nx + 2, "("):
                    if name not in _SAFE_METHODS:
                        raise _UnclassifiedError(f".{name}() applied to the value")
                    self.require_literal_args(t, nx + 2)
                    b = t.match[nx + 2]
                    a_call = True
                    continue
                if name not in _SAFE_METHODS:
                    raise _UnclassifiedError(f".{name} read from the value")
                b = nx + 1
                continue
            if t.is_p(nx, "["):
                b = t.match[nx]
                continue
            if t.is_p(nx, "(") or t.typ[nx:nx + 1] in (["tpl"], ["tpl_head"]):
                raise _UnclassifiedError("the value is called")
            return b

    def require_literal_args(self, t: _Toks, o: int) -> None:
        for j in range(o + 1, t.match[o]):
            if t.typ[j] not in ("str", "num", "regex") and not t.is_p(j, ","):
                raise _UnclassifiedError("non-literal argument to a string method")

    def expand(self, t: _Toks, a: int, b: int) -> tuple[int, int]:
        """Widen [a, b] over operators to the enclosing expression's boundaries."""
        open_q = 0
        j = a - 1
        while j >= 0:
            ty, v = t.typ[j], t.val[j]
            if ty == "punct" and v in (")", "]", "}"):
                if v == "}":
                    break
                j = t.match[j] - 1
                continue
            if ty == "tpl_tail":
                j = t.match[j] - 1
                continue
            if ty in ("tpl_head", "tpl_mid"):
                break
            if ty == "punct" and v in _LEFT_STOP_PUNCT:
                break
            if ty == "id" and v in _STOP_KW:
                break
            if ty == "punct" and v == ":":
                if self.has_q_left(t, j):
                    open_q -= 1
                    j -= 1
                    continue
                break
            if ty == "punct" and v == "?":
                open_q += 1
            if t.nl[j + 1] if j + 1 < len(t) else False:
                # ASI: a statement ended at the newline before token j+1.
                if self.asi_break(t, j):
                    break
            j -= 1
        a = j + 1
        cnt = 0
        pend = max(open_q, 0)
        k = b + 1
        while k < len(t):
            ty, v = t.typ[k], t.val[k]
            if ty in ("tpl_mid", "tpl_tail"):
                break
            if ty == "punct" and v in ("(", "[", "{"):
                if v == "{":
                    break
                k = t.match[k] + 1
                continue
            if ty == "tpl_head":
                k = t.match[k] + 1
                continue
            if ty == "punct" and v in _RIGHT_STOP_PUNCT:
                break
            if ty == "id" and v in _STOP_KW:
                break
            if ty == "punct" and v == "?":
                cnt += 1
            elif ty == "punct" and v == ":":
                if cnt > 0:
                    cnt -= 1
                elif pend > 0:
                    pend -= 1
                else:
                    break
            if t.nl[k] and self.asi_break(t, k - 1):
                break
            k += 1
        return a, k - 1

    def asi_break(self, t: _Toks, j: int) -> bool:
        """A newline after token ``j`` ends a statement (approximate ASI)."""
        if j < 0 or j + 1 >= len(t):
            return False
        left_end = t.typ[j] in ("id", "str", "tpl", "tpl_tail", "num", "regex") \
            or t.is_p(j, ")", "]", "}", "++", "--")
        right_start = t.typ[j + 1] in ("id", "str", "tpl", "tpl_head", "num") \
            or t.is_p(j + 1, "++", "--", "!", "~")
        if t.typ[j] == "id" and t.val[j] in ("typeof", "void", "new", "delete", "in",
                                              "instanceof", "await"):
            return False
        return left_end and right_start

    def has_q_left(self, t: _Toks, j: int) -> bool:
        """Is the ':' at ``j`` a ternary colon (a '?' to its left in the same
        expression)?"""
        k = j - 1
        depth_q = 0
        while k >= 0:
            ty, v = t.typ[k], t.val[k]
            if ty == "punct" and v in (")", "]"):
                k = t.match[k] - 1
                continue
            if ty == "tpl_tail":
                k = t.match[k] - 1
                continue
            if ty == "punct" and v == ":":
                depth_q += 1
            elif ty == "punct" and v == "?":
                if depth_q == 0:
                    return True
                depth_q -= 1
            elif (ty == "punct" and v in _LEFT_STOP_PUNCT | {"}"}) or ty in (
                    "tpl_head", "tpl_mid") or (ty == "id" and v in _STOP_KW):
                return False
            k -= 1
        return False

    def callee(self, t: _Toks, o: int) -> tuple[list[str], int, bool] | None:
        """For the '(' at ``o``: the callee's member chain, its first token, and
        whether ``new`` precedes it; None when '(' is not a call."""
        j = o - 1
        if j < 0:
            return None
        if t.typ[j] == "id" and t.val[j] in _KEYWORDS and t.val[j] not in ("super",):
            return None
        if not (t.typ[j] == "id" or t.is_p(j, ")", "]")):
            return None
        names: list[str] = []
        while True:
            if t.typ[j] == "id":
                names.append(t.val[j])
                if t.is_p(j - 1, ".", "?.") and j - 2 >= 0:
                    j -= 2
                    continue
                break
            return [], j, False  # `f()(…)` / `a[b](…)`: unknown callee
        names.reverse()
        is_new = t.is_id(j - 1, "new")
        return names, j - (1 if is_new else 0), is_new

    def in_open(self, path: str, t: _Toks, o: int, a: int, b: int):
        """The value is inside the group opened at ``o``. Returns a new range to keep
        climbing, or None when the value has been classified as safe."""
        v = t.val[o] if t.typ[o] == "punct" else ""
        if v == "(":
            c = self.callee(t, o)
            if c is None:
                kw = t.val[o - 1] if t.is_id(o - 1) else ""
                if kw in _COND_KW:
                    return None  # condition: the value is tested, not run
                if kw == "catch" or kw == "function" or kw == "with":
                    raise _UnclassifiedError(f"value in {kw}(…)")
                if not t.is_p(t.match[o] + 1, "=>"):
                    # grouping (or a sequence inside parens)
                    if any(t.is_p(j, ",") and self.enclosing_open(t, j) == o
                           for j in range(o + 1, t.match[o])):
                        if b + 1 != t.match[o]:
                            return None  # not the last element of a sequence
                    return o, t.match[o]
                raise _UnclassifiedError("value in arrow parameters")
            names, first, is_new = c
            if not names:
                raise _UnclassifiedError("unknown callee")
            return self.call(path, t, o, names, first, is_new)
        if v == "[":
            j = o - 1
            if j >= 0 and (t.typ[j] in ("id", "str", "tpl", "tpl_tail")
                           and t.val[j] not in _KEYWORDS or t.is_p(j, ")", "]")):
                raise _UnclassifiedError("value used as a computed key")
            return o, t.match[o]
        if v == "{":
            if self.specifier(t, a, path) and a == b:
                return None
            raise _UnclassifiedError("value in an object literal or block")
        raise _UnclassifiedError("value in an unknown group")

    def call(self, path: str, t: _Toks, o: int, names: list[str], first: int,
             is_new: bool):
        last = names[-1]
        # String formatting: `chalk.bold(x)`, `import_chalk.default.dim(x)`, `String(x)`.
        lib_at = next((i for i, n in enumerate(names) if _COLOR_LIB_RE.search(n)), None)
        if names == ["String"] or (
                lib_at is not None and all(n in _STYLE_NAMES for n in names[lib_at + 1:])):
            if len(names) > 1:
                self.require_method_safe(path, names, must_exist=False)
            self.require_plain_args(path, t, o)
            return first, t.match[o]
        # Array building: `lines.push(x)` → follow `lines`.
        if len(names) == 2 and last in ("push", "unshift"):
            self.follow_binding(path, t, names[0], first)
            return None
        # Output.
        if names[0] == "console" and len(names) == 2 and last in _CONSOLE_METHODS:
            self.require_console_unshadowed()
            return None
        if names in (["process", "stdout", "write"], ["process", "stderr", "write"]):
            return None
        if len(names) >= 2 and last in _OUTPUT_METHODS and names[0] != "console":
            self.require_method_safe(path, names, must_exist=True)
            self.require_plain_args(path, t, o)
            return None
        # Error messages: `new Error(x)`, `reject(new Error(x))`, `throw Error(x)`.
        if len(names) == 1 and last in _BUILTIN_ERRORS:
            self.require_not_redefined(last)
            self.require_no_catch_exec()
            return None
        raise _UnclassifiedError(f"value passed to {'.'.join(names)}()")

    # -- bindings ------------------------------------------------------------------
    def assigned(self, path: str, t: _Toks, eq: int) -> None:
        """``NAME = value`` / ``const NAME = value`` / ``NAME += value``."""
        lhs = eq - 1
        if not t.is_id(lhs) or t.val[lhs] in _KEYWORDS:
            raise _UnclassifiedError("assignment to a member, pattern or keyword")
        before = lhs - 1
        if t.is_p(before, ".", "?."):
            raise _UnclassifiedError("assignment to a member")
        name = t.val[lhs]
        if t.is_id(before, "var", "let", "const"):
            decl = before
        elif t.is_p(before, ","):
            decl = self.decl_of_list(t, before)
            if decl is None:
                raise _UnclassifiedError("assignment inside a sequence")
        else:
            if not (before < 0 or t.is_p(before, ";", "{", "}") or t.nl[lhs]):
                raise _UnclassifiedError("chained or nested assignment")
            self.follow_binding(path, t, name, lhs)
            return
        self.follow_decl(path, t, name, lhs, decl)

    def decl_of_list(self, t: _Toks, comma: int) -> int | None:
        j = comma - 1
        while j >= 0:
            if t.is_p(j, ")", "]", "}") or t.typ[j] == "tpl_tail":
                j = t.match[j] - 1
                continue
            if t.is_id(j, "var", "let", "const"):
                return j
            if t.is_p(j, ";", "(", "[", "{") or t.typ[j] in ("tpl_head", "tpl_mid"):
                return None
            j -= 1
        return None

    def follow_binding(self, path: str, t: _Toks, name: str, near: int) -> None:
        """Follow a name assigned without a declaration keyword: find its
        declaration in the file (it must have one)."""
        decls = [k for k in t.by_val.get(name, [])
                 if t.is_id(k - 1, "var", "let", "const")
                 or (t.is_p(k - 1, ",") and self.decl_of_list(t, k - 1) is not None
                     and t.is_p(k + 1, "=", ";", ","))]
        if len(decls) != 1:
            raise _UnclassifiedError(f"no single declaration for {name}")
        k = decls[0]
        decl = k - 1 if t.is_id(k - 1) else self.decl_of_list(t, k - 1)
        self.follow_decl(path, t, name, k, decl)

    def follow_decl(self, path: str, t: _Toks, name: str, at: int, decl: int) -> None:
        key = (path, "decl", at)
        if key in self.followed:
            return
        self.followed.add(key)
        kind = t.val[decl]
        o = self.enclosing_open(t, decl)
        if kind == "var":
            # Function scope: widen to the outermost block of this top-level statement.
            while o != -1:
                outer = self.enclosing_open(t, o)
                if outer == -1:
                    break
                o = outer
        top_level = o == -1
        if top_level:
            lo, hi = 0, len(t) - 1
        else:
            if not t.is_p(o, "{"):
                o2 = o
                while o2 != -1 and not t.is_p(o2, "{"):
                    o2 = self.enclosing_open(t, o2)
                if o2 == -1:
                    lo, hi = 0, len(t) - 1
                    top_level = True
                else:
                    o = o2
            if not top_level:
                lo, hi = o, t.match[o]
        exported = top_level and (t.is_id(decl - 1, "export") or self.mentions_exported(
            path, name))
        self.require_no_direct_eval(t, lo, hi)
        self.check_name_unmentioned(
            name, path, exclude=(path, at),
            span=None if (exported or (top_level and self.package)) else (lo, hi))
        if exported:
            self.check_namespace_imports(path)
        # A top-level name is followed into every file of a package even when it is
        # not exported (a script evaluated into the global scope shares it).
        files = self.scope_files(path, exported or (top_level and self.package)) \
            if top_level else [path]
        used_before = self.uses
        for fp in files:
            if name not in self.files[fp]:
                continue
            ft = self.toks(fp)
            for r in ft.by_val.get(name, []):
                if fp == path and (r == at or not (lo <= r <= hi)):
                    continue
                self.read(fp, ft, r)
        if self.uses == used_before:
            raise _UnclassifiedError("never read: nothing shows it to a person")

    def read(self, fp: str, ft: _Toks, r: int) -> None:
        """Classify one occurrence of a followed variable name."""
        if ft.is_p(r - 1, ".", "?."):
            return  # `obj.name`: a different property
        if ft.is_p(r + 1, ":") and ft.is_p(r - 1, "{", ",") and self.enclosing_open(
                ft, r) != -1 and ft.is_p(self.enclosing_open(ft, r), "{") \
                and not self.has_q_left(ft, r + 1):
            return  # `{ name: … }`: an object key
        if ft.is_p(r + 1, "=", "+=") and not ft.is_p(r - 1, ",", "{", "["):
            return  # overwritten / appended to: a write, not a read
        if ft.is_id(r - 1, "var", "let", "const", "function", "class"):
            raise _UnclassifiedError("name redeclared")
        if self.specifier(ft, r, fp):
            return
        self.value(fp, r, r)

    def specifier(self, t: _Toks, r: int, path: str) -> bool:
        """``import { NAME } from …`` / ``export { NAME }``: neutral in a package
        scan (importers are followed by name); unknown in a per-file scan."""
        o = self.enclosing_open(t, r)
        if o == -1 or not t.is_p(o, "{"):
            return False
        j = o - 1
        if t.is_p(j, ","):
            j -= 1
            if t.is_id(j):
                j -= 1
        if not t.is_id(j, "import", "export"):
            if t.is_id(j, "type") and t.is_id(j - 1, "import", "export"):
                j -= 1
            else:
                return False
        if t.is_id(r + 1, "as") or t.is_id(r - 1, "as"):
            raise _UnclassifiedError("renamed import / export")
        if not self.package:
            raise _UnclassifiedError("name leaves the file (export)")
        return True

    def returned(self, path: str, t: _Toks, ret: int) -> None:
        """``return value``: follow every call of the enclosing function."""
        o = self.enclosing_open(t, ret)
        while o != -1:
            if t.is_p(o, "{"):
                name = self.function_name(t, o)
                if name is not None:
                    if name == "":
                        raise _UnclassifiedError("returned from an anonymous function")
                    self.follow_function(path, t, name, o)
                    return
            o = self.enclosing_open(t, o)
        raise _UnclassifiedError("return outside a function")

    def function_name(self, t: _Toks, o: int) -> str | None:
        """Name of the function whose body opens at ``o``; "" if anonymous; None
        if the block is not a function body."""
        j = o - 1
        if t.is_p(j, ":") and t.typ[j - 1] == "id":  # TS return type `): T {`
            k = j - 1
            while k >= 0 and not t.is_p(k, ")"):
                k -= 1
            j = k
        if t.is_p(j, "=>"):
            return self.arrow_binding(t, j)
        if not t.is_p(j, ")"):
            return None
        po = t.match[j]
        q = po - 1
        if t.is_id(q, "function"):
            return self.anon_binding(t, q)
        if t.is_id(q) and t.val[q] not in _KEYWORDS:
            if t.is_id(q - 1, "function") or t.is_p(q - 1, "*"):
                return t.val[q]
            if t.is_p(q - 1, "{", "}", ";", ",") or t.is_id(q - 1, "async", "static", "get",
                                                            "set") or t.nl[q]:
                return t.val[q]  # method shorthand
            return None
        if t.is_id(q, "if", "for", "while", "switch", "catch", "with"):
            return None
        return None

    def anon_binding(self, t: _Toks, fn: int) -> str:
        j = fn - 1
        if t.is_id(j, "async"):
            j -= 1
        if t.is_p(j, "=", ":") and t.is_id(j - 1):
            return t.val[j - 1]
        return ""

    def arrow_binding(self, t: _Toks, arrow: int) -> str:
        j = arrow - 1
        if t.is_p(j, ")"):
            j = t.match[j] - 1
        elif t.is_id(j):
            j -= 1
        else:
            return ""
        if t.is_id(j, "async"):
            j -= 1
        if t.is_p(j, "=", ":") and t.is_id(j - 1):
            return t.val[j - 1]
        return ""

    def arrow_returned(self, path: str, t: _Toks, arrow: int) -> None:
        name = self.arrow_binding(t, arrow)
        if not name:
            raise _UnclassifiedError("concise body of an anonymous arrow")
        self.follow_function(path, t, name, arrow)

    def follow_function(self, path: str, t: _Toks, name: str, at: int) -> None:
        key = ("fn", name)
        if key in self.followed:
            return
        self.followed.add(key)
        self.check_name_unmentioned(name, path, exclude=None)
        files = self.scope_files(path, True) if self.package else [path]
        if not self.package and self.mentions_exported(path, name):
            raise _UnclassifiedError("function leaves the file (export)")
        if self.package:
            self.check_namespace_imports(path)
        used_before = self.uses
        for fp in files:
            if name not in self.files[fp]:
                continue
            ft = self.toks(fp)
            for r in ft.by_val.get(name, []):
                if ft.is_p(r + 1, "("):
                    # a call: its result carries the value
                    start = r
                    while ft.is_p(start - 1, ".", "?.") and ft.is_id(start - 2):
                        start -= 2
                    if ft.is_id(start - 1, "function"):
                        continue  # the declaration itself
                    if self.function_name_decl_at(ft, r):
                        continue
                    self.value(fp, start, ft.match[r + 1])
                    continue
                if ft.is_p(r + 1, "=", ":") and (self.function_def_follows(ft, r)):
                    continue  # `name = function (…)` / `name: (…) =>` definition
                if ft.is_id(r - 1, "function"):
                    continue
                if self.specifier(ft, r, fp):
                    continue
                raise _UnclassifiedError(f"function {name} used other than by a call")
        if self.uses == used_before:
            raise _UnclassifiedError("never read: nothing shows it to a person")

    def function_name_decl_at(self, t: _Toks, r: int) -> bool:
        """Is the ``name(`` at ``r`` a method-shorthand definition (``name(a) {``)?"""
        close = t.match.get(r + 1)
        if close is None:
            return False
        nxt = close + 1
        if t.is_p(nxt, ":"):
            nxt += 1
            while nxt < len(t) and not t.is_p(nxt, "{", ";", "=>"):
                nxt += 1
        return t.is_p(nxt, "{") and (t.is_p(r - 1, "{", "}", ";", ",")
                                      or t.is_id(r - 1, "async", "static", "get", "set")
                                      or t.nl[r])

    def function_def_follows(self, t: _Toks, r: int) -> bool:
        j = r + 2
        if t.is_id(j, "async"):
            j += 1
        if t.is_id(j, "function"):
            return True
        if t.is_p(j, "("):
            return t.is_p(t.match[j] + 1, "=>")
        return t.is_id(j) and t.is_p(j + 1, "=>")

    # -- package-wide guards ---------------------------------------------------------
    def scope_files(self, path: str, leaves_file: bool) -> list[str]:
        if not leaves_file:
            return [path]
        if not self.package:
            raise _UnclassifiedError("name leaves the file")
        return [path] + [p for p in self.code_paths if p != path]

    def mentions_exported(self, path: str, name: str) -> bool:
        text = self.files[path]
        n = re.escape(name)
        return bool(re.search(
            r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?|class|const|let|var)"
            r"\s+" + n + r"\b|\bexport\s*\{[^}]*\b" + n + r"\b|\bexports\s*\.\s*" + n
            + r"\b|module\s*\.\s*exports\b[^;]*\b" + n + r"\b", text))

    def check_name_unmentioned(self, name: str, path: str, exclude, span=None) -> None:
        """A followed name inside a string (``this['X']``, ``eval('X')``) or in a
        non-code file (package.json, a shell script) keeps the finding."""
        rx = re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])")
        paths = [path] if span is not None else list(self.files)
        for fp in paths:
            text = self.files[fp]
            if not text or name not in text:
                continue
            low = fp.lower()
            if Path(low).suffix in JS_EXTS and not low.endswith(_DTS_SUFFIXES):
                ft = self.toks(fp)
                rng = range(span[0], span[1] + 1) if (span and fp == path) else range(len(ft))
                for k in rng:
                    if ft.typ[k] in ("str", "tpl", "tpl_head", "tpl_mid", "tpl_tail", "regex") \
                            and rx.search(text, ft.st[k], ft.en[k]):
                        raise _UnclassifiedError(f"{name} named inside a string")
            elif low.endswith(_INERT_SUFFIXES):
                continue
            elif rx.search(text):
                raise _UnclassifiedError(f"{name} mentioned in {fp}")

    def check_namespace_imports(self, path: str) -> None:
        """A module whose exports are reachable as a namespace (``import * as m``,
        ``require('./m')``, ``import('./m')``, ``export * from``) can be iterated."""
        stem = Path(path).stem
        if not stem:
            return
        rx = re.compile(r"""['"`][^'"`\n]*[/'"`]""" + re.escape(stem)
                        + r"""(?:\.[cm]?[jt]sx?)?['"`]""")
        for fp in self.code_paths:
            text = self.files[fp]
            if stem not in text:
                continue
            ft = self.toks(fp)
            for m in rx.finditer(text):
                k = ft.at(m.start())
                if k < 0 or ft.typ[k] != "str":
                    continue
                # Allowed: `import { a, b } from "./m"` / `export { a } from "./m"`.
                if ft.is_id(k - 1, "from") and ft.is_p(k - 2, "}"):
                    o = ft.match[k - 2]
                    j = o - 1
                    if ft.is_id(j, "type"):
                        j -= 1
                    if ft.is_id(j, "import", "export"):
                        continue
                if ft.is_id(k - 1, "import") and ft.is_p(k + 1, ";"):
                    continue  # side-effect import
                raise _UnclassifiedError(f"{fp} reaches {path} as a namespace")

    def require_no_direct_eval(self, t: _Toks, lo: int, hi: int) -> None:
        for k in t.by_val.get("eval", []):
            if lo <= k <= hi and t.is_p(k + 1, "(") and not t.is_p(k - 1, "."):
                raise _UnclassifiedError("direct eval in scope")

    def require_console_unshadowed(self) -> None:
        if self._console_ok is None:
            self._console_ok = not any(
                _CONSOLE_SHADOW_RE.search(self.files[p]) for p in self.code_paths)
        if not self._console_ok:
            raise _UnclassifiedError("console is reassigned or shadowed")

    def require_not_redefined(self, name: str) -> None:
        rx = re.compile(r"\b(?:class|function)\s+" + name + r"\b|(?<![\w$.])" + name
                        + r"\s*=(?!=)|\b(?:var|let|const)\s+" + name + r"\b")
        for p in self.code_paths:
            if rx.search(self.files[p]):
                raise _UnclassifiedError(f"{name} is redefined")

    def require_no_catch_exec(self) -> None:
        """A caught error handed to a command runner turns a message into a command."""
        if self._catch_ok is None:
            ok = True
            for p in self.code_paths:
                text = self.files[p]
                if not any(w in text for w in ("catch", "Exception", "Rejection", "then",
                                               "'error'", '"error"')):
                    continue
                for m in _CATCH_RE.finditer(text):
                    v = m.group(1) or m.group(2) or m.group(3) or m.group(4)
                    if not v or v in _KEYWORDS:
                        continue
                    if self.handler_runs(text, _handler_body(text, m.end()), v):
                        ok = False
                        break
                if not ok:
                    break
            self._catch_ok = ok
        if not self._catch_ok:
            raise _UnclassifiedError("a caught error reaches a command runner")

    def handler_runs(self, text: str, body: str, v: str) -> bool:
        """Does ``body`` hand ``v`` (or a name derived from it) to a command runner,
        directly or through a function the package defines with a runner inside?"""
        derived = {v}
        for _ in range(4):
            grew = False
            for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]{0,300})",
                                 body):
                if m.group(1) not in derived and any(
                        re.search(r"(?<![\w$])" + re.escape(d) + r"(?![\w$])", m.group(2))
                        for d in derived):
                    derived.add(m.group(1))
                    grew = True
            if not grew:
                break
        names = "|".join(re.escape(d) for d in derived)
        mention = r"[^;]*?(?<![\w$])(?:" + names + r")(?![\w$])"
        if re.search(r"\b" + _JS_RUN_CALL + r"\s*(?:\.\s*(?:call|apply)\s*)?\(" + mention, body) \
                or re.search(r"\$\s*`[^`]*\$\{[^}]*(?<![\w$])(?:" + names + r")", body):
            return True
        for m in re.finditer(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\((" + mention + r")", body):
            fn = m.group(1)
            if fn in _KEYWORDS:
                continue
            for p in self.code_paths:
                if fn in self.files[p] and any(_JS_SINK_RE.search(bb)
                                               for bb in _def_bodies(self.files[p], fn)):
                    return True
        return False

    def require_plain_args(self, path: str, t: _Toks, o: int) -> None:
        """No argument of a print / format call names a command runner (a ``color``
        callback parameter could be handed ``execSync``)."""
        if _JS_SINK_RE.search(self.files[path], t.en[o], t.st[t.match[o]]):
            raise _UnclassifiedError("a command runner is passed to the print call")

    def receiver_file(self, path: str, root: str, hops: int = 4,
                      allow_deps: bool = False) -> str | None:
        """The package file that defines ``root`` (the object a print method is called
        on), following relative imports. A receiver from a dependency, a parameter or a
        global is unknown."""
        if root == "this":
            return path
        if hops <= 0:
            raise _UnclassifiedError("receiver import chain too long")
        text = self.files[path]
        spec = _binding_spec(text, root)
        if spec is not None:
            if not spec.startswith((".", "/")):
                if allow_deps and spec.split("/")[0] in _SAFE_OUTPUT_DEPS:
                    return None  # a terminal-colour dependency (chalk, ansis …)
                raise _UnclassifiedError(f"{root} comes from the dependency {spec}")
            target = self.resolve_import(path, spec)
            if target is None:
                raise _UnclassifiedError(f"cannot resolve {spec}")
            return self.receiver_file(target, root, hops - 1, allow_deps)
        r = re.escape(root)
        if re.search(r"\b(?:var|let|const|class|function)\s+" + r + r"\b|[,;{}]\s*" + r
                     + r"\s*=(?![=>])|^\s*" + r + r"\s*=(?![=>])", text, re.M):
            return path
        raise _UnclassifiedError(f"{root} is not defined in the package")

    def resolve_import(self, path: str, spec: str) -> str | None:
        import posixpath
        base = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        stem = re.sub(r"\.[cm]?js$", "", base)
        for cand in (base, stem + ".js", stem + ".mjs", stem + ".cjs", stem + ".ts",
                     stem + ".mts", stem + ".cts", stem + ".tsx", base + "/index.js",
                     base + "/index.ts"):
            if cand in self.files:
                return cand
        return None

    def require_method_safe(self, path: str, names: list[str], must_exist: bool) -> None:
        """The print / format method ``names[-1]`` as defined in the file that defines
        the receiver runs nothing, down three calls."""
        def_file = self.receiver_file(path, names[0], allow_deps=not must_exist)
        if def_file is None:
            return
        method = names[-1]
        text = self.files[def_file]
        bodies = _def_bodies(text, method)
        if must_exist and not bodies:
            raise _UnclassifiedError(f"{'.'.join(names)}() has no definition in the package")
        if self.aliased_to_sink(text, method):
            raise _UnclassifiedError(f"{method} is bound to a command runner")
        self.check_bodies(def_file, bodies, 3, set())

    def check_bodies(self, fp: str, bodies: list[str], depth: int, seen: set) -> None:
        text = self.files[fp]
        for body in bodies:
            if _JS_SINK_RE.search(body):
                raise _UnclassifiedError("a print method runs a command")
            if re.search(r"\.\s*write\s*\(", body) and re.search(r"\bstd(?:in|io)\b", text):
                raise _UnclassifiedError("a print method writes to a stream in a file "
                                         "that touches a child's stdin")
            for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*\(", body):
                n = m.group(1)
                if n in _KEYWORDS or n in _STYLE_NAMES or n in seen or n in (
                        "console", "String", "Number", "Boolean", "write", "format",
                        "require"):
                    continue
                seen.add(n)
                if len(seen) > 60:
                    raise _UnclassifiedError("a print method calls too much to follow")
                if self.aliased_to_sink(text, n):
                    raise _UnclassifiedError(f"{n} is bound to a command runner")
                spec = _binding_spec(text, n)
                if spec is not None:
                    if not spec.startswith((".", "/")):
                        if spec.split("/")[0] not in _SAFE_OUTPUT_DEPS:
                            raise _UnclassifiedError(f"a print method calls {n} from {spec}")
                        continue
                    target = self.resolve_import(fp, spec)
                    if target is None:
                        raise _UnclassifiedError(f"cannot resolve {spec}")
                    if self.aliased_to_sink(self.files[target], n):
                        raise _UnclassifiedError(f"{n} is bound to a command runner")
                    if depth > 0:
                        self.check_bodies(target, _def_bodies(self.files[target], n),
                                          depth - 1, seen)
                    continue
                if depth > 0:
                    self.check_bodies(fp, _def_bodies(text, n), depth - 1, seen)

    def aliased_to_sink(self, text: str, name: str) -> bool:
        """``log: cp.execSync`` / ``const log = run`` / ``this.log = exec.bind(…)``:
        ``name`` bound to something other than a function literal that is (or was
        assigned) a command runner."""
        rx = re.compile(r"(?<![\w$])" + re.escape(name)
                        + r"\s*(?::|=(?![=>]))\s*([^;\n,}]{0,200})")
        for m in rx.finditer(text):
            rhs = m.group(1).strip()
            if re.match(r"(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[\w$]+\s*=>)", rhs):
                continue
            if _JS_SINK_RE.search(rhs):
                return True
            ident = re.match(r"([\w$]+)(?:\s*\.\s*([\w$]+))*\s*$", rhs)
            if ident:
                last = re.findall(r"[\w$]+", rhs)[-1]
                if last == name or last in _KEYWORDS:
                    continue
                if re.search(r"(?<![\w$])" + re.escape(last)
                             + r"\s*(?::|=(?![=>]))\s*[^;\n,}]{0,200}?(?:"
                             + _JS_SINK_RE.pattern + ")", text):
                    return True
                if any(_JS_SINK_RE.search(b) for b in _def_bodies(text, last)):
                    return True
        return False


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_PY_PRINT_ATTRS = frozenset({
    "echo", "secho", "info", "warning", "warn", "error", "debug", "critical",
    "exception", "log", "print", "fatal",
})
_PY_PRINT_BASES = frozenset({
    "click", "typer", "logging", "logger", "log", "_logger", "LOGGER", "LOG", "console",
    "rich", "warnings", "self.logger", "self.log", "self._logger", "cls.logger",
})
_PY_STR_METHODS = frozenset({
    "format", "strip", "rstrip", "lstrip", "join", "replace", "upper", "lower",
})
_PY_SINK_RE = re.compile(
    r"\bsubprocess\b|\bos\.(?:system|popen|exec\w*|spawn\w*)|\bexec\s*\(|\beval\s*\(|"
    r"\bPopen\b|\bpty\.spawn|\bcompile\s*\(|\brunpy\b|\bcommands\.|\bsh\.|\bplumbum\b")


class _PyFlow:
    def __init__(self, files: dict[str, str], package: bool) -> None:
        self.files = files
        self.package = package
        self._trees: dict[str, tuple[ast.AST, dict]] = {}
        self.steps = 0
        self.followed: set = set()
        self.py_paths = [p for p in files if Path(p.lower()).suffix in PY_EXTS]
        self.uses = 0

    def tree(self, path: str):
        if path not in self._trees:
            try:
                tr = ast.parse(self.files[path])
            except (SyntaxError, ValueError) as exc:
                raise _UnclassifiedError("does not parse") from exc
            parents: dict = {}
            for node in ast.walk(tr):
                for ch in ast.iter_child_nodes(node):
                    parents[ch] = node
            self._trees[path] = (tr, parents)
        return self._trees[path]

    def tick(self) -> None:
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise _UnclassifiedError("walk too long")

    def literal(self, path: str, line_no: int, col: int, end_col: int) -> None:
        tr, parents = self.tree(path)
        line = self.files[path].split("\n")[line_no - 1]
        bcol = len(line[:col].encode("utf-8"))
        bend = len(line[:end_col].encode("utf-8"))
        best = None
        for node in ast.walk(tr):
            if not isinstance(node, (ast.Constant, ast.JoinedStr)):
                continue
            if isinstance(node, ast.Constant) and not isinstance(node.value, str):
                continue
            if isinstance(parents.get(node), ast.JoinedStr):
                continue
            s = (node.lineno, node.col_offset)
            e = (node.end_lineno, node.end_col_offset)
            if s <= (line_no, bcol) and (line_no, bend) <= e:
                if best is None or (s >= (best.lineno, best.col_offset)):
                    best = node
        if best is None:
            raise _UnclassifiedError("match is not inside one string literal")
        if isinstance(parents.get(best), ast.Expr):
            raise _UnclassifiedError("a docstring / bare string")  # left to the prose rules
        self.value(path, best)

    def value(self, path: str, node: ast.AST) -> None:
        self.uses += 1
        tr, parents = self.tree(path)
        while True:
            self.tick()
            par = parents.get(node)
            if par is None:
                raise _UnclassifiedError("no parent")
            if isinstance(par, (ast.JoinedStr, ast.FormattedValue, ast.IfExp, ast.BoolOp,
                                ast.List, ast.Tuple)):
                if isinstance(par, ast.IfExp) and node is par.test:
                    return
                node = par
                continue
            if isinstance(par, ast.BinOp) and isinstance(par.op, (ast.Add, ast.Mod)):
                node = par
                continue
            if isinstance(par, ast.Compare):
                return
            if isinstance(par, ast.Attribute) and par.value is node:
                gp = parents.get(par)
                if par.attr in _PY_STR_METHODS and isinstance(gp, ast.Call) and gp.func is par:
                    node = gp
                    continue
                raise _UnclassifiedError(f".{par.attr} on the value")
            if isinstance(par, ast.Call):
                if node is par.func:
                    raise _UnclassifiedError("the value is called")
                f = par.func
                if isinstance(f, ast.Attribute) and f.attr in ("join", "format") and \
                        isinstance(f.value, (ast.Constant, ast.JoinedStr)):
                    node = par
                    continue
                if self.is_print(path, par):
                    return
                if self.is_exception(path, f, parents.get(par)):
                    return
                raise _UnclassifiedError(f"value passed to {ast.unparse(f)[:60]}()")
            if isinstance(par, ast.keyword):
                raise _UnclassifiedError("value passed as a keyword argument")
            if isinstance(par, ast.Raise):
                return
            if isinstance(par, ast.Return):
                self.returned(path, par)
                return
            if isinstance(par, (ast.Assign, ast.AnnAssign)) and getattr(par, "value", None) is node:
                targets = par.targets if isinstance(par, ast.Assign) else [par.target]
                if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                    raise _UnclassifiedError("assignment to a non-name")
                self.follow_name(path, targets[0].id, par)
                return
            if isinstance(par, ast.Expr):
                return  # discarded
            raise _UnclassifiedError(f"value in {type(par).__name__}")

    def is_print(self, path: str, call: ast.Call) -> bool:
        f = call.func
        if self.streams_rebound():
            return False
        if isinstance(f, ast.Name) and f.id == "print":
            for kw in call.keywords:
                if kw.arg == "file" and ast.unparse(kw.value) not in ("sys.stdout",
                                                                      "sys.stderr"):
                    return False  # print(cmd, file=proc.stdin) feeds a shell
                if kw.arg is None:
                    return False
            return not self.redefined("print")
        if isinstance(f, ast.Attribute) and f.attr in _PY_PRINT_ATTRS:
            base = ast.unparse(f.value)
            if base in _PY_PRINT_BASES or base.endswith(("logger", "log", "console")):
                if f.attr in ("echo", "secho") and any(
                        kw.arg in ("file", None) for kw in call.keywords):
                    return False
                # A logging handler's emit() / a logger method the package defines runs
                # whatever its body runs.
                return not (self.redefined(f.attr) or self.redefined("emit")
                            or self.redefined("handle") or self.redefined("format")
                            or self.redefined("filter"))
        if isinstance(f, ast.Attribute) and f.attr == "write" and ast.unparse(f.value) in (
                "sys.stdout", "sys.stderr"):
            return True
        return False

    def streams_rebound(self) -> bool:
        if not hasattr(self, "_streams"):
            self._streams = any(re.search(
                r"\bsys\s*\.\s*std(?:out|err)\s*=(?!=)|setattr\s*\(\s*sys\b|"
                r"redirect_std(?:out|err)", self.files[p]) for p in self.py_paths)
        return self._streams

    def is_exception(self, path: str, f: ast.AST, gp) -> bool:
        name = f.id if isinstance(f, ast.Name) else (
            f.attr if isinstance(f, ast.Attribute) else "")
        if not re.search(r"(?:Error|Exception|Warning|Exit|Abort)$", name or ""):
            return False
        if not isinstance(gp, ast.Raise):
            return False
        return not (self.redefined(name) or self.except_runs())

    def except_runs(self) -> bool:
        """Some ``except … as e`` (or ``sys.excepthook``) in the package hands the
        caught exception to a command runner: a message can become a command."""
        if hasattr(self, "_except_runs"):
            return self._except_runs
        found = False
        for p in self.py_paths:
            text = self.files[p]
            if "excepthook" in text:
                found = True
                break
            if " as " not in text or not _PY_SINK_RE.search(text):
                continue
            try:
                tr, _ = self.tree(p)
            except _UnclassifiedError:
                found = True
                break
            for node in ast.walk(tr):
                if isinstance(node, ast.ExceptHandler) and node.name:
                    # Whole handler: `c = str(e)` then `os.system(c)` is two statements.
                    src = "\n".join(ast.unparse(sub) for sub in node.body)
                    if _PY_SINK_RE.search(src) and re.search(
                            r"(?<![\w])" + re.escape(node.name) + r"(?![\w])", src):
                        found = True
                if found:
                    break
            if found:
                break
        self._except_runs = found
        return found

    def redefined(self, name: str) -> bool:
        """A def / class of ``name`` in the package whose body runs a command, or an
        attribute rebinding (``logger.info = os.system``)."""
        rx = re.compile(r"^([ \t]*)(?:async\s+)?(?:def|class)\s+" + re.escape(name) + r"\b",
                        re.M)
        rebind = re.compile(r"\.\s*" + re.escape(name) + r"\s*=(?!=)|setattr\s*\([^)]*['\"]"
                            + re.escape(name) + r"['\"]" + (
                                r"|^\s*print\s*=(?!=)|\bbuiltins\.print\b"
                                if name == "print" else ""), re.M)
        for p in self.py_paths:
            text = self.files[p]
            if name not in text:
                continue
            if rebind.search(text):
                return True
            for m in rx.finditer(text):
                indent = len(m.group(1))
                rest = text[m.end():].split("\n")
                body_lines = [rest[0]]
                for ln in rest[1:400]:
                    if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                        break
                    body_lines.append(ln)
                if _PY_SINK_RE.search("\n".join(body_lines)):
                    return True
        return False

    def scope_of(self, path: str, node: ast.AST):
        tr, parents = self.tree(path)
        p = parents.get(node)
        while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                   ast.Lambda, ast.ClassDef)):
            p = parents.get(p)
        return p

    def follow_name(self, path: str, name: str, at: ast.AST) -> None:
        key = (path, name, id(self.scope_of(path, at)))
        if key in self.followed:
            return
        self.followed.add(key)
        scope = self.scope_of(path, at)
        tr, parents = self.tree(path)
        if isinstance(scope, ast.ClassDef):
            raise _UnclassifiedError("class attribute")
        root = scope if scope is not None else tr
        self.check_strings(path, name, root)
        used_before = self.uses
        for node in ast.walk(root):
            if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
                raise _UnclassifiedError("global / nonlocal")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
                    node.func.id in ("locals", "globals", "vars", "eval", "exec"):
                raise _UnclassifiedError("dynamic namespace access")
            if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
                self.value(path, node)
        if scope is None:
            self.module_level(path, name)
        if self.uses == used_before:
            raise _UnclassifiedError("never read: nothing shows it to a person")

    def module_level(self, path: str, name: str) -> None:
        """A module-level name can be imported from anywhere in the package."""
        if not self.package:
            raise _UnclassifiedError("module-level name leaves the file")
        stem = Path(path).stem
        rx = re.compile(r"(?<![\w])" + re.escape(name) + r"(?![\w])")
        for fp, text in self.files.items():
            if fp == path or not text or name not in text or not rx.search(text):
                continue
            low = fp.lower()
            if Path(low).suffix not in PY_EXTS:
                if low.endswith(_INERT_SUFFIXES) or low.endswith(".pyi"):
                    continue
                raise _UnclassifiedError(f"{name} mentioned in {fp}")
            tr, parents = self.tree(fp)
            self.check_strings(fp, name, tr)
            for node in ast.walk(tr):
                if isinstance(node, ast.Name) and node.id == name and isinstance(
                        node.ctx, ast.Load):
                    self.value(fp, node)
                elif isinstance(node, ast.Attribute) and node.attr == name and isinstance(
                        node.ctx, ast.Load):
                    self.value(fp, node)
                elif isinstance(node, ast.alias) and node.asname and node.name == name:
                    raise _UnclassifiedError("imported under another name")
        for fp in self.py_paths:
            text = self.files[fp]
            if stem in text and re.search(
                    r"\b(?:vars|getattr|dir|inspect\.getmembers)\s*\(|__dict__|import\s+\*",
                    text):
                raise _UnclassifiedError(f"{fp} may read {path} dynamically")

    def check_strings(self, path: str, name: str, root: ast.AST) -> None:
        rx = re.compile(r"(?<![\w])" + re.escape(name) + r"(?![\w])")
        for node in ast.walk(root):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                    rx.search(node.value):
                raise _UnclassifiedError(f"{name} named inside a string")

    def returned(self, path: str, ret: ast.Return) -> None:
        fn = self.scope_of(path, ret)
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise _UnclassifiedError("return outside a named function")
        key = ("fn", fn.name)
        if key in self.followed:
            return
        self.followed.add(key)
        outer = self.scope_of(path, fn)
        if (outer is None or isinstance(outer, ast.ClassDef)) and not self.package:
            raise _UnclassifiedError("function leaves the file")
        paths = self.py_paths if self.package else [path]
        used_before = self.uses
        for fp in paths:
            if fn.name not in self.files[fp]:
                continue
            tr, parents = self.tree(fp)
            self.check_strings(fp, fn.name, tr)
            for node in ast.walk(tr):
                ref = (isinstance(node, ast.Name) and node.id == fn.name) or (
                    isinstance(node, ast.Attribute) and node.attr == fn.name)
                if not ref or not isinstance(node.ctx, ast.Load):
                    continue
                call = parents.get(node)
                if isinstance(call, ast.Call) and call.func is node:
                    self.value(fp, call)
                else:
                    raise _UnclassifiedError(f"{fn.name} used other than by a call")
        if self.package:
            for fp, text in self.files.items():
                low = fp.lower()
                if Path(low).suffix not in PY_EXTS and fn.name in text and not low.endswith(
                        _INERT_SUFFIXES) and re.search(r"\b" + re.escape(fn.name) + r"\b", text):
                    raise _UnclassifiedError(f"{fn.name} mentioned in {fp}")
        if self.uses == used_before:
            raise _UnclassifiedError("never read: nothing shows it to a person")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

class Hints:
    """Answers :func:`hint_only` for many findings over one set of files, sharing
    tokenization and the package-wide checks between them."""

    MAX_QUESTIONS = 64  # findings past this many in one package keep their severity

    def __init__(self, files: dict[str, str], *, package: bool) -> None:
        self.files = files
        self.package = package
        self._js: _JsFlow | None = None
        self._py: _PyFlow | None = None
        self.asked = 0

    def why_not(self, path: str, line_no: int, pattern: re.Pattern) -> str | None:
        """None when every match on the line is a printed hint, else the reason."""
        if not is_supported(path):
            return "unsupported file type"
        text = self.files.get(path)
        if not text:
            return "no text"
        lines = text.split("\n")
        if not (0 < line_no <= len(lines)):
            return "line out of range"
        matches = list(pattern.finditer(lines[line_no - 1]))
        if not matches:
            return "no match on the line"
        self.asked += 1
        if self.asked > self.MAX_QUESTIONS:
            return "too many findings to follow"
        try:
            if Path(path.lower()).suffix in PY_EXTS:
                if self._py is None:
                    self._py = _PyFlow(self.files, self.package)
                for m in matches:
                    self._py.steps = 0
                    self._py.followed = set()
                    self._py.literal(path, line_no, m.start(), m.end())
                return None
            if self._js is None:
                self._js = _JsFlow(self.files, self.package)
            offset = sum(len(ln) + 1 for ln in lines[:line_no - 1])
            for m in matches:
                self._js.steps = 0
                self._js.followed = set()
                self._js.literal(path, offset + m.start(), offset + m.end())
            return None
        except _UnclassifiedError as exc:
            return str(exc) or "unknown"
        except (RecursionError, KeyError, IndexError, ValueError) as exc:
            return f"walk error: {type(exc).__name__}"


def hint_only(files: dict[str, str], path: str, line_no: int, pattern: re.Pattern,
              *, package: bool) -> bool:
    """True when EVERY pipe-to-shell match of ``pattern`` on 1-based ``line_no`` of
    ``path`` is a string whose value only reaches human-facing output."""
    return Hints(files, package=package).why_not(path, line_no, pattern) is None


def why_not(files: dict[str, str], path: str, line_no: int, pattern: re.Pattern,
            *, package: bool) -> str | None:
    """None when :func:`hint_only` holds, else the reason the walk stopped."""
    return Hints(files, package=package).why_not(path, line_no, pattern)
