"""A request-bin / tunnel host inside a regex or pattern string ARRAY is a signature.

A defensive script lists the hosts it looks for (clawdefender's ``CREDENTIAL_EXFIL=(
'webhook\\.site' 'POST.*webhook.site.*API_KEY' ...)`` fed to ``grep -E``); the line
engine's "Outbound webhook/exfil URL" rule read those elements as destinations and
answered Do not connect (2026-10-26 sample, yuanyuekejiJN/AivoClaw).

The relaxation holds only when, in the same file:

* every host match on the line sits inside a quoted string that is an element of an
  array literal (shell ``NAME=( ... )``, Python ``NAME = [ ... ]`` / ``( ... )`` /
  ``{ ... }``, JS ``const NAME = [ ... ]``), on the opener line or on element-only
  lines under it;
* the array is used as patterns (a ``grep`` / ``=~`` / ``re.*`` / ``RegExp`` /
  ``.test`` / ``.match`` / ``in`` use of it or of an element);
* neither the array nor any element, nor any value built from them (followed by name
  through assignments, loop bindings and appends), reaches a network sink or
  request-string building (a line with a URL scheme or ``http``), a same-file
  function whose body has a network sink, or a command / call the file does not
  define and that is not a plain matcher or printer (a helper in an imported module
  may send it);
* the file does no dynamic name access (``eval``, ``${!x}``, ``globals()``,
  ``getattr``); a shell nameref (``local -n p=$2``) is followed like the array.

Anything else keeps the critical. The caller reports a relaxed match as low and
re-raises it when another file of the tree names the array or loads the file
(``npm_scripts.restore_signature_hosts``).
"""
from __future__ import annotations

import re

_STR = r"""(?:[rRbBuUfF]{0,2}"(?:\\.|[^"\\\n])*"|[rRbBuUfF]{0,2}'[^'\n]*')"""
_STR_RE = re.compile(_STR)
# A line that holds nothing but string elements (and a trailing comment).
_ELEMS_ONLY_RE = re.compile(
    r"""^\s*(?:\(?\s*""" + _STR + r"""\s*\)?\s*[,]?\s*)+[\])}]*\s*[,;]?\s*(?:(?:#|//).*)?$""")
_CONT_LINE_RE = re.compile(r"""^\s*(?:(?:#|//).*)?$""")
# The array's opener: the name, `=`, the bracket; elements may follow on the line.
_OPEN_RES = {
    "sh": re.compile(
        r"""^\s*(?:(?:declare|local|readonly|typeset)\s+(?:-[aAr]+\s+)*)?"""
        r"""(?P<name>[A-Za-z_]\w*)\+?=\(\s*(?P<rest>.*)$"""),
    "py": re.compile(
        r"""^\s*(?P<name>[A-Za-z_]\w*)\s*(?::[^=\n]{1,60})?=\s*"""
        r"""(?:(?:frozenset|set|tuple|list)\s*\(\s*)?[\[({]\s*(?P<rest>.*)$"""),
    "js": re.compile(
        r"""^\s*(?:export\s+)?(?:const|let|var|static\s+readonly|readonly)?\s*"""
        r"""(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=\n]{1,60})?=\s*"""
        r"""(?:new\s+Set\s*\(\s*|Object\.freeze\s*\(\s*)?\[\s*(?P<rest>.*)$"""),
}
_SH_EXT = (".sh", ".bash", ".zsh", ".ksh")
_PY_EXT = (".py",)
_JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts")

# A network sink or request-string building on a line.
_NET_RE = re.compile(
    r"""(?<![\w-])(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp)\b"""
    r"""|/dev/(?:tcp|udp)/|://|\b(?i:https?)\b|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b"""
    r"""|\bsendBeacon\b|\bWebSocket\b|\bEventSource\b|\brequests\s*\.|\bhttpx\s*\."""
    r"""|\burllib\w*\b|\burlopen\s*\(|\baiohttp\b|\bsocket\b|\bhttp\.client\b"""
    r"""|\b(?:https?|net|tls|dgram|http2)\s*\.\s*\w+\s*\(|\bgot\s*\(|\bundici\b"""
    r"""|\.(?:post|put|patch|send|request|connect|emit)\s*\(|\bsmtplib\b|\bdns\b""")
# Dynamic name access: a tainted value could be reached without naming it.
_DYNAMIC_RE = re.compile(
    r"""(?<![\w-])eval\b|\$\{!|\bglobals\s*\(|\bvars\s*\(|\bgetattr\s*\(|\b__dict__\b|\bimportlib\b"""
    r"""|\bnew\s+Function\s*\(|\bReflect\.|\bexec\s*\(""")
# A use of the array / an element as a pattern.
_MATCHER_RE = re.compile(
    r"""\b(?:e?grep|fgrep|rg|ag)\b|=~|\bre\s*\.\s*(?:compile|search|match|fullmatch|findall"""
    r"""|finditer|sub|split)\s*\(|\bRegExp\s*\(|\.(?:test|match|matchAll|search|includes"""
    r"""|startswith|endswith|startsWith|endsWith)\s*\(|\bfnmatch\b|\bin\s+[\w$.]+""")
# Calls / commands a tainted value may go through without leaving the process.
_SAFE_SH_CMDS = frozenset({
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "tr", "cut",
    "head", "tail", "sort", "uniq", "wc", "local", "declare", "readonly", "typeset",
    "export", "return", "test", "[", "[[", "case", "if", "then", "elif", "else", "while",
    "until", "for", "do", "done", "fi", "esac", "read", "jq", "true", "false", "!",
    "shift", "continue", "break", "unset", "set", "{", "}", "(", ")",
})
_SAFE_CALLS = frozenset({
    "compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "split",
    "escape", "RegExp", "test", "matchAll", "includes", "startswith", "endswith",
    "startsWith", "endsWith", "lower", "upper", "strip", "lstrip", "rstrip", "trim",
    "toLowerCase", "toUpperCase", "replace", "join", "format", "len", "any", "all",
    "str", "repr", "list", "tuple", "set", "frozenset", "sorted", "print", "log", "warn",
    "error", "info", "debug", "append", "add", "extend", "push", "map", "filter",
    "some", "every", "forEach", "enumerate", "zip", "isinstance", "fnmatch", "dumps",
    "stringify", "String", "Array", "from", "has", "get", "keys", "values", "items",
    "if", "for", "while", "elif", "return", "not", "and", "or", "in",
})


def _lang(path: str) -> str | None:
    p = (path or "").lower()
    if p.endswith(_SH_EXT):
        return "sh"
    if p.endswith(_PY_EXT):
        return "py"
    if p.endswith(_JS_EXT):
        return "js"
    return None


def _is_comment(line: str) -> bool:
    t = line.lstrip()
    return t.startswith("//") or re.match(r"#(?:\s|!|$)", t) is not None


def _in_string(line: str, start: int, end: int) -> tuple[int, int] | None:
    for m in _STR_RE.finditer(line):
        if m.start() < start and end < m.end():
            return m.start(), m.end()
    return None


def _array_name(lines: list[str], idx: int, lang: str) -> tuple[str, int] | None:
    """(array name, opener line) when line ``idx`` is inside an array literal."""
    rx = _OPEN_RES[lang]
    om = rx.match(lines[idx])
    if om:
        return om.group("name"), idx
    if not _ELEMS_ONLY_RE.match(lines[idx]):
        return None
    for j in range(idx - 1, max(-1, idx - 400), -1):
        ln = lines[j]
        om = rx.match(ln)
        if om:
            rest = om.group("rest").strip()
            if not rest or _ELEMS_ONLY_RE.match(rest):
                return om.group("name"), j
            return None
        if not (_ELEMS_ONLY_RE.match(ln) or _CONT_LINE_RE.match(ln)):
            return None
    return None


def _array_end(lines: list[str], start: int, lang: str) -> int:
    """The last line of the array opened on ``start``."""
    depth = 0
    for j in range(start, min(len(lines), start + 2000)):
        code = _STR_RE.sub('""', lines[j])
        if not _is_comment(lines[j]):
            depth += code.count("(") + code.count("[") + code.count("{")
            depth -= code.count(")") + code.count("]") + code.count("}")
        if depth <= 0:
            return j
    return start


def _ref_re(names: set[str], lang: str = "", array: str = "") -> re.Pattern[str]:
    """A use of one of ``names``. In shell only an expansion (``$x``, ``${x[@]}``) is
    a use, plus the array's bare name (passed to a nameref: ``f "$in" ARRAY``)."""
    alt = "|".join(re.escape(n) for n in sorted(names))
    if lang == "sh":
        bare = (r"|(?<![\w$.<-])" + re.escape(array) + r"(?![\w$>])") if array else ""
        return re.compile(r"\$\{?(?:" + alt + r")(?![\w$])" + bare)
    return re.compile(r"(?<![\w$.])\$?\{?(?:" + alt + r")(?![\w$])")


def _functions(lines: list[str], lang: str) -> dict[str, tuple[int, int]]:
    """Same-file function name -> (first, last) line."""
    out: dict[str, tuple[int, int]] = {}
    if lang == "py":
        for i, ln in enumerate(lines):
            m = re.match(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(", ln)
            if not m:
                continue
            ind, end = len(m.group(1)), i
            for j in range(i + 1, len(lines)):
                if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) <= ind:
                    break
                end = j
            out[m.group(2)] = (i, end)
        return out
    head = (re.compile(r"^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{?")
            if lang == "sh" else re.compile(
                r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([\w$]+)\s*\("
                r"|^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?"
                r"(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)"))
    for i, ln in enumerate(lines):
        m = head.match(ln)
        if not m:
            continue
        name = next(g for g in m.groups() if g)
        depth, opened, end = 0, False, i
        for j in range(i, min(len(lines), i + 3000)):
            code = _STR_RE.sub('""', lines[j])
            depth += code.count("{") - code.count("}")
            opened = opened or "{" in code
            end = j
            if opened and depth <= 0:
                break
        out[name] = (i, end)
    return out


def _segments(line: str) -> list[str]:
    """Shell command segments of a line (split at pipes, lists, substitutions)."""
    code = re.sub(r"'[^'\n]*'", "''", line)
    return [s for s in re.split(r"\|\|?|&&|;|\$\(|`|\bthen\b|\bdo\b|\belse\b", code)
            if s.strip()]


_SH_ASSIGN_RE = re.compile(r"^\s*(?:(?:local|declare|readonly|export|typeset)\s+(?:-\w+\s+)*)?"
                           r"([A-Za-z_]\w*)\+?=")
_SH_FOR_RE = re.compile(r"\bfor\s+([A-Za-z_]\w*)\s+in\b")
_SH_READ_RE = re.compile(r"\bread\s+(?:-\w+\s+)*((?:[A-Za-z_]\w*\s*)+)")
_PY_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*)\s*(?::[^=\n]+)?"
                           r"[-+*/|&]?=(?!=)")
_JS_ASSIGN_RE = re.compile(r"(?:\b(?:const|let|var)\s+([\w$]+)|(?<![\w$.])([\w$]+(?:\.[\w$]+)*))"
                           r"\s*[-+]?=(?![=>])")
_LOOP_BIND_RE = re.compile(
    r"\bfor\s*\(?\s*(?:const\s+|let\s+|var\s+)?\(?([\w$]+)(?:\s*,\s*([\w$]+))?\)?\s+(?:in|of)\b"
    r"|\b(?:forEach|map|filter|some|every|find|reduce)\s*\(\s*(?:async\s+)?\(?\s*([\w$]+)")
_CALL_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(|\.\s*([A-Za-z_$][\w$]*)\s*\(")
_RECEIVER_ADD_RE = re.compile(
    r"(?<![\w$.])([\w$]+)\s*\.\s*(?:append|add|extend|push|insert|update)\s*\(")


def _call_ok(line: str, refs: re.Pattern[str], funcs: dict[str, tuple[int, int]],
             sink_funcs: set[str], lang: str) -> bool:
    """Every command / call on ``line`` that receives a tainted value is a matcher /
    printer, or a same-file function with no network sink."""
    if lang == "sh":
        for seg in _segments(line):
            if not refs.search(seg):
                continue
            words = seg.split()
            while words and re.match(r"^[A-Za-z_]\w*\+?=", words[0]):
                words = words[1:]            # `X=$v cmd` / an assignment
            if not words:
                continue
            w = words[0].lstrip("!(").strip()
            if not w or w.startswith(("$", '"', "'")) or w in _SAFE_SH_CMDS:
                continue
            if w in funcs and w not in sink_funcs:
                continue
            return False
        return True
    for m in _CALL_RE.finditer(line):
        name = m.group(1) or m.group(2)
        a = m.end() - 1
        depth, j = 0, a
        while j < len(line):
            if line[j] in "([{":
                depth += 1
            elif line[j] in ")]}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if not refs.search(line[a:j + 1]):
            continue
        if name in _SAFE_CALLS or (name in funcs and name not in sink_funcs):
            continue
        return False
    return True


def signature_array_entry(lines: list[str], idx: int, pattern: re.Pattern[str],
                          path: str) -> set[str]:
    """``{array name}`` when every host match on line ``idx`` is an element of a
    pattern array that never reaches a network sink (module docstring); else empty."""
    lang = _lang(path)
    if lang is None:
        return set()
    line = lines[idx]
    matches = list(pattern.finditer(line))
    if not matches or any(_in_string(line, m.start(), m.end()) is None for m in matches):
        return set()
    found = _array_name(lines, idx, lang)
    if not found:
        return set()
    name, start = found
    end = _array_end(lines, start, lang)
    if not start <= idx <= end:
        return set()
    decl = range(start, end + 1)
    # Code lines (comments and the array's own element lines aside).
    body = [(i, ln) for i, ln in enumerate(lines)
            if i not in decl and not _is_comment(ln)]
    funcs = _functions(lines, lang)
    sink_funcs = {f for f, (a, b) in funcs.items()
                  if any(_NET_RE.search(_STR_RE.sub('""', lines[k]))
                         or _NET_RE.search(lines[k]) for k in range(a, b + 1)
                         if not _is_comment(lines[k]) and not _ELEMS_ONLY_RE.match(lines[k]))}
    tainted = {name}
    if lang == "sh":
        # A nameref (`local -n patterns=$2`) can alias the array without naming it:
        # its uses are checked like the array's own.
        tainted |= {m.group(1) for _i, ln in body for m in re.finditer(
            r"\b(?:local|declare|typeset)\s+(?:-\w*\s+)*-\w*n\w*\s+([A-Za-z_]\w*)=", ln)}
    for _ in range(8):
        refs = _ref_re(tainted, lang, name)
        grew = False
        for _i, ln in body:
            if not refs.search(ln):
                continue
            new: list[str] = []
            if lang == "sh":
                m = _SH_ASSIGN_RE.match(ln)
                if m:
                    new.append(m.group(1))
                new += _SH_FOR_RE.findall(ln)
                for rm in _SH_READ_RE.finditer(ln):
                    new += rm.group(1).split()
                if re.match(r"\s*done\s*<", ln):
                    # `while read -r a b; do … done <<< "$tainted"`: the loop's
                    # variables (any `read` in the file, conservatively).
                    new += [v for _j, other in body for rm in _SH_READ_RE.finditer(other)
                            for v in rm.group(1).split()]
            else:
                rx = _PY_ASSIGN_RE if lang == "py" else _JS_ASSIGN_RE
                for m in rx.finditer(ln):
                    for g in m.groups():
                        if g:
                            new += [x.strip().split(".")[0] for x in g.split(",")]
                for m in _LOOP_BIND_RE.finditer(ln):
                    new += [g for g in m.groups() if g]
                new += _RECEIVER_ADD_RE.findall(ln)
            for n in new:
                if n and n not in tainted and n not in ("in", "of", "const", "let", "var"):
                    tainted.add(n)
                    grew = True
        if not grew:
            break
    refs = _ref_re(tainted, lang, name)
    used_as_pattern = False
    for _i, ln in body:
        if not refs.search(ln):
            continue
        if _NET_RE.search(ln) or _DYNAMIC_RE.search(ln):
            return set()
        if not _call_ok(ln, refs, funcs, sink_funcs, lang):
            return set()
        # A matcher on the line once the loop binding itself (`for p in ARR`) is out.
        if _MATCHER_RE.search(re.sub(r"\bfor\s*\(?\s*(?:const\s+|let\s+|var\s+)?[\w$]+"
                                     r"(?:\s*,\s*[\w$]+)?\)?\s+(?:in|of)\s+[^\s;:)]+", "", ln)):
            used_as_pattern = True
    # A tainted value handed to a function by NAME elsewhere (`local -n p=$2`, a
    # callback table) is dynamic access: refuse when the file does any.
    if any(_DYNAMIC_RE.search(_STR_RE.sub('""', ln)) and not _is_comment(ln)
           for _i, ln in body):
        return set()
    return {name} if used_as_pattern else set()
