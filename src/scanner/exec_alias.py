"""Command execution reached through a renamed reference (per file, bounded).

The exec rules match the call by its own name: ``execSync(x)``, ``cp.spawn(x)``,
``subprocess.run(x)``, ``os.system(x)``. The same call through a name the file binds to
it was missed or graded lower:

* JS / TS: ``const { execSync: run } = require('child_process')``,
  ``import { exec as e } from 'node:child_process'``, ``const run = cp.execSync``,
  ``const r = require('child_process').exec``, ``const ex = promisify(exec)``, and a
  name bound to one of those (``const go = run``);
* Python: ``from subprocess import run as r``, ``from os import system``,
  ``import os as o`` / ``import subprocess as sp`` (then ``o.system(x)``), and
  ``sh = os.system`` / ``r2 = r``.

This module only finds those bindings and the calls through them; the call is then
classified by the SAME classifier as the direct call, with the function the alias
stands for (``src/scanner/exec_classify.py``), so it gets the same severity, the same
constant-argument calibration and the same exemptions.

Bounded on purpose: one file, textual bindings, a fixed number of alias-of-alias hops.
No dataflow through function parameters, object properties or other modules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_JS_CP_FUNCS = ("execSync", "spawnSync", "execFileSync", "execFile", "exec", "spawn", "fork")
_JS_CP_FUNC_SET = frozenset(_JS_CP_FUNCS)
_JS_MODULE = r"""['"](?:node:)?child_process['"]"""
_JS_ID = r"[A-Za-z_$][\w$]*"
_JS_REQ = r"require\s*\(\s*" + _JS_MODULE + r"\s*\)"
_DECL = r"\b(?:const|let|var)\s+"

# `const { execSync: run, spawn } = require('child_process')`
_JS_DESTRUCTURE_RE = re.compile(_DECL + r"\{([^{}]*)\}\s*=\s*" + _JS_REQ)
# `import { exec as e } from 'node:child_process'` (also `import cp, { exec as e } from`)
_JS_IMPORT_NAMED_RE = re.compile(
    r"\bimport\s+(?:" + _JS_ID + r"\s*,\s*)?\{([^{}]*)\}\s*from\s*" + _JS_MODULE)
# Module bindings: `const cp = require('child_process')`, `import * as cp from …`,
# `import cp from …`.
_JS_MODULE_ALIAS_RE = re.compile(
    _DECL + r"(" + _JS_ID + r")\s*=\s*" + _JS_REQ
    + r"(?!\s*\.)|\bimport\s+(?:\*\s+as\s+)?(" + _JS_ID + r")\s*(?:,\s*\{[^{}]*\}\s*)?from\s*"
    + _JS_MODULE)
# `const run = <expr>` where <expr> is read below (one binding per match).
_JS_BIND_RE = re.compile(_DECL + r"(" + _JS_ID + r")\s*=\s*([^;\n]{1,200})")
_JS_PROMISIFY_RE = re.compile(
    r"""^(?:[\w$]+\s*\.\s*|require\s*\(\s*['"](?:node:)?util['"]\s*\)\s*\.\s*)?"""
    r"""promisify\s*\(\s*([^()]+?)\s*\)\s*;?\s*$""")
_JS_BIND_SUFFIX_RE = re.compile(r"\s*\.\s*bind\s*\([^()]*\)\s*;?\s*$")

_PY_SUBPROCESS_FUNCS = ("run", "Popen", "call", "check_output", "check_call")
_PY_OS_FUNCS = ("system", "popen")
_PY_MODULE_FUNCS = {"subprocess": frozenset(_PY_SUBPROCESS_FUNCS),
                    "os": frozenset(_PY_OS_FUNCS)}
_PY_ID = r"[A-Za-z_]\w*"
# `import subprocess as sp`, `import os as o` (also inside a comma list).
_PY_IMPORT_AS_RE = re.compile(r"^\s*import\s+(.+)$", re.MULTILINE)
# `from subprocess import run as r, Popen` / `from os import (system as s)`.
_PY_FROM_RE = re.compile(r"^\s*from\s+(subprocess|os)\s+import\s+\(?([^)\n#]+)\)?",
                         re.MULTILINE)
# `sh = os.system` / `r = sp.run` / `r2 = r` (the whole right-hand side is the name).
_PY_BIND_RE = re.compile(r"^\s*(" + _PY_ID + r")\s*=\s*(" + _PY_ID + r"(?:\s*\.\s*"
                         + _PY_ID + r")?)\s*(?:#.*)?$", re.MULTILINE)

_MAX_HOPS = 4


@dataclass
class Aliases:
    """Per-file alias table. ``funcs``: a bare name → the function it stands for
    (``run`` → ``execSync``; Python ``r`` → ``run`` with ``module`` ``subprocess``).
    ``modules``: a name bound to the module itself (Python only; JS module aliases are
    already read by the direct rule)."""

    lang: str
    funcs: dict[str, tuple[str, str]] = field(default_factory=dict)  # name → (module, func)
    modules: dict[str, str] = field(default_factory=dict)            # name → module

    def __bool__(self) -> bool:
        return bool(self.funcs or self.modules)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------

def _js_defines(content: str, name: str) -> bool:
    """``function name(`` in this file: a local function, whatever else is bound."""
    return re.search(r"\bfunction\s*\*?\s*" + re.escape(name) + r"\s*\(", content) is not None


def js_aliases(content: str) -> Aliases:
    out = Aliases("js")
    if "child_process" not in content:
        return out
    funcs: dict[str, str] = {}
    direct: set[str] = set()   # cp functions bound under their own name
    for m in _JS_DESTRUCTURE_RE.finditer(content):
        for part in m.group(1).split(","):
            src, _, alias = (s.strip() for s in part.partition(":"))
            alias = alias.split("=")[0].strip()
            if src in _JS_CP_FUNC_SET:
                if alias and re.fullmatch(_JS_ID, alias):
                    funcs[alias] = src
                else:
                    direct.add(src)
    for m in _JS_IMPORT_NAMED_RE.finditer(content):
        for part in m.group(1).split(","):
            bits = part.split()
            if not bits or bits[0] not in _JS_CP_FUNC_SET:
                continue
            if len(bits) == 3 and bits[1] == "as" and re.fullmatch(_JS_ID, bits[2]):
                funcs[bits[2]] = bits[0]
            else:
                direct.add(bits[0])
    modules = {"child_process"} | {a for m in _JS_MODULE_ALIAS_RE.finditer(content)
                                   for a in m.groups() if a}
    mod_member = re.compile(
        r"^(?:" + _JS_REQ + r"|(?:" + "|".join(re.escape(x) for x in sorted(modules))
        + r"))\s*\.\s*(" + "|".join(_JS_CP_FUNCS) + r")$")
    binds = [(m.group(1), m.group(2).strip()) for m in _JS_BIND_RE.finditer(content)]
    for _ in range(_MAX_HOPS):
        changed = False
        for name, rhs in binds:
            if name in funcs or name in _JS_CP_FUNC_SET:
                continue
            expr = _JS_BIND_SUFFIX_RE.sub("", rhs).rstrip("; ").strip()
            pm = _JS_PROMISIFY_RE.match(expr)
            if pm:
                expr = pm.group(1).strip()
            got = None
            mm = mod_member.match(expr)
            if mm:
                got = mm.group(1)
            elif expr in funcs:
                got = funcs[expr]
            elif expr in direct:
                got = expr
            if got:
                funcs[name] = got
                changed = True
        if not changed:
            break
    out.funcs = {a: ("child_process", f) for a, f in funcs.items()
                 if not _js_defines(content, a)}
    return out


def js_call_re(al: Aliases) -> re.Pattern[str] | None:
    """A bare call through an alias; group 1 is the alias name."""
    if not al.funcs:
        return None
    names = "|".join(re.escape(a) for a in sorted(al.funcs, key=len, reverse=True))
    return re.compile(r"(?<![.\w$])(" + names + r")\s*\(")


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def py_aliases(content: str) -> Aliases:
    out = Aliases("python")
    if "subprocess" not in content and "os" not in content:
        return out
    modules: dict[str, str] = {}
    for m in _PY_IMPORT_AS_RE.finditer(content):
        for part in m.group(1).split("#")[0].split(","):
            bits = part.split()
            if len(bits) == 3 and bits[0] in _PY_MODULE_FUNCS and bits[1] == "as" \
                    and re.fullmatch(_PY_ID, bits[2]) and bits[2] != bits[0]:
                modules[bits[2]] = bits[0]
    funcs: dict[str, tuple[str, str]] = {}
    for m in _PY_FROM_RE.finditer(content):
        mod = m.group(1)
        for part in m.group(2).split(","):
            bits = part.split()
            if not bits or bits[0] not in _PY_MODULE_FUNCS[mod]:
                continue
            if len(bits) == 3 and bits[1] == "as" and re.fullmatch(_PY_ID, bits[2]):
                funcs[bits[2]] = (mod, bits[0])
            elif len(bits) == 1:
                funcs[bits[0]] = (mod, bits[0])
    binds = [(m.group(1), re.sub(r"\s+", "", m.group(2)))
             for m in _PY_BIND_RE.finditer(content)]
    for _ in range(_MAX_HOPS):
        changed = False
        for name, rhs in binds:
            if name in funcs:
                continue
            got = None
            if "." in rhs:
                base, attr = rhs.split(".", 1)
                mod = modules.get(base, base if base in _PY_MODULE_FUNCS else None)
                if mod and attr in _PY_MODULE_FUNCS[mod]:
                    got = (mod, attr)
            elif rhs in funcs:
                got = funcs[rhs]
            if got:
                funcs[name] = got
                changed = True
        if not changed:
            break
    out.modules = modules
    # A module-level `def run(` shadows the imported name (a method `def run(self)`
    # does not: it is called as `self.run(`).
    out.funcs = {a: v for a, v in funcs.items()
                 if not re.search(r"^(?:async\s+)?def\s+" + re.escape(a) + r"\s*\(",
                                  content, re.MULTILINE)}
    return out


def py_call_re(al: Aliases, module: str) -> re.Pattern[str] | None:
    """A call through an alias that stands for a ``module`` function: a bare alias
    (``r(…)``, group 1) or ``<module alias>.<func>(…)`` (group 2 alias, group 3 func)."""
    names = [a for a, (mod, _f) in al.funcs.items() if mod == module]
    mods = [a for a, mod in al.modules.items() if mod == module]
    alts = []
    if names:
        alts.append(r"(?<![.\w])(" + "|".join(
            re.escape(a) for a in sorted(names, key=len, reverse=True)) + r")\s*\(")
    if mods:
        alts.append(r"(?<![.\w])(" + "|".join(re.escape(a) for a in sorted(mods)) + r")\.("
                    + "|".join(sorted(_PY_MODULE_FUNCS[module])) + r")\s*\(")
    if not alts:
        return None
    if len(alts) == 1 and not names:
        # Keep the group numbering stable: group 1 is always the bare alias.
        return re.compile(r"(?!)()|" + alts[0])
    return re.compile("|".join(alts))


def py_func_of(al: Aliases, m: re.Match) -> str:
    """The function a :func:`py_call_re` match calls."""
    if m.group(1):
        return al.funcs[m.group(1)][1]
    return m.group(3)
