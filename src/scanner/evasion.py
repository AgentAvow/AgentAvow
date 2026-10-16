"""Scanner-evasion shapes from published research on malicious MCP servers.

Pluto Security's "Malicious MCP servers, clean scans" (2026-09-15) built two working
malicious servers that every scanner it tried graded clean. Two of its tricks hide a
dangerous call from pattern rules without changing what the code does:

- a dangerous name assembled from string pieces at the lookup site, so the literal
  ``popen`` never appears: ``os.__dict__["po" + "pen"]``, ``getattr(os, "sys" + "tem")``,
  ``__import__("subpro" + "cess")``, ``cp["ex" + "ec"]``, ``require("child_" + "process")``;
- a payload decoded from hex/base64 and XOR'd with a key, then run by ``exec``/``eval``
  in another function, so no single line holds both the decode and the exec.

Both functions here are pure and work on the text of one file. ``scan._scan_content``
turns their hits into findings.
"""
from __future__ import annotations

import re

# A short string literal with no escapes. The pieces of an assembled name are short.
_LIT = r"""(?:"[^"\\\n]{0,40}"|'[^'\\\n]{0,40}'|`[^`\\\n$]{0,40}`)"""
# Two or more literals joined with ``+``.
_CONCAT_RE = re.compile(rf"""({_LIT})((?:\s*\+\s*{_LIT})+)""")
_LIT_PART_RE = re.compile(_LIT)

# Names whose only use, once hidden this way, is to reach code execution, a process,
# the import system or a raw socket. Compared lowercased.
DANGEROUS_NAMES = frozenset({
    "popen", "system", "exec", "execv", "execve", "execvp", "execvpe", "execl", "execlp",
    "execle", "spawn", "spawnsync", "spawnv", "spawnve", "execsync", "execfile",
    "execfilesync", "fork", "eval", "compile", "function", "subprocess", "child_process",
    "node:child_process", "os", "posix", "nt", "builtins", "__builtins__", "__import__",
    "import_module", "check_output", "check_call", "getoutput", "getstatusoutput", "ctypes",
    "marshal", "pickle", "socket", "pty", "/bin/sh", "/bin/bash", "bash", "sh", "cmd.exe",
    "powershell", "vm", "node:vm", "runinnewcontext", "runinthiscontext",
})

# What sits right before the concatenation when it is a lookup: Python attribute and
# module lookups, a JS module load, or a bracket member access on an object.
_PY_LOOKUP_RE = re.compile(
    r"""(?:\bgetattr\s*\(\s*[\w.\[\]()'"]+\s*,|__dict__\s*\[|\bglobals\s*\(\s*\)\s*\[|"""
    r"""\bvars\s*\([^()]*\)\s*\[|\b__import__\s*\(|\bimport_module\s*\(|"""
    r"""\bsetattr\s*\(\s*[\w.]+\s*,)\s*$""")
_JS_MODULE_RE = re.compile(r"""(?:\brequire|\bimport)\s*\(\s*$""")
_JS_MEMBER_RE = re.compile(r"""[\w$)\]]\s*\[\s*$""")


def _joined(first: str, rest: str) -> str:
    parts = [first] + _LIT_PART_RE.findall(rest)
    return "".join(p[1:-1] for p in parts)


def assembled_name_hits(
    lines: list[str], lang: str | None, prose: set[int] | None = None,
) -> list[tuple[int, str, str, str]]:
    """Lines that look up a dangerous name built from string pieces.

    Returns ``(line_index, joined_name, context, severity)`` per hit; ``context`` is
    ``lookup`` (Python getattr/__dict__/__import__/…, or a JS bracket member) or
    ``module`` (JS ``require``/``import``). A JS module load is ``high``, since a bundler
    workaround can split a module name the same way; every other hit is ``critical``.
    Prose lines (docstrings, multi-line strings) are skipped.
    """
    prose = prose or set()
    out: list[tuple[int, str, str, str]] = []
    for i, ln in enumerate(lines):
        if i in prose or "+" not in ln or ln.lstrip().startswith(("#", "//", "*")):
            continue
        for m in _CONCAT_RE.finditer(ln):
            name = _joined(m.group(1), m.group(2))
            if name.lower() not in DANGEROUS_NAMES:
                continue
            before = ln[:m.start()]
            if lang == "python":
                if _PY_LOOKUP_RE.search(before):
                    out.append((i, name, "lookup", "critical"))
                    break
            elif lang in ("javascript", "typescript"):
                if _JS_MODULE_RE.search(before):
                    out.append((i, name, "module", "high"))
                    break
                if _JS_MEMBER_RE.search(before):
                    out.append((i, name, "lookup", "critical"))
                    break
    return out


# XOR over decoded bytes: ``bytes(b ^ k for b in bytes.fromhex(P))``,
# ``bytearray(x ^ KEY for x in base64.b64decode(s))``, ``"".join(chr(c ^ k) for c in …)``.
_XOR_DECODE_RE = re.compile(
    r"""\^\s*[\w.\[\]()]+.{0,80}?\bfor\b.{0,80}?\b(?:fromhex|unhexlify|b64decode|"""
    r"""a85decode|b32decode|b16decode|decompress|frombytes)\s*\(""")
_PY_EXEC_CALL_RE = re.compile(r"""(?<![.\w])(?:exec|eval)\s*\(""")
_DEF_EXEC_RE = re.compile(r"""^\s*def\s+(?:exec|eval)\s*\(""")


def xor_decode_exec_hit(lines: list[str], prose: set[int] | None = None) -> int | None:
    """0-based line of an XOR-over-decoded-bytes expression in a Python file that also
    calls ``exec``/``eval``; None otherwise. Not bounded by distance: the decode and the
    exec sitting in different functions is the evasion."""
    prose = prose or set()
    decode = next((i for i, ln in enumerate(lines)
                   if i not in prose and _XOR_DECODE_RE.search(ln)), None)
    if decode is None:
        return None
    for i, ln in enumerate(lines):
        if i in prose or _DEF_EXEC_RE.search(ln):
            continue
        if _PY_EXEC_CALL_RE.search(ln):
            return decode
    return None
