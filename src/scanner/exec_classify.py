"""Exec-family classification: defect vs capability (precision pass #2 / #7).

A `subprocess.run(["git", "status"])` or `spawn('node', [script])` is a CAPABILITY the
tool has (it runs a fixed command, no shell), not a defect — a reviewer would never
agree it is "high". What stays a DEFECT is the shape malware actually uses: a shell
(`shell=True`, `sh -c`, `os.system`, `execSync`) with a dynamic string, an interpreter
handed inline code (`python -c` / `node -e` with a variable), a downloader or decoder
as argv0 (`curl`, `wget`, `base64`), a remote URL in the argv, or dynamic argv next to
untrusted input (request body / fetched content).

Everything here is static text analysis: the matched call is extracted with a
string- and comment-aware paren walker (so multi-line calls are seen whole) and parsed
with `ast` (Python) or a small top-level-argument splitter (JS). Nothing is executed.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from src.scanner.patterns import (
    DANGEROUS_ARGV0_NET,
    DANGEROUS_ARGV0_SHELLS,
    DANGEROUS_ARGV_FLAGS,
    INLINE_CODE_DANGER_RE,
    INTERPRETER_ARGV0,
    SHELL_DANGER_RE,
)

CAP_SPAWN = "process:spawn"
CAP_EVAL = "code:eval"
CAP_DESERIALIZE = "data:deserialize"
CAP_DELETE = "filesystem:delete"
CAP_FS_READ = "filesystem:read"
CAP_FS_WRITE = "filesystem:write"
CAP_PEM = "secret:pem_handling"
CAP_HEX = "binary:hex_literal"

# Human labels for the capability taxonomy (the `capabilities` summary on a result).
CAPABILITY_LABELS: dict[str, str] = {
    CAP_SPAWN: "Runs external commands (fixed argv, no shell)",
    CAP_EVAL: "Evaluates code strings at runtime (eval/exec)",
    CAP_DESERIALIZE: "Deserializes pickle/marshal data from a local source",
    CAP_DELETE: "Deletes directory trees",
    CAP_FS_READ: "Reads files at runtime-chosen paths",
    CAP_FS_WRITE: "Writes files at runtime-chosen paths",
    CAP_PEM: "Handles PEM private-key markers (no key body present)",
    CAP_HEX: "Embeds long hex-escaped byte literals",
}

_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_PY_SHELL_FUNCS = frozenset({"system", "popen"})


@dataclass
class ExecVerdict:
    """How one exec-family match should be reported."""

    kind: str                 # "defect" | "capability"
    severity: str             # defect: critical|high|medium — capability: info|low
    label: str                # one-line reason, shown as the finding's remediation hint
    capability: str = ""      # taxonomy tag when kind == "capability"
    consumed_lines: int = 1   # how many source lines the call spanned (>=1)


def _defect(severity: str, label: str, consumed: int = 1) -> ExecVerdict:
    return ExecVerdict("defect", severity, label, "", consumed)


def _cap(severity: str, label: str, tag: str, consumed: int = 1) -> ExecVerdict:
    return ExecVerdict("capability", severity, label, tag, consumed)


# ---------------------------------------------------------------------------
# Balanced-call extraction (string/comment aware; never executes anything)
# ---------------------------------------------------------------------------

def extract_call(
    lines: list[str], idx: int, start_col: int, *, lang: str = "python", max_lines: int = 40,
) -> tuple[str, int] | None:
    """Return ``(call_source, n_lines)`` for the balanced call that starts at
    ``lines[idx][start_col:]`` — i.e. from the callee name through its closing paren.
    Honors ``'…'`` / ``"…"`` / triple-quoted / template-literal strings and ``#`` /
    ``//`` comments so a paren inside a string or comment does not unbalance the walk.
    ``None`` if the call does not close within ``max_lines``."""
    buf: list[str] = []
    depth = 0
    opened = False
    in_str: str | None = None
    escape = False
    end = min(len(lines), idx + max_lines)
    for n in range(idx, end):
        line = lines[idx][start_col:] if n == idx else lines[n]
        i = 0
        cut = len(line)
        while i < len(line):
            ch = line[i]
            if in_str is not None:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif line.startswith(in_str, i):
                    i += len(in_str)
                    in_str = None
                    continue
                i += 1
                continue
            if ch in "\"'`":
                if lang == "python" and line.startswith(ch * 3, i):
                    in_str = ch * 3
                    i += 3
                    continue
                in_str = ch
                i += 1
                continue
            if lang == "python" and ch == "#":
                cut = i
                break
            if lang != "python" and ch == "/" and line.startswith("//", i):
                cut = i
                break
            if ch in "([{":
                depth += 1
                opened = True
            elif ch in ")]}":
                depth -= 1
                if opened and depth <= 0:
                    buf.append(line[: i + 1])
                    return "\n".join(buf), n - idx + 1
            i += 1
        buf.append(line[:cut])
        # Only triple-quoted / template strings span lines; a stray quote must not eat
        # the rest of the file.
        if in_str is not None and len(in_str) == 1 and in_str != "`":
            in_str = None
        escape = False
    return None


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------

def _parse_expr(src: str) -> ast.AST | None:
    try:
        return ast.parse(src.strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
    return None


def _is_sys_executable(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute) and node.attr == "executable"
        and isinstance(node.value, ast.Name) and node.value.id == "sys"
    )


def _is_dynamic_string(node: ast.AST) -> bool:
    """f-string / concatenation / ``%`` / ``.format(`` — a command built from parts.
    A LIST concatenation (``["git", "log"] + args``, ``shlex.split(cc) + [...]``) is an
    argv, not a string: see :func:`_argv_sequence`."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _argv_sequence(node) is None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr in ("format", "join", "replace"):
        return True
    return False


def _argv_elements(node: ast.AST) -> tuple[list[str | None], bool] | None:
    """For a list/tuple literal return ``(elements, any_dynamic)`` where a constant
    string element is its text and a non-constant one is ``None``. ``None`` for
    anything that is not a literal sequence."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out: list[str | None] = []
    dynamic = False
    for el in node.elts:
        s = _const_str(el)
        if s is None and _is_sys_executable(el):
            s = "python"
        if s is None:
            dynamic = True
            if isinstance(el, ast.Starred):
                # `[*base_cmd, x]` — still a list, just not fully known
                pass
        out.append(s)
    return out, dynamic


# Calls that return an argv LIST (so `shlex.split(x) + [...]` is list concatenation).
_LIST_CALLS = frozenset({"split", "list", "sorted"})


def _is_list_expr(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.ListComp)):
        return True
    if isinstance(node, ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        # `shlex.split(...)` / `list(...)` — but NOT `"a b".split()` style string calls
        # on a constant, which still yield a list (fine either way).
        return name in _LIST_CALLS
    return False


def _argv_sequence(node: ast.AST, _depth: int = 0) -> tuple[list[str | None], bool] | None:
    """Like :func:`_argv_elements` but also flattens list CONCATENATION
    (``[npx, "@x/inspector"] + uv_cmd``): known literal parts keep their text, any
    other operand contributes one unknown (``None``) element. ``None`` when the node is
    not argv-shaped (a string command)."""
    seq = _argv_elements(node)
    if seq is not None:
        return seq
    if _depth > 40:  # pathological concatenation chain: not an argv we can read
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = node.left, node.right
        # Each operand is evaluated ONCE (a long `"a" + b + "c" + …` chain must stay
        # linear, not exponential).
        subs = [_argv_sequence(left, _depth + 1), _argv_sequence(right, _depth + 1)]
        if not (_is_list_expr(left) or _is_list_expr(right)
                or subs[0] is not None or subs[1] is not None):
            return None
        out: list[str | None] = []
        dynamic = False
        for sub in subs:
            if sub is None:
                out.append(None)
                dynamic = True
            else:
                out.extend(sub[0])
                dynamic = dynamic or sub[1]
        return out, dynamic
    return None


def _basename(argv0: str) -> str:
    base = argv0.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    # `python3.12`, `python3.11-config` → `python`
    m = re.match(r"^(python|pypy|node|ruby|perl|php|deno|bun)[\d.]*$", base)
    return m.group(1) if m else base


def classify_argv(
    elements: list[str | None], dynamic: bool, *, untrusted_near: bool, consumed: int = 1,
) -> ExecVerdict:
    """Shared Python/JS rule set over an argv (``None`` = non-constant element).

    Never widens what counts as safe for ``sh -c`` / ``node -e`` / ``python -c`` /
    ``curl``: those stay defects whatever the argv shape; a URL in the argv stays a
    defect; a dynamic binary near untrusted input is a medium defect.
    """
    argv0 = elements[0] if elements else None
    base = _basename(argv0) if argv0 is not None else None
    consts = [e for e in elements if e is not None]

    if base is not None and base in DANGEROUS_ARGV0_SHELLS:
        sev = "critical" if (dynamic and untrusted_near) else "high"
        return _defect(sev, f"spawns a shell ({base}) — a shell string is evaluated", consumed)
    if base is not None and base in DANGEROUS_ARGV0_NET:
        return _defect("high", f"spawns a downloader/decoder binary ({base})", consumed)
    if base is not None and (base in INTERPRETER_ARGV0 or argv0 == "python"):
        for i, el in enumerate(elements[1:], 1):
            if el in DANGEROUS_ARGV_FLAGS:
                code = elements[i + 1] if i + 1 < len(elements) else None
                if code is None:
                    sev = "critical" if untrusted_near else "high"
                    return _defect(
                        sev, f"inline interpreter eval ({base} {el}) of a dynamic string", consumed,
                    )
                if INLINE_CODE_DANGER_RE.search(code):
                    return _defect(
                        "high", f"inline interpreter eval ({base} {el}) of code that execs/"
                        "decodes/fetches", consumed,
                    )
                return _cap(
                    "low", f"runs a constant inline {base} snippet ({el})", CAP_SPAWN, consumed,
                )
    if any(_URL_RE.search(c) for c in consts):
        return _defect("high", "argv contains a remote URL (download at runtime)", consumed)
    if argv0 is None:
        if untrusted_near:
            return _defect(
                "medium", "spawns a command from dynamic arguments next to untrusted input",
                consumed,
            )
        return _cap("low", "runs a command built at runtime (no shell)", CAP_SPAWN, consumed)
    if dynamic:
        if untrusted_near:
            return _defect(
                "medium", f"runs {base} with dynamic arguments next to untrusted input",
                consumed,
            )
        return _cap("low", f"runs {base} with runtime arguments (no shell)", CAP_SPAWN, consumed)
    return _cap("info", f"runs a fixed command: {' '.join(consts)[:60]}", CAP_SPAWN, consumed)


# Shell metacharacters that make a shell=True argv do more than run one program.
_SHELL_METACHAR_RE = re.compile(r"[|;&$()<>`\n\r]")


def _shell_argv_calibration(
    first: ast.AST | None, *, untrusted_near: bool, cli_origin: bool, resolve_name,
    consumed: int,
) -> ExecVerdict | None:
    """Precision PR 2 (founder-approved calibration, tracked item #2): ``shell=True``
    whose command is an argv LIST is a medium defect, not high, when

    * every element is a constant (a literal, a name bound to one, or a loop variable
      over a literal list) free of shell metacharacters (``| ; & $ ( ) < >`` backtick);
      or
    * the dynamic elements come only from the program's OWN command line (the call sits
      in a typer/click command or an argparse/sys.argv main) — the user is attacking
      themselves.

    ``None`` = no calibration: a string command, metacharacters, a shell / downloader /
    inline-interpreter argv0 (``sh -c``, ``curl``, ``python -c``), a URL in the argv,
    or untrusted input (request body / fetched content) nearby keep today's high or
    critical verdict."""
    if first is None or untrusted_near:
        return None
    node = first
    if isinstance(node, ast.Name) and resolve_name is not None:
        resolved = resolve_name(node.id)
        if resolved is not None:
            node = resolved
    seq = _argv_sequence(node)
    if seq is None:
        return None
    raw_elements = _argv_nodes(node)
    elements: list[str | None] = list(seq[0])
    # Resolve bare-name elements (`[cmd, "--version"]` with `for cmd in [...]` above).
    if raw_elements is not None and len(raw_elements) == len(elements):
        for i, el in enumerate(raw_elements):
            if elements[i] is None and isinstance(el, ast.Name) and resolve_name is not None:
                vals = _const_values(resolve_name(el.id))
                if vals:
                    elements[i] = " ".join(vals)  # every candidate is metachar-checked
    if not elements:
        return None
    consts = [e for e in elements if e is not None]
    if any(_SHELL_METACHAR_RE.search(c) for c in consts):
        return None
    if any(_URL_RE.search(c) for c in consts):
        return None
    for c in consts:
        for tok in c.split():
            if tok in DANGEROUS_ARGV_FLAGS:
                return None
    argv0_candidates = elements[0].split() if elements[0] is not None else []
    for cand in argv0_candidates:
        base = _basename(cand)
        if base in DANGEROUS_ARGV0_SHELLS or base in DANGEROUS_ARGV0_NET:
            return None
    if all(e is not None for e in elements):
        return _defect("medium", "shell=True with a constant argv (no shell metacharacters)",
                       consumed)
    if cli_origin and not _dynamic_parts_look_dangerous(raw_elements or [node], resolve_name):
        return _defect("medium", "shell=True with arguments from the program's own command "
                       "line (no untrusted input nearby)", consumed)
    return None


def _dynamic_parts_look_dangerous(nodes: list[ast.AST], resolve_name) -> bool:
    """Inside a CLI command, a dynamic argv part that is (or is bound to) a decode /
    fetch / exec expression — `payload = b64decode(BLOB).decode()` — is not "the user's
    own argument": keep today's verdict."""
    for el in nodes:
        if isinstance(el, ast.Constant):
            continue
        expr = el
        if isinstance(el, ast.Name) and resolve_name is not None:
            resolved = resolve_name(el.id)
            if resolved is not None:
                expr = resolved
        try:
            src = ast.unparse(expr)
        except Exception:  # noqa: BLE001 — unreadable: be conservative
            return True
        if INLINE_CODE_DANGER_RE.search(src) or _URL_RE.search(src):
            return True
    return False


def _argv_nodes(node: ast.AST, _depth: int = 0) -> list[ast.AST] | None:
    """The element nodes of a literal argv list/tuple (flattening list concatenation
    the same way as :func:`_argv_sequence`; an opaque operand is one element)."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return list(node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and _depth <= 40:
        out: list[ast.AST] = []
        for part in (node.left, node.right):
            sub = _argv_nodes(part, _depth + 1)
            out.extend(sub if sub is not None else [part])
        return out
    return None


def _const_values(node: ast.AST | None) -> list[str] | None:
    """Constant string value(s) a name can hold: ``x = "npx"`` → ``["npx"]``;
    ``for x in ["npx.cmd", "npx.exe"]`` (resolved to the list) → both."""
    if node is None:
        return None
    s = _const_str(node)
    if s is not None:
        return [s]
    if isinstance(node, (ast.List, ast.Tuple)):
        vals = [_const_str(e) for e in node.elts]
        if vals and all(v is not None for v in vals):
            return vals  # type: ignore[return-value]
    return None


def _shell_verdict(arg: ast.AST | None, *, untrusted_near: bool, consumed: int,
                   how: str) -> ExecVerdict:
    """A shell IS being invoked (os.system / shell=True / string command). A literal is
    high (a reviewer should see a shell); a dynamic string next to untrusted input is
    the command-injection critical."""
    s = _const_str(arg) if arg is not None else None
    if s is not None and not s.strip() and how.startswith("os."):
        # `os.system("")` — the well-known no-op that enables ANSI escape handling in a
        # Windows console. It runs nothing.
        return _cap("info", f"{how}(\"\") no-op (enables ANSI escapes on Windows)",
                    CAP_SPAWN, consumed)
    if s is not None:
        if SHELL_DANGER_RE.search(s):
            return _defect("high", f"{how} runs a literal shell command with pipe/subshell/"
                           "download tokens", consumed)
        return _defect("high", f"{how} runs a literal shell command", consumed)
    sev = "critical" if untrusted_near else "high"
    return _defect(sev, f"{how} runs a shell command built at runtime", consumed)


def classify_python_exec(
    call_src: str, func_name: str, *, untrusted_near: bool,
    resolve_name=None, consumed: int = 1, cli_origin: bool = False,
) -> ExecVerdict:
    """Classify one ``subprocess.*`` / ``os.system`` / ``os.popen`` call.

    ``resolve_name(name) -> ast.AST | None`` lets the caller look up ``cmd = [...]``
    assigned earlier in the file. Parse failures fall back to a conservative regex
    read (never silently to "capability")."""
    node = _parse_expr(call_src)
    if not isinstance(node, ast.Call):
        return _regex_fallback(call_src, untrusted_near=untrusted_near, consumed=consumed)

    kw = {k.arg: k.value for k in node.keywords if k.arg}
    first = node.args[0] if node.args else kw.get("args")
    if isinstance(first, ast.Starred):
        first = None

    if func_name in _PY_SHELL_FUNCS:
        return _shell_verdict(first, untrusted_near=untrusted_near, consumed=consumed,
                              how=f"os.{func_name}")

    shell = kw.get("shell")
    if shell is not None:
        if isinstance(shell, ast.Constant) and shell.value is False:
            pass
        else:
            # shell=True, or shell=<variable> (treated as True — conservative)
            calibrated = _shell_argv_calibration(
                first, untrusted_near=untrusted_near, cli_origin=cli_origin,
                resolve_name=resolve_name, consumed=consumed,
            )
            if calibrated is not None:
                return calibrated
            return _shell_verdict(first, untrusted_near=untrusted_near, consumed=consumed,
                                  how="shell=True")

    if first is None:
        # `Popen(*args, **kwargs)` — a pass-through wrapper: the command is whatever
        # the caller hands in. A capability unless untrusted input sits nearby.
        return classify_argv([None], True, untrusted_near=untrusted_near, consumed=consumed)

    seq = _argv_sequence(first)
    if seq is None and isinstance(first, ast.Name) and resolve_name is not None:
        resolved = resolve_name(first.id)
        if resolved is not None:
            seq = _argv_sequence(resolved)
            if seq is None and _is_dynamic_string(resolved):
                first = resolved
    if seq is not None:
        elements, dynamic = seq
        return classify_argv(elements, dynamic, untrusted_near=untrusted_near,
                             consumed=consumed)

    s = _const_str(first)
    if s is not None:
        # A plain string without shell=True is ONE program name (args are not split).
        # `"ls -la"` would fail at runtime; treat whitespace/metachars as shell intent.
        if re.search(r"[\s|&;$`<>]", s):
            return _defect("high", "string command without shell=True — probable shell intent",
                           consumed)
        return classify_argv([s], False, untrusted_near=untrusted_near, consumed=consumed)
    if _is_dynamic_string(first):
        sev = "critical" if untrusted_near else "high"
        return _defect(sev, "command built from a dynamic string (f-string/concat/format)",
                       consumed)
    # Name / Call (shlex.split(...)) / Attribute / Subscript / BinOp(list + list) / …
    return classify_argv([None], True, untrusted_near=untrusted_near, consumed=consumed)


_FALLBACK_ARGV0_RE = re.compile(r"""^\s*[\w.]+\s*\(\s*[\[(]\s*['"]([^'"]+)['"]""")


def _regex_fallback(call_src: str, *, untrusted_near: bool, consumed: int) -> ExecVerdict:
    """When the call cannot be parsed (truncated, Python 2, odd syntax), keep today's
    conservative read: a defect unless the argv0 is a visible, benign literal."""
    if re.search(r"shell\s*=\s*True", call_src):
        return _defect("critical" if untrusted_near else "high",
                       "shell=True (unparsed call)", consumed)
    m = _FALLBACK_ARGV0_RE.match(call_src)
    if m and not _URL_RE.search(call_src):
        base = _basename(m.group(1))
        if base not in DANGEROUS_ARGV0_SHELLS and base not in DANGEROUS_ARGV0_NET \
                and base not in INTERPRETER_ARGV0:
            return _cap("low", f"runs {base} (argv list; call not fully parsed)",
                        CAP_SPAWN, consumed)
    return _defect("high", "exec call could not be parsed — kept as a defect", consumed)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript (regex)
# ---------------------------------------------------------------------------

_JS_SHELL_FUNCS = frozenset({"exec", "execSync"})
_JS_FILE_FUNCS = frozenset({"execFile", "execFileSync", "spawn", "spawnSync", "fork"})


def split_top_level_args(inner: str) -> list[str]:
    """Split a JS argument list on top-level commas (strings/brackets respected)."""
    out: list[str] = []
    depth = 0
    in_str: str | None = None
    escape = False
    cur: list[str] = []
    for ch in inner:
        if in_str is not None:
            cur.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in "\"'`":
            in_str = ch
            cur.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _js_literal(arg: str) -> str | None:
    """The text of a plain string literal (no interpolation), else None."""
    a = arg.strip()
    if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'":
        return a[1:-1]
    if len(a) >= 2 and a[0] == a[-1] == "`" and "${" not in a:
        return a[1:-1]
    return None


def _js_array_elements(arg: str) -> tuple[list[str | None], bool] | None:
    a = arg.strip()
    if not (a.startswith("[") and a.endswith("]")):
        return None
    out: list[str | None] = []
    dynamic = False
    for el in split_top_level_args(a[1:-1]):
        lit = _js_literal(el)
        if lit is None:
            dynamic = True
        out.append(lit)
    return out, dynamic


def classify_js_exec(
    call_src: str, func_name: str, *, untrusted_near: bool, consumed: int = 1,
) -> ExecVerdict:
    """Classify a child_process call: ``exec``/``execSync`` always go through a shell;
    ``spawn``/``execFile``/``fork`` take an argv (plus an options object whose
    ``shell: true`` turns it back into a shell)."""
    open_i = call_src.find("(")
    close_i = call_src.rfind(")")
    inner = call_src[open_i + 1: close_i] if 0 <= open_i < close_i else ""
    args = split_top_level_args(inner)

    if func_name in _JS_SHELL_FUNCS:
        lit = _js_literal(args[0]) if args else None
        if lit is not None:
            if SHELL_DANGER_RE.search(lit):
                return _defect("high", f"{func_name} runs a literal shell command with "
                               "pipe/subshell/download tokens", consumed)
            return _defect("high", f"{func_name} runs a literal shell command", consumed)
        sev = "critical" if untrusted_near else "high"
        return _defect(sev, f"{func_name} runs a shell command built at runtime", consumed)

    if re.search(r"\bshell\s*:\s*(?:true|['\"][^'\"]+['\"])", inner):
        sev = "critical" if untrusted_near else "high"
        return _defect(sev, f"{func_name} with shell: true", consumed)

    if func_name == "fork":
        lit = _js_literal(args[0]) if args else None
        elements: list[str | None] = ["node", lit]
        rest = _js_array_elements(args[1]) if len(args) > 1 else None
        dynamic = lit is None
        if rest is not None:
            elements += rest[0]
            dynamic = dynamic or rest[1]
        elif len(args) > 1 and not args[1].strip().startswith("{"):
            dynamic = True
        return classify_argv(elements, dynamic, untrusted_near=untrusted_near,
                             consumed=consumed)

    argv0 = _js_literal(args[0]) if args else None
    elements = [argv0]
    dynamic = argv0 is None
    if len(args) > 1:
        arr = _js_array_elements(args[1])
        if arr is not None:
            elements += arr[0]
            dynamic = dynamic or arr[1]
        elif not args[1].strip().startswith("{"):
            dynamic = True
    return classify_argv(elements, dynamic, untrusted_near=untrusted_near, consumed=consumed)
