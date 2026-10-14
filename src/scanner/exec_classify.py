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
    DECODE_SINK_RE,
    INLINE_CODE_DANGER_RE,
    INTERPRETER_ARGV0,
    SHELL_DANGER_RE,
    SHELL_PAYLOAD_DANGER_RE,
)

CAP_SPAWN = "process:spawn"
CAP_EVAL = "code:eval"
CAP_DESERIALIZE = "data:deserialize"
CAP_DELETE = "filesystem:delete"
CAP_FS_READ = "filesystem:read"
CAP_FS_WRITE = "filesystem:write"
CAP_PEM = "secret:pem_handling"
CAP_HEX = "binary:hex_literal"
CAP_INSTALLER = "install:remote_script"

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
    CAP_INSTALLER: "Ships a one-time installer script that downloads and runs a remote script",
}

_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_OSASCRIPT_DANGER_RE = re.compile(
    r"do\s+shell\s+script|https?://|curl|wget|password|keychain|System Events", re.I)
_PY_SHELL_FUNCS = frozenset({"system", "popen"})


@dataclass
class ExecVerdict:
    """How one exec-family match should be reported."""

    kind: str                 # "defect" | "capability"
    severity: str             # defect: critical|high|medium — capability: info|low
    label: str                # one-line reason, shown as the finding's remediation hint
    capability: str = ""      # taxonomy tag when kind == "capability"
    consumed_lines: int = 1   # how many source lines the call spanned (>=1)
    # Payload-shaped: the call downloads / decodes / runs inline code, or untrusted
    # input reaches it. Graded at full severity even where the file is downgraded
    # (a test dir shipped inside a published artifact); see ``_scan_content``.
    payload: bool = False


def _flow(untrusted_near: bool, untrusted_flow: bool | None) -> bool:
    """Does untrusted input REACH this call? Precision PR 2: the critical lift needs a
    flow (the call uses a request / fetched value, directly or through a name assigned
    from one), not mere proximity. ``None`` = the caller did no flow analysis -> fall
    back to proximity (unit callers, older paths)."""
    if untrusted_flow is None:
        return untrusted_near
    return untrusted_near and untrusted_flow


def _defect(severity: str, label: str, consumed: int = 1, *,
            payload: bool = False) -> ExecVerdict:
    # A critical needs untrusted input reaching the call: always payload-shaped.
    return ExecVerdict("defect", severity, label, "", consumed,
                       payload=payload or severity == "critical")


def _cap(severity: str, label: str, tag: str, consumed: int = 1) -> ExecVerdict:
    return ExecVerdict("capability", severity, label, tag, consumed)


# ---------------------------------------------------------------------------
# Shell severity ladder (precision PR 2)
# ---------------------------------------------------------------------------
# A shell command is a risk when something an attacker controls can reach it, or when
# its own text downloads / decodes / runs inline code. A shell library, a test runner,
# a REPL's `!cmd`, an editor launcher or a file watcher running a command line is the
# tool doing its job. The ladder, for the standard shell APIs (`os.system`,
# `shell=True`, `exec`/`execSync`, `spawn(..., {shell: true})`):
#
#   untrusted input REACHES the command (flow)              critical
#   a decoded / fetched value builds the command            high
#   the visible command text carries payload tokens         high
#   untrusted input in the same file, no flow found         high
#   otherwise (literal, or built from local values)         medium
#
# A medium is still a defect: it is reported and costs score, it just does not make the
# answer "Review before you connect" on its own.

# A dynamic part that is itself a decode / fetch expression is a payload, not a value.
# Character-code assembly (`"".join(chr(c) for c in [...])`, `bytes([...]).decode()`,
# `String.fromCharCode(...)`) is a decode: it hides the command text from a reader.
ASSEMBLY_DECODE_RE = re.compile(
    r"(?<![\w.])(?:chr|unichr)\s*\(|\bbytes\s*\(\s*[\[(]|\bbytearray\s*\("
    r"|\bfromCharCode\s*\(|\bfromCodePoint\s*\(",
)
_PAYLOAD_EXPR_RE = re.compile(
    DECODE_SINK_RE.pattern + r"|\bfetch\s*\(|urlopen|urlretrieve|requests\.|httpx\.|axios"
    r"|https?\.get\s*\(|" + ASSEMBLY_DECODE_RE.pattern,
)
# `rm -rf ` / `rm -r -f ` immediately followed by a runtime value: the deleted path is
# not visible, so it can be `$HOME` (adversarial review of #160).
_RM_RECURSIVE_TAIL_RE = re.compile(
    r"""\brm\s+(?:-[\w-]+\s+)*-\w*[rR]\w*(?:\s+-[\w-]+)*\s*['"]?$""")


# Inline interpreter code (`python -c`, `node -e`, a constant `exec("...")`) is
# payload-shaped when its text carries shell payload tokens, or when it both decodes /
# fetches and runs something. INLINE_CODE_DANGER_RE (pickle, ctypes, a bare import,
# `requests.`) keeps such code a high defect; it is not on its own a payload
# (`python -OO -c "import pickle; pickle.loads(pickle.dumps(x))"` in a test suite).
_CODE_RUN_RE = re.compile(
    r"\b(?:exec|eval|compile)\s*\(|\bFunction\s*\(|os\.system|os\.popen|subprocess"
    r"|child_process|\bexecSync\s*\(|\bspawn(?:Sync)?\s*\(",
)


def inline_code_is_payload(code: str) -> bool:
    """Does constant inline code download / decode AND run something (or carry shell
    payload tokens)? The payload notion for ``Finding.payload`` (see scan.py)."""
    if SHELL_PAYLOAD_DANGER_RE.search(code):
        return True
    return bool(_PAYLOAD_EXPR_RE.search(code) and _CODE_RUN_RE.search(code))


def _literal_shell_verdict(how: str, text: str, consumed: int) -> ExecVerdict:
    """A shell command whose text is fully visible."""
    if SHELL_PAYLOAD_DANGER_RE.search(text):
        return _defect("high", f"{how} runs a literal shell command with download/decode/"
                       "inline-code tokens", consumed, payload=True)
    return _defect("medium", f"{how} runs a literal shell command (no download, decode or "
                   "inline-code tokens)", consumed)


def _dynamic_shell_verdict(
    how: str, consts: list[str], dyn: list[str], *, untrusted_near: bool,
    untrusted_flow: bool | None, payload_flow: bool, consumed: int,
) -> ExecVerdict:
    """A shell command built at runtime: ``consts`` are the visible text pieces, ``dyn``
    the source of each runtime part (an opaque variable is one ``dyn`` entry)."""
    if _flow(untrusted_near, untrusted_flow):
        return _defect("critical", f"{how} runs a shell command built from untrusted input",
                       consumed)
    if payload_flow or any(_PAYLOAD_EXPR_RE.search(d) for d in dyn):
        return _defect("high", f"{how} runs a shell command built from a decoded or fetched "
                       "value", consumed, payload=True)
    if SHELL_PAYLOAD_DANGER_RE.search(" ".join(consts)):
        return _defect("high", f"{how} runs a shell command with download/decode/inline-code "
                       "tokens", consumed, payload=True)
    if dyn and any(_RM_RECURSIVE_TAIL_RE.search(c) for c in consts):
        return _defect("high", f"{how} recursively deletes a path chosen at runtime", consumed)
    if untrusted_near:
        return _defect("high", f"{how} runs a shell command built at runtime next to untrusted "
                       "input", consumed)
    return _defect("medium", f"{how} runs a shell command built at runtime (no untrusted "
                   "input reaches it)", consumed)


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
    import warnings

    try:
        with warnings.catch_warnings():
            # Third-party source with an invalid escape (`"\|"`) parses fine but warns.
            warnings.simplefilter("ignore", SyntaxWarning)
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
    untrusted_flow: bool | None = None,
) -> ExecVerdict:
    """Shared Python/JS rule set over an argv (``None`` = non-constant element).

    Never widens what counts as safe for ``sh -c`` / ``node -e`` / ``python -c`` /
    ``curl``: those stay defects whatever the argv shape; a URL in the argv stays a
    defect; a dynamic binary near untrusted input is a medium defect.
    """
    flow = _flow(untrusted_near, untrusted_flow)
    argv0 = elements[0] if elements else None
    base = _basename(argv0) if argv0 is not None else None
    consts = [e for e in elements if e is not None]

    if base is not None and base in DANGEROUS_ARGV0_SHELLS:
        if not dynamic:
            # Precision PR 2: every argv element is a constant, so the shell runs text a
            # reviewer can read in place (`["powershell.exe", "-command",
            # "Get-Clipboard"]`, `spawnSync('cmd.exe', ['/s', '/c', 'chcp'])`). Payload
            # tokens keep it high. A runtime string handed to an explicit shell binary
            # (`spawn('sh', ['-c', cmd])`, the dropper shape) is unchanged below.
            return _literal_shell_verdict(f"spawns a shell ({base}) that", " ".join(consts[1:]),
                                          consumed)
        sev = "critical" if (dynamic and flow) else "high"
        return _defect(sev, f"spawns a shell ({base}) — a shell string is evaluated", consumed)
    if base is not None and base in DANGEROUS_ARGV0_NET and base != "osascript":
        # osascript is also an interpreter: `osascript -e "<constant>"` is judged by the
        # inline-code rule below (Pillow's clipboard read), `do shell script` stays high.
        return _defect("high", f"spawns a downloader/decoder binary ({base})", consumed)
    if base == "osascript" and (
            dynamic or any(_OSASCRIPT_DANGER_RE.search(c) for c in consts)
            or not any(e in DANGEROUS_ARGV_FLAGS for e in elements[1:])):
        return _defect("high", f"spawns a downloader/decoder binary ({base})", consumed)
    if base is not None and (base in INTERPRETER_ARGV0 or argv0 == "python"):
        for i, el in enumerate(elements[1:], 1):
            if el in DANGEROUS_ARGV_FLAGS:
                code = elements[i + 1] if i + 1 < len(elements) else None
                if code is None:
                    sev = "critical" if flow else "high"
                    return _defect(
                        sev, f"inline interpreter eval ({base} {el}) of a dynamic string", consumed,
                    )
                if INLINE_CODE_DANGER_RE.search(code):
                    return _defect(
                        "high", f"inline interpreter eval ({base} {el}) of code that execs/"
                        "decodes/fetches", consumed, payload=inline_code_is_payload(code),
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


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 — unreadable: an opaque dynamic part
        return "?"


def _py_command_parts(node: ast.AST, resolve_name=None, _depth: int = 0,
                      ) -> tuple[list[str], list[str]]:
    """``(visible text pieces, sources of runtime parts)`` of a Python command
    expression: an f-string's literal text vs its ``{…}`` fields, a ``+`` / ``%``
    concatenation, ``"…".format(…)``, an argv list, or a name bound to one of those
    earlier in the function. Anything else is one opaque runtime part."""
    if _depth > 20:
        return [], [_unparse(node)]
    s = _const_str(node)
    if s is not None:
        return [s], []
    if isinstance(node, ast.JoinedStr):
        consts: list[str] = []
        dyn: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                consts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                dyn.append(_unparse(v.value))
        return consts, dyn
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        lc, ld = _py_command_parts(node.left, resolve_name, _depth + 1)
        if isinstance(node.op, ast.Mod):
            return lc, ld + [_unparse(node.right)]
        rc, rd = _py_command_parts(node.right, resolve_name, _depth + 1)
        return lc + rc, ld + rd
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and _const_str(node.func.value) is not None
            and node.args and isinstance(node.args[0], (ast.List, ast.Tuple))):
        # `" ".join(["curl", "-s", host, "|", "sh"])`: the assembled text is visible;
        # read it as the string it builds so the payload check sees `curl … | sh`
        # (adversarial review of #160: assembly must never be quieter than the string).
        sep = _const_str(node.func.value) or ""
        consts, dyn, run = [], [], []
        for el in node.args[0].elts:
            s = _const_str(el)
            if s is not None:
                run.append(s)
                continue
            if run:
                consts.append(sep.join(run))
                run = []
            c, d = _py_command_parts(el, resolve_name, _depth + 1)
            consts += c
            dyn += d
        if run:
            consts.append(sep.join(run))
        return consts, dyn
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        rc, rd = _py_command_parts(node.func.value, resolve_name, _depth + 1)
        return rc, rd + [_unparse(a) for a in node.args] + \
            [_unparse(k.value) for k in node.keywords]
    if isinstance(node, (ast.List, ast.Tuple)):
        consts, dyn = [], []
        for el in node.elts:
            c, d = _py_command_parts(el, resolve_name, _depth + 1)
            consts += c
            dyn += d
        return consts, dyn
    if isinstance(node, ast.Name) and resolve_name is not None and _depth < 4:
        resolved = resolve_name(node.id)
        if resolved is not None:
            return _py_command_parts(resolved, resolve_name, _depth + 1)
    return [], [_unparse(node)]


def _is_const_join(node: ast.AST) -> bool:
    """`"<sep>".join([<only string constants>])`."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and _const_str(node.func.value) is not None
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))
            and all(_const_str(e) is not None for e in node.args[0].elts))


def _visible_shell_parts_py(nodes: list[ast.AST], resolve_name=None,
                            ) -> tuple[list[str], list[str]] | None:
    """For the argv AFTER an explicit shell binary: ``(consts, dyn)`` when every element
    is a constant or a VISIBLE template (f-string / concat / ``.format``) — the command
    text a reviewer can read with holes for values. ``None`` when any element is an
    opaque value (a bare name or call): an unseen string handed to a shell."""
    consts: list[str] = []
    dyn: list[str] = []
    for el in nodes:
        s = _const_str(el)
        if s is not None:
            consts.append(s)
            continue
        if isinstance(el, ast.Name) and resolve_name is not None:
            vals = _const_values(resolve_name(el.id))
            if vals and len(vals) == 1:
                consts.append(vals[0])
                continue
        if _is_const_join(el) or (_is_dynamic_string(el) and not (
                isinstance(el, ast.Call) and isinstance(el.func, ast.Attribute)
                and el.func.attr in ("join", "replace"))):
            c, d = _py_command_parts(el, resolve_name)
            consts += c
            dyn += d
            continue
        return None
    return consts, dyn


def _shell_verdict(arg: ast.AST | None, *, untrusted_near: bool, consumed: int,
                   how: str, untrusted_flow: bool | None = None,
                   payload_flow: bool = False, resolve_name=None) -> ExecVerdict:
    """A shell IS being invoked (os.system / shell=True / string command): the severity
    ladder above. Untrusted input reaching a runtime-built command is the
    command-injection critical."""
    s = _const_str(arg) if arg is not None else None
    if s is not None and not s.strip() and how.startswith("os."):
        # `os.system("")` — the well-known no-op that enables ANSI escape handling in a
        # Windows console. It runs nothing.
        return _cap("info", f"{how}(\"\") no-op (enables ANSI escapes on Windows)",
                    CAP_SPAWN, consumed)
    if s is not None:
        return _literal_shell_verdict(how, s, consumed)
    if arg is None:
        consts, dyn = [], ["?"]
    else:
        consts, dyn = _py_command_parts(arg, resolve_name)
        listed = arg
        if isinstance(listed, ast.Name) and resolve_name is not None:
            listed = resolve_name(listed.id) or listed
        elements = _argv_nodes(listed)
        if elements is not None and any(
                _SHELL_METACHAR_RE.search(c) for c in
                (_const_str(e) for e in elements) if c is not None):
            # An argv LIST whose element is `;` / `|` / `> /etc/passwd`: the shell joins
            # the list and runs a SECOND command hidden in what reads as one argv.
            sev = "critical" if _flow(untrusted_near, untrusted_flow) else "high"
            return _defect(sev, f"{how} with an argv element carrying shell metacharacters "
                           "(a second command)", consumed)
    if not dyn and not _flow(untrusted_near, untrusted_flow):
        return _literal_shell_verdict(how, " ".join(consts), consumed)
    return _dynamic_shell_verdict(how, consts, dyn or ["?"], untrusted_near=untrusted_near,
                                  untrusted_flow=untrusted_flow, payload_flow=payload_flow,
                                  consumed=consumed)


def classify_python_exec(
    call_src: str, func_name: str, *, untrusted_near: bool,
    resolve_name=None, consumed: int = 1, cli_origin: bool = False,
    untrusted_flow: bool | None = None, payload_flow: bool = False,
) -> ExecVerdict:
    """Classify one ``subprocess.*`` / ``os.system`` / ``os.popen`` call.

    ``resolve_name(name) -> ast.AST | None`` lets the caller look up ``cmd = [...]``
    assigned earlier in the file. ``payload_flow``: the caller saw a decoded value
    reach the call. Parse failures fall back to a conservative regex read (never
    silently to "capability")."""
    node = _parse_expr(call_src)
    if not isinstance(node, ast.Call):
        return _regex_fallback(call_src, untrusted_near=untrusted_near, consumed=consumed,
                               untrusted_flow=untrusted_flow)

    kw = {k.arg: k.value for k in node.keywords if k.arg}
    first = node.args[0] if node.args else kw.get("args")
    if isinstance(first, ast.Starred):
        first = None

    if func_name in _PY_SHELL_FUNCS:
        return _shell_verdict(first, untrusted_near=untrusted_near,
                              untrusted_flow=untrusted_flow, consumed=consumed,
                              how=f"os.{func_name}", payload_flow=payload_flow,
                              resolve_name=resolve_name)

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
            return _shell_verdict(first, untrusted_near=untrusted_near,
                                  untrusted_flow=untrusted_flow, consumed=consumed,
                                  how="shell=True", payload_flow=payload_flow,
                                  resolve_name=resolve_name)

    if first is None:
        # `Popen(*args, **kwargs)` — a pass-through wrapper: the command is whatever
        # the caller hands in. A capability unless untrusted input sits nearby.
        return classify_argv([None], True, untrusted_near=untrusted_near, consumed=consumed,
                             untrusted_flow=untrusted_flow)

    seq = _argv_sequence(first)
    if seq is None and isinstance(first, ast.Name) and resolve_name is not None:
        resolved = resolve_name(first.id)
        if resolved is not None:
            seq = _argv_sequence(resolved)
            if seq is None and _is_dynamic_string(resolved):
                first = resolved
    if seq is not None:
        elements, dynamic = seq
        if dynamic and resolve_name is not None:
            # `[ps_script_var, ...]` / `["powershell.exe", "-command", ps_script]`: a name
            # bound to ONE constant earlier in the function reads as that constant.
            arg_node = first
            if isinstance(arg_node, ast.Name):
                arg_node = resolve_name(arg_node.id) or arg_node
            raw = _argv_nodes(arg_node)
            if raw is not None and len(raw) == len(elements):
                elements = list(elements)
                for i, el in enumerate(raw):
                    if elements[i] is None and isinstance(el, ast.Name):
                        vals = _const_values(resolve_name(el.id))
                        if vals and len(vals) == 1 and not isinstance(
                                resolve_name(el.id), (ast.List, ast.Tuple)):
                            elements[i] = vals[0]
                dynamic = any(e is None for e in elements)
        if dynamic and elements and elements[0] is not None \
                and _basename(elements[0]) in DANGEROUS_ARGV0_SHELLS:
            # `("sh", "-c", ". {0} && npm install -g npm@{1}".format(...))`: an explicit
            # shell with a VISIBLE command template reads like any shell string (the
            # ladder). An opaque string (`["sh", "-c", cmd]`) stays high below.
            arg_node = first
            if isinstance(arg_node, ast.Name) and resolve_name is not None:
                arg_node = resolve_name(arg_node.id) or arg_node
            raw = _argv_nodes(arg_node)
            vis = _visible_shell_parts_py(raw[1:], resolve_name) if raw else None
            if vis is not None:
                return _dynamic_shell_verdict(
                    f"spawns a shell ({_basename(elements[0])}) that", vis[0], vis[1] or ["?"],
                    untrusted_near=untrusted_near, untrusted_flow=untrusted_flow,
                    payload_flow=payload_flow, consumed=consumed)
        if dynamic and elements and elements[0] is not None and (
                _basename(elements[0]) in INTERPRETER_ARGV0 or elements[0] == "python"):
            # `[sys.executable, "-c", "import %s; %s.%s()" % (mod, mod, fn)]` (alembic's
            # console-script hook): inline code from a VISIBLE template is judged on its
            # text and reach, like a shell string. Opaque code (`["node", "-e", code]`)
            # stays high in classify_argv.
            arg_node = first
            if isinstance(arg_node, ast.Name) and resolve_name is not None:
                arg_node = resolve_name(arg_node.id) or arg_node
            raw = _argv_nodes(arg_node)
            if raw and len(raw) == len(elements):
                for i, el in enumerate(elements[1:-1], 1):
                    if el not in DANGEROUS_ARGV_FLAGS:
                        continue
                    code = raw[i + 1]
                    # Elements AFTER the code are the snippet's sys.argv, not code.
                    others_dynamic = any(e is None for e in elements[:i + 1])
                    if elements[i + 1] is None and not others_dynamic and _is_const_join(code):
                        # `";".join(["import x", "x.main()"])`: constant code, assembled.
                        text = " ".join(_py_command_parts(code, resolve_name)[0])
                        base = _basename(elements[0])
                        if INLINE_CODE_DANGER_RE.search(text) or \
                                SHELL_PAYLOAD_DANGER_RE.search(text):
                            return _defect("high", f"inline interpreter eval ({base} {el}) of "
                                           "code that execs/decodes/fetches", consumed,
                                           payload=inline_code_is_payload(text))
                        return _cap("low", f"runs a constant inline {base} snippet ({el})",
                                    CAP_SPAWN, consumed)
                    if elements[i + 1] is None and not others_dynamic and _is_dynamic_string(
                            code) and not (isinstance(code, ast.Call)
                                           and isinstance(code.func, ast.Attribute)
                                           and code.func.attr in ("join", "replace")):
                        consts, dyn = _py_command_parts(code, resolve_name)
                        base = _basename(elements[0])
                        if INLINE_CODE_DANGER_RE.search(" ".join(consts)):
                            return _defect("high", f"inline interpreter eval ({base} {el}) of "
                                           "code that execs/decodes/fetches", consumed,
                                           payload=inline_code_is_payload(" ".join(consts)))
                        return _dynamic_shell_verdict(
                            f"inline {base} {el} code built from a template", consts,
                            dyn or ["?"], untrusted_near=untrusted_near,
                            untrusted_flow=untrusted_flow, payload_flow=payload_flow,
                            consumed=consumed)
                    break
        return classify_argv(elements, dynamic, untrusted_near=untrusted_near,
                             consumed=consumed, untrusted_flow=untrusted_flow)

    s = _const_str(first)
    if s is not None:
        # A plain string without shell=True is ONE program name (args are not split).
        # `"ls -la"` would fail at runtime; treat whitespace/metachars as shell intent.
        if re.search(r"[\s|&;$`<>]", s):
            return _defect("high", "string command without shell=True — probable shell intent",
                           consumed)
        return classify_argv([s], False, untrusted_near=untrusted_near, consumed=consumed,
                             untrusted_flow=untrusted_flow)
    if _is_dynamic_string(first):
        # Precision PR 2: same ladder as a shell string (without shell=True there is
        # not even a shell; on Windows the string is one command line).
        consts, dyn = _py_command_parts(first, resolve_name)
        return _dynamic_shell_verdict(
            "a command string (f-string/concat/format)", consts,
            dyn or ["?"], untrusted_near=untrusted_near, untrusted_flow=untrusted_flow,
            payload_flow=payload_flow, consumed=consumed)
    # Name / Call (shlex.split(...)) / Attribute / Subscript / BinOp(list + list) / …
    return classify_argv([None], True, untrusted_near=untrusted_near, consumed=consumed,
                             untrusted_flow=untrusted_flow)


_FALLBACK_ARGV0_RE = re.compile(r"""^\s*[\w.]+\s*\(\s*[\[(]\s*['"]([^'"]+)['"]""")


def _regex_fallback(call_src: str, *, untrusted_near: bool, consumed: int,
                    untrusted_flow: bool | None = None) -> ExecVerdict:
    """When the call cannot be parsed (truncated, Python 2, odd syntax), keep today's
    conservative read: a defect unless the argv0 is a visible, benign literal."""
    if re.search(r"shell\s*=\s*True", call_src):
        return _defect("critical" if _flow(untrusted_near, untrusted_flow) else "high",
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


_JS_INTERP_RE = re.compile(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}")


def _js_command_parts(arg: str) -> tuple[list[str], list[str]] | None:
    """Split a JS shell-command argument into (constant text pieces, dynamic
    expressions): a template literal's text vs its ``${...}`` parts, or a ``+``
    concatenation of string literals and expressions. ``None`` if unreadable."""
    a = arg.strip()
    if len(a) >= 2 and a[0] == a[-1] == "`":
        body = a[1:-1]
        dyn = [m.group(1).strip() for m in _JS_INTERP_RE.finditer(body)]
        # One text piece per stretch between `${…}` holes, so a piece that ENDS where a
        # runtime value begins (`rm -rf ${dir}`) stays visible as such.
        pieces: list[str] = []
        last = 0
        for m in _JS_INTERP_RE.finditer(body):
            pieces.append(body[last:m.start()])
            last = m.end()
        pieces.append(body[last:])
        return pieces, dyn
    pieces = split_top_level_plus(a)
    if len(pieces) < 2:
        return None
    consts: list[str] = []
    dyn: list[str] = []
    for p in pieces:
        lit = _js_literal(p)
        if lit is not None:
            consts.append(lit)
            continue
        sub = _js_command_parts(p) if p.startswith("`") else None
        if sub is not None:
            consts += sub[0]
            dyn += sub[1]
        else:
            dyn.append(p)
    return consts, dyn


def split_top_level_plus(expr: str) -> list[str]:
    """Split a JS expression on top-level ``+`` (strings / brackets respected)."""
    out: list[str] = []
    depth = 0
    in_str: str | None = None
    escape = False
    cur: list[str] = []
    for ch in expr:
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
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _js_cli_calibration(arg: str, is_cli_expr, consumed: int) -> ExecVerdict | None:
    """JS counterpart of the Python own-CLI calibration (founder-approved, tracked #2):
    ``exec``/``execSync`` of a shell string whose dynamic parts ALL come from the
    program's own command line or environment (``process.argv``, ``process.env``, a
    minimist / yargs / commander option, or a name bound to one) is a medium defect.
    Shell metacharacters in the constant text, a shell / downloader / inline
    interpreter as the program, a URL, or any dynamic part not traced to the CLI keep
    today's verdict."""
    if is_cli_expr is None:
        return None
    parts = _js_command_parts(arg)
    if parts is None:
        return None
    consts, dyn = parts
    if not dyn:
        return None
    const_text = " ".join(consts)
    if re.search(r"[|;&<>`]|\$\(", const_text) or SHELL_DANGER_RE.search(const_text):
        return None
    words = const_text.split()
    base = _basename(words[0]) if words else ""
    if base in DANGEROUS_ARGV0_SHELLS or base in DANGEROUS_ARGV0_NET or \
            base in INTERPRETER_ARGV0:
        return None
    if not all(is_cli_expr(d) for d in dyn):
        return None
    return _defect("medium", "shell command built from the program's own command line / "
                   "environment (no untrusted input reaches it)", consumed)


_JS_ARRAY_JOIN_RE = re.compile(r"""^\[(.*)\]\s*\.\s*join\s*\(\s*(['"`])(.*?)\2\s*\)$""", re.S)


def _js_parts(arg: str) -> tuple[list[str], list[str]]:
    """Visible text pieces and runtime parts of one JS argument (a literal, a template,
    a ``+`` concatenation, an array literal; anything else is one opaque part)."""
    lit = _js_literal(arg)
    if lit is not None:
        return [lit], []
    a = arg.strip()
    jm = _JS_ARRAY_JOIN_RE.match(a)
    if jm:
        # `['curl', '-s', host, '|', 'sh'].join(' ')`: read the text it assembles.
        sep = jm.group(3)
        consts: list[str] = []
        dyn: list[str] = []
        run: list[str] = []
        for el in split_top_level_args(jm.group(1)):
            lit = _js_literal(el)
            if lit is not None:
                run.append(lit)
                continue
            if run:
                consts.append(sep.join(run))
                run = []
            c, d = _js_parts(el)
            consts += c
            dyn += d
        if run:
            consts.append(sep.join(run))
        return consts, dyn
    if a.startswith("[") and a.endswith("]"):
        consts: list[str] = []
        dyn: list[str] = []
        for el in split_top_level_args(a[1:-1]):
            c, d = _js_parts(el)
            consts += c
            dyn += d
        return consts, dyn
    parts = _js_command_parts(a)
    if parts is not None:
        return parts
    return [], [a]


def classify_js_exec(
    call_src: str, func_name: str, *, untrusted_near: bool, consumed: int = 1,
    untrusted_flow: bool | None = None, is_cli_expr=None, payload_flow: bool = False,
) -> ExecVerdict:
    """Classify a child_process call: ``exec``/``execSync`` always go through a shell;
    ``spawn``/``execFile``/``fork`` take an argv (plus an options object whose
    ``shell: true`` turns it back into a shell)."""
    open_i = call_src.find("(")
    close_i = call_src.rfind(")")
    inner = call_src[open_i + 1: close_i] if 0 <= open_i < close_i else ""
    args = split_top_level_args(inner)

    # `exec('git', ['status'])` / `exec(cmd, [...args, ...files])` is an argv-taking
    # wrapper (tinyexec, execa, a project helper), never child_process.exec, whose second
    # parameter is an options object or a callback. Read it as a spawn (precision PR 2).
    argv_wrapper = (func_name in _JS_SHELL_FUNCS and len(args) > 1
                    and args[1].strip().startswith("["))

    if func_name in _JS_SHELL_FUNCS and not argv_wrapper:
        lit = _js_literal(args[0]) if args else None
        if lit is not None:
            return _literal_shell_verdict(func_name, lit, consumed)
        flow = _flow(untrusted_near, untrusted_flow)
        if not flow and args:
            cal = _js_cli_calibration(args[0], is_cli_expr, consumed)
            if cal is not None:
                return cal
        consts, dyn = _js_parts(args[0]) if args else ([], ["?"])
        return _dynamic_shell_verdict(func_name, consts, dyn or ["?"],
                                      untrusted_near=untrusted_near,
                                      untrusted_flow=untrusted_flow,
                                      payload_flow=payload_flow, consumed=consumed)

    if re.search(r"\bshell\s*:\s*(?:true|['\"][^'\"]+['\"])", inner):
        consts, dyn = [], []
        for a in args:
            if a.strip().startswith("{"):
                continue  # the options object
            c, d = _js_parts(a)
            consts += c
            dyn += d
        how = f"{func_name} with shell: true"
        if not dyn and not _flow(untrusted_near, untrusted_flow):
            return _literal_shell_verdict(how, " ".join(consts), consumed)
        return _dynamic_shell_verdict(how, consts, dyn or ["?"],
                                      untrusted_near=untrusted_near,
                                      untrusted_flow=untrusted_flow,
                                      payload_flow=payload_flow, consumed=consumed)

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
                             consumed=consumed, untrusted_flow=untrusted_flow)

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
    if dynamic and argv0 is not None and _basename(argv0) in DANGEROUS_ARGV0_SHELLS \
            and len(args) > 1 and args[1].strip().startswith("["):
        # `spawnSync('cmd.exe', ['/s', '/c', `chcp ${codepage}`])`: an explicit shell with
        # a VISIBLE command template reads like any shell string (the ladder). An opaque
        # string (`spawn('sh', ['-c', cmd])`, the dropper shape) stays high below.
        consts: list[str] = []
        dyn: list[str] = []
        visible = True
        a1 = args[1].strip()
        for el in split_top_level_args(a1[1:-1]):
            lit = _js_literal(el)
            if lit is not None:
                consts.append(lit)
                continue
            e = el.strip()
            parts = _js_command_parts(e) if (e.startswith("`") or "+" in e) else None
            if parts is None:
                visible = False
                break
            consts += parts[0]
            dyn += parts[1]
        if visible:
            return _dynamic_shell_verdict(
                f"{func_name} of a shell ({_basename(argv0)}) that", consts, dyn or ["?"],
                untrusted_near=untrusted_near, untrusted_flow=untrusted_flow,
                payload_flow=payload_flow, consumed=consumed)
    return classify_argv(elements, dynamic, untrusted_near=untrusted_near, consumed=consumed,
                         untrusted_flow=untrusted_flow)
