"""Printed install hints in Go and Rust: a ``curl … | sh`` the program shows a person
(audit class 1, 2026-11-14).

coder prints ``download the server version with: 'curl -fsSL …/install.sh | sh …'``
when the client and server versions differ; sem's self-update returns
``format!("… or reinstall:\\n  curl -fsSL …/install.sh | sh")`` as its error. Both
matched the critical "curl/wget piped to shell" rule as text, and neither runs it.

:func:`why_not` checks, for the pipe-to-shell matches on one line of a ``.go`` /
``.rs`` file, that each string reaches ONLY human-facing output (None) or says why
not. Like the JS / Python walk (``src.scanner.printed_hint``) it follows the value
conservatively and returns None only when every path ends in

* a print / log call (Go ``fmt.Print*``, ``fmt.Fprint*`` to a standard stream,
  ``log.*``; Rust ``println!`` / ``eprintln!`` / ``panic!`` / ``log`` and ``tracing``
  macros);
* an error value (Go ``fmt.Errorf`` / ``errors.New`` / ``xerrors.*``; Rust ``Err(…)``,
  ``anyhow!`` / ``bail!``), and no code of that language in view hands an error's
  text to a process (``exec.Command(…, err.Error())``, ``.arg(e.to_string())``).

On the way the value may pass through formatting (``fmt.Sprintf``, ``format!``,
``.into()`` / ``.to_string()``), a local variable (every later read in the function
is followed), or the return value of an unexported Go function / a private Rust
function (every call site in the same package / crate directory is followed).
Anything else keeps the finding: a struct field, a slice, a closure, a call the walk
does not know, a file that does not tokenize cleanly.
"""
from __future__ import annotations

import re
from pathlib import Path

GO_EXTS = frozenset({".go"})
RUST_EXTS = frozenset({".rs"})

_MAX_STEPS = 300


class _UnclassifiedError(Exception):
    pass


# ---------------------------------------------------------------------------------
# Tokenizer (Go and Rust share it: strings, comments, identifiers, punctuation)
# ---------------------------------------------------------------------------------

_ID_RE = re.compile(r"[A-Za-z_][\w]*")
_NUM_RE = re.compile(r"\d[\w.]*")
_PUNCTS = sorted("""
:= ... :: -> => == != <= >= && || << >> += -= *= /= |= &= ^= %= { } ( ) [ ] ; , . : = < >
+ - * / % & | ^ ! ? # @ ~ $
""".split(), key=len, reverse=True)
_PUNCT_RE = re.compile("|".join(re.escape(p) for p in _PUNCTS))
_DQ_RE = re.compile(r'"(?:[^"\\]|\\[\s\S])*"')
_RUST_RAW_RE = re.compile(r'b?r(#*)"[\s\S]*?"\1')
_RUST_CHAR_RE = re.compile(r"b?'(?:[^'\\\n]|\\[^\n]{1,10}?)'")


class _Toks:
    __slots__ = ("typ", "st", "en", "val", "match", "clean")

    def __init__(self, text: str, rust: bool) -> None:
        typ: list[str] = []
        st: list[int] = []
        en: list[int] = []
        val: list[str] = []
        match: dict[int, int] = {}
        stack: list[int] = []
        clean = True
        i, n = 0, len(text)

        def emit(t: str, a: int, b: int) -> None:
            typ.append(t)
            st.append(a)
            en.append(b)
            val.append(text[a:b] if t in ("id", "punct") else "")

        while i < n:
            c = text[i]
            if c in " \t\r\n\f\v":
                i += 1
                continue
            if text.startswith("//", i):
                j = text.find("\n", i)
                i = n if j == -1 else j
                continue
            if text.startswith("/*", i):
                if rust:  # nested block comments
                    depth, j = 0, i
                    while j < n:
                        if text.startswith("/*", j):
                            depth += 1
                            j += 2
                        elif text.startswith("*/", j):
                            depth -= 1
                            j += 2
                            if depth == 0:
                                break
                        else:
                            j += 1
                    if depth:
                        clean = False
                        break
                    i = j
                else:
                    j = text.find("*/", i + 2)
                    if j == -1:
                        clean = False
                        break
                    i = j + 2
                continue
            if rust and (c == "r" or (c == "b" and text.startswith("br", i))):
                m = _RUST_RAW_RE.match(text, i)
                if m:
                    emit("str", i, m.end())
                    i = m.end()
                    continue
            if c == '"' or (rust and c == "b" and text.startswith('b"', i)):
                m = _DQ_RE.match(text, i + (1 if c == "b" else 0))
                if not m:
                    clean = False
                    break
                emit("str", i, m.end())
                i = m.end()
                continue
            if c == "`" and not rust:
                j = text.find("`", i + 1)
                if j == -1:
                    clean = False
                    break
                emit("str", i, j + 1)
                i = j + 1
                continue
            if c == "'" or (rust and c == "b" and text.startswith("b'", i)):
                m = _RUST_CHAR_RE.match(text, i)
                if m:
                    emit("char", i, m.end())
                    i = m.end()
                    continue
                if rust:  # a lifetime / label: `'a`
                    m = _ID_RE.match(text, i + 1)
                    if m:
                        emit("life", i, m.end())
                        i = m.end()
                        continue
                clean = False
                break
            m = _ID_RE.match(text, i)
            if m:
                emit("id", i, m.end())
                i = m.end()
                continue
            m = _NUM_RE.match(text, i)
            if m:
                emit("num", i, m.end())
                i = m.end()
                continue
            m = _PUNCT_RE.match(text, i)
            if m:
                emit("punct", i, m.end())
                k = len(typ) - 1
                p = m.group(0)
                if p in ("(", "[", "{"):
                    stack.append(k)
                elif p in (")", "]", "}"):
                    want = {")": "(", "]": "[", "}": "{"}[p]
                    if stack and val[stack[-1]] == want:
                        o = stack.pop()
                        match[o] = k
                        match[k] = o
                    else:
                        clean = False
                i = m.end()
                continue
            clean = False  # a stray byte
            i += 1
        if stack:
            clean = False
        self.typ, self.st, self.en, self.val = typ, st, en, val
        self.match, self.clean = match, clean

    def __len__(self) -> int:
        return len(self.typ)

    def is_p(self, k: int, *vals: str) -> bool:
        return 0 <= k < len(self.typ) and self.typ[k] == "punct" and self.val[k] in vals

    def is_id(self, k: int, *vals: str) -> bool:
        return 0 <= k < len(self.typ) and self.typ[k] == "id" and (
            not vals or self.val[k] in vals)

    def at(self, pos: int) -> int:
        lo, hi = 0, len(self.st)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.st[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid
        k = lo - 1
        if k >= 0 and self.st[k] <= pos < self.en[k]:
            return k
        return -1


# ---------------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------------

# Value-preserving formatting: the call's result carries the string on.
_GO_FORMAT = frozenset({"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "pretty.Sprint",
                        "pretty.Sprintf", "strings.TrimSpace", "strings.TrimSuffix",
                        "strings.TrimPrefix"})
_GO_PRINT = frozenset({"fmt.Print", "fmt.Printf", "fmt.Println", "log.Print", "log.Printf",
                       "log.Println", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic",
                       "log.Panicf", "log.Panicln"})
_GO_FPRINT = frozenset({"fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln"})
# First argument of Fprint*: a standard stream.
_GO_STD_STREAM_RE = re.compile(
    r"^(?:os\.Std(?:err|out)|[\w.]+\.Std(?:err|out)|[\w.]+\.(?:ErrOrStderr|OutOrStdout)\(\))$")
_GO_ERROR = frozenset({"fmt.Errorf", "errors.New", "errors.Errorf", "xerrors.Errorf",
                       "xerrors.New", "errors.Wrap", "errors.Wrapf", "pkgerrors.Errorf"})
_RUST_FORMAT = frozenset({"format", "concat"})
_RUST_STD_PRINT = frozenset({"println", "eprintln", "print", "eprint"})
_RUST_PRINT = frozenset({
    "println", "eprintln", "print", "eprint", "panic", "unreachable", "todo",
    "unimplemented", "warn", "error", "info", "debug", "trace", "log::warn",
    "log::error", "log::info", "log::debug", "log::trace", "tracing::warn",
    "tracing::error", "tracing::info", "tracing::debug", "tracing::trace",
})
_RUST_ERROR_MACROS = frozenset({"anyhow", "bail", "eyre", "anyhow::anyhow", "anyhow::bail",
                                "eyre::eyre", "eyre::bail"})
_RUST_PASSTHRU = frozenset({"into", "to_string", "to_owned", "as_str", "trim", "clone"})

# A call that starts a process (`exec.Command("sh", "-c", s)`, `.arg(&s)`). An error's
# text can reach one under any name (`s := problem.Error()`, `fmt.Sprint(problem)`,
# `if let Err(msg) = …`, `let s = format!("{e}")`), so an error value counts as shown
# only when no process in view takes anything but literals, no child's stdin is
# opened and Go's `log` output stays on a standard stream.
_GO_EXEC_CALL_RE = re.compile(
    r"(?:\bexec(?:abs)?\.Command(?:Context)?|\b(?:syscall|unix)\.Exec|\bos\.StartProcess)\s*\(")
_RUST_EXEC_CALL_RE = re.compile(r"(?:Command::new|\.args?)\s*\(")
_GO_STDIN_RE = re.compile(r"\.StdinPipe\s*\(|\.Stdin\s*=[^=]")
_RUST_STDIN_RE = re.compile(
    r"\.stdin\s*\((?!\s*(?:std::process::)?Stdio::(?:null|inherit)\(\)\s*\))")
# Any logger's output (`log.SetOutput`, `log.Default().SetOutput`, `l.SetOutput`) sent
# somewhere other than a standard stream.
_GO_LOG_REDIRECT_RE = re.compile(r"\.SetOutput\s*\((?!\s*os\.Std(?:err|out)\s*\))")
# Other ways an error's text reaches a process or a file a process may run (second
# review of #378): the child's environment, its argv set by hand, an exec.Cmd literal,
# a fork/exec call, a function value of exec.Command, inherited file descriptors, a
# written file, a swapped standard stream. Matched on the text with strings blanked.
_GO_RISK_RE = re.compile(
    r"\b(?:syscall|unix)\.(?:ForkExec|StartProcess|Exec\w*|Syscall\w*|RawSyscall\w*|"
    r"Dup\d?|Open\w*|Creat)\b"
    r"|\bexec\.Cmd\s*\{|\bnew\s*\(\s*exec\.Cmd\s*\)|=\s*exec\.Cmd\b|\bProcAttr\s*\{"
    r"|\bexec(?:abs)?\.Command(?:Context)?\b(?!\s*\()"
    r"|\.(?:Args|ExtraFiles)\s*=[^=]"
    r"|\b(?:os|ioutil)\.(?:WriteFile|Create\w*|OpenFile|NewFile|Pipe|TempFile)\s*\("
    r"|\bos\.Std(?:in|out|err)\s*=[^=]")
# Go imports that start processes under another name: an aliased or dot import of
# os/exec / syscall / x/sys, cgo, or a library that runs shell code.
_GO_RISK_IMPORT_RE = re.compile(
    r'(?m)^\s*(?:import\s+)?(?:(?!_\s)[A-Za-z_]\w*|\.)\s+"(?:os/exec|syscall|'
    r'golang\.org/x/sys/(?:unix|execabs|windows))"'
    r'|^\s*import\s+"C"'
    r'|"(?:mvdan\.cc/sh[^"]*|github\.com/bitfield/script[^"]*|github\.com/go-cmd/cmd|'
    r'github\.com/codeskyblue/go-sh|github\.com/traefik/yaegi[^"]*|'
    r'github\.com/creack/pty|github\.com/(?:google/goexpect|Netflix/go-expect)|'
    r'golang\.org/x/sys/execabs)"')
# `cmd.Env = append(os.Environ(), "K=v")`: the child's environment, checked like an
# argument list once the parent's own environment is taken out.
_GO_ENV_ASSIGN_RE = re.compile(r"\.Env\s*=(?!=)([^\n]*)")
_GO_ENV_KEEP_RE = re.compile(r"\bappend\b|\bos\.Environ\s*\(\s*\)|[\w.]+\.Env\b")
_RUST_RISK_RE = re.compile(
    r"\bfs::write\b|\bFile::(?:create\w*|options)\b|\bOpenOptions\b|\bfrom_raw_fd\b"
    r"|\bNamedTempFile\b|\btempfile\b"
    r"|\b(?:libc|nix)::|\bstd::os::unix::process\b|\bCommandExt\b"
    r"|\bCommand\s+as\b|\bprocess\s+as\b|\btype\s+\w+\s*=\s*(?:[\w:]*::)?Command\b"
    r"|\bCommand::new\b(?!\s*\()"
    r"|\bcmd!|\bduct::|\bxshell\b|\bcmd_lib\b|\brun_cmd!|\brun_fun!|\bsubprocess::"
    r"|\brun_script\b|\basync_process\b|\bexpectrl\b|\brexpect\b|\bportable_pty\b"
    r"|\bpty_process\b|\bdup2?\b|\bset_output_capture\b|\bgag::"
    # loggers that write to files without a File in user code
    r"|\btracing_appender\b|\blog4rs\b|\bfern\b|\bflexi_logger\b|\bWriteLogger\b")
_RUST_FFI_RE = re.compile(r'\bextern\s+"(?:C|system)"')
_RUST_ENV_CALL_RE = re.compile(r"(?:\.envs?|\bset_var)\s*\(")
_ARG_ID_RE = re.compile(r"(?<![\w.:])[A-Za-z_]\w*")
_RUST_PATH_PARAM_RE = (r"\b{}\s*:\s*(?:&\s*)?(?:mut\s+)?(?:std::path::|std::ffi::)?"
                       r"(?:Path|PathBuf|OsStr|OsString)\b")
_ARG_WORDS = frozenset({"mut", "ref", "as", "true", "false", "nil", "self"})


def _arg_ids_plain(args: str, text: str, rust: bool) -> bool:
    """Every identifier in a process call's argument list (strings blanked; method and
    path segments skipped) is a constant of this file, or in Rust a parameter typed
    as a filesystem path (`tmp: &Path`)."""
    for m in _ARG_ID_RE.finditer(args):
        name = m.group(0)
        if name in _ARG_WORDS:
            continue
        if re.search(r"\bconst\s+" + re.escape(name) + r"\b", text):
            continue
        if rust and re.search(_RUST_PATH_PARAM_RE.format(re.escape(name)), text):
            continue
        return False
    return True


def _flat(text: str, rust: bool) -> str | None:
    """``text`` as code only: comments dropped, every string and char literal blanked
    to ``""`` / ``''``, and ``a . b`` / ``a :: b`` closed up. None when it does not
    tokenize cleanly."""
    t = _Toks(text, rust)
    if not t.clean:
        return None
    out: list[str] = []
    for k in range(len(t)):
        if k:
            out.append("\n" if "\n" in text[t.en[k - 1]:t.st[k]] else " ")
        typ = t.typ[k]
        out.append('""' if typ == "str" else "''" if typ == "char"
                   else text[t.st[k]:t.en[k]])
    return re.sub(r"\s*(::|\.)\s*", r"\1", "".join(out))


def _call_args(flat: str, start: int) -> str:
    depth, j = 1, start
    while j < len(flat) and depth and j - start < 2000:
        if flat[j] == "(":
            depth += 1
        elif flat[j] == ")":
            depth -= 1
        j += 1
    return flat[start:j - 1]


def _output_swapped(text: str, rust: bool) -> bool:
    """Could the program's standard output / error be something other than the
    terminal: a standard stream reassigned or dup'ed, or (Rust) captured?"""
    flat = _flat(text, rust)
    if flat is None:
        return True
    if rust:
        return bool(re.search(r"\bdup[23]?\b|\bset_output_capture\b|\bgag::|\b(?:libc|nix)::",
                              flat) or _RUST_FFI_RE.search(text))
    return bool(re.search(r"\bos\.Std(?:out|err)\s*=[^=]|\b(?:syscall|unix)\.Dup\d?\b", flat)
                or re.search(r'(?m)^\s*import\s+"C"', text))


def _err_to_exec(text: str, rust: bool) -> bool:
    """Could an error's text reach a process in ``text``? Yes when a process-starting
    call takes a non-literal argument, a child's stdin is opened, (Go) a logger's
    output goes somewhere other than a standard stream, or any other channel to a
    process is in view: the child's environment (``cmd.Env``, ``os.Setenv``,
    ``.env(…)``, ``set_var``) unless it takes only literals, argv set by hand
    (``cmd.Args =``, an ``exec.Cmd`` literal), a fork / exec call, an aliased or
    function-valued ``exec.Command`` / ``Command::new``, cgo / FFI / libc, a library
    that runs shell code, or a file written at all (the text may be run from it)."""
    flat = _flat(text, rust)
    if flat is None:
        return True
    if rust:
        if _RUST_STDIN_RE.search(flat) or _RUST_RISK_RE.search(flat) \
                or _RUST_FFI_RE.search(text):
            return True
        for m in _RUST_ENV_CALL_RE.finditer(flat):
            if not _arg_ids_plain(_call_args(flat, m.end()), text, rust):
                return True
    else:
        flat = re.sub(r"\b_\s*=\s*exec\.Command\b(?!\s*\()", "", flat)  # keeps an import
        if _GO_STDIN_RE.search(flat) or _GO_LOG_REDIRECT_RE.search(flat) \
                or _GO_RISK_RE.search(flat) or _GO_RISK_IMPORT_RE.search(text):
            return True
        for m in re.finditer(r"\b(?:os|syscall)\.Setenv\s*\(", flat):
            if not _arg_ids_plain(_call_args(flat, m.end()), text, rust):
                return True
        for m in _GO_ENV_ASSIGN_RE.finditer(flat):
            if not _arg_ids_plain(_GO_ENV_KEEP_RE.sub(" ", m.group(1)), text, rust):
                return True
    call_re = _RUST_EXEC_CALL_RE if rust else _GO_EXEC_CALL_RE
    for m in call_re.finditer(flat):
        args = _call_args(flat, m.end())
        if not rust and "CommandContext" in m.group(0):
            args = args.split(",", 1)[1] if "," in args else ""  # the context
        if not _arg_ids_plain(args, text, rust):
            return True
    return False


# ---------------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------------

class _Flow:
    def __init__(self, files: dict[str, str], rust: bool) -> None:
        self.files = files
        self.rust = rust
        self.exts = RUST_EXTS if rust else GO_EXTS
        self._toks: dict[str, _Toks] = {}
        self.steps = 0
        self.followed: set[tuple] = set()
        self._err_ok: bool | None = None
        self._out_ok: bool | None = None

    def toks(self, path: str) -> _Toks:
        t = self._toks.get(path)
        if t is None:
            t = self._toks[path] = _Toks(self.files[path], self.rust)
        if not t.clean:
            raise _UnclassifiedError(f"{path} does not tokenize cleanly")
        return t

    def tick(self) -> None:
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise _UnclassifiedError("too many steps")

    # -- helpers -------------------------------------------------------------------
    def enclosing_open(self, t: _Toks, k: int) -> int:
        j = k - 1
        while j >= 0:
            if t.is_p(j, ")", "]", "}"):
                j = t.match[j] - 1
                continue
            if t.is_p(j, "(", "[", "{"):
                return j
            j -= 1
        return -1

    def callee(self, t: _Toks, o: int) -> str | None:
        """The dotted / path name before ``(`` at ``o`` (``fmt.Sprintf``,
        ``format`` for ``format!(``, ``log::warn`` …), else None."""
        j = o - 1
        if self.rust and t.is_p(j, "!"):
            j -= 1
        if not t.is_id(j):
            return None
        parts = [t.val[j]]
        sep = "::" if self.rust else "."
        while t.is_p(j - 1, ".", "::") and t.is_id(j - 2):
            if self.rust and t.is_p(j - 1, "."):
                return None  # a method call: handled by the caller
            parts.append(t.val[j - 2])
            j -= 2
        if self.rust and t.is_p(o - 1, "!"):
            return sep.join(reversed(parts))
        name = sep.join(reversed(parts))
        return name + ("()" if self.rust else "")

    def _code(self):
        from src.scanner.test_files import judged
        return [text for p, text in self.files.items()
                if text and Path(p).suffix.lower() in self.exts and not judged(p)
                and not p.endswith("_test.go")]

    def require_errors_shown(self) -> None:
        """An error value (or a print whose sink the walk cannot see, such as a writer
        field or a Rust logger) counts as shown only while no code in view has any
        channel by which text could reach a process (:func:`_err_to_exec`)."""
        if self._err_ok is None:
            self._err_ok = not any(_err_to_exec(text, self.rust) for text in self._code())
        if not self._err_ok:
            raise _UnclassifiedError("some code can hand an error's text to a process")
        self.require_output_shown()

    def require_output_shown(self) -> None:
        """A print to stdout / stderr counts as shown only while no code in view swaps
        those streams (``os.Stderr = w``, ``dup2``, an output capture)."""
        if self._out_ok is None:
            self._out_ok = not any(_output_swapped(text, self.rust) for text in self._code())
        if not self._out_ok:
            raise _UnclassifiedError("standard output may be sent somewhere else")

    def require_log_shown(self) -> None:
        """Go ``log.*`` prints only while no code in view sends its output elsewhere."""
        if any(_GO_LOG_REDIRECT_RE.search(_flat(text, False) or ".SetOutput(")
               for text in self._code()):
            raise _UnclassifiedError("log output sent somewhere other than a standard stream")
        self.require_output_shown()

    def func_bounds(self, t: _Toks, k: int) -> tuple[int, int, str | None]:
        """(body `{`, body `}`, function name) of the function holding token ``k``."""
        j = k
        while True:
            o = self.enclosing_open(t, j)
            if o == -1:
                raise _UnclassifiedError("not inside a function")
            if t.is_p(o, "{"):
                # Go: `func name(…) T {` / `func (r R) name(…) T {`; Rust: `fn name(…) -> T {`
                q = o - 1
                while q >= 0 and not t.is_p(q, ";", "{", "}") and q > o - 60:
                    if t.is_id(q, "func", "fn"):
                        name = t.val[q + 1] if t.is_id(q + 1) else None
                        if not self.rust and t.is_p(q + 1, "("):
                            r = t.match.get(q + 1)
                            name = t.val[r + 1] if r is not None and t.is_id(r + 1) else None
                        return o, t.match[o], name
                    q -= 1
            j = o

    # -- climbing ------------------------------------------------------------------
    def value(self, path: str, a: int, b: int) -> None:
        t = self.toks(path)
        key = (path, a, b)
        if key in self.followed:
            return
        self.followed.add(key)
        while True:
            self.tick()
            # Rust postfix: `.into()`, `.to_string()` …
            while self.rust and t.is_p(b + 1, ".") and t.is_id(b + 2) \
                    and t.val[b + 2] in _RUST_PASSTHRU and t.is_p(b + 3, "(") \
                    and t.is_p(b + 4, ")"):
                b += 4
            if self.rust and t.is_p(b + 1, "?"):
                raise _UnclassifiedError("value after ?")
            p = a - 1
            nx = b + 1
            if t.is_p(p, "(", ",") or t.is_p(nx, ",", ")") and t.is_p(p, "("):
                o = p if t.is_p(p, "(") else self.enclosing_open(t, a)
                if o == -1 or not t.is_p(o, "("):
                    raise _UnclassifiedError("value in a list or literal")
                r = self.in_call(path, t, o, a)
                if r is None:
                    return
                a, b = r
                continue
            if t.is_p(p, "+") or t.is_p(nx, "+"):
                # string concatenation: climb over the whole `x + y + z`
                a, b = self.concat(t, a, b)
                continue
            if (not self.rust and t.is_p(p, ":=", "=")) or (
                    self.rust and t.is_p(p, "=")):
                self.assigned(path, t, p, b)
                return
            if t.is_id(p, "return"):
                self.returned(path, t, p)
                return
            raise _UnclassifiedError(f"value after {t.val[p] or t.typ[p] if p >= 0 else 'start'}")

    def concat(self, t: _Toks, a: int, b: int) -> tuple[int, int]:
        while t.is_p(a - 1, "+") and (t.typ[a - 2] in ("str", "id") or t.is_p(a - 2, ")")):
            a = t.match[a - 2] - (1 if t.is_id(t.match[a - 2] - 1) else 0) \
                if t.is_p(a - 2, ")") else a - 2
        while t.is_p(b + 1, "+") and t.typ[b + 2] in ("str", "id"):
            b += 2
            if t.is_p(b + 1, "("):
                b = t.match[b + 1]
        return a, b

    def in_call(self, path: str, t: _Toks, o: int, a: int):
        close = t.match[o]
        if self.rust and t.is_id(o - 1, "Err") and not t.is_p(o - 2, ".", "::"):
            if self.err_returned(t, o - 1):
                self.require_errors_shown()
                return None
            raise _UnclassifiedError("Err(…) that is not returned")
        name = self.callee(t, o)
        if name is None:
            raise _UnclassifiedError("value passed to an unknown call")
        if self.rust:
            if name in _RUST_STD_PRINT:
                self.require_output_shown()
                return None
            if name in _RUST_PRINT:
                # A panic message goes through the panic hook, a log line through
                # whatever logger is set up: sinks the walk does not see, so they are
                # held to the same bar as an error value.
                self.require_errors_shown()
                return None
            if name in _RUST_FORMAT:
                return (o - 2, close)
            if name in _RUST_ERROR_MACROS:
                self.require_errors_shown()
                return None
            if name in ("write", "writeln"):
                first = self.first_arg(t, o)
                if re.fullmatch(r"(?:std::)?io::std(?:err|out)\(\)(?:\.lock\(\))?", first):
                    self.require_output_shown()
                    return None
            raise _UnclassifiedError(f"value passed to {name}")
        if name in _GO_PRINT:
            if name.startswith("log."):
                self.require_log_shown()
            self.require_output_shown()
            return None
        if name in _GO_FPRINT:
            first = self.first_arg(t, o)
            if _GO_STD_STREAM_RE.match(first) and a > o + 1:
                if not re.fullmatch(r"os\.Std(?:err|out)", first):
                    # A writer field (`inv.Stderr`, `cmd.ErrOrStderr()`) can hold any
                    # writer, a child's stdin or a file included.
                    self.require_errors_shown()
                self.require_output_shown()
                return None
            raise _UnclassifiedError(f"Fprint to {first or 'an unknown writer'}")
        if name in _GO_FORMAT:
            start = o - 1
            while t.is_p(start - 1, ".") and t.is_id(start - 2):
                start -= 2
            return start, close
        if name in _GO_ERROR:
            self.require_errors_shown()
            return None
        raise _UnclassifiedError(f"value passed to {name}()")

    def err_returned(self, t: _Toks, k: int) -> bool:
        """``Err(…)`` at ``k`` is the function's result: after ``return``, or the tail
        expression of the function body (nothing but ``}`` / ``;`` after it)."""
        if t.is_id(k - 1, "return"):
            return True
        close = t.match.get(k + 1)
        if close is None:
            return False
        try:
            _s, end, _fn = self.func_bounds(t, k)
        except _UnclassifiedError:
            return False
        if close + 1 == end and t.is_p(k - 1, "{", ";", "}"):
            return True
        return False

    def first_arg(self, t: _Toks, o: int) -> str:
        j = o + 1
        close = t.match[o]
        out = []
        while j < close and not t.is_p(j, ","):
            if t.is_p(j, "(", "[", "{"):
                out.append(self.files_text(t, j, t.match[j]))
                j = t.match[j] + 1
                continue
            out.append(t.val[j] if t.typ[j] in ("id", "punct") else "?")
            j += 1
        return "".join(out)

    def files_text(self, t: _Toks, a: int, b: int) -> str:
        return "".join(t.val[k] if t.typ[k] in ("id", "punct") else "?"
                       for k in range(a, b + 1))

    def assigned(self, path: str, t: _Toks, eq: int, b: int) -> None:
        """``x := v`` / ``var x = v`` (Go), ``let [mut] x = v`` (Rust): follow every
        later read of ``x`` in the same function."""
        lhs = eq - 1
        if not t.is_id(lhs):
            raise _UnclassifiedError("assignment to a field, index or pattern")
        if t.is_p(lhs - 1, ".", ",", "::", "*"):
            raise _UnclassifiedError("assignment to a field, a pointer or several names")
        name = t.val[lhs]
        if name == "_":
            return  # discarded
        # Only a binding this function declares: `x := v` / `var x = v` (Go),
        # `let [mut] x = v` (Rust), or `x = v` after such a declaration in the same
        # function. Otherwise `x` may be a package-level / outer variable whose
        # readers elsewhere are not followed.
        start, _end, _fn = self.func_bounds(t, eq)
        if not any(self.declares(t, k, name) for k in range(start, eq)):
            raise _UnclassifiedError(f"{name} is not declared here (may be read elsewhere)")
        _start, end, _fn = self.func_bounds(t, eq)
        used = False
        for k in range(b + 1, end):
            if not t.is_id(k, name) or t.is_p(k - 1, ".", "::"):
                continue
            if t.is_p(k + 1, "=", ":="):
                continue  # a later write, not a read
            if t.is_p(k + 1, ".", "[") or t.is_p(k - 1, "&") and t.is_id(k - 2, "mut"):
                raise _UnclassifiedError(f"{name} used other than as a whole value")
            used = True
            self.value(path, k - 1 if self.rust and t.is_p(k - 1, "&") else k, k)
        if not used:
            raise _UnclassifiedError(f"{name} is never read")

    def declares(self, t: _Toks, k: int, name: str) -> bool:
        """Token ``k`` is ``name`` bound as a local: ``let [mut] name`` (Rust),
        ``name :=`` / ``var name`` (Go)."""
        if not t.is_id(k, name) or t.is_p(k - 1, ".", "::"):
            return False
        if self.rust:
            return t.is_id(k - 1, "let") or (t.is_id(k - 1, "mut") and t.is_id(k - 2, "let"))
        return t.is_p(k + 1, ":=") and not t.is_p(k - 1, ",") or t.is_id(k - 1, "var")

    def returned(self, path: str, t: _Toks, ret: int) -> None:
        _s, _e, fn = self.func_bounds(t, ret)
        if not fn:
            raise _UnclassifiedError("returned from an anonymous function")
        if self.rust:
            raise _UnclassifiedError("returned from a Rust function (not followed)")
        if fn[0].isupper():
            raise _UnclassifiedError(f"returned from exported {fn}: callers may be elsewhere")
        pkg = str(Path(path).parent)
        sites = 0
        for fp, text in self.files.items():
            if str(Path(fp).parent) != pkg or Path(fp).suffix != ".go" \
                    or fp.endswith("_test.go") or not text or fn not in text:
                continue
            ft = self.toks(fp)
            for k in range(len(ft)):
                if not ft.is_id(k, fn) or ft.is_p(k - 1, "."):
                    continue
                if ft.is_id(k - 1, "func") or (ft.is_p(k - 1, ")") and fp == path
                                               and ft.is_id(ft.match[k - 1] - 1, "func")):
                    continue  # the definition
                if not ft.is_p(k + 1, "("):
                    raise _UnclassifiedError(f"{fn} used other than by a call")
                sites += 1
                self.value(fp, k, ft.match[k + 1])
        if not sites:
            raise _UnclassifiedError(f"{fn} is never called")


def is_supported(path: str) -> bool:
    return Path(path.lower()).suffix in GO_EXTS | RUST_EXTS


def why_not(files: dict[str, str], path: str, line_no: int,
            pattern: re.Pattern) -> str | None:
    """None when every pipe-to-shell match on 1-based ``line_no`` of ``path`` (a Go or
    Rust file) is a string that reaches only human-facing output, else the reason."""
    if not is_supported(path):
        return "unsupported file type"
    text = files.get(path)
    if not text:
        return "no text"
    lines = text.split("\n")
    if not 0 < line_no <= len(lines):
        return "line out of range"
    matches = list(pattern.finditer(lines[line_no - 1]))
    if not matches:
        return "no match on the line"
    rust = Path(path.lower()).suffix in RUST_EXTS
    flow = _Flow(files, rust)
    offset = sum(len(ln) + 1 for ln in lines[:line_no - 1])
    try:
        t = flow.toks(path)
        for m in matches:
            k = t.at(offset + m.start())
            if k < 0 or t.typ[k] != "str" or t.en[k] < offset + m.end():
                return "match is not inside one string literal"
            flow.steps = 0
            flow.value(path, k, k)
        return None
    except _UnclassifiedError as exc:
        return str(exc) or "unknown"
    except (RecursionError, KeyError, IndexError) as exc:
        return f"walk error: {type(exc).__name__}"
