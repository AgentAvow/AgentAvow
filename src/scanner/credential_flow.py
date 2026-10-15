"""Credential-file exfiltration: a credential file's contents reaching an outbound send.

``open(os.path.expanduser('~/.ssh/id_rsa')).read()`` followed by
``requests.post(url, data=k)`` is the stealer shape (the ``ua-parser-js`` /
``ctx`` / PyPI typosquat class). The per-line exfil rules miss it: the read and the
send sit on different lines and the send's arguments name an ordinary variable. This
module follows the value in one file, Python or JavaScript / TypeScript:

* a SOURCE is a read (``open`` / ``read_text`` / ``readFileSync`` / ``sqlite3.connect``
  …) of a credential path. The path may be one literal (``'~/.ssh/id_rsa'``) or built
  from parts (``Path.home() / '.ssh' / 'id_rsa'``, ``os.path.join(os.environ['HOME'],
  '.aws', 'credentials')``, ``path.join(os.homedir(), '.ssh', 'id_rsa')``), inline or
  through a path variable;
* the value flows through assignments, ``with … as f``, read callbacks and returns,
  scoped to the function it is in, plus one function hop each way (a helper that
  returns the contents, a helper that sends its parameter);
* a SINK is an outbound send (requests / httpx / urllib / aiohttp / http.client /
  socket / DNS lookups; fetch / axios / http(s).request / net / dns) whose arguments
  carry the value.

Precision: a read whose contents only reach an SDK or auth client (boto3, paramiko's
``connect(pkey=…)``, keyring) never meets a send. A send to the credential's own
official host (``*.amazonaws.com`` for AWS keys, ``upload.pypi.org`` for ``.pypirc``,
the npm registry for ``.npmrc``) is the tool authenticating, and so is a value used
only as ``auth=`` / an ``Authorization`` header with no literal third-party host.
A read with no send is left to the existing rules.

Pure text analysis: no imports from ``scan`` (it calls in here), never executes code.
"""
from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Credential paths
# ---------------------------------------------------------------------------

_SSH_RE = re.compile(r"(?:^|[/~])\.ssh(?:/([^/]+))?(?=/|$)")
_SSH_NOT_SECRET = frozenset({"known_hosts", "known_hosts2", "authorized_keys",
                             "authorized_keys2", "config"})
_ID_KEY_RE = re.compile(r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?=/|$)")
_CRED_KIND_RES: list[tuple[str, re.Pattern[str]]] = [
    ("aws", re.compile(r"\.aws/(?:credentials|sso/cache|cli/cache)(?=/|$)")),
    ("gcloud", re.compile(r"\.config/gcloud(?=/|$)|(?:^|/)application_default_credentials"
                          r"\.json$|(?:^|/)gcloud/(?:credentials|access_tokens)\.db$")),
    ("kube", re.compile(r"\.kube/config(?=/|$)")),
    ("netrc", re.compile(r"(?:^|/)[._]netrc$|(?:^|/)\.git-credentials$")),
    ("npmrc", re.compile(r"(?:^|/)\.npmrc$")),
    ("pypirc", re.compile(r"(?:^|/)\.pypirc$")),
    ("docker", re.compile(r"\.docker/config\.json$")),
    ("browser", re.compile(
        r"(?:^|/)(?:Login Data|Login Data For Account|Web Data)$|(?:^|/)cookies\.sqlite$|"
        r"(?:^|/)logins\.json$|(?:^|/)key[34]\.db$|(?:^|/)signons\.sqlite$|"
        r"Cookies\.binarycookies$|(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|Firefox|"
        r"Mozilla)\b.*/(?:Network/)?Cookies$")),
    ("wallet", re.compile(
        r"(?:^|/)wallet\.dat$|(?:^|/)\.(?:bitcoin|litecoin|dogecoin|dash)(?=/|$)|"
        r"\.ethereum/keystore|(?:^|/)keystore/UTC--|[Ee]lectrum/wallets|"
        r"solana/id\.json$|exodus\.wallet|nkbihfbeogaeaoehlefnkodbefgpgknn")),
]
_ENV_FILE_RE = re.compile(r"^(?:~/|\./|/)?\.env$")
# Literals that are not path parts: open() modes, encodings, the HOME env-var name, URLs.
_NOT_PATH_PART_RE = re.compile(
    r"^(?:[rwabxtU+]{1,3}|utf-?8|utf8|ascii|latin-?1|utf-?16|binary|base64|hex|HOME|"
    r"USERPROFILE|APPDATA|LOCALAPPDATA)$|://", re.IGNORECASE)


def credential_kind(path: str) -> str | None:
    """The credential class a (joined) path names, or None."""
    p = re.sub(r"[\\/]+", "/", path)
    for m in _SSH_RE.finditer(p):
        part = m.group(1)
        if part is None or (part not in _SSH_NOT_SECRET and not part.endswith(".pub")):
            return "ssh"
    if _ID_KEY_RE.search(p):
        return "ssh"
    for kind, rx in _CRED_KIND_RES:
        if rx.search(p):
            return kind
    if _ENV_FILE_RE.match(p):
        return "env"
    return None


# Official hosts: a credential sent to its own service is authentication, not exfil.
_OFFICIAL_HOSTS: dict[str, tuple[str, ...]] = {
    "aws": ("amazonaws.com", "amazonaws.com.cn", "aws.amazon.com", "api.aws"),
    "gcloud": ("googleapis.com", "google.com"),
    "npmrc": ("npmjs.org", "npmjs.com", "npm.pkg.github.com", "yarnpkg.com"),
    "pypirc": ("pypi.org", "pythonhosted.org"),
    "docker": ("docker.io", "docker.com", "ghcr.io", "gcr.io", "quay.io", "pkg.dev",
               "azurecr.io", "amazonaws.com"),
    "netrc": ("github.com", "gitlab.com", "bitbucket.org"),
}
_URL_HOST_RE = re.compile(r"^[a-zA-Z][\w+.-]*://(?:[^@/]*@)?([^/:?#\s]+)")
# Argument keys that make a value authentication (it rides an auth header to the host).
_AUTH_KEYS = frozenset({"auth", "headers", "authorization", "httpauth", "basicauth",
                        "basic_auth", "proxy-authorization"})


def _official(kind: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in _OFFICIAL_HOSTS.get(kind, ()))


# ---------------------------------------------------------------------------
# Lexing: code with string bodies / comments blanked (offsets preserved) + literals
# ---------------------------------------------------------------------------


@dataclass
class _Lexed:
    code: str                                  # same length as the source
    literals: list[tuple[int, int, str]]       # (start, end, value) of each string


def _js_regex_start(src: str, i: int) -> bool:
    """A `/` where an expression starts (after `(`, `=`, `,` … or `return`) opens a
    regex literal; after a value it is division."""
    k = i - 1
    while k >= 0 and src[k] in " \t":
        k -= 1
    if k < 0 or src[k] in "(,=:[!&|?{};+-*%<>~^\n":
        return True
    return src[max(0, k - 5):k + 1] in ("return", "typeof")


def _lex(src: str, python: bool) -> _Lexed:
    out = list(src)
    lits: list[tuple[int, int, str]] = []
    n, i = len(src), 0

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            out[k] = " "

    while i < n:
        c = src[i]
        if python and c == "#":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if not python and c == "/" and i + 1 < n and src[i + 1] in "/*":
            if src[i + 1] == "/":
                j = src.find("\n", i)
                j = n if j < 0 else j
            else:
                j = src.find("*/", i + 2)
                j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if not python and c == "/" and _js_regex_start(src, i):
            # A regex literal (`/["']/g`): skip it so its quotes don't open a string.
            j, in_class = i + 1, False
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                elif src[j] == "/" and not in_class:
                    break
                j += 1
            blank(i, min(j + 1, n))
            i = j + 1
            continue
        if c in "'\"" or (c == "`" and not python):
            # Python string prefix (f / rf / b …) decides interpolation.
            k = i - 1
            while k >= 0 and src[k].isalpha() and i - k <= 2:
                k -= 1
            prefix = src[k + 1:i].lower() if python else ""
            interp = ("f" in prefix) if python else (c == "`")
            triple = python and src.startswith(c * 3, i)
            q = c * 3 if triple else c
            j = i + len(q)
            buf: list[str] = []
            while j < n:
                if src[j] == "\\" and "r" not in prefix:
                    buf.append(src[j:j + 2])
                    blank(j, min(j + 2, n))
                    j += 2
                    continue
                if src.startswith(q, j):
                    break
                if not triple and c != "`" and src[j] == "\n":
                    break                      # unterminated: stop at end of line
                if python and interp and src.startswith("{{", j):
                    buf.append("{")
                    j += 2
                    continue
                if interp and (src[j] == "{" if python else src.startswith("${", j)):
                    # Keep the interpolated expression as code.
                    depth, e = 0, j + (0 if python else 1)
                    while e < n:
                        if src[e] == "{":
                            depth += 1
                        elif src[e] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        e += 1
                    for m in range(j + (1 if python else 2), min(e, n)):
                        out[m] = src[m]
                    buf.append("/")
                    j = e + 1
                    continue
                out[j] = " "
                buf.append(src[j])
                j += 1
            end = min(j + len(q), n)
            lits.append((i, end, "".join(buf)))
            i = end
            continue
        i += 1
    return _Lexed("".join(out), lits)


# ---------------------------------------------------------------------------
# Statements and scopes
# ---------------------------------------------------------------------------


@dataclass
class _Stmt:
    start: int
    end: int
    code: str
    scope: tuple[int, ...]
    indent: int = 0
    lits: list[tuple[int, int, str]] = field(default_factory=list)


_JS_OBJ_PREV = set("=(,:[?!&|+")
_JS_FN_HEADER_RE = re.compile(
    r"\bfunction\b|=>\s*\{$|\bclass\b|^\s*(?:static\s+)?(?:async\s+)?"
    r"(?!(?:if|for|while|switch|catch|with)\b)[\w$]+\s*\([^)]*\)\s*\{$")


def _continued(code: str, i: int) -> bool:
    """A Python line ending in a backslash continues onto the next."""
    k = i - 1
    while k >= 0 and code[k] in " \t\r":
        k -= 1
    return k >= 0 and code[k] == "\\"


def _statements(src: str, lx: _Lexed, python: bool) -> list[_Stmt]:
    code = lx.code
    stmts: list[_Stmt] = []
    depth = 0
    # Per open `{`: None = an object literal (counted in depth), else a JS block and
    # the bracket depth outside it (restored when it closes). A callback body inside a
    # call's arguments is a block too, so a bundle's IIFE is not one statement.
    braces: list[int | None] = []
    # JS open blocks: the header statement's index for a function / class body (a
    # scope), None for an if / for / try block.
    blocks: list[int | None] = []
    start = 0

    def emit(a: int, b: int) -> bool:
        text = code[a:b]
        if text.strip():
            stmts.append(_Stmt(a, b, text, tuple(x for x in blocks if x is not None)))
            return True
        return False

    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        elif c == "{":
            is_obj = python
            if not python:
                k = i - 1
                while k >= 0 and code[k] in " \t\r\n":
                    k -= 1
                prev = code[k] if k >= 0 else ""
                is_obj = prev in _JS_OBJ_PREV or code[max(0, k - 5):k + 1] == "return"
                if prev == ">" and k >= 1 and code[k - 1] == "=":
                    is_obj = False                 # `=> {` is a function body
            if is_obj:
                braces.append(None)
                depth += 1
            else:
                braces.append(depth)
                depth = 0
                opened = emit(start, i + 1)
                is_fn = opened and _JS_FN_HEADER_RE.search(stmts[-1].code) is not None
                blocks.append(len(stmts) - 1 if is_fn else None)
                start = i + 1
        elif c == "}":
            saved = braces.pop() if braces else None
            if saved is None:
                depth = max(0, depth - 1)
            else:
                emit(start, i)
                if blocks:
                    blocks.pop()
                depth = saved
                start = i + 1
        elif depth == 0 and (c == ";" or (c == "\n" and not (
                python and _continued(code, i)))):
            emit(start, i)
            start = i + 1
        i += 1
    emit(start, n)

    lit_starts = [lt[0] for lt in lx.literals]
    for st in stmts:
        a = bisect.bisect_left(lit_starts, st.start)
        b = bisect.bisect_left(lit_starts, st.end)
        st.lits = lx.literals[a:b]
    if python:
        stack: list[tuple[int, int]] = []        # (indent, def statement index)
        for idx, st in enumerate(stmts):
            line_start = src.rfind("\n", 0, st.start) + 1
            first = src[line_start:st.end]
            st.indent = len(first) - len(first.lstrip(" \t"))
            while stack and st.indent <= stack[-1][0]:
                stack.pop()
            st.scope = tuple(s for _i, s in stack)
            if _PY_DEF_RE.match(st.code) or re.match(r"\s*class\s", st.code):
                stack.append((st.indent, idx))
    return stmts


# ---------------------------------------------------------------------------
# Reads, sends, assignments
# ---------------------------------------------------------------------------

_PY_READ_RE = re.compile(
    r"(?<![\w.])(?:io\.|codecs\.|aiofiles\.)?open\s*\(|\.open\s*\(|"
    r"\.read_(?:text|bytes)\s*\(|\bsqlite3\.connect\s*\(|(?<![\w.])\w+\.read\s*\(")
_JS_READ_RE = re.compile(
    r"\b(?:readFileSync|readFile|createReadStream)\s*\(|"
    r"\bnew\s+(?:\w+\.)*(?:Database|DatabaseSync)\s*\(")
_PY_SEND_RE = re.compile(
    r"(?<![\w])(?:requests|httpx)\.(?:post|put|patch|get|request|delete)\s*\(|"
    r"(?<![\w])(?:[\w.]*\.)?\w*(?:session|client|http|sess|api|conn|pool)\w*\."
    r"(?:post|put|patch|get|request)\s*\(|"
    r"\.(?:post|request)\s*\(|(?<![\w.])urlopen\s*\(|\burllib\.request\.urlopen\s*\(|"
    r"(?<![\w])(?:urllib\.request\.)?Request\s*\(|"
    r"\.(?:send|sendall|sendto|sendmsg|sendmail|send_message|storbinary)\s*\(|"
    r"\b(?:socket\.)?(?:gethostbyname(?:_ex)?|getaddrinfo|create_connection)\s*\(|"
    r"\bresolver\.(?:resolve|query)\s*\(|\bdns\.resolver\.\w+\s*\(",
    re.IGNORECASE)
_JS_SEND_RE = re.compile(
    r"(?<![\w.$])fetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bhttps?\.(?:request|get)\s*\(|"
    r"\b(?:got|needle|superagent|undici|ky)(?:\.\w+)?\s*\(|\.post\s*\(|"
    r"\b(?:\w*(?:http|client|api|request|session|instance)\w*)\.(?:put|patch)\s*\(|"
    r"(?<![\w$])(?!(?:res|resp|response|reply|ctx|process)\.)[\w$.]*\.send\s*\(|"
    r"\bnavigator\.sendBeacon\s*\(|\bdns\.(?:promises\.)?(?:resolve\w*|lookup)\s*\(")
# `.write(` / `.end(` carry data on a socket / request only in a file that uses one.
_JS_STREAM_SEND_RE = re.compile(
    r"(?<![\w$])(?!(?:process\.std(?:out|err)|console|res|resp|response|reply|ctx|fs|"
    r"file|stream|out|log)\.)[\w$.]*\.(?:write|end)\s*\(")
_JS_NET_MODULE_RE = re.compile(
    r"""(?:require\s*\(\s*|from\s+)['"](?:node:)?(?:https?|net|tls|dgram|http2)['"]""")
_PY_DEF_RE = re.compile(r"\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)")
_JS_DEF_RES = [
    re.compile(r"\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([\w$]+)\s*"
               r"\(([^)]*)\)"),
    re.compile(r"\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?"
               r"(?:function\s*[\w$]*\s*)?\(([^)]*)\)\s*(?:=>)?"),
    re.compile(r"\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?"
               r"([\w$]+)\s*=>"),
    re.compile(r"\s*(?:static\s+)?(?:async\s+)?(?!(?:if|for|while|switch|catch|function|"
               r"return|with)\b)([\w$]+)\s*\(([^)]*)\)\s*\{\s*$"),
]
# A statement-level assignment (kwargs inside a call are not targets).
_PY_ASSIGN_RE = re.compile(
    r"^\s*([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)[ \t]*(?::[^=\n]{1,80}?)?(?:[-+*/|&:])?=(?!=)")
_JS_ASSIGN_RE = re.compile(
    r"(?:\b(?:const|let|var)\s+([\w$]+|\{[^}]*\}|\[[^\]]*\])|"
    r"(?<![\w$.])([\w$]+(?:\.[\w$]+)*))\s*(?:\+)?=(?![=>])")
_AS_RE = re.compile(r"\bas\s+(\w+)")
_FOR_IN_RE = re.compile(r"\bfor\s+(?:const\s+|let\s+|var\s+)?\(?\s*([\w$]+)[\w$,\s]*\)?\s+"
                        r"(?:in|of)\s+([\w$.]+)")
_CALLBACK_PARAMS_RE = re.compile(
    r"(?:\(([^()]*)\)|([\w$]+))\s*=>|function\s*[\w$]*\s*\(([^)]*)\)")
_RETURN_RE = re.compile(r"(?<![\w$.])return\b|(?<![\w$.])yield\b|=>")


def _names(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", text)


def _params(raw: str) -> list[str]:
    out = []
    for part in raw.split(","):
        part = part.strip().lstrip("*").strip()
        m = re.match(r"[A-Za-z_$][\w$]*", part)
        if m and m.group(0) not in ("self", "cls"):
            out.append(m.group(0))
    return out


@functools.lru_cache(maxsize=4096)
def _call_re(name: str) -> re.Pattern[str]:
    # A call of the function (not its `def` / `function` header).
    return re.compile(r"(?<![\w$])(?<!def )(?<!function )" + re.escape(name) + r"\s*\(")


@functools.lru_cache(maxsize=4096)
def _ref_re(name: str) -> re.Pattern[str]:
    # A use of the name: not an attribute of something else, not a kwarg / object key.
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])(?!\s*=(?![=]))"
                      r"(?!\s*:(?!:))")


def _arg_span(code: str, open_paren: int) -> int:
    depth, i = 0, open_paren
    while i < len(code):
        if code[i] in "([{":
            depth += 1
        elif code[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(code)


# A helper worth summarizing for the one-function hop is small.
_MAX_HELPER_STATEMENTS = 200


@dataclass
class _Hit:
    pos: int            # absolute offset of the send call
    kind: str           # credential kind


@dataclass
class _Sink:
    """A function that sends its parameter: per hit, the hosts and auth-only flag."""
    hits: list[tuple[list[str], bool]]


class _Analyzer:
    def __init__(self, src: str, python: bool) -> None:
        self.src = src
        self.python = python
        self.lx = _lex(src, python)
        self.stmts = _statements(src, self.lx, python)
        self.read_re = _PY_READ_RE if python else _JS_READ_RE
        self.send_res = [_PY_SEND_RE] if python else [_JS_SEND_RE]
        if not python and _JS_NET_MODULE_RE.search(src):
            self.send_res.append(_JS_STREAM_SEND_RE)
        self.sinks: dict[str, _Sink] = {}
        self.sources: dict[str, str] = {}
        # Function headers: index -> offset (in the statement) where the header ends,
        # so a method NAMED `fetch` / `post` is not read as a call of one.
        self.header_end: dict[int, int] = {}
        self.lit_kinds = [self._lit_kind(st) for st in self.stmts]

    # -- per-statement facts ------------------------------------------------
    def _lit_kind(self, st: _Stmt, a: int = -1, b: int = -1) -> str | None:
        lits = [v for s, _e, v in st.lits if a < 0 or a <= s < b]
        parts = [v.strip() for v in lits if v.strip() and not _NOT_PATH_PART_RE.search(v)]
        for v in parts:
            k = credential_kind(v)
            if k:
                return k
        if len(parts) > 1:
            joined = re.sub(r"/+", "/", "/".join(parts))
            return credential_kind(joined)
        return None

    def _hosts(self, st: _Stmt, a: int, b: int) -> list[str]:
        out = []
        for s, _e, v in st.lits:
            if a <= s < b:
                m = _URL_HOST_RE.match(v.strip())
                if m:
                    out.append(m.group(1))
        return out

    def _auth_only(self, a: int, b: int, refs: list[int]) -> bool:
        """Every use of the value at [refs] sits under an auth / headers key."""
        if not refs:
            return False
        for r in refs:
            before = self.src[a:r]
            keys = re.findall(r"""['"]?([\w-]+)['"]?\s*(?:=(?!=)|:)""", before)
            if not keys or keys[-1].lower() not in _AUTH_KEYS:
                return False
        return True

    # -- the flow -----------------------------------------------------------
    def run(self, idxs: list[int], init: dict[str, tuple[str, tuple[int, ...]]] | None = None,
            ) -> tuple[list[_Hit], list[tuple[list[str], bool]], str | None]:
        """Follow credential values through ``idxs``. Returns (hits, param-sink hits for
        a 'param' kind as (hosts, auth_only), the kind a ``return`` carries)."""
        taint: dict[str, tuple[str, tuple[int, ...]]] = dict(init or {})
        pathvars: dict[str, tuple[str, tuple[int, ...]]] = {}
        hits: list[_Hit] = []
        param_hits: list[tuple[list[str], bool]] = []
        returns: str | None = None

        def visible(table: dict[str, tuple[str, tuple[int, ...]]], scope: tuple[int, ...]
                    ) -> dict[str, str]:
            return {nm: k for nm, (k, sc) in table.items() if scope[:len(sc)] == sc}

        for idx in idxs:
            st = self.stmts[idx]
            code = st.code
            vis_t = visible(taint, st.scope)
            vis_p = visible(pathvars, st.scope)
            lit_kind = self.lit_kinds[idx]
            path_kind = lit_kind or next(
                (k for nm, k in vis_p.items() if _ref_re(nm).search(code)), None)
            has_read = bool(self.read_re.search(code))
            src_kind = next((k for nm, k in self.sources.items()
                             if _call_re(nm).search(code)), None)
            ref_kind = next((k for nm, k in vis_t.items() if _ref_re(nm).search(code)), None)
            value_kind = (path_kind if (path_kind and has_read) else None) or src_kind
            carried = value_kind or ref_kind

            targets = self._targets(code)
            if carried:
                for nm in targets:
                    taint[nm] = (carried, st.scope)
                for m in _AS_RE.finditer(code):
                    taint[m.group(1)] = (carried, st.scope)
                if value_kind and not self.python:
                    for m in _CALLBACK_PARAMS_RE.finditer(code):
                        for p in _params(next(g for g in m.groups() if g is not None)
                                         if any(m.groups()) else ""):
                            if p not in ("err", "error", "e"):
                                taint[p] = (value_kind, st.scope)
                # `cp.read(path)` (configparser) loads the file into the receiver.
                if path_kind and self.python:
                    for m in re.finditer(r"(?<![\w.])(\w+)\.read\s*\(", code):
                        taint[m.group(1)] = (path_kind, st.scope)
            elif path_kind:
                for nm in targets:
                    pathvars[nm] = (path_kind, st.scope)
            for m in _FOR_IN_RE.finditer(code):
                it = m.group(2)
                if it in vis_p:
                    pathvars[m.group(1)] = (vis_p[it], st.scope)
                elif it in vis_t:
                    taint[m.group(1)] = (vis_t[it], st.scope)
                elif path_kind and not value_kind:
                    # `for p in glob.glob(expanduser('~/.ssh/*')):`
                    pathvars[m.group(1)] = (path_kind, st.scope)
            vis_t = visible(taint, st.scope)

            if carried and _RETURN_RE.search(code):
                returns = returns or carried

            if not (vis_t or vis_p or lit_kind or self.sources):
                continue                           # nothing here can carry a credential
            skip_to = self.header_end.get(idx, 0)
            for send_re in self.send_res:
                for m in send_re.finditer(code, skip_to):
                    a = m.end() - 1
                    b = _arg_span(code, a)
                    self._check_call(st, a, b, vis_t, vis_p, hits, param_hits)
            for nm, _sink in self.sinks.items():
                for m in _call_re(nm).finditer(code, skip_to):
                    a = m.end() - 1
                    b = _arg_span(code, a)
                    self._check_call(st, a, b, vis_t, vis_p, hits, param_hits, sink=nm)
        return hits, param_hits, returns

    def _targets(self, code: str) -> list[str]:
        out: list[str] = []
        if self.python:
            for m in _PY_ASSIGN_RE.finditer(code):
                for part in m.group(1).split(","):
                    nm = part.strip()
                    if re.fullmatch(r"[A-Za-z_][\w.]*", nm):
                        out.append(nm)
        else:
            for m in _JS_ASSIGN_RE.finditer(code):
                if m.group(1):
                    out.extend(n for n in _names(m.group(1)) if "." not in n)
                elif m.group(2):
                    out.append(m.group(2))
        return out

    def _check_call(self, st: _Stmt, a: int, b: int, vis_t: dict[str, str],
                    vis_p: dict[str, str], hits: list[_Hit],
                    param_hits: list[tuple[list[str], bool]], sink: str | None = None) -> None:
        span = st.code[a:b]
        kind: str | None = None
        refs: list[int] = []
        # An inline read of a credential path inside the call's arguments.
        if self.read_re.search(span):
            kind = self._lit_kind(st, st.start + a, st.start + b) or next(
                (k for nm, k in vis_p.items() if _ref_re(nm).search(span)), None)
        if not kind:
            for nm, k in self.sources.items():
                if _call_re(nm).search(span):
                    kind = k
                    break
        if not kind:
            for nm, k in vis_t.items():
                found = [st.start + a + mm.start() for mm in _ref_re(nm).finditer(span)]
                if found:
                    kind = kind or k
                    if k == kind:
                        refs.extend(found)
        if not kind:
            return
        abs_a, abs_b = st.start + a, st.start + b
        if sink is not None:
            # A call into a function that sends its parameter.
            sk = self.sinks[sink]
            if kind == "param":
                param_hits.extend(sk.hits)
                return
            if any(not self._excused(kind, hosts, auth) for hosts, auth in sk.hits):
                hits.append(_Hit(abs_a, kind))
            return
        hosts = self._hosts(st, abs_a, abs_b)
        auth = self._auth_only(abs_a, abs_b, refs)
        if kind == "param":
            param_hits.append((hosts, auth))
            return
        if not self._excused(kind, hosts, auth):
            hits.append(_Hit(abs_a, kind))

    @staticmethod
    def _excused(kind: str, hosts: list[str], auth_only: bool) -> bool:
        if hosts:
            return all(_official(kind, h) for h in hosts)
        return auth_only

    # -- one function hop ---------------------------------------------------
    def functions(self) -> list[tuple[str, list[str], int, list[int]]]:
        """(name, params, header index, body statement indices) for each function."""
        bodies: dict[int, list[int]] = {}
        for j, st in enumerate(self.stmts):
            for owner in st.scope:
                bodies.setdefault(owner, []).append(j)
        out = []
        for idx, st in enumerate(self.stmts):
            m = None
            if self.python:
                m = _PY_DEF_RE.match(st.code)
            else:
                for rx in _JS_DEF_RES:
                    m = rx.match(st.code)
                    if m:
                        break
            if not m:
                continue
            self.header_end[idx] = m.end()
            out.append((m.group(1), _params(m.group(2)), idx, bodies.get(idx, [])))
        return out

    def summarize(self, fns: list[tuple[str, list[str], int, list[int]]]) -> None:
        """Mark helpers that send a parameter (sinks) or return a credential file's
        contents (sources). Only small functions with a send / a credential path (or a
        call of a known source) are candidates: a bundle's module wrapper is neither."""
        has_send = [any(r.search(st.code) for r in self.send_res) for st in self.stmts]
        for name, params, idx, body in fns:
            if len(body) > _MAX_HELPER_STATEMENTS:
                continue
            st = self.stmts[idx]
            # One-liners (`def f(p): return …`, `const f = (p) => fetch(…)`) carry the
            # body in the header statement itself.
            idxs = [idx, *body]
            if params and name not in self.sinks and any(has_send[j] for j in idxs):
                _h, ph, _r = self.run(idxs, {p: ("param", st.scope) for p in params})
                if ph:
                    self.sinks[name] = _Sink(ph)
            if name not in self.sources and (
                    any(self.lit_kinds[j] for j in idxs)
                    or any(_call_re(s).search(self.stmts[j].code)
                           for s in self.sources for j in idxs)):
                _h, _ph, ret = self.run(idxs)
                if ret and ret != "param":
                    self.sources[name] = ret


def credential_exfil_hits(content: str, lang: str | None) -> list[tuple[int, str]]:
    """``(line_number, credential_kind)`` for each send that carries a credential file's
    contents in ``content`` (``lang``: python / javascript / typescript)."""
    if lang not in ("python", "javascript", "typescript"):
        return []
    python = lang == "python"
    # Cheap pre-check: some credential path word and some send word in the file.
    if not re.search(r"\.ssh|id_(?:rsa|dsa|ecdsa|ed25519)|\.aws|gcloud|\.kube|netrc|"
                     r"git-credentials|\.npmrc|\.pypirc|\.docker|Login Data|Cookies|"
                     r"cookies\.sqlite|logins\.json|key[34]\.db|wallet|\.bitcoin|"
                     r"\.litecoin|\.dogecoin|\.dash\b|\.ethereum|keystore|[Ee]lectrum|"
                     r"solana|exodus|nkbihfbeogaeaoehlefnkodbefgpgknn|\.env\b", content):
        return []
    an = _Analyzer(content, python)
    if not any(an.lit_kinds):
        return []                                  # no credential path in any statement
    fns = an.functions()
    # Two rounds, so a helper defined after the one that calls it still resolves.
    an.summarize(fns)
    an.summarize(fns)
    hits, _ph, _r = an.run(list(range(len(an.stmts))))
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    for h in hits:
        line = content.count("\n", 0, h.pos) + 1
        if line not in seen:
            seen.add(line)
            out.append((line, h.kind))
    return out
