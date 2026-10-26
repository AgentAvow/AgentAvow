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

from src.scanner.skill_key_flow import (
    VENDOR_KEYS,
    host_is_own_vendor,
    is_local_host,
    registrable_domain,
)

_NAME = r"([A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD))"
# A named key pulled OUT of a .env (`line.startswith("OPENROUTER_API_KEY=")`,
# `env.match(/X_TOKEN=(.*)/)`, `values["SLACK_BOT_TOKEN"]`, `.get("FOO_KEY")`): the
# only names that may excuse a .env read; a bare mention (comment, help text) never.
_EXTRACT_RE = re.compile(
    r"(?<![\w.])(?!(?:print|echo|log|warn|info|debug|error|Error|TypeError|format|"
    r"console|exit|die|raise|throw|f)\b)(?:[\w$]+\.)*[\w$]+"
    r"\s*\(\s*[rbf]?[\"'/`]\^?\s*" + _NAME + r"\b"
    r"|\[\s*[\"']" + _NAME + r"[\"']\s*\]"
    r"|/\^?" + _NAME + r"=")

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
# The whole environment (``env_dump_exfil_hits``)
# ---------------------------------------------------------------------------

_ENV_DUMP = "envdump"
# The whole environment serialized or copied, on code with string bodies blanked. A
# single variable (`JSON.stringify(process.env.FOO)`, `os.environ["X"]`) is not a
# dump, and neither is an alias (`const env = process.env`: `env.API_URL` is one var).
_ENV_TAIL = r"(?!\s*(?:\.|\[|\?\.))"
_JS_ENV_DUMP_RE = re.compile(
    r"JSON\.stringify\(\s*process\.env" + _ENV_TAIL + r"|\.\.\.\s*process\.env" + _ENV_TAIL
    + r"|Object\.(?:entries|values|assign)\([^()]*?process\.env" + _ENV_TAIL)
_PY_ENV_DUMP_RE = re.compile(
    r"\bdict\(\s*(?:\*\*\s*)?os\.environ\s*\)|\bos\.environ\.copy\(\s*\)"
    r"|\b(?:json\.dumps|str|repr)\(\s*(?:dict\(\s*)?os\.environ" + _ENV_TAIL
    + r"|\{\s*\*\*\s*os\.environ" + _ENV_TAIL)
# `Object.entries(process.env).filter(…)`: a chosen subset (a prefix), not a dump.
_FILTERED_RE = re.compile(r"\s*\)?\s*\.\s*filter\s*\(")
# The bare mapping as a whole argument / body of a send (`axios.post(url, process.env)`).
_BARE_ENV_ARG_RE = re.compile(
    r"(?:^\(|,|\b(?:body|json|data)\s*[:=])\s*(?:process\.env|os\.environ)\s*[,)}]")
# Child-process launches: the environment handed to them is not sent anywhere.
_JS_CHILD_CALL_RE = re.compile(
    r"(?<![\w$])(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork|execa|execaSync"
    r"|execaCommand|execaCommandSync|execaNode)\s*\(|\bnew\s+Worker\s*\(")
_PY_CHILD_CALL_RE = re.compile(
    r"\bsubprocess\.\w+\s*\(|(?<![\w.])(?:Popen|check_output|check_call|run|call)\s*\("
    r"|\bos\.(?:exec\w*|spawn\w*|system|popen|posix_spawnp?)\s*\("
    r"|\basyncio\.create_subprocess_\w+\s*\(|\bpexpect\.\w+\s*\(")
# `res.status(200).send(…)`: the HTTP response to the caller, not an outbound send.
_RESPONSE_SEND_RE = re.compile(
    r"(?<![\w$.])(?:res|resp|response|reply)\s*\.\s*status\s*\(\s*\d+\s*\)\s*\.\s*send\s*\($")
# A file that can reach the network at all (checked on the raw text: module names are
# string literals).
_JS_OUTBOUND_RE = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"](?:node:)?(?:https?|net|tls|dgram|http2|"""
    r"""ws|axios|node-fetch|got|undici|needle|superagent|socket\.io-client|request)['"]"""
    r"""|(?<![\w.$])fetch\s*\(|\bnew\s+WebSocket\s*\(|\baxios\b|\bsendBeacon\s*\(""")
_PY_OUTBOUND_RE = re.compile(
    r"^\s*(?:import\s+(?:[\w.]+\s*,\s*)*|from\s+)(?:requests|httpx|urllib3?|socket|"
    r"aiohttp|websockets?|websocket|smtplib|ftplib|http\.client|pycurl)\b|\burlopen\s*\(",
    re.MULTILINE)


def _blank_child_calls(code: str, python: bool) -> str:
    rx = _PY_CHILD_CALL_RE if python else _JS_CHILD_CALL_RE
    if not rx.search(code):
        return code
    out = list(code)
    for m in rx.finditer(code):
        a = m.end() - 1
        for k in range(a, _arg_span(code, a)):
            out[k] = " "
    return "".join(out)


def _dump_in(code: str, python: bool) -> bool:
    """The whole environment serialized / copied in ``code`` (outside a child-process
    call's arguments, and not narrowed by a ``.filter``)."""
    rx = _PY_ENV_DUMP_RE if python else _JS_ENV_DUMP_RE
    if not rx.search(code):
        return False
    code = _blank_child_calls(code, python)
    return any(python or not _FILTERED_RE.match(code, m.end()) for m in rx.finditer(code))


def _is_response_send(code: str, end: int) -> bool:
    return _RESPONSE_SEND_RE.search(code[max(0, end - 80):end]) is not None


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


# Python string prefixes: ``f"…"`` is a literal, not a use of a variable ``f`` (the
# lexer keeps the prefix and the quotes as code). ``with open(".env") as f`` then an
# f-string URL in a request read as the .env contents being sent (browser-act, DNC
# sample 2026-10-19).
_STR_PREFIXES = frozenset({"f", "b", "r", "u", "rb", "br", "fr", "rf"})


@functools.lru_cache(maxsize=4096)
def _ref_re(name: str) -> re.Pattern[str]:
    # A use of the name: not an attribute of something else, not a kwarg / object key.
    tail = r"(?![\"'])" if name.lower() in _STR_PREFIXES else ""
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])(?!\s*=(?![=]))"
                      r"(?!\s*:(?!:))" + tail)


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


def _split_args(code: str, a: int, b: int) -> list[tuple[int, str]]:
    """(offset, text) of each top-level argument of the call whose ``(`` is at ``a``
    and whose span ends at ``b`` (string bodies are already blanked in ``code``)."""
    out: list[tuple[int, str]] = []
    depth, start = 0, a + 1
    for i in range(a, max(a, b - 1)):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 1:
            out.append((start, code[start:i]))
            start = i + 1
    tail = code[start:max(start, b - 1)]
    if tail.strip():
        out.append((start, tail))
    return out


# ---------------------------------------------------------------------------
# A key pulled out of a .env, and a signed payload (precision 2026-10-26)
# ---------------------------------------------------------------------------

# Taint kind of one key pulled out of a .env BY NAME: ``"env_key:" + names``. It is
# still a .env credential (reported as "env"), but the only kind the own-vendor
# authentication excuse applies to.
_ENV_KEY = "env_key:"
_KEY_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])" + _NAME + r"(?![A-Za-z0-9_])")
_REGEX_OP_RE = re.compile(
    r"\bre\s*\.\s*(?:search|match|fullmatch|findall)\s*\(|\.(?:match|exec|search)\s*\(")
_CAPTURE_RE = re.compile(
    r"\.group\s*\(\s*[1-9]|\.groups\s*\(\s*\)|\)\s*\??\.?\s*\[\s*[0-9]\s*\]")
# A KEY=VALUE line split on "=" and an element after the name taken (``[1]``,
# ``[-1]``, ``partition("=")[2]``) or unpacked (``k, v = line.split("=")``).
_LINE_SPLIT_RE = re.compile(
    r"""\.(?:r?split|r?partition)\s*\(\s*[rbuf]?['"`]=['"`](?:\s*,\s*[1-9]\d*)?\s*\)"""
    r"""\s*\[\s*(?:-?[1-9]\d*)\s*\]"""
    r"""|^\s*[\w$]+\s*,\s*[\w$]+\s*=\s*[\w$.]+\.(?:r?split|r?partition)\s*\(\s*"""
    r"""[rbuf]?['"`]=['"`]""")


def _base_kind(kind: str) -> str:
    return "env" if kind.startswith(_ENV_KEY) else kind


def _pick(kinds: list[str]) -> str | None:
    """The strictest of several kinds a statement or call carries: a credential's
    contents over one extracted key over a helper's parameter."""
    def rank(k: str) -> int:
        return 2 if k == "param" else 1 if k.startswith(_ENV_KEY) else 0
    return min(kinds, key=rank) if kinds else None


# A signing key OBJECT built from key material: what a known signing call takes.
_KEYOBJ_CTOR_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?[\w$.]+\s*(?::[^=\n]{1,60})?=\s*(?:await\s+)?(?:new\s+)?"
    r"(?:[\w$]+\.)*(?:Keypair\s*\.\s*(?:from_bytes|from_seed|from_base58_string|from_json"
    r"|from_secret_key|fromSecretKey|fromSeed)|Keypair|SigningKey(?:\s*\.\s*from_\w+)?"
    r"|keyPair\s*\.\s*fromSe(?:cretKey|ed)|Ed25519PrivateKey\s*\.\s*from_private_bytes"
    r"|[Aa]ccount\s*\.\s*from_key|Wallet(?:\s*\.\s*from(?:Mnemonic|Phrase))?)\s*\(")
# Known signing calls: the value they return is a signature / signed transaction,
# not the key (solders / solana-py, PyNaCl / tweetnacl, ed25519, ethers, web3).
_SIGN_CALL_RE = re.compile(
    r"(?<![\w$])(?:Versioned)?Transaction\s*\(|\bTransaction\s*\.\s*new_signed_with_payer\s*\("
    r"|\bnacl\s*\.\s*sign(?:\s*\.\s*detached)?\s*\(|\bed25519\s*\.\s*sign\s*\("
    r"|\.\s*(?:sign|partial_sign|partialSign|sign_message|signMessage|sign_transaction"
    r"|signTransaction|sign_all_transactions|signAllTransactions)\s*\(")
# Public-key accessors of a key object: reading one carries nothing secret.
_PUBLIC_ACCESSOR = (r"\s*\.\s*(?:pubkey|public_key|publicKey|verify_key|verifyKey|address"
                    r"|get_address|getAddress)\b")
# A serializing wrapper right before a bare name: ``bytes(kp)`` is the key bytes.
_SERIALIZE_BEFORE_RE = re.compile(
    r"(?:\bbytes|\bbytearray|\bstr|\brepr|\blist|\bdumps|\bstringify|\bb58encode|\bb64encode"
    r"|\bencode|\bfrom|\bString|\bArray|\bhex)\s*\(\s*$")


def _is_keyobj_ctor(code: str) -> bool:
    return _KEYOBJ_CTOR_RE.match(code) is not None


# Signing libraries whose calls may excuse a key passed as an ARGUMENT (reviewer guard,
# PR #232): the call target must resolve to one of these imports, and the class / method
# must not be defined or reassigned in this file (another file of the package is checked
# by the tree pass, ``npm_scripts.restore_signing_relaxed``).
_SIGN_LIBS_PY = r"(?:solders|solana|nacl|ed25519|eth_account|ethers)"
_SIGN_LIBS_JS = (r"(?:@solana/web3\.js|tweetnacl|ed25519|@noble/ed25519"
                 r"|@noble/curves[\w/.-]*|ethers)")
_PY_FROM_IMPORT_RE = re.compile(
    r"^[ \t]*from[ \t]+" + _SIGN_LIBS_PY + r"(?:\.[\w.]+)?[ \t]+import[ \t]+\(?([^)\n#]+)",
    re.M)
_PY_IMPORT_RE = re.compile(
    r"^[ \t]*import[ \t]+(" + _SIGN_LIBS_PY + r"(?:\.[\w.]+)?)(?:[ \t]+as[ \t]+(\w+))?", re.M)
_JS_IMPORT_RE = re.compile(
    r"(?:\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\s*\(\s*['\"]"
    + _SIGN_LIBS_JS + r"['\"]\s*\)"
    r"|\bimport\s+(?:\*\s+as\s+([\w$]+)|(\{[^}]*\})|([\w$]+)(?:\s*,\s*(\{[^}]*\}))?)\s+from\s+"
    r"['\"]" + _SIGN_LIBS_JS + r"['\"])")


def _sign_lib_names(src: str, python: bool) -> set[str]:
    """Local names bound to a known signing library or one of its exports."""
    out: set[str] = set()
    if python:
        for m in _PY_FROM_IMPORT_RE.finditer(src):
            for part in m.group(1).split(","):
                bits = part.split()
                if bits:
                    out.add(bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0])
        for m in _PY_IMPORT_RE.finditer(src):
            out.add(m.group(2) or m.group(1).split(".")[0])
        return {n for n in out if re.fullmatch(r"\w+", n)}
    for m in _JS_IMPORT_RE.finditer(src):
        for g in m.groups():
            if not g:
                continue
            for part in g.strip("{} ").split(","):
                bits = part.replace(":", " as ").split()
                if bits:
                    out.add(bits[-1])
    return {n for n in out if re.fullmatch(r"[\w$]+", n)}


@functools.lru_cache(maxsize=1024)
def _redefine_re(name: str) -> re.Pattern[str]:
    """A definition or reassignment of ``name`` (class, function, method, attribute,
    object-literal member, setattr / defineProperty)."""
    n = re.escape(name)
    return re.compile(
        r"\bclass\s+" + n + r"\b|\bdef\s+" + n + r"\s*\(|\bfunction\s*\*?\s*" + n + r"\s*\("
        r"|(?<![\w$.])" + n + r"\s*(?::[^=\n]{1,60})?=(?![=>])|\.\s*" + n + r"\s*=(?![=>])"
        r"|^\s*(?:static\s+|async\s+)*" + n + r"\s*\([^)\n]*\)\s*\{"
        r"|(?<![\w$.])['\"]?" + n + r"['\"]?\s*:\s*(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>)"
        r"|\bsetattr\s*\([^)]*['\"]" + n + r"['\"]|\bdefineProperty\s*\([^)]*['\"]" + n
        + r"['\"]",
        re.M)


class _SignCtx:
    """What a signing call's target resolves to in one file."""

    def __init__(self, src: str, python: bool) -> None:
        # The library imports themselves (`const nacl = require('tweetnacl')`) are not
        # a redefinition.
        self.src = src
        for rx_imp in ((_PY_FROM_IMPORT_RE, _PY_IMPORT_RE) if python else (_JS_IMPORT_RE,)):
            self.src = rx_imp.sub(lambda m: " " * len(m.group(0)), self.src)
        self.libs = _sign_lib_names(src, python)
        self._redef: dict[str, bool] = {}
        self.relied: set[str] = set()
        # Names assigned from a constructor / factory of a resolved library name
        # (`tx = Transaction().add(ix)`, `const tx = new Transaction({...})`).
        self.objs: set[str] = set()
        rx = re.compile(r"^\s*(?:(?:const|let|var)\s+)?([\w$]+)\s*(?::[^=\n]{1,60})?=(?![=>])"
                        r"\s*(?:await\s+)?(?:new\s+)?([\w$]+(?:\s*\.\s*[\w$]+)*)\s*\(", re.M)
        bad: set[str] = set()
        for m in rx.finditer(self.src):
            chain = [c.strip() for c in m.group(2).split(".")]
            if chain[0] in self.libs and not any(self.redefined(c) for c in chain):
                self.objs.add(m.group(1))
            else:
                bad.add(m.group(1))
        # Every assignment of the name must be such a constructor (`tx = evil` later
        # makes `tx.sign(kp)` unresolved).
        assign = re.compile(r"^\s*(?:(?:const|let|var)\s+)?([\w$]+)\s*(?::[^=\n]{1,60})?"
                            r"=(?![=>])", re.M)
        n_assign: dict[str, int] = {}
        for m in assign.finditer(self.src):
            n_assign[m.group(1)] = n_assign.get(m.group(1), 0) + 1
        n_ctor: dict[str, int] = {}
        for m in rx.finditer(self.src):
            n_ctor[m.group(1)] = n_ctor.get(m.group(1), 0) + 1
        self.objs = {o for o in self.objs - bad if n_assign.get(o) == n_ctor.get(o)}

    def redefined(self, name: str) -> bool:
        if name not in self._redef:
            self._redef[name] = _redefine_re(name).search(self.src) is not None
        return self._redef[name]

    def resolves(self, code: str, sm: re.Match[str]) -> list[str] | None:
        """The library names a signing call at ``sm`` relies on, or None when its
        target is unresolved or defined / reassigned in this file."""
        receiver = sm.group(0).lstrip().startswith(".")
        # `a.b.Transaction(` (chain ends in a dot) / `a.b.sign(` (chain ends in a name).
        head = re.search(r"((?:[\w$]+\s*\.\s*)*[\w$]+)\s*$" if receiver
                         else r"((?:[\w$]+\s*\.\s*)*)$", code[:sm.start()])
        call = re.sub(r"\s+", "", sm.group(0)).rstrip("(").lstrip(".")
        chain = [c for c in re.sub(r"\s+", "", head.group(1) if head else "").split(".") if c]
        if receiver:
            # `<receiver>.sign(` : the receiver is a resolved library object / name.
            if not chain or (chain[0] not in self.libs and chain[0] not in self.objs):
                return None
            # A library object's own name was checked where it was built.
            parts = (chain[1:] if chain[0] in self.objs else chain) + [call]
        else:
            parts = chain + [c for c in call.split(".") if c]
            if parts[0] not in self.libs:
                return None
        if any(self.redefined(p) for p in parts):
            return None
        return parts


def _mask_signing(code: str, keys: set[str], ctx: _SignCtx | None = None,
                  allow_args: bool = True) -> str:
    """``code`` with the harmless uses of key objects ``keys`` blanked (same length):

    * a public-key accessor (``payer.pubkey()``);
    * the key as the RECEIVER of a known signing method (``kp.sign(msg)``,
      ``keypair.sign_message(m)``);
    * the key passed BARE as an argument of a signing call whose target resolves to a
      known library import (``ctx``: solders / solana / @solana/web3.js / tweetnacl /
      ed25519 / ethers / eth_account) and is not defined or reassigned in the file
      (``Transaction([payer], [ix], bh)`` from ``solders.transaction``). A package-
      defined ``class Transaction`` or an ``uploader.sign(kp)`` keeps the key.

    A serializing use stays (``bytes(payer)``, ``payer.secret()``, ``kp.secretKey``,
    ``to_bytes()``, ``to_base58_string()``, ``to_json()``, a mnemonic / seed): such a
    value sent anywhere is the key. The names an argument excuse relied on are added to
    ``ctx.relied``; ``allow_args=False`` turns argument excuses off."""
    out = list(code)

    def blank(i: int, j: int) -> None:
        for k in range(i, j):
            out[k] = " "

    for nm in keys:
        for m in re.finditer(r"(?<![\w$.])" + re.escape(nm) + r"(?=" + _PUBLIC_ACCESSOR + ")",
                             code):
            blank(m.start(), m.end())
    for sm in _SIGN_CALL_RE.finditer(code):
        a = sm.end() - 1
        b = _arg_span(code, a)
        if sm.group(0).lstrip().startswith("."):
            rm = re.search(r"(?<![\w$.])([\w$]+)\s*$", code[:sm.start()])
            if rm and rm.group(1) in keys:
                blank(rm.start(1), rm.end(1))         # the receiver: `kp.sign(msg)`
        parts = ctx.resolves(code, sm) if (ctx is not None and allow_args) else None
        if parts is None:
            continue                                  # unresolved: arguments stay keys
        used = False
        for nm in keys:
            for m in re.finditer(r"(?<![\w$.])" + re.escape(nm) + r"(?![\w$])", code[a:b]):
                i, j = a + m.start(), a + m.end()
                if re.match(r"\s*[.\[]", code[j:b]):
                    continue                          # `kp.secret_key`, `kp[0:32]`
                if _SERIALIZE_BEFORE_RE.search(code[max(0, i - 40):i]):
                    continue                          # `bytes(kp)` inside the call
                blank(i, j)
                used = True
        if used and ctx is not None:
            ctx.relied.update(parts)
    return "".join(out)


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
    def __init__(self, src: str, python: bool, dump: bool = False) -> None:
        self.src = src
        self.python = python
        # Environment-dump mode (``env_dump_exfil_hits``): the source is the whole
        # environment serialized or copied, not a credential file.
        self.dump = dump
        self.lx = _lex(src, python)
        self.stmts = _statements(src, self.lx, python)
        self.read_re = _PY_READ_RE if python else _JS_READ_RE
        self.send_res = [_PY_SEND_RE] if python else [_JS_SEND_RE]
        if not python and _JS_NET_MODULE_RE.search(src):
            self.send_res.append(_JS_STREAM_SEND_RE)
        self.sinks: dict[str, _Sink] = {}
        self.sink_params: dict[str, tuple[list[str], dict[str, list[tuple[list[str], bool]]]]] = {}
        self.sources: dict[str, str] = {}
        # Function headers: index -> offset (in the statement) where the header ends,
        # so a method NAMED `fetch` / `post` is not read as a call of one.
        self.header_end: dict[int, int] = {}
        self.lit_kinds = ([None] * len(self.stmts) if dump
                          else [self._lit_kind(st) for st in self.stmts])
        self.dump_kinds = [(_ENV_DUMP if dump and _dump_in(st.code, python) else None)
                           for st in self.stmts]
        # The bare mapping as a send's argument: checked in the call, never carried.
        self.bare_env = [dump and bool(_BARE_ENV_ARG_RE.search(st.code)) for st in self.stmts]
        # Signing calls: what their targets resolve to; argument excuses on / off.
        self.sign_ctx = _SignCtx(src, python)
        self.allow_sign_args = True
        # Own-vendor key uses excused (``_excused``): (offset, vendor) for disclosure.
        self.vendor_uses: list[tuple[int, str]] = []

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
            # Pieces glued with ``+`` (``"/.s" + "sh/id_" + "rsa"``) hide the path from
            # a per-literal match and from a path-separator join alike.
            return credential_kind(joined) or credential_kind("".join(parts))
        return None

    def _hosts(self, st: _Stmt, a: int, b: int) -> list[str]:
        out = []
        for s, _e, v in st.lits:
            if a <= s < b:
                m = _URL_HOST_RE.match(v.strip())
                if m:
                    out.append(m.group(1))
        return out

    def _auth_only(self, a: int, b: int, refs: list[int], loose: bool = False) -> bool:
        """Every use of the value at [refs] sits under an auth / headers key."""
        if not refs:
            return False
        for r in refs:
            before = self.src[a:r]
            keys = re.findall(r"""['"]?([\w-]+)['"]?\s*(?:=(?!=)|:)""", before)
            if keys and keys[-1].lower() in _AUTH_KEYS:
                continue
            if loose and self._in_headers(before):
                continue
            return False
        return True

    @staticmethod
    def _in_headers(before: str) -> bool:
        """The text up to a value ends inside a ``headers`` object literal still open
        there (``headers={"X-API-KEY": <value>``): a request header of any name."""
        m = None
        for m in re.finditer(r"""['"]?\bheaders['"]?\s*(?:=(?!=)|:)\s*\{""", before, re.I):
            pass
        if m is None:
            return False
        tail = before[m.end():]
        return tail.count("{") - tail.count("}") >= 0 and not re.search(r"[)\]]", re.sub(
            r"\([^()]*\)|\[[^\[\]]*\]", "", tail))

    # -- a key pulled out of a .env by name (#195, 2026-10-26) --------------
    def _key_extraction(self, st: _Stmt, code: str, env_refs: list[str],
                        line_vars: set[str], value_read: bool) -> set[str]:
        """The key NAMES this statement pulls out of a .env's contents, or an empty set
        when it carries the contents (or a part of them that is not one named key).

        * ``values["X_KEY"]`` / ``values.get("X_KEY")``;
        * a regex capture for the name (``re.search(r"X_KEY=(.*)", env).group(1)``,
          ``env.match(/X_KEY=(.*)/)[1]``) in the one statement;
        * a LINE of the file (``for line in f``) split on ``=`` (``line.split("=",
          1)[1]``, ``k, v = line.split("=")``) under a guard that names the key
          (``if line.startswith("X_KEY=")`` / ``if "X_KEY" in line``) on this or the
          three lines above.

        The statement must touch exactly one tainted name (or read the file inline), so
        ``m.group(1) + whole_env`` is not an extraction."""
        raw = self.src[st.start:st.end]
        n_refs = sum(len(_ref_re(nm).findall(code)) for nm in env_refs)
        if not (n_refs == 1 or (n_refs == 0 and value_read)):
            return set()
        # Key names inside strings / regexes of the statement (blanked in ``code``).
        names = {m.group(1) for m in _KEY_NAME_RE.finditer(raw)
                 if not code[m.start():m.end()].strip()}
        if names:
            alt = "|".join(re.escape(n) for n in names)
            if re.search(r"""\[\s*['"](?:""" + alt + r""")['"]\s*\]"""
                         r"""|\.get\s*\(\s*['"](?:""" + alt + r""")['"]""", raw):
                return names
            if _REGEX_OP_RE.search(code) and _CAPTURE_RE.search(code):
                return names
        line_ref = [nm for nm in env_refs if nm in line_vars and _ref_re(nm).search(code)]
        if len(line_ref) != 1 or not _LINE_SPLIT_RE.search(raw):
            return set()
        lv = re.escape(line_ref[0])
        before = self.src[:st.start].splitlines()[-3:]
        guarded: set[str] = set()
        for ln in [*before, raw]:
            if re.search(r"(?<![\w$.])" + lv + r"(?![\w$])", ln) and re.search(
                    r"\bif\b|startswith|startsWith|includes|\bin\b", ln):
                guarded |= {m.group(1) for m in _KEY_NAME_RE.finditer(ln)
                            if ln[max(0, m.start() - 1):m.start()] in ("'", '"', "`", "^")}
        return guarded

    # -- the flow -----------------------------------------------------------
    def run(self, idxs: list[int], init: dict[str, tuple[str, tuple[int, ...]]] | None = None,
            ) -> tuple[list[_Hit], list[tuple[list[str], bool]], str | None]:
        """Follow credential values through ``idxs``. Returns (hits, param-sink hits for
        a 'param' kind as (hosts, auth_only), the kind a ``return`` carries)."""
        taint: dict[str, tuple[str, tuple[int, ...]]] = dict(init or {})
        pathvars: dict[str, tuple[str, tuple[int, ...]]] = {}
        # Names bound to a signing key OBJECT built from a credential (``Keypair.
        # from_bytes(...)``), and names bound to one line of a .env's contents.
        keyobjs: dict[str, tuple[str, tuple[int, ...]]] = {}
        line_vars: dict[str, tuple[str, tuple[int, ...]]] = {}
        hits: list[_Hit] = []
        param_hits: list[tuple[list[str], bool]] = []
        returns: str | None = None

        def visible(table: dict[str, tuple[str, tuple[int, ...]]], scope: tuple[int, ...]
                    ) -> dict[str, str]:
            return {nm: k for nm, (k, sc) in table.items() if scope[:len(sc)] == sc}

        for idx in idxs:
            st = self.stmts[idx]
            vis_t = visible(taint, st.scope)
            # A signed payload is not the key (2026-10-26): a key object passed bare to
            # a known signing call, or read only for its public key, carries nothing.
            vis_k = set(visible(keyobjs, st.scope)) & set(vis_t)
            code = (_mask_signing(st.code, vis_k, self.sign_ctx, self.allow_sign_args)
                    if vis_k else st.code)
            vis_p = visible(pathvars, st.scope)
            lit_kind = self.lit_kinds[idx]
            path_kind = lit_kind or next(
                (k for nm, k in vis_p.items() if _ref_re(nm).search(code)), None)
            has_read = bool(self.read_re.search(code))
            src_kind = next((k for nm, k in self.sources.items()
                             if _call_re(nm).search(code)), None)
            # A value handed to a child process (`spawn(cmd, {env: {...process.env}})`,
            # `subprocess.run(cmd, env=env)`) is not carried by what the call returns.
            ref_code = _blank_child_calls(code, self.python) if self.dump else code
            ref_kind = _pick([k for nm, k in vis_t.items() if _ref_re(nm).search(ref_code)])
            value_kind = ((path_kind if (path_kind and has_read) else None) or src_kind
                          or self.dump_kinds[idx])
            carried = _pick([k for k in (value_kind, ref_kind) if k])
            if carried == "env":
                env_refs = [nm for nm, k in vis_t.items() if k == "env"]
                keys = self._key_extraction(
                    st, code, env_refs, set(visible(line_vars, st.scope)),
                    bool(path_kind == "env" and has_read))
                if keys:
                    carried = _ENV_KEY + ",".join(sorted(keys))

            # `tx.sign(kp)` with a signer that did not resolve to a library (the key
            # was not masked above): the receiver now holds what it was given.
            for sm in _SIGN_CALL_RE.finditer(code):
                if not sm.group(0).lstrip().startswith("."):
                    continue
                rm = re.search(r"(?<![\w$.])([\w$]+)\s*$", code[:sm.start()])
                a0 = sm.end() - 1
                arg_kinds = [k for nm, k in vis_t.items()
                             if _ref_re(nm).search(code[a0:_arg_span(code, a0)])]
                if rm and arg_kinds:
                    taint[rm.group(1)] = (_pick(arg_kinds), st.scope)

            targets = self._targets(code)
            if carried:
                for nm in targets:
                    taint[nm] = (carried, st.scope)
                if _is_keyobj_ctor(code):
                    for nm in targets:
                        keyobjs[nm] = (carried, st.scope)
                else:
                    for nm in targets:
                        keyobjs.pop(nm, None)
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
                    if vis_t[it] == "env":
                        line_vars[m.group(1)] = ("env", st.scope)
                elif path_kind and not value_kind:
                    # `for p in glob.glob(expanduser('~/.ssh/*')):`
                    pathvars[m.group(1)] = (path_kind, st.scope)
            vis_t = visible(taint, st.scope)

            if carried and _RETURN_RE.search(code):
                returns = returns or carried

            if not (vis_t or vis_p or lit_kind or self.sources or self.dump_kinds[idx]
                    or self.bare_env[idx]):
                continue                           # nothing here can carry a credential
            skip_to = self.header_end.get(idx, 0)
            for send_re in self.send_res:
                for m in send_re.finditer(code, skip_to):
                    if self.dump and _is_response_send(code, m.end()):
                        continue                   # an HTTP response to the caller
                    a = m.end() - 1
                    b = _arg_span(code, a)
                    self._check_call(st, a, b, vis_t, vis_p, hits, param_hits, code=code)
            for nm, _sink in self.sinks.items():
                for m in _call_re(nm).finditer(code, skip_to):
                    a = m.end() - 1
                    b = _arg_span(code, a)
                    self._check_call(st, a, b, vis_t, vis_p, hits, param_hits, sink=nm,
                                     code=code)
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
                    param_hits: list[tuple[list[str], bool]], sink: str | None = None,
                    code: str | None = None) -> None:
        code = st.code if code is None else code
        span = code[a:b]
        kind: str | None = None
        # Every tainted reference in the call, by kind: the strictest kind decides, and
        # "only as authentication" must hold for all of them (a key in the headers
        # does not excuse a file's contents in the body).
        refs_by_kind: dict[str, list[int]] = {}
        # An inline read of a credential path inside the call's arguments.
        if self.read_re.search(span):
            kind = self._lit_kind(st, st.start + a, st.start + b) or next(
                (k for nm, k in vis_p.items() if _ref_re(nm).search(span)), None)
        if not kind and self.dump and (_dump_in(span, self.python)
                                       or _BARE_ENV_ARG_RE.search(span)):
            kind = _ENV_DUMP
        if not kind:
            for nm, k in self.sources.items():
                if _call_re(nm).search(span):
                    kind = k
                    break
        if not kind:
            for nm, k in vis_t.items():
                found = [st.start + a + mm.start() for mm in _ref_re(nm).finditer(span)]
                if found:
                    refs_by_kind.setdefault(k, []).extend(found)
            if "param" in refs_by_kind:
                # Inside a helper being summarized: its parameter reaches this send.
                prefs = refs_by_kind.pop("param")
                abs_a, abs_b = st.start + a, st.start + b
                if sink is not None:
                    param_hits.extend(self.sinks[sink].hits)
                else:
                    param_hits.append((self._hosts(st, abs_a, abs_b),
                                       self._auth_only(abs_a, abs_b, prefs)
                                       and not self.read_re.search(span)))
            kind = _pick(list(refs_by_kind))
        if not kind:
            return
        refs = [r for rs in refs_by_kind.values() for r in rs]
        abs_a, abs_b = st.start + a, st.start + b
        if sink is not None:
            # A call into a function that sends its parameter.
            reached = self._sink_hits(sink, st, a, b, code, vis_t, kind)
            if any(not self._excused(kind, hosts, auth) for hosts, auth in reached):
                hits.append(_Hit(abs_a, kind))
            else:
                for hosts, auth in reached:
                    if hosts:
                        self._excused(kind, hosts, auth, abs_a)   # disclosure note
                        break
            return
        hosts = self._hosts(st, abs_a, abs_b)
        # A read inside the call itself sends the file's contents, never one key. An
        # extracted key may ride a request header of any name (X-API-KEY) to its vendor.
        auth = self._auth_only(abs_a, abs_b, refs, loose=kind.startswith(_ENV_KEY)) \
            and not self.read_re.search(span)
        if not self._excused(kind, hosts, auth, abs_a):
            hits.append(_Hit(abs_a, kind))

    def _sink_hits(self, sink: str, st: _Stmt, a: int, b: int, code: str,
                   vis_t: dict[str, str], kind: str) -> list[tuple[list[str], bool]]:
        """(hosts, auth_only) of the sends a call into helper ``sink`` reaches with the
        tainted value. Per parameter when every tainted argument maps to one (positional
        or ``name=``): only that parameter's sends count, with the call's own URL
        literals added to their hosts (``post(body, "https://api.vendor.com/x",
        headers={...})``). Otherwise every send the helper makes, as before."""
        params, per = self.sink_params.get(sink, ([], {}))
        hosts_here = self._hosts(st, st.start + a, st.start + b)
        names = [nm for nm, k in vis_t.items() if k != "param"]
        chosen: list[str] = []
        pos = 0
        for off, arg in _split_args(code, a, b):
            kw = re.match(r"\s*([A-Za-z_]\w*)\s*=(?!=)", arg) if self.python else None
            carries = (any(_ref_re(nm).search(arg) for nm in names)
                       or any(_call_re(s).search(arg) for s in self.sources)
                       or bool(self.read_re.search(arg)))
            if kw:
                p = kw.group(1)
            else:
                p = params[pos] if pos < len(params) else None
                pos += 1
            if not carries:
                continue
            if p is None or p not in per or arg.lstrip().startswith("*"):
                return list(self.sinks[sink].hits)
            chosen.append(p)
        if not chosen:
            return list(self.sinks[sink].hits)
        return [([*hs, *hosts_here], auth) for p in chosen for hs, auth in per[p]]

    def _excused(self, kind: str, hosts: list[str], auth_only: bool,
                 pos: int | None = None) -> bool:
        if kind == _ENV_DUMP:
            # The whole environment is never authentication; only a loopback
            # destination (a local daemon the tool talks to) is not a network sink.
            return bool(hosts) and all(is_local_host(h) for h in hosts)
        if hosts:
            if all(_official(_base_kind(kind), h) for h in hosts):
                return True
            # A key pulled out of a .env BY NAME and used as the Authorization of a
            # request to that key's own vendor (OPENROUTER_API_KEY -> openrouter.ai,
            # VJ_API_KEY -> video-jungle.com) is the tool authenticating (DNC sample
            # 2026-10-19; precision 2026-10-26). Only an extracted key counts
            # (``_key_extraction``), matched to the vendor of a key it was extracted
            # BY NAME on the reviewed vendor list or by the own-name rule
            # (``host_is_own_vendor``), never by subdomain or homepage. The whole
            # contents, a line of it, or an unrelated name keep the finding.
            if not kind.startswith(_ENV_KEY) or not auth_only:
                return False
            keys = [k for k in kind[len(_ENV_KEY):].split(",") if k]
            ok = bool(keys) and all(
                any(host_is_own_vendor(h, k) for k in keys) for h in hosts)
            if ok and pos is not None:
                # Disclosed, not silent: the caller adds a capability note.
                k = next(k for k in keys if any(host_is_own_vendor(h, k) for h in hosts))
                vendor = VENDOR_KEYS[k][0] if k in VENDOR_KEYS else registrable_domain(hosts[0])
                self.vendor_uses.append((pos, vendor))
            return ok
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
                    # Which parameter reaches which send (``_sink_hits``). Without the
                    # helper itself as a sink: `requests.post(` inside `def post(...)`
                    # is not a call of the helper.
                    own = self.sinks.pop(name)
                    self.sink_params[name] = (params, {
                        p: self.run(idxs, {p: ("param", st.scope)})[1] for p in params})
                    self.sinks[name] = own
            if name not in self.sources and (
                    any(self.lit_kinds[j] or self.dump_kinds[j] for j in idxs)
                    or any(_call_re(s).search(self.stmts[j].code)
                           for s in self.sources for j in idxs)):
                _h, _ph, ret = self.run(idxs)
                if ret and ret != "param":
                    self.sources[name] = ret


# Cheap pre-check: some credential path word in the file.
_CREDENTIAL_HINT_RE = re.compile(
    r"\.ssh|id_(?:rsa|dsa|ecdsa|ed25519)|\.aws|gcloud|\.kube|netrc|"
    r"git-credentials|\.npmrc|\.pypirc|\.docker|Login Data|Cookies|"
    r"cookies\.sqlite|logins\.json|key[34]\.db|wallet|\.bitcoin|"
    r"\.litecoin|\.dogecoin|\.dash\b|\.ethereum|keystore|[Ee]lectrum|"
    r"solana|exodus|nkbihfbeogaeaoehlefnkodbefgpgknn|\.env\b")
# A path split into pieces (``"/.s" + "sh/id_" + "rsa"``) carries no credential word,
# so the pre-check also passes a file that joins string literals with ``+`` and names
# the home directory.
_HOME_HINT_RE = re.compile(r"expanduser|homedir|Path\.home|USERPROFILE|['\"]~['\"/]|\bHOME\b")
_LIT_CONCAT_HINT_RE = re.compile(r"""['"`]\s*\+\s*['"`]""")


def credential_exfil_hits(content: str, lang: str | None, *, lf=None,
                          relaxed: list | None = None,
                          vendor_uses: list | None = None) -> list[tuple[int, str]]:
    """``(line_number, credential_kind)`` for each send that carries a credential file's
    contents in ``content`` (``lang``: python / javascript / typescript). ``lf``: the
    caller's ``prefilter.LineFilter`` over ``content``, for a faster pre-check (same
    answer).

    ``relaxed`` (optional out-list) receives ``(line, kind, names)`` for each send that
    is clean only because a key went bare into a library signing call (``names``: the
    library class / method names that excuse relied on). The caller reports those low
    and the tree pass restores them when another file of the package defines or
    reassigns one of ``names``. ``vendor_uses`` (optional out-list) receives ``(line,
    vendor)`` for each extracted .env key excused as its own vendor's authentication,
    for a disclosure note."""
    if lang not in ("python", "javascript", "typescript"):
        return []
    python = lang == "python"
    hint = (lf.search(_CREDENTIAL_HINT_RE) if lf is not None
            else _CREDENTIAL_HINT_RE.search(content))
    if not hint:
        hint = ((lf.search(_LIT_CONCAT_HINT_RE) if lf is not None
                 else _LIT_CONCAT_HINT_RE.search(content))
                and _HOME_HINT_RE.search(content))
    if not hint:
        return []

    def analyze(allow_args: bool) -> tuple[_Analyzer, list[tuple[int, str]]] | None:
        an = _Analyzer(content, python)
        an.allow_sign_args = allow_args
        if not any(an.lit_kinds):
            return None                            # no credential path in any statement
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
                out.append((line, _base_kind(h.kind)))
        return an, out

    first = analyze(True)
    if first is None:
        return []
    an, out = first
    if vendor_uses is not None:
        seen_v: set[int] = set()
        for pos, vendor in an.vendor_uses:
            line = content.count("\n", 0, pos) + 1
            if line not in seen_v:
                seen_v.add(line)
                vendor_uses.append((line, vendor))
    if relaxed is not None and an.sign_ctx.relied:
        strict = analyze(False)
        have = {ln for ln, _k in out}
        names = sorted(an.sign_ctx.relied)
        for line, kind in (strict[1] if strict else []):
            if line not in have:
                relaxed.append((line, kind, names))
    return out


def env_dump_exfil_hits(content: str, lang: str | None, *, lf=None) -> list[int]:
    """Line numbers of sends that carry the whole environment (``JSON.stringify(
    process.env)``, ``{...process.env}``, ``Object.entries(process.env)``,
    ``dict(os.environ)``, ``os.environ.copy()``, ``json.dumps(dict(os.environ))``) in
    ``content`` (python / javascript / typescript), followed through the same flow as a
    credential file's contents. A copy handed to a child process
    (``spawn(cmd, {env: {...process.env}})``) is not a send; nor is a send to a
    loopback host or an HTTP response (``res.status(200).send(…)``)."""
    if lang not in ("python", "javascript", "typescript"):
        return []
    python = lang == "python"
    hint_re = _PY_ENV_DUMP_RE if python else _JS_ENV_DUMP_RE
    bare = re.compile(r"process\.env|os\.environ")
    if not (lf.search(bare) if lf is not None else bare.search(content)):
        return []
    if not (_PY_OUTBOUND_RE if python else _JS_OUTBOUND_RE).search(content):
        return []
    if not hint_re.search(content) and not _BARE_ENV_ARG_RE.search(content):
        return []
    an = _Analyzer(content, python, dump=True)
    if not any(an.dump_kinds) and not any(an.bare_env):
        return []
    fns = an.functions()
    an.summarize(fns)
    an.summarize(fns)
    hits, _ph, _r = an.run(list(range(len(an.stmts))))
    return sorted({content.count("\n", 0, h.pos) + 1 for h in hits})
