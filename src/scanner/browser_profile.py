"""Browser automation that drives the user's real browser profile (bundled skill scripts).

A script that launches Playwright (``launch_persistent_context``), Puppeteer
(``userDataDir``) or Selenium (``--user-data-dir``) with the user's own Chrome / Chromium
/ Edge / Brave / Firefox profile directory runs a browser that is logged in to every
site the user is. That is a strong capability (a high finding), but on its own it is not
a credential read: the script never opens the cookie or password store, the browser
does.

* ``profile_launch_line`` finds the shape (a launch plus a real profile path).
* ``launch_only`` decides whether a file's real-profile paths are used ONLY as that
  launch argument, with nothing else in the skill reading files inside the profile,
  reading the context's cookies / storage state, or sending page content anywhere: not
  over the network, and not through the browser itself (a value read from the page
  filled / typed / uploaded / assigned into a page on another origin). Only then does
  ``skill_scan`` drop its critical credential-read finding for the file.

Everything here is conservative: a use the analysis cannot place (the path handed to a
helper, copied, joined to a file name, opened, archived) keeps the critical.

Pure text analysis over comment-stripped code; never executes anything.
"""
from __future__ import annotations

import re

from src.scanner.browser_credentials import (
    _AUTOMATION_RE,
    _CONTEXT_SESSION_READ_RE,
    _INTERP_RE,
    _PAGE_DUMP_SOURCE_RE,
    _STORE_KEY_RE,
    _STORE_SCHEMA_RE,
    _call_span,
    _strip_strings,
)

PROFILE_LAUNCH_NAME = (
    "Bundled script {path} drives your real browser profile (all logged-in sessions); "
    "the skill's instructions can have your agent act as you in those sites")
PROFILE_LAUNCH_REMEDIATION = (
    "The script starts a browser (Playwright / Puppeteer / Selenium) with your own "
    "browser profile, so it runs logged in to every site you are: mail, chat, banking. "
    "Anything that controls the script can act as you on those sites. This check reads "
    "the bundled scripts only: the skill's instructions (SKILL.md) can still direct "
    "your agent to use this browser as you. Prefer a dedicated automation profile."
)

_LANG_EXT = (".py", ".js", ".ts", ".mjs", ".cjs")

# A real browser profile directory: macOS, Linux and Windows layouts.
PROFILE_PATH_RE = re.compile(
    r"Application Support[/\\]+(?:Google[/\\]+Chrome|Chromium|BraveSoftware|Microsoft Edge"
    r"|Firefox)"
    r"|\.config[/\\]+(?:google-chrome|chromium|BraveSoftware|microsoft-edge)"
    r"|\.mozilla[/\\]+firefox"
    r"|(?:Google[/\\]+Chrome|Chromium|BraveSoftware[/\\]+Brave-Browser|Microsoft[/\\]+Edge)"
    r"[/\\]+User Data"
    r"|Mozilla[/\\]+Firefox[/\\]+Profiles"
    r"""|['"]Google['"]\s*[,/]\s*['"]Chrome['"]"""
    r"""|['"]\.config['"]\s*[,/]\s*['"](?:google-chrome|chromium)['"]"""
)
# A launch that takes a profile directory.
_LAUNCH_RE = re.compile(
    r"launch_persistent_context|launchPersistentContext|\buser_data_dir\b|\buserDataDir\b"
    r"|user-data-dir")
# The profile-directory slot of a launch (the path follows it).
_SLOT_KEY_RE = re.compile(
    r"""\buser_data_dir['"]?\s*[=:]\s*|\buserDataDir['"]?\s*:\s*|user-data-dir="""
    r"""|launch_?[pP]ersistent_?[cC]ontext\s*\(\s*""")
_SELENIUM_RE = re.compile(
    r"^\s*(?:import|from)\b[^\n]*\b(?:selenium|undetected_chromedriver|seleniumbase|nodriver)\b"
    r"""|\brequire\s*\(\s*['"]selenium-webdriver""", re.MULTILINE)

# Files inside a profile: the cookie / password / key stores and the history databases.
_PROFILE_FILE_RE = re.compile(
    r"""['"/\\](?:Cookies|Login Data(?: For Account)?|Local State|Web Data|History"""
    r"""|Network[/\\]+Cookies|key[34]\.db|logins\.json|cookies\.sqlite|signons\.sqlite"""
    r"""|places\.sqlite|formhistory\.sqlite|Cookies\.binarycookies)['"]"""
    r"|\bLogin Data\b|\bLocal State\b|\bkey[34]\.db\b|\blogins\.json\b|\bcookies\.sqlite\b"
    r"|Cookies\.binarycookies"
)
# Session data read from the driven browser (or a page): cookies, storage state, web
# storage. Anywhere in the skill, it ends the relaxation (it may be saved, then sent).
_SESSION_READ_RE = re.compile(
    _CONTEXT_SESSION_READ_RE.pattern + "|" + _PAGE_DUMP_SOURCE_RE.pattern
    + r"|\b(?:localStorage|sessionStorage)\b|\bdocument\.cookie\b"
    r"|\bstorage_?[sS]tate\b|\bget_cookies\b|\bgetCookies\b")
# Operations that must never touch a profile path.
_FORBIDDEN_RE = re.compile(
    r"(?i)\bcopy|\bcp\b|sqlite|\bopen\s*\(|read_?(?:text|bytes|file)|readFile|\bwalk\b"
    r"|listdir|scandir|readdir|\bglob|archive|\b(?:g?zip|tar)(?:file)?\b|upload|\bsend|\bpost\b"
    r"|\bmove\b|rename|\brsync\b")

# Page content read from the driven browser.
_PAGE_READ_RE = re.compile(
    r"\.(?:inner_text|innerText|text_content|textContent|inner_html|innerHTML|content"
    r"|evaluate|evaluate_handle|eval_on_selector(?:_all)?|\$eval|\$\$eval|screenshot|pdf"
    r"|title|get_attribute|getAttribute|input_value|inputValue|all_inner_texts"
    r"|allInnerTexts|all_text_contents|allTextContents|find_elements?|query_selector(?:_all)?"
    r"|querySelector(?:All)?|locator|wait_for_selector|waitForSelector|execute_script"
    r"|executeScript|get_by_\w+|getBy\w+)\s*\("
    r"|\.page_source\b")
# Network sinks (navigation counts only when it carries page data).
_SINK_RE = re.compile(
    r"\b(?:requests|httpx|session|client|aiohttp|urllib3|http)\.(?:get|post|put|patch|delete"
    r"|request|head|stream)\s*\(|\burlopen\s*\(|\burllib\.request\.Request\s*\("
    r"|(?<![\w.$])fetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bgot(?:\.\w+)?\s*\(|\bsuperagent\b"
    r"|\bnavigator\.sendBeacon\s*\(|\bXMLHttpRequest\b|\bsocket\.\w+|\.sendall?\s*\("
    r"|\bsmtplib\b|\.send_?message\s*\(|\bsendmail\s*\(|\bcurl\b|\bwget\b|\bWebSocket\b"
    r"|\bwebhook\b|\.goto\s*\(|\.navigate\s*\(|\bdriver\.get\s*\(|\.new_page\s*\(\s*\w")
# Page data named inside a page script (a send from the page itself).
_PAGE_SIDE_RE = re.compile(
    r"\b(?:innerText|textContent|innerHTML|outerHTML)\b"
    r"|\bdocument\.(?:body|documentElement|querySelector\w*|getElement\w*|title)\b")
_FILE_SEND_RE = re.compile(
    r"\bopen\s*\(|read_(?:text|bytes)\s*\(|readFileSync|createReadStream|\bfiles\s*=|"
    r"\bfile\s*:|FormData|\bdata\s*=\s*open")

_IDENT = r"[A-Za-z_$][\w$]*"
_ASSIGN_RE = re.compile(
    rf"^\s*(?:export\s+)?(?:(?:const|let|var|final)\s+)?(?P<lhs>{_IDENT}(?:\s*,\s*{_IDENT})*)"
    r"\s*(?::\s*[\w\[\]<>|, .]+)?\s*(?P<op>[+]?=)(?!=)\s*(?P<rhs>.*)$")
_DEF_RE = re.compile(
    rf"^\s*(?:async\s+)?def\s+(?P<a>{_IDENT})\s*\("
    rf"|^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<b>{_IDENT})\s*\("
    rf"|^\s*(?:export\s+)?(?:const|let|var)\s+(?P<c>{_IDENT})\s*=\s*(?:async\s*)?"
    rf"(?:\([^)]*\)|{_IDENT})\s*=>")
_RETURN_RE = re.compile(r"^\s*(?:return|yield)\b")
_FOR_RE = re.compile(
    r"^\s*(?:async\s+)?for\s*\(?\s*(?:const|let|var)?\s*(?P<v>[\w$,\s()\[\]]+?)\s+(?:in|of)\s+"
    r"(?P<src>.+)$")
_MUTATE_RE = re.compile(rf"^\s*(?P<n>{_IDENT})\s*(?:\.(?:append|extend|push|insert|add|update)"
                        r"\s*\(|\[[^\]]*\]\s*=(?!=))")
_IMPORT_RE = re.compile(r"^\s*(?:from\s+\S+\s+)?import\b|\brequire\s*\(")
_LOG_RE = re.compile(
    r"^\s*(?:print|logger\.\w+|logging\.\w+|log\.\w+|console\.\w+|sys\.std(?:err|out)\.write"
    r"|click\.echo|warnings\.warn|tqdm\.write)\s*\(")
# Calls an assignment may wrap a profile path in and stay a path.
_PATH_CALLS = frozenset({
    "str", "Path", "PurePath", "join", "expanduser", "expandvars", "abspath", "realpath",
    "resolve", "normpath", "home", "homedir", "get", "getenv", "environ", "fspath",
    "String", "os", "path", "cwd", "joinpath",
})
_CALL_NAME_RE = re.compile(rf"({_IDENT})\s*\(")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _uses(stripped: str, name: str) -> list[re.Match[str]]:
    """Uses of ``name`` as a value (not an attribute, a keyword-argument name or an
    object key) in a line already reduced by ``_strip_strings``."""
    out = []
    for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", stripped):
        rest = stripped[m.end():]
        if re.match(r"\s*=(?!=)", rest) and re.search(r"[(,]\s*$", stripped[:m.start()]):
            continue                          # f(name=...) keyword name
        if re.match(r"\s*:(?!:)", rest) and re.search(r"[{,]\s*$", stripped[:m.start()]):
            continue                          # {name: ...} object key
        out.append(m)
    return out


def _slot_count(raw: str, name: str) -> int:
    """How many of ``name``'s uses on ``raw`` are the profile-directory argument of a
    browser launch (or an existence check, or a ``return`` of the bare name)."""
    e = re.escape(name)
    tail = r"\b(?!\s*(?:[./\[]|\())"            # not `name / "Cookies"`, `name.x`, `name(`
    pats = [
        rf"\buser_data_dir\s*=\s*(?:str\(\s*)?{e}{tail}",
        rf"""['"]?\b(?:user_data_dir|userDataDir)['"]?\s*:\s*(?:String\(\s*)?{e}{tail}""",
        rf"launch_?[pP]ersistent_?[cC]ontext\s*\(\s*(?:str\(\s*)?{e}{tail}",
        rf"""user-data-dir=[^'"`\n]*\$?\{{\s*{e}\s*\}}""",
        rf"""user-data-dir=['"`]\s*\+\s*(?:str\(\s*)?{e}{tail}""",
        rf"\bos\.path\.(?:exists|isdir)\s*\(\s*{e}\s*\)",
        rf"\bfs\.existsSync\s*\(\s*{e}\s*\)",
        rf"\bPath\s*\(\s*{e}\s*\)\s*\.\s*(?:exists|is_dir)\s*\(\s*\)",
        rf"(?<![\w$.]){e}\s*\.\s*(?:exists|is_dir)\s*\(\s*\)",
    ]
    return sum(len(re.findall(p, raw)) for p in pats)


def _enclosing_def(lines: list[str], i: int) -> str | None:
    ind = _indent(lines[i])
    for j in range(i - 1, -1, -1):
        ln = lines[j]
        if not ln.strip() or _indent(ln) >= ind:
            continue
        m = _DEF_RE.match(ln)
        if m:
            return m.group("a") or m.group("b") or m.group("c")
        ind = _indent(ln)
        if ind == 0:
            return None
    return None


def _statement_head(lines: list[str], i: int) -> int | None:
    """For an element line of a multi-line literal, the line that opens it."""
    ind = _indent(lines[i])
    for j in range(i - 1, max(-1, i - 40), -1):
        ln = lines[j]
        if not ln.strip() or _indent(ln) >= ind:
            continue
        return j if re.search(r"[\[{(]\s*$", ln.rstrip()) else None
    return None


def _pure_rhs(rhs: str, tracked: set[str]) -> bool:
    """The right-hand side only builds a path: every call in it is a path helper or a
    tracked function, and nothing forbidden happens on it."""
    if _FORBIDDEN_RE.search(rhs):
        return False
    return all(m.group(1) in _PATH_CALLS or m.group(1) in tracked
               for m in _CALL_NAME_RE.finditer(_strip_strings(rhs)))


def _lhs_names(m: re.Match[str]) -> list[str]:
    return [n.strip() for n in m.group("lhs").split(",") if n.strip()]


def _track(lines: list[str], seeds: set[str]) -> set[str] | None:
    """Follow ``seeds`` (names holding a profile path, or functions returning one)
    through ``lines``. Returns every name the path reaches, or ``None`` when a use is
    anything but a launch argument, an existence check, a log line, a pure path
    assignment or a ``return``."""
    tracked = set(seeds)
    for _round in range(8):
        grew = False
        for i, raw in enumerate(lines):
            if not raw.strip() or _IMPORT_RE.match(raw):
                continue
            d = _DEF_RE.match(raw)
            if d and (d.group("a") or d.group("b") or d.group("c")) in tracked \
                    and "=>" not in raw:
                continue
            stripped = _strip_strings(raw)
            n_uses = sum(len(_uses(stripped, t)) for t in tracked)
            if not n_uses:
                continue
            if _FORBIDDEN_RE.search(stripped):
                return None
            if _LOG_RE.match(raw):
                continue
            free = n_uses - sum(_slot_count(raw, t) for t in tracked)
            if free <= 0:
                continue
            a = _ASSIGN_RE.match(raw)
            if a and a.group("op") == "=" and not _LOG_RE.match(a.group("rhs")):
                if not _pure_rhs(a.group("rhs"), tracked):
                    return None
                for n in _lhs_names(a):
                    if n not in tracked:
                        tracked.add(n)
                        grew = True
                continue
            if _RETURN_RE.match(raw):
                if not _pure_rhs(re.sub(r"^\s*(?:return|yield)\b", "", raw), tracked):
                    return None
                fn = _enclosing_def(lines, i)
                if fn is None:
                    return None
                if fn not in tracked:
                    tracked.add(fn)
                    grew = True
                continue
            return None
        if not grew:
            return tracked
    return tracked


def _seed(lines: list[str], i: int) -> str | None | bool:
    """What holds the real-profile path written on line ``i``: a name (assignment), a
    function (return), ``True`` when the line IS the launch argument, ``None`` when the
    path is used some other way."""
    raw = lines[i]
    if _FORBIDDEN_RE.search(_strip_strings(raw)) or _FORBIDDEN_RE.search(
            PROFILE_PATH_RE.sub("", raw)):
        return None
    if _LAUNCH_RE.search(raw):
        # The path must sit in the launch's profile slot: nothing but its own path
        # expression (no `,` / `;`, only path helpers) between the slot and the path.
        at = PROFILE_PATH_RE.search(raw).start()
        return any(not re.search(r"[,;]", raw[m.end():at]) and _pure_rhs(
            raw[m.end():at] + ")", set()) for m in _SLOT_KEY_RE.finditer(raw[:at])) or None
    a = _ASSIGN_RE.match(raw)
    if a and a.group("op") == "=":
        names = _lhs_names(a)
        return names[0] if len(names) == 1 and _pure_rhs(a.group("rhs"), set()) else None
    if _RETURN_RE.match(raw):
        return _enclosing_def(lines, i) if _pure_rhs(
            re.sub(r"^\s*(?:return|yield)\b", "", raw), set()) else None
    if _LOG_RE.match(raw):
        return True
    # An element of a multi-line dict / list literal.
    head = _statement_head(lines, i)
    if head is not None and re.match(r"""^\s*(?:['"][^'"]*['"]\s*:\s*)?[^()]*,?\s*$""",
                                     _strip_strings(raw)):
        hl = lines[head]
        a = _ASSIGN_RE.match(hl)
        if a and a.group("op") == "=":
            names = _lhs_names(a)
            return names[0] if len(names) == 1 else None
        if _RETURN_RE.match(hl):
            return _enclosing_def(lines, head)
    return None


def _code(text: str, path: str) -> str:
    from src.scanner.skill_key_flow import strip_comments
    code = strip_comments(text, path)
    if path.lower().endswith(".py"):
        code = re.sub(r"""(?m)^[ \t]*[rRbBuU]?(\"\"\"|''')[\s\S]*?\1""",
                      lambda m: "\n" * m.group(0).count("\n"), code)
    return code


def _drives_browser(code: str) -> bool:
    return bool(_AUTOMATION_RE.search(code) or _SELENIUM_RE.search(code))


def profile_launch_line(text: str, path: str) -> int | None:
    """1-based line of a real browser profile path in a file that launches a browser
    with a profile directory (Python / JavaScript / TypeScript), else ``None``."""
    if not path.lower().endswith(_LANG_EXT) or not text:
        return None
    code = _code(text, path)
    if not _LAUNCH_RE.search(code) or not _drives_browser(code):
        return None
    for i, ln in enumerate(code.split("\n")):
        if PROFILE_PATH_RE.search(ln):
            return i + 1
    return None


def _block(lines: list[str], i: int) -> range:
    """Lines of the def starting at ``i`` (indentation-delimited)."""
    ind = _indent(lines[i])
    end = i + 1
    while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > ind
                                or lines[end].strip().startswith((")", "}", "]"))):
        end += 1
    return range(i, end)


def _stmt(lines: list[str], i: int) -> str:
    """Line ``i``, continued to its closing bracket when it opens more than it closes."""
    ln = lines[i]
    opens = sum(ln.count(c) for c in "([{") - sum(ln.count(c) for c in ")]}")
    return _call_span(lines, i, 0) if opens > 0 else ln


def _defs(lines: list[str]) -> list[tuple[str, range]]:
    out = []
    for i, ln in enumerate(lines):
        m = _DEF_RE.match(ln)
        if m:
            out.append((m.group("a") or m.group("b") or m.group("c"), _block(lines, i)))
    return out


def _string_interior(lines: list[str], py: bool) -> set[int]:
    """0-based lines that start inside a multi-line string (a page script in a Python
    triple-quoted string, a JS template literal): text, not this file's statements."""
    out: set[int] = set()
    inside = ""
    for i, ln in enumerate(lines):
        if inside:
            out.add(i)
        toks = re.findall(r'"""|\'\'\'' if py else r"(?<!\\)`", ln)
        for t in toks:
            if not inside:
                inside = t
            elif t == inside:
                inside = ""
    return out


_NAV_RE = re.compile(r"\.(?:goto|navigate)\s*\(|\bdriver\.get\s*\(|\.new_page\s*\(")


def page_data_sent(lines: list[str], py: bool = True) -> int | None:
    """The 1-based line where page content read from the driven browser reaches a
    network sink in this file, else ``None``. Taint runs over assignments, loops and
    container appends inside one function (module-level names everywhere), and through
    the calls of a function that returns page data. A call of a local function that
    itself sends is a sink; navigation is a sink only for page data."""
    defs = _defs(lines)
    interior = _string_interior(lines, py)
    scope = [""] * len(lines)
    for k, (_n, r) in sorted(enumerate(defs), key=lambda kv: -len(kv[1][1])):
        for j in r:
            scope[j] = f"{k}"
    body = {k: [j for j in r if j != r.start] for k, (_n, r) in enumerate(defs)}

    def calls(names: set[str], text: str) -> bool:
        return any(re.search(rf"(?<![\w$.]){re.escape(n)}\s*\(", text) for n in names)

    sink_fns = {n for k, (n, _r) in enumerate(defs)
                if any(_SINK_RE.search(lines[j]) and not _NAV_RE.search(lines[j])
                       for j in body[k] if j not in interior)}
    for _round in range(6):
        more = {n for k, (n, _r) in enumerate(defs)
                if n not in sink_fns and any(calls(sink_fns, lines[j]) for j in body[k])}
        if not more:
            break
        sink_fns |= more

    def taint(source: re.Pattern[str]):
        """``hot(text, scope)``: whether ``text`` carries page data under ``source``
        (taint over assignments, loops, appends and page-returning functions)."""
        tainted: set[tuple[str, str]] = set()
        page_fns: set[str] = set()

        def hot(text: str, sc: str, code_only: bool = False) -> bool:
            st = _args_code(text) if code_only else text
            if source.search(st) or calls(page_fns, st):
                return True
            st = st if code_only else _strip_strings(text)
            return any(s in (sc, "") and re.search(rf"(?<![\w$.]){re.escape(t)}(?![\w$])", st)
                       for s, t in tainted)

        for _round in range(8):
            before = len(tainted) + len(page_fns)
            for k, (n, _r) in enumerate(defs):
                if n not in page_fns and any(
                        _RETURN_RE.match(lines[j]) and hot(_stmt(lines, j), scope[j])
                        for j in body[k] if j not in interior):
                    page_fns.add(n)
            for i, raw in enumerate(lines):
                if i in interior or not raw.strip() or _DEF_RE.match(raw):
                    continue
                sc = scope[i]
                a = _ASSIGN_RE.match(raw)
                if a:
                    rhs = a.group("rhs")
                    if rhs.count("(") > rhs.count(")"):
                        rhs = _call_span(lines, i, a.start("rhs"))
                    if hot(rhs, sc):
                        tainted.update((sc, n) for n in _lhs_names(a))
                    continue
                f = _FOR_RE.match(raw)
                if f and hot(f.group("src"), sc):
                    tainted.update((sc, n) for n in re.findall(_IDENT, f.group("v")))
                    continue
                m = _MUTATE_RE.match(raw)
                if m and hot(raw[m.end("n"):], sc):
                    tainted.add((sc, m.group("n")))
            if len(tainted) + len(page_fns) == before:
                break
        return hot

    hot = taint(re.compile(_PAGE_READ_RE.pattern + "|" + _PAGE_SIDE_RE.pattern))

    sink_call = re.compile(_SINK_RE.pattern + "".join(
        rf"|(?<![\w$.]){re.escape(s)}\s*\(" for s in sorted(sink_fns)))
    for i, raw in enumerate(lines):
        if _DEF_RE.match(raw):
            continue
        if i in interior and _SINK_RE.search(raw) and not _NAV_RE.search(raw):
            return i + 1                     # a page script that sends
        for m in sink_call.finditer(raw):
            span = _call_span(lines, i, m.start())
            nav = _NAV_RE.match(raw, m.start()) or _NAV_RE.search(m.group(0))
            if hot(span, scope[i]) or (not nav and _FILE_SEND_RE.search(span)):
                return i + 1                 # page data, or a file's contents, sent

    # Exfil through the browser itself: a page-derived VALUE typed, filled, uploaded or
    # assigned into a page. Allowed only when every navigation in the file goes to one
    # literal origin (the value stays on the site it came from); unresolved: fail closed.
    value_hot = taint(_PAGE_VALUE_RE)
    one_origin = len(_nav_origins(lines) or ()) == 1
    for i, raw in enumerate(lines):
        if i in interior or _DEF_RE.match(raw):
            continue
        for m in _INPUT_RE.finditer(raw):
            args = _call_args(lines, i, m.end() - 1)
            if not value_hot(args, scope[i], code_only=True):
                continue
            if (m.group("script") and not m.group("exec")
                    and not _JS_ASSIGN_RE.search(args)):
                continue                     # evaluate() reading, not writing, the page
            if not one_origin:
                return i + 1
    return None


# A value read out of the page (text, markup, an evaluate() result, a capture).
_PAGE_VALUE_RE = re.compile(
    r"\.(?:inner_text|innerText|text_content|textContent|inner_html|innerHTML|content"
    r"|evaluate|evaluate_handle|evaluateHandle|eval_on_selector(?:_all)?|\$eval|\$\$eval"
    r"|screenshot|pdf|all_inner_texts|allInnerTexts|all_text_contents|allTextContents"
    r"|input_value|inputValue|get_attribute|getAttribute|execute_script|executeScript)\s*\("
    r"|\.page_source\b|\.(?:text|textContent|innerText|innerHTML)\b(?!\s*\()")
# Calls that put a value into a page: typing, filling, uploading, a script with args.
_INPUT_RE = re.compile(
    r"\.(?:fill|type|press_sequentially|pressSequentially|set_input_files|setInputFiles"
    r"|insert_text|insertText|send_keys|sendKeys|select_option|selectOption)\s*\("
    r"|(?P<script>\.(?:evaluate|evaluate_handle|evaluateHandle|\$eval|\$\$eval"
    r"|eval_on_selector(?:_all)?|(?P<exec>execute_script|executeScript|execute_async_script"
    r"|executeAsyncScript)))\s*\(")
_JS_ASSIGN_RE = re.compile(r"(?<![=!<>])=(?![=>])")
_URL_LIT_RE = re.compile(r"""\s*(['"`])(https?://[^/'"`\s?#]+)[^'"`\s]*\1\s*[,)]""")
_TRIPLE_RE = re.compile(
    r"""(?P<f>\b[fF][rR]?|\b[rR][fF])?(?P<q>\"\"\"|\'\'\')(?P<body>[\s\S]*?)(?P=q)""")


def _call_args(lines: list[str], i: int, col: int, max_lines: int = 300) -> str:
    """The call whose ``(`` is at ``lines[i][col]``, to its matching ``)``, skipping
    brackets inside strings (a page script in a triple-quoted or template string)."""
    text = "\n".join([lines[i][col:], *lines[i + 1:i + max_lines]])
    depth, k, n, quote = 0, 0, len(text), ""
    while k < n:
        if quote:
            if text[k] == "\\":
                k += 2
                continue
            if text.startswith(quote, k):
                k += len(quote)
                quote = ""
                continue
            if len(quote) == 1 and quote != "`" and text[k] == "\n":
                quote = ""                   # an unterminated one-line string
            k += 1
            continue
        c = text[k]
        if text.startswith(('"""', "'''"), k):
            quote = text[k:k + 3]
            k += 3
            continue
        if c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth <= 0:
                return text[:k + 1]
        k += 1
    return text


def _args_code(text: str) -> str:
    """Call text with string bodies removed (multi-line ones too), f-string / template
    interpolations kept: the code the call passes, not the script or message text."""
    def tri(m: re.Match[str]) -> str:
        if not m.group("f"):
            return '""'
        body = m.group("body").replace("{{", "").replace("}}", "")
        return '" ' + " ".join(i.group(1) for i in _INTERP_RE.finditer(body)) + ' "'
    return _strip_strings(_TRIPLE_RE.sub(tri, text))


def _nav_origins(lines: list[str]) -> set[str] | None:
    """The origins every navigation in the file goes to, when each is a literal URL;
    ``None`` when any navigation's URL is not a literal."""
    out: set[str] = set()
    for i, raw in enumerate(lines):
        for m in re.finditer(r"\.(?:goto|navigate)\s*\(|\bdriver\.get\s*\(", raw):
            span = _call_span(lines, i, m.end() - 1)
            u = _URL_LIT_RE.match(span, 1)
            if not u:
                return None
            out.add(u.group(2).lower())
    return out


def launch_only(path: str, text: str, others: dict[str, str] | None = None) -> bool:
    """Every real-profile path in ``text`` only feeds a browser launch's profile
    directory, nothing in the skill reads files inside a profile or the context's
    cookies / storage state, and no page content from the browser reaches a network
    sink. ``others``: the skill's other bundled scripts (path -> text)."""
    if profile_launch_line(text, path) is None:
        return False
    code = _code(text, path)
    lines = code.split("\n")
    others = {p: _code(t, p) for p, t in (others or {}).items() if t and p != path}

    # (b) / (c) skill-wide: no profile file names, store schema, or session reads.
    for c in [code, *others.values()]:
        if (_PROFILE_FILE_RE.search(c) or _STORE_SCHEMA_RE.search(c)
                or _STORE_KEY_RE.search(c) or _SESSION_READ_RE.search(c)):
            return False

    # (a) the path only reaches the launch.
    seeds: set[str] = set()
    for i, ln in enumerate(lines):
        if not PROFILE_PATH_RE.search(ln):
            continue
        s = _seed(lines, i)
        if s is None or s is False:
            return False
        if isinstance(s, str):
            seeds.add(s)
    tracked = _track(lines, seeds) if seeds else set()
    if tracked is None:
        return False
    # Function / module-level names another bundled file can import.
    defs = {n for n, _r in _defs(lines)}
    exported = {t for t in tracked if t in defs} | {
        t for t in tracked
        if any(re.match(rf"^(?:export\s+)?(?:(?:const|let|var)\s+)?{re.escape(t)}\s*=", ln)
               for ln in lines)}
    for p, c in others.items():
        olines = c.split("\n")
        hit = {t for t in exported
               if any(_uses(_strip_strings(ln), t) for ln in olines if not _IMPORT_RE.match(ln))}
        if hit and _track(olines, hit) is None:
            return False

    # (c) this file: page content never reaches a network sink; no bundled script
    # uploads a file (page text or session state saved here, sent from there).
    if page_data_sent(lines, path.lower().endswith(".py")) is not None:
        return False
    return all(page_data_sent(c.split("\n"), p.lower().endswith(".py")) is None
               for p, c in others.items())
