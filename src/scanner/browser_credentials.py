"""Browser credential handling: saved logins, session cookies and web storage.

Websites object to AI agents mostly over what a browser tool does with the user's
credentials. This module looks for the three shapes that matter, in one Python /
JavaScript / TypeScript file at a time:

* **Credential-store read** (defect, high): the code opens a browser's saved-password or
  cookie database (Chrome ``Login Data`` / ``Cookies``, Firefox ``logins.json`` /
  ``cookies.sqlite``) and reads it with the store's own schema (``encrypted_value``,
  ``password_value``, ``FROM moz_cookies``) or fetches the key that decrypts it
  (``Chrome Safe Storage``, ``os_crypt.encrypted_key``, NSS ``PK11SDR_Decrypt``). That
  is what an infostealer does, and what a "use my browser cookies" helper does too: the
  tool gets every session the user has. When the contents are also sent off the
  machine, ``credential_flow`` already reports a critical and this finding is dropped.

* **Session data sent to a network endpoint** (defect, critical with a literal remote
  host, high otherwise): a value read from the page or browser context
  (``document.cookie``, ``localStorage`` / ``sessionStorage`` reads,
  ``context.cookies()``, ``storageState()``, CDP ``Network.getAllCookies``,
  ``chrome.cookies.getAll``, a password field's ``value``, a captured ``Authorization``
  / ``Cookie`` request header) reaches the body or URL of an outbound request. A value
  that only rides a ``cookies=`` argument or a ``Cookie`` / ``Authorization`` header is
  the session being replayed to the site, not exfiltration, and a request to localhost
  is a local bridge to the agent; neither is reported.

* **Capabilities** (reported, never scored): the tool reads cookies / storage state
  from a browser it drives, saves that state to disk (Playwright's documented
  ``storageState({path})``), or launches the browser with the user's real profile
  directory (their logged-in sessions). These are what browser-automation tools are
  for, and are listed so a reader knows the tool can act as the user.

Pure text analysis; never imports ``scan`` (it calls in here) and never executes code.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

CAP_SESSION_READ = "browser:session_read"
CAP_SESSION_PERSIST = "browser:session_persist"
CAP_REAL_PROFILE = "browser:real_profile"

STORE_READ_NAME = "Reads the browser's saved-password / cookie database"
SESSION_EXFIL_NAME = "Browser cookies / storage / password sent to a network endpoint"

_LANGS = ("python", "javascript", "typescript")

# ---------------------------------------------------------------------------
# Credential-store read
# ---------------------------------------------------------------------------

# The store's own schema: Chromium cookie / login tables, Firefox's moz_* tables.
_STORE_SCHEMA_RE = re.compile(
    r"\b(?:encrypted_value|password_value)\b|\bFROM\s+moz_(?:cookies|logins)\b|"
    r"(?i:\bselect\b[^\n]*\bfrom\s+(?:cookies|logins|credit_cards)\b)"
)
# The key that decrypts the store: macOS keychain item ("Chrome Safe Storage"), the
# Windows/Linux Local State key (os_crypt.encrypted_key), Firefox's NSS decrypt call.
_STORE_KEY_RE = re.compile(
    r"""Safe Storage['"]|\bos_crypt\b[^\n]{0,80}\bencrypted_key\b|"""
    r"""\bencrypted_key\b[^\n]{0,80}\bos_crypt\b|\bPK11SDR_Decrypt\b"""
)
# Somewhere in the file: a browser store file or a real browser profile directory.
_BROWSER_STORE_CONTEXT_RE = re.compile(
    r"""['"/\\](?:Login Data|Login Data For Account|Web Data|Cookies|cookies\.sqlite|"""
    r"""logins\.json|key[34]\.db|signons\.sqlite|Cookies\.binarycookies)['"]|"""
    r"""Google[/\\ ]Chrome|google-chrome|BraveSoftware|Microsoft[/\\ ]Edge|"""
    r"""\.mozilla|Firefox[/\\]Profiles|User Data"""
)

# ---------------------------------------------------------------------------
# Session-data sources (a value read from the page / browser context)
# ---------------------------------------------------------------------------

# Whole-jar page reads: every cookie, the whole of web storage, a password field, a
# captured auth header. The stealer shape wherever it appears.
_PAGE_DUMP_SOURCE_RE = re.compile(
    # the whole cookie string: not an assignment (that sets one cookie), not parsed
    # down to one named cookie (`.match(/csrf=…/)`, `.split('; ')` is a CSRF helper)
    r"""\bdocument\.cookie\b(?!\s*=[^=])(?!\s*\.\s*(?:match|split|replace|includes|indexOf)\b)|"""
    r"""(?:JSON\.stringify|Object\.(?:entries|keys|values|assign))\s*\(\s*(?:\{\s*)?"""
    r"""(?:\.\.\.\s*)?(?:window\.)?(?:localStorage|sessionStorage)\b|"""
    r"""\.\.\.\s*(?:window\.)?(?:localStorage|sessionStorage)\b|"""
    # a password field's value
    r"""type\s*=\s*\\?['"]?password\\?['"]?\s*\]['"`]?\s*\)?\s*\??\.\s*value\b|"""
    r"""type\s*=\s*\\?['"]?password\\?['"]?\s*\]['"`]?\s*\)\s*\.\s*(?:inputValue|input_value)\s*\(|"""
    # a captured Authorization / Cookie request header (Playwright / Puppeteer Request)
    r"""\.(?:all)?[hH]eaders\s*\(\s*\)\s*\)?\s*\[\s*['"](?i:authorization|cookie)['"]\s*\]|"""
    r"""\.headerValue\s*\(\s*['"](?i:authorization|cookie)['"]"""
)
# One named item (`localStorage.getItem('token')`, one parsed cookie): what every web
# front end does with its OWN token. Counted only in a file that drives a browser, where
# the page belongs to some other site.
_PAGE_ITEM_SOURCE_RE = re.compile(
    r"""\b(?:localStorage|sessionStorage)\s*(?:\.\s*(?:getItem|key)\s*\(|\[)|"""
    r"""\bdocument\.cookie\b(?!\s*=[^=])"""
)
# The subset that is a browser-context session read (the capability chip). Page-side
# `document.cookie` / `localStorage` are left out: every web front end reads its own.
_CONTEXT_SESSION_READ_RE = re.compile(
    r"""\.(?:cookies|get_cookies|getCookies)\s*\(|\.(?:storageState|storage_state)\s*\(|"""
    r"""\b(?:Network|Storage)\.(?:getAllCookies|getCookies)\b|"""
    r"""\b(?:chrome|browser)\.cookies\.(?:getAll|get)\s*\(|"""
    # the extension API through an alias (`api.cookies.getAll({ url }, cb)`); its
    # details-object argument tells it from a framework's `req.cookies.getAll()`
    r"""\.cookies\.getAll\s*\(\s*\{"""
)
_SESSION_SOURCE_RE = re.compile("|".join(
    f"(?:{rx.pattern})" for rx in (_PAGE_DUMP_SOURCE_RE, _PAGE_ITEM_SOURCE_RE,
                                   _CONTEXT_SESSION_READ_RE)))
# The file drives a browser: it imports an automation library or calls a browser-control
# API. A bare word ("Chromium", "devtools") in a front end's comment is not enough, since
# this gate is what lets single-item reads and variable destinations count.
_AUTOMATION_RE = re.compile(
    r"""^\s*(?:import|from)\b[^\n]*\b(?:playwright|puppeteer|pyppeteer|selenium|webdriver|"""
    r"""browser_use|chrome-remote-interface|devtools-protocol|patchright|undetected_chromedriver)\b|"""
    r"""\brequire\s*\(\s*['"](?:playwright|puppeteer|selenium-webdriver|chrome-remote-interface|"""
    r"""patchright)[\w/-]*['"]|"""
    r"""\b(?:chromium|firefox|webkit)\.(?:launch|connect)\w*\s*\(|createCDPSession|CDPSession|"""
    r"""\bcdp_client\b|\bchrome\.(?:debugger|cookies|tabs|devtools)\.|\.cookies\.getAll\s*\(\s*\{|"""
    r"""\bnewContext\s*\(|\bnew_context\s*\(|launch_?[pP]ersistent_?[cC]ontext""",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

_SEND_RE = re.compile(
    r"""(?<![\w.$])fetch\s*\(|\baxios(?:\.(?:post|put|patch|request))?\s*\(|"""
    r"""\b(?:requests|httpx|session|client|aiohttp)\.(?:post|put|patch)\s*\(|"""
    r"""\bnavigator\.sendBeacon\s*\(|\b\w*xhr\w*\.send\s*\(|\burlopen\s*\(|"""
    r"""\bnew\s+Image\s*\(\s*\)\s*\.src\s*=|\.src\s*=\s*['"`]https?://|"""
    r"""\bgot\.(?:post|put)\s*\(|\bsuperagent\.(?:post|put)\s*\(""",
    re.IGNORECASE,
)
_URL_HOST_RE = re.compile(r"""['"`]https?://(?:[^@/'"`\s]*@)?([^/:?#'"`\s$]+)""")
_LOCAL_HOST_RE = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$",
    re.IGNORECASE)
# A use of a tainted name that replays the session to the site (authentication).
_AUTH_USE_BEFORE_RE = re.compile(
    r"""(?:\bcookies\s*=\s*|['"]?(?i:cookie|authorization|x-(?:csrf|xsrf)[\w-]*)['"]?\s*[:=]\s*"""
    r"""(?:f?['"`][^'"`]*)?)$"""
)
# The request's first argument is a same-origin path (`fetch('/api/x', …)`).
_RELATIVE_URL_RE = re.compile(r"""\s*['"`](?:/(?!/)|\./|\.\./)""")
# What follows a name that is a keyword-argument name (`cookies=jar`) or an object key
# (`{cookies: x}`), not a use of the value.
_KEY_AFTER_RE = re.compile(r"\s*(?:=(?!=)|:(?!:))")
_WRITE_RE = re.compile(
    r"""\b(?:fs\.)?(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(|"""
    r"""\.write_text\s*\(|\bjson\.dump\s*\(|\.write\s*\("""
)
# Playwright's documented save form: storageState({ path }) / storage_state(path=…).
_STATE_SAVE_RE = re.compile(
    r"""\.storageState\s*\(\s*\{[^}]*\bpath\s*:|\.storage_state\s*\(\s*path\s*="""
)

# ---------------------------------------------------------------------------
# Real profile reuse
# ---------------------------------------------------------------------------

_REAL_PROFILE_RE = re.compile(
    r"""Application Support[/\\](?:Google[/\\]Chrome|Chromium|BraveSoftware|Microsoft Edge)|"""
    r"""Google[/\\]+Chrome[/\\]+User Data|\.config[/\\](?:google-chrome|chromium|"""
    r"""BraveSoftware)|\.mozilla[/\\]firefox|Firefox[/\\]Profiles|"""
    # pathlib / os.path.join parts: 'Google', 'Chrome'  /  'Google' / 'Chrome'
    r"""['"]Google['"]\s*[,/]\s*['"]Chrome['"]|['"]\.config['"]\s*[,/]\s*['"]google-chrome['"]"""
)
_PROFILE_LAUNCH_RE = re.compile(
    r"""user_data_dir|userDataDir|user-data-dir|launchPersistentContext|"""
    r"""launch_persistent_context|profile[-_]directory|profileDirectory"""
)

_ASSIGN_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var|final)?\s*"""
    r"""(?:\{\s*(?P<destr>[\w\s,:]+)\}|(?P<name>[A-Za-z_$][\w$]*))\s*"""
    r"""(?::\s*[\w\[\]<>|, .]+)?\s*:?=(?!=)\s*(?P<rhs>.*)$"""
)
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
# Cheap pre-check: nothing below can fire without one of these words.
_HINT_RE = re.compile(
    r"cookie|Storage|password|Safe Storage|encrypted_value|password_value|moz_|os_crypt|"
    r"PK11SDR|user_data_dir|userDataDir|user-data-dir|PersistentContext|profile[-_]directory|"
    r"profileDirectory|headers\s*\(|headerValue",
    re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*(?:#|//|/?\*)")
_MAX_CALL_LINES = 12


@dataclass
class BrowserCredentialHit:
    """One finding's worth of evidence (scan.py turns it into a ``Finding``)."""

    line: int                 # 1-based
    name: str
    severity: str             # defect: critical | high ; capability: info
    kind: str = "defect"      # "defect" | "capability"
    capability: str = ""
    detail: str = ""


def _code_lines(lines: list[str]) -> list[int]:
    return [i for i, ln in enumerate(lines) if ln.strip() and not _COMMENT_RE.match(ln)]


def _store_read(lines: list[str], code: list[int], content: str) -> BrowserCredentialHit | None:
    if not _BROWSER_STORE_CONTEXT_RE.search(content):
        return None
    for i in code:
        ln = lines[i]
        if _STORE_SCHEMA_RE.search(ln) or _STORE_KEY_RE.search(ln):
            return BrowserCredentialHit(
                line=i + 1, name=STORE_READ_NAME, severity="high",
                detail=(
                    "This code reads a browser's saved-password or cookie database (or the "
                    "key that decrypts it). Whoever runs it gets every login and session "
                    "the user has in that browser. A tool that needs a site session should "
                    "use a dedicated browser profile or an explicit storage-state file."
                ),
            )
    return None


def _call_span(lines: list[str], i: int, start_col: int) -> str:
    """The text of the call starting at ``lines[i][start_col:]`` up to its closing paren
    (or ``_MAX_CALL_LINES`` lines)."""
    depth = 0
    out: list[str] = []
    seen_open = False
    for j in range(i, min(len(lines), i + _MAX_CALL_LINES)):
        seg = lines[j][start_col:] if j == i else lines[j]
        for k, ch in enumerate(seg):
            if ch in "([{":
                depth += 1
                seen_open = True
            elif ch in ")]}":
                depth -= 1
                if seen_open and depth <= 0:
                    out.append(seg[:k + 1])
                    return "\n".join(out)
        out.append(seg)
    return "\n".join(out)


def _is_source(text: str, automation: bool) -> bool:
    """A session-data read in ``text``. In a file that drives a browser every form
    counts; elsewhere only the whole-jar page reads do (a web front end reading its own
    token, or some framework object's ``.cookies()``, is not a browser tool's capture)."""
    if automation:
        return _SESSION_SOURCE_RE.search(text) is not None
    return _PAGE_DUMP_SOURCE_RE.search(text) is not None


def _tainted_names(lines: list[str], code: list[int], automation: bool) -> dict[str, int]:
    """Names assigned from a session-data source, plus names assigned from an expression
    that uses one (three rounds). Value: the 1-based line of the originating source."""
    tainted: dict[str, int] = {}
    assigns: list[tuple[int, list[str], str]] = []
    for i in code:
        m = _ASSIGN_RE.match(lines[i])
        if not m:
            continue
        names = ([n for n in _IDENT_RE.findall(m.group("destr") or "") if n]
                 if m.group("destr") else [m.group("name")])
        rhs = m.group("rhs")
        # A multi-line right-hand side (`await page.evaluate(() => {` … `})`).
        if rhs.count("(") > rhs.count(")"):
            rhs = _call_span(lines, i, m.start("rhs"))
        assigns.append((i, names, rhs))
    for i, names, rhs in assigns:
        if _is_source(rhs, automation):
            for n in names:
                tainted.setdefault(n, i + 1)
    for _round in range(3):
        grew = False
        for i, names, rhs in assigns:
            code_rhs = _strip_strings(rhs)
            hit = next((t for t in tainted
                        if re.search(rf"(?<![\w$.]){re.escape(t)}\b", code_rhs)), None)
            if hit is None:
                continue
            for n in names:
                if n not in tainted:
                    tainted[n] = tainted[hit]
                    grew = True
        if not grew:
            break
    return tainted


_STRING_LIT_RE = re.compile(
    r"""(?P<f>\b[fF][rR]?|\b[rR][fF])?(?P<q>['"`])(?P<body>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)""")
_INTERP_RE = re.compile(r"""\$?\{([^{}]*)\}""")


def _strip_strings(text: str) -> str:
    """``text`` with each string literal reduced to its interpolations (``${x}`` in a
    template, ``{x}`` in an f-string), so a name inside a URL or message is not a use."""
    def repl(m: re.Match[str]) -> str:
        if m.group("q") == "`" or m.group("f"):
            inner = " ".join(i.group(1) for i in _INTERP_RE.finditer(m.group("body")))
            return f"{m.group('q')} {inner} {m.group('q')}"
        return m.group("q") * 2
    return _STRING_LIT_RE.sub(repl, text)


def _non_auth_use(span: str, name: str) -> bool:
    """``name`` appears in ``span`` (outside string text) somewhere other than a
    cookies= / Cookie-header slot."""
    span = _strip_strings(span)
    for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}\b", span):
        if _KEY_AFTER_RE.match(span, m.end()):
            continue                       # a keyword-argument name / object key
        before = span[max(0, m.start() - 60):m.start()]
        if not _AUTH_USE_BEFORE_RE.search(before):
            return True
    return False


def _session_exfil(lines: list[str], code: list[int], tainted: dict[str, int],
                   automation: bool) -> list[BrowserCredentialHit]:
    out: list[BrowserCredentialHit] = []
    for i in code:
        ln = lines[i]
        m = _SEND_RE.search(ln)
        if not m:
            continue
        # `.src = 'https://…?c=' + value` is an assignment: the rest of the line is it.
        span = (ln[m.start():] if ".src" in m.group(0)
                else _call_span(lines, i, m.start()))
        carried = _is_source(span, automation) or any(
            _non_auth_use(span, n) for n in tainted)
        if not carried:
            continue
        if _RELATIVE_URL_RE.match(span[m.end() - m.start():]):
            continue                       # same-origin: the browser sends it there anyway
        hosts = [h.lower() for h in _URL_HOST_RE.findall(span)]
        if hosts and all(_LOCAL_HOST_RE.match(h) for h in hosts):
            continue
        remote = any(not _LOCAL_HOST_RE.match(h) for h in hosts)
        # Outside a browser tool, only a literal remote destination is reported: a web
        # app posting to its own (configured) API is not the shape.
        if not remote and not automation:
            continue
        out.append(BrowserCredentialHit(
            line=i + 1, name=SESSION_EXFIL_NAME,
            severity="critical" if remote else "high",
            detail=(
                "Cookies, web storage, a password field or an auth header read from the "
                "browser are sent in an outbound request. Session cookies and tokens are "
                "the user's logged-in identity; a tool that ships them elsewhere can act "
                "as the user on that site. Keep session data on the machine."
            ),
        ))
    return out


def browser_credential_hits(
    content: str, lang: str | None, *, prose_lines: Callable[[], set[int]] | None = None,
) -> list[BrowserCredentialHit]:
    """Findings for one file (``lang``: python / javascript / typescript).
    ``prose_lines``: returns the 0-based lines inside a multi-line string (a Python
    docstring), skipped like comments by the store-read and capability rules; called
    only when the file has a hint. The send rule still reads them: a page script held
    in a Python string runs in the browser."""
    if lang not in _LANGS or not _HINT_RE.search(content):
        return []
    lines = content.split("\n")
    code = _code_lines(lines)
    stated = code
    if prose_lines is not None:
        prose = prose_lines()
        if prose:
            stated = [i for i in code if i not in prose]
    hits: list[BrowserCredentialHit] = []

    store = _store_read(lines, stated, content)
    if store:
        hits.append(store)

    automation = _AUTOMATION_RE.search(content) is not None
    if _is_source(content, automation) and _SEND_RE.search(content):
        tainted = _tainted_names(lines, code, automation)
        hits.extend(_session_exfil(lines, code, tainted, automation))

    if automation and not any(h.kind == "defect" and h.name == SESSION_EXFIL_NAME
                              for h in hits):
        read = next((i for i in stated if _CONTEXT_SESSION_READ_RE.search(lines[i])
                     and not _STATE_SAVE_RE.search(lines[i])), None)
        if read is not None:
            hits.append(BrowserCredentialHit(
                line=read + 1, name="Reads cookies / storage state from the browser",
                severity="info", kind="capability", capability=CAP_SESSION_READ))
        save = next((i for i in stated if _STATE_SAVE_RE.search(lines[i])), None)
        if save is None and read is not None:
            # a cookie / state value written to a file
            tainted = _tainted_names(lines, code, automation)
            if tainted:
                save = next((i for i in stated if _WRITE_RE.search(lines[i]) and any(
                    re.search(rf"(?<![\w$.]){re.escape(t)}\b", lines[i]) for t in tainted)),
                    None)
        if save is not None:
            hits.append(BrowserCredentialHit(
                line=save + 1, name="Saves browser session state (cookies / storage) to disk",
                severity="info", kind="capability", capability=CAP_SESSION_PERSIST))

    # A file that reads the store itself already carries the stronger finding.
    if store is None and _PROFILE_LAUNCH_RE.search(content):
        prof = next((i for i in stated if _REAL_PROFILE_RE.search(lines[i])), None)
        if prof is not None:
            hits.append(BrowserCredentialHit(
                line=prof + 1,
                name="Can run the browser with your real browser profile",
                severity="info", kind="capability", capability=CAP_REAL_PROFILE))
    return hits
