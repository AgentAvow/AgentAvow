"""What install-time code does: the signals that make an install hook suspicious.

An npm ``preinstall`` / ``install`` / ``postinstall`` script or a PyPI ``setup.py``
runs on the installing machine with no further prompt. Having one is common and on its
own is a medium (node-gyp builds, esbuild / sharp binary downloads, husky, native
``build_ext``). What the dependency-confusion probes and droppers in the wild add on
top is narrow and readable:

* **recon + network**: the hook collects the host name, the user name, the network
  interfaces, the external IP or the whole serialised environment, and the same code
  talks to the network (an HTTPS beacon, a DNS lookup of ``<user>.<host>.attacker.tld``);
* **an out-of-band host**: an interaction / request-bin / webhook service built to
  receive callbacks (``*.oast.fun``, Burp Collaborator, interact.sh, pipedream,
  webhook.site, a Discord / Telegram bot), or a URL at a raw public IP address;
* **stored credentials, persistence, a dropper**: an npm auth token or SSH key read, a
  systemd user unit / crontab / login item written, ``exec(urlopen(...))`` held as text;
* **an obfuscated payload**: javascript-obfuscator output, or ``eval`` / ``Function``
  applied directly to a decode (``atob``, ``Buffer.from``, ``String.fromCharCode``) or
  to a char-code array.

A plain build or a binary fetch from the project's own release host has none of
these, so it stays a medium. Bundled hooks are common, so each signal needs the
specific shape, not a word: ``Function('return this')()`` (a global-object shim),
``os.userInfo().homedir``, ``Object.keys(process.env)`` filtering ``npm_config_*`` and a
CLI that defines a ``whoami`` command are all ordinary.

Every pattern here is linear (no nested or adjacent unbounded repeats that can
overlap), and every entry point reads at most ``MAX_SIGNAL_TEXT`` characters (head and
tail): hook files can be megabytes. This module only reads text; nothing is run.
"""

from __future__ import annotations

import re

# A hook file is read whole for signals up to this size (every pattern is linear, so
# padding a beacon into the middle of a file does not hide it); past it, head + tail.
MAX_SIGNAL_TEXT = 2 * 1024 * 1024
_TAIL = 512 * 1024


def clip(text: str) -> str:
    if len(text) <= MAX_SIGNAL_TEXT:
        return text
    return text[: MAX_SIGNAL_TEXT - _TAIL] + "\n" + text[-_TAIL:]


# Out-of-band interaction / callback-collector services, and URLs at a raw IPv4
# address (loopback / unspecified / private ranges excluded: a local dev server). No
# leading subdomain group: search() finds the service name wherever it sits.
OOB_HOST_RE = re.compile(
    r"""(?:oast\.(?:fun|pro|live|site|online|me)|oastify\.com"""
    r"""|burpcollaborator\.net|interact\.sh|interactsh\.com|pipedream\.net"""
    r"""|webhook\.site|requestbin\.(?:com|net)|requestcatcher\.com|beeceptor\.com"""
    r"""|hookbin\.com|ngrok(?:-free)?\.(?:io|app|dev)|dnslog\.(?:cn|link)|ceye\.io"""
    r"""|canarytokens\.(?:com|org)|trycloudflare\.com|bf\.gy|ptrace\.dev"""
    r"""|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)"""
    r"""|https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.))"""
    r"""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""",
)  # matched against lower-cased text (case-insensitive matching is ~5x slower)

# Stored credentials an install hook has no business reading: npm auth tokens, SSH
# private keys, cloud / git / registry credential files.
CREDS_RE = re.compile(
    r"""_authToken|\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)|\.aws/credentials|\.git-credentials"""
    r"""|\.docker/config\.json|\.config/gcloud/""")
# Persistence: a user service, a login item or a scheduled job set up by the hook.
PERSIST_RE = re.compile(
    r"""\.config/systemd/user|systemctl\s+--user\s+enable|\bcrontab\s+-|/etc/cron\."""
    r"""|Library/LaunchAgents|CurrentVersion\\{1,2}Run\b|schtasks\s*/create""",
    re.IGNORECASE)
# Code that downloads and runs more code, held as text (written out, or decoded).
DROPPER_CODE_RE = re.compile(
    r"""\b(?:exec|eval)\s*\([^\n]{0,200}?\b(?:urlopen|requests\.get|urlretrieve)\s*\(""")

# ---------------------------------------------------------------------------
# JavaScript (a file an npm lifecycle script runs)
# ---------------------------------------------------------------------------

_JS_NET_MODULES = (
    r"http|https|http2|net|dns|dgram|tls|axios|node-fetch|got|request|undici|needle"
    r"|superagent|ws|phin|cross-fetch|isomorphic-fetch"
)
_JS_NET_RE = re.compile(
    rf"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"`](?:node:)?(?:{_JS_NET_MODULES})['"`]"""
    r"""|\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\("""
    # a downloader / resolver spawned from the script
    r"""|['"`]\s*(?:curl|wget|nslookup|dig|ping|nc|ncat)\s""",
)
# Who / where the machine is. The whole environment counts only when serialised;
# `whoami` only inside a spawned command string; the user name in `_js_username_sent`.
_JS_RECON_RE = re.compile(
    r"""\b(?:hostname|networkInterfaces)\s*\(\s*\)"""
    r"""|\{\s*username\s*[,}][^;\n]{0,80}?=\s*(?:os\s*\.\s*)?userInfo\s*\("""
    r"""|JSON\.stringify\s*\(\s*process\.env\s*[,)]"""
    r"""|\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*['"`][^'"`\n]{0,200}?"""
    r"""\bwhoami\b"""
    r"""|readFileSync\s*\(\s*['"`]/etc/passwd"""
    r"""|ipinfo\.io|ifconfig\.me|api\.ipify\.org|icanhazip\.com|checkip\.amazonaws\.com"""
    r"""|ip-api\.com""",
)
# Names bound to `os.userInfo()`, and every `<name>.username` / `userInfo().username`.
# Identifiers start only where no identifier character precedes, so each is scanned once.
_JS_USERINFO_VAR_RE = re.compile(
    r"""(?<![\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:os\s*\.\s*)?userInfo\s*\(""")
_JS_USERNAME_USE_RE = re.compile(
    r"""(?<![\w$])(?:([A-Za-z_$][\w$]*)|userInfo\s*\(\s*\))\s*\.\s*username\b""")
# A statement that uses the user name for a local path (a per-user cache or temp dir),
# not to send it anywhere.
_LOCAL_USE_RE = re.compile(
    r"""/tmp/|\bpath\s*\.\s*(?:join|resolve)\b|\.cache\b|\bmkdir|\bwriteFile|\breadFile"""
    r"""|\bexistsSync\b|\bhomedir\b|\btmpdir\b|\bchown"""
    # ... or one that only shows it to the person installing (a thank-you banner)
    r"""|\bconsole\s*\.\s*(?:log|info|warn|error)\s*\(|\bprocess\s*\.\s*std(?:out|err)\b""")
_SEND_USE_RE = re.compile(
    r"""https?:|\brequest\s*\(|\bfetch\s*\(|\blookup\s*\(|\.get\s*\("""
    r"""|\bsend\s*\(|\baxios\b|\bdns\b|encodeURIComponent|JSON\.stringify""")
_JS_OBFUSCATOR_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
# eval / Function applied DIRECTLY to a decode, or to a function whose body decodes a
# char-code array (`eval(function(s,n){…fromCharCode…}([40,105,…]))`).
_JS_EVAL_DECODE_RE = re.compile(
    r"""\b(?:eval|Function)\s*\(\s*(?:atob\s*\(|Buffer\s*\.\s*from\s*\(|"""
    r"""String\s*\.\s*fromCharCode\b|unescape\s*\(|decodeURIComponent\s*\(|"""
    r"""function\s*\([^)]{0,60}\)\s*\{[^}]{0,600}?fromCharCode)""")
# A name bound to a decode, later passed to eval / Function.
_JS_DECODED_VAR_RE = re.compile(
    r"""(?<![\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:atob\s*\(|Buffer\s*\.\s*from\s*\([^)\n]{0,4000}?"""
    r"""['"](?:base64|hex)['"]|String\s*\.\s*fromCharCode\b)""")

# ---------------------------------------------------------------------------
# Shell (an inline lifecycle command, or a .sh file one runs)
# ---------------------------------------------------------------------------

_SH_NET_RE = re.compile(
    r"""\b(?:curl|wget|nslookup|dig|ping|nc|ncat|socat|telnet|Invoke-WebRequest|iwr"""
    r"""|Invoke-RestMethod)\b|/dev/(?:tcp|udp)/""",
    re.IGNORECASE,
)
_SH_RECON_RE = re.compile(
    r"""\b(?:whoami|hostname|printenv)\b|\buname\s+-a\b|\$\{?(?:USER|USERNAME|HOSTNAME)\b"""
    r"""|\$\(\s*pwd\s*\)|`\s*pwd\s*`|%USERNAME%|%COMPUTERNAME%|/etc/passwd""",
)

# ---------------------------------------------------------------------------
# Python (a .py file an npm hook runs; setup.py itself goes through the AST visitor in
# ``src.scanner.artifact_scan``)
# ---------------------------------------------------------------------------

# Calls whose result always names the machine or the user (`uname` only for its node
# name: the AST visitor checks how it is used).
PY_RECON_CALLS = frozenset({
    "gethostname", "getfqdn", "gethostbyname", "getuser", "getlogin", "getpwuid",
})
_PY_NET_RE = re.compile(
    r"""^[ \t]*(?:import|from)[ \t]+(?:requests|httpx|urllib3?|aiohttp|socket|http\.client"""
    r"""|urllib\.request|pycurl|dns)\b|\burlopen\s*\(""",
    re.MULTILINE,
)
_PY_RECON_RE = re.compile(
    r"""\b(?:gethostname|getfqdn|getuser|getlogin)\s*\(|\bplatform\.node\s*\("""
    r"""|\buname\s*\(\s*\)\s*(?:\.\s*nodename\b|\[\s*1\s*\])"""
    r"""|\b(?:json\.dumps|str|repr)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\s*\)"""
    r"""|['"]whoami['"]|ipinfo\.io|ifconfig\.me|api\.ipify\.org""",
)


def common_signals(text: str, out: set[str] | None = None) -> set[str]:
    """The signals read the same way in any language: ``oob``, ``creds``, ``persist``,
    ``dropper``."""
    out = set() if out is None else out
    text = clip(text)
    if OOB_HOST_RE.search(text.lower()):
        out.add("oob")
    if CREDS_RE.search(text):
        out.add("creds")
    if PERSIST_RE.search(text):
        out.add("persist")
    if DROPPER_CODE_RE.search(text):
        out.add("dropper")
    return out


def py_signals(text: str) -> set[str]:
    """Signals in a Python file an npm install hook runs."""
    text = clip(text)
    out: set[str] = set()
    if _PY_NET_RE.search(text):
        out.add("net")
    if _PY_RECON_RE.search(text):
        out.add("recon")
    return common_signals(text, out)


def _statement(text: str, pos: int, end: int) -> str:
    """The statement around a match: back to the previous `;` / newline and on to the
    next, at most 300 characters each way (minified bundles have no newlines)."""
    lo = max(pos - 300, 0)
    cut = max(text.rfind(";", lo, pos), text.rfind("\n", lo, pos))
    hi = min(end + 300, len(text))
    stops = [i for i in (text.find(";", end, hi), text.find("\n", end, hi)) if i != -1]
    return text[(cut + 1 if cut != -1 else lo):(min(stops) if stops else hi)]


def _js_username_sent(text: str) -> bool:
    """The user name read from ``os.userInfo()`` and used anywhere but a local path
    (``/tmp/tool-${info.username}``) or a line printed to the installer
    (``console.log(`Thanks ${…username}!`)``), unless that statement also sends
    something. A property in a payload object (``{username: …}``) or a variable later
    put in a URL still counts. One pass for the bound names, one for the uses."""
    names = {m.group(1) for m in _JS_USERINFO_VAR_RE.finditer(text)}
    for m in _JS_USERNAME_USE_RE.finditer(text):
        if m.group(1) is not None and m.group(1) not in names:
            continue
        stmt = _statement(text, m.start(), m.end())
        if not _LOCAL_USE_RE.search(stmt) or _SEND_USE_RE.search(stmt):
            return True
    return False


def _js_recon(text: str) -> bool:
    return bool(_JS_RECON_RE.search(text)) or _js_username_sent(text)


# eval / Function applied to a plain name (checked against the names bound to a decode).
_JS_EVAL_NAME_RE = re.compile(r"""\b(?:eval|Function)\s*\(\s*([A-Za-z_$][\w$]*)\s*[),]""")


def _is_obfuscated_js(text: str) -> bool:
    if len(_JS_OBFUSCATOR_RE.findall(text)) >= 10:
        return True
    if _JS_EVAL_DECODE_RE.search(text):
        return True
    decoded = {m.group(1) for m in _JS_DECODED_VAR_RE.finditer(text)}
    return bool(decoded) and any(
        m.group(1) in decoded for m in _JS_EVAL_NAME_RE.finditer(text))


def js_signals(text: str) -> set[str]:
    """Signals in JavaScript an install hook runs: ``net``, ``recon``, ``obfuscated``,
    plus :func:`common_signals`."""
    text = clip(text)
    out: set[str] = set()
    if _JS_NET_RE.search(text):
        out.add("net")
    if _js_recon(text):
        out.add("recon")
    if _is_obfuscated_js(text):
        out.add("obfuscated")
    return common_signals(text, out)


def shell_signals(text: str) -> set[str]:
    """Signals in a shell command / script an install hook runs."""
    text = clip(text)
    out: set[str] = set()
    if _SH_NET_RE.search(text):
        out.add("net")
    if _SH_RECON_RE.search(text):
        out.add("recon")
    return common_signals(text, out)


# (signal(s), reason) in the order a reason is chosen. Net + recon needs both; every
# other entry stands alone.
_REASONS: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"net", "recon"}), "sends host or user details over the network at install"),
    (frozenset({"creds"}), "reads stored credentials (npm, SSH or cloud tokens) at install"),
    (frozenset({"oob"}), "contacts a callback-collector or raw-IP host at install"),
    (frozenset({"dropper"}), "writes or runs code that downloads and runs more code at install"),
    (frozenset({"persist"}), "sets up a startup service or scheduled job at install"),
    (frozenset({"obfuscated"}), "runs obfuscated or encoded code at install"),
)


def suspicious_reason(signals: set[str]) -> str | None:
    """The plain-language reason an install hook with these signals is suspicious, or
    ``None`` when it is an ordinary hook (build, binary fetch, banner)."""
    return next((reason for need, reason in _REASONS if need <= signals), None)
