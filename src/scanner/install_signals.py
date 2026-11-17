"""What install-time code does: the signals that make an install hook suspicious.

An npm ``preinstall`` / ``install`` / ``postinstall`` script or a PyPI ``setup.py``
runs on the installing machine with no further prompt. Having one is common and on its
own is a medium (node-gyp builds, esbuild / sharp binary downloads, husky, native
``build_ext``). What the dependency-confusion probes and droppers in the wild add on
top is narrow and readable:

* **recon + network**: the hook collects the host name, the user name, the network
  interfaces, the external IP or the whole environment, and the same code talks to the
  network (an HTTPS beacon, a DNS lookup of ``<user>.<host>.attacker.tld``);
* **an out-of-band host**: an interaction / request-bin / webhook service built to
  receive callbacks (``*.oast.fun``, Burp Collaborator, interact.sh, pipedream,
  webhook.site, a Discord / Telegram bot), or a URL at a raw IP address;
* **an obfuscated payload**: javascript-obfuscator output, ``eval`` / ``Function`` /
  ``exec`` of a decoded string, a long char-code array.

A plain build or a binary fetch from the project's own release host has none of
these, so it stays a medium. This module only reads text; nothing is run.
"""

from __future__ import annotations

import re

# Out-of-band interaction / callback-collector services, and URLs at a raw IPv4
# address (loopback / unspecified / private ranges excluded: a local dev server).
OOB_HOST_RE = re.compile(
    r"""(?:[\w-]+\.)*(?:oast\.(?:fun|pro|live|site|online|me)|oastify\.com"""
    r"""|burpcollaborator\.net|interact\.sh|interactsh\.com|pipedream\.net"""
    r"""|webhook\.site|requestbin\.(?:com|net)|requestcatcher\.com|beeceptor\.com"""
    r"""|hookbin\.com|ngrok(?:-free)?\.(?:io|app|dev)|dnslog\.(?:cn|link)|ceye\.io"""
    r"""|canarytokens\.(?:com|org)|trycloudflare\.com|bf\.gy|ptrace\.dev"""
    r"""|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)"""
    r"""|https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.))"""
    r"""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""",
    re.IGNORECASE,
)

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
_JS_RECON_RE = re.compile(
    r"""\b(?:hostname|userInfo|networkInterfaces)\s*\(\s*\)"""
    r"""|(?:JSON\.stringify|Object\.(?:keys|entries|values))\s*\(\s*process\.env\s*[,)]"""
    r"""|\bwhoami\b|/etc/passwd"""
    r"""|ipinfo\.io|ifconfig\.me|api\.ipify\.org|icanhazip\.com|checkip\.amazonaws\.com"""
    r"""|ip-api\.com""",
)

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
    r"""\b(?:exec|eval)\s*\([^\n]{0,200}\b(?:urlopen|requests\.get|urlretrieve)\s*\(""")
_JS_OBFUSCATOR_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_JS_DYNAMIC_EVAL_RE = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`]")
_JS_DECODE_RE = re.compile(
    r"""\batob\s*\(|['"]base64['"]|String\.fromCharCode\s*\(|\\x[0-9a-fA-F]{2}"""
    r"""|\.charCodeAt\s*\(|\bdecodeURIComponent\s*\(""")
_NUM_ARRAY_RE = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){99,}")

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
# ``src.scanner.artifact_scan``, which uses PY_RECON_CALLS and OOB_HOST_RE)
# ---------------------------------------------------------------------------

# Calls that read who / where the installing machine is.
PY_RECON_CALLS = frozenset({
    "gethostname", "getfqdn", "gethostbyname", "getuser", "getlogin", "uname", "node",
    "getpwuid",
})
_PY_NET_RE = re.compile(
    r"""^\s*(?:import|from)\s+(?:requests|httpx|urllib3?|aiohttp|socket|http\.client"""
    r"""|urllib\.request|pycurl|dns)\b|\burlopen\s*\(""",
    re.MULTILINE,
)
_PY_RECON_RE = re.compile(
    r"""\b(?:gethostname|getfqdn|getuser|getlogin)\s*\(|\bplatform\.(?:node|uname)\s*\("""
    r"""|\bos\.uname\s*\(|\bdict\(\s*os\.environ\s*\)|\bos\.environ\.copy\s*\("""
    r"""|\bwhoami\b|ipinfo\.io|ifconfig\.me|api\.ipify\.org""",
)


def common_signals(text: str, out: set[str] | None = None) -> set[str]:
    """The signals read the same way in any language: ``oob``, ``creds``, ``persist``,
    ``dropper``."""
    out = set() if out is None else out
    if OOB_HOST_RE.search(text):
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
    out: set[str] = set()
    if _PY_NET_RE.search(text):
        out.add("net")
    if _PY_RECON_RE.search(text):
        out.add("recon")
    return common_signals(text, out)


def _is_obfuscated_js(text: str) -> bool:
    if len(_JS_OBFUSCATOR_RE.findall(text[:400_000])) >= 10:
        return True
    if _NUM_ARRAY_RE.search(text) and _JS_DYNAMIC_EVAL_RE.search(text):
        return True
    return bool(_JS_DYNAMIC_EVAL_RE.search(text) and _JS_DECODE_RE.search(text))


def js_signals(text: str) -> set[str]:
    """Signals in JavaScript an install hook runs: ``net``, ``recon``, ``oob``,
    ``obfuscated``, ``creds``, ``persist``, ``dropper``."""
    out: set[str] = set()
    if _JS_NET_RE.search(text):
        out.add("net")
    if _JS_RECON_RE.search(text):
        out.add("recon")
    if _is_obfuscated_js(text):
        out.add("obfuscated")
    return common_signals(text, out)


def shell_signals(text: str) -> set[str]:
    """Signals in a shell command / script an install hook runs."""
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
