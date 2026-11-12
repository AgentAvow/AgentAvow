"""Precision for the critical "curl/wget piped to shell" rule (DNC sample, 2026-10-19).

The rule was the top finding on 44 of 57 Do-not-connect repos, and a false alarm or too
harsh in every sampled case. :func:`classify_line` looks at each match on a line and
says what it is:

* ``DROP``: not a command. No target at all or only a placeholder (``curl ... | sh``,
  ``curl <url> | bash``); a regex in a detection table (an escaped ``\\|``, or regex
  syntax with no URL); or, in a PROSE file (Markdown / text / reST, never JSON or a
  script), a sentence that forbids it: "never / do not / don't / refuse to (run | pipe
  | execute | use) <the command>", where the negation governs that verb, or "<the
  command> is an attack / is malicious / is forbidden / is unsafe / must be rejected".
  "Don't worry, just run curl … | sh" is an instruction and stays critical.
* ``OFFICIAL``: exactly one HTTPS URL on :data:`VENDOR_INSTALLERS` (uv from astral.sh,
  rustup, Docker, Claude Code …), no other argument, and no curl / wget flag that reads
  a config, adds a URL or proxy, or writes a file. Reported **high** (Review). Never in
  an install-lifecycle file (package.json scripts, setup.py): those stay critical.
* ``CRITICAL``: everything else, as before: ``http://``, ``--insecure``, raw IP hosts,
  paste hosts, shorteners, a target built from variables, base64 on the line, any
  other host (including the project's own: an author-declared homepage proves nothing
  for a package that is malicious from day one), extra arguments, a second URL.

A dev / CI script (``.github/``, ``build-docs.sh``) is handled by the existing
``shipped: false`` path in ``src.scanner.scan`` (``_is_unshipped_script``), not here.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

PIPE_TO_SHELL = "curl/wget piped to shell"

DROP = "drop"
OFFICIAL = "official"
PINNED = "pinned"
CRITICAL = "critical"
_RANK = {DROP: 0, OFFICIAL: 1, PINNED: 1, CRITICAL: 2}

# A raw GitHub file at a full 40-hex commit SHA: the bytes fetched can never change,
# which is what the rule's own remediation asks for ("pin remote payloads by commit
# SHA"; colinhacks/zod's devcontainer, 2026-11-11). Reported high (Review), never in an
# install hook. Residual risk, accepted: a repo owner can name a BRANCH as 40 hex
# characters; the answer is still Review, never Safe.
_PINNED_RAW_RE = re.compile(
    r"^https://(?:raw\.githubusercontent\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/"
    r"|github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/raw/)[0-9a-f]{40}/[^\s?#]+$")

# Reviewed allowlist of well-known official installers, as (host, path prefix). Only
# HTTPS URLs qualify, and the path prefix pins the installer itself where the host also
# serves third-party content (deno.land/x, raw.githubusercontent.com). Keep it short:
# every entry turns a critical into a Review for anyone who pipes that URL to a shell.
VENDOR_INSTALLERS: tuple[tuple[str, str], ...] = (
    ("astral.sh", "/"),                                   # uv, ruff
    ("sh.rustup.rs", "/"),                                # rustup
    ("get.docker.com", "/"),                              # Docker convenience script
    ("deno.land", "/install.sh"),                         # Deno
    ("bun.sh", "/install"),                               # Bun
    ("claude.ai", "/install.sh"),                         # Claude Code
    ("raw.githubusercontent.com", "/homebrew/install/"),  # Homebrew
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),        # nvm
    ("pyenv.run", "/"),                                   # pyenv
    ("get.pnpm.io", "/install.sh"),                       # pnpm
    ("ollama.com", "/install.sh"),                        # Ollama
    # Round 2 (2026-10-19), each checked against the vendor's own install docs:
    ("ollama.ai", "/install.sh"),                         # Ollama (older domain)
    ("foundry.paradigm.xyz", "/"),                        # Foundry (foundryup)
    ("raw.githubusercontent.com", "/leanprover/elan/master/elan-init.sh"),  # elan
    ("elan.lean-lang.org", "/elan-init.sh"),              # elan (current docs)
    ("aider.chat", "/install.sh"),                        # aider
    ("func-e.io", "/install.sh"),                         # func-e (Tetrate)
    # Round 3 (2026-11-10): the `hf` CLI installer, as huggingface.co/docs/
    # huggingface_hub/installation gives it (hf.co redirects to huggingface.co).
    ("hf.co", "/cli/install.sh"),                         # Hugging Face hf CLI
    ("huggingface.co", "/cli/install.sh"),                # Hugging Face hf CLI
)

_TOOL_RE = re.compile(r"\b(?:curl|wget)\b")
_URL_RE = re.compile(r"""(?:https?|ftp)://[^\s'"`)|>\]]+""", re.IGNORECASE)
# A target the shell expands: $VAR, ${VAR}, $(cmd), `cmd`, %VAR%, {{ template }}.
_VAR_RE = re.compile(r"""\$\{?\w|\$\(|`[^`]*\$|%\w+%|\{\{""")
_PLACEHOLDER_ARG_RE = re.compile(r"""^(?:\.{2,}|…+|<[^>]*>|\[[^\]]*\]|url|URL|\.\.\.\w*)$""")
_INSECURE_FLAG_RE = re.compile(r"""(?:^|\s)(?:-k|--insecure|--no-check-certificate)\b""")
_BASE64_RE = re.compile(r"""\bbase64\b|\batob\s*\(|\bb64decode\b""", re.IGNORECASE)
# Regex syntax around the target: a detection pattern, not a command. Counted only
# with no URL in the target (a `?.*` in a real URL's query is not a regex), or when
# the pipe itself is escaped (`\|` is a literal bar, never a pipe).
_REGEX_SHAPE_RE = re.compile(r"""\.\*|\.\+|\\[sSwWdb]|\[\^|\(\?[:!=<]""")
# A token that names a host without a scheme (`evil.com/x`, `evil\.com`): curl / wget
# fetch it, so regex syntax elsewhere in the target never makes it a pattern.
_HOSTISH_RE = re.compile(
    r"""(?<![\w\\])[A-Za-z0-9-]+(?:\\?\.[A-Za-z0-9-]+)*\\?\.[A-Za-z]{2,}"""
    # ...or a raw IPv4 target (`1.2.3.4/x.*`, `1.2.3.4:8080/i`)
    r"""|(?<![\w.\\])\d{1,3}(?:\\?\.\d{1,3}){3}(?::\d+)?(?=[/\s'"`]|$)""")
# JS / TS string escapes: "\|" is a plain "|", so an escaped bar there still pipes.
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})

# Prose only: in JSON (package.json scripts, MCP "command" / "args") and in scripts the
# "negation" would sit inside the command string itself.
_PROSE_EXTS = frozenset({".md", ".mdx", ".mdc", ".markdown", ".txt", ".rst"})
# Install-lifecycle files: a pipe-to-shell there runs on install, never lowered.
_INSTALL_HOOK_NAMES = frozenset({"package.json", "setup.py"})
# A sentence break: . ! ? followed by whitespace, not part of an ellipsis.
_SENTENCE_END_RE = re.compile(r"""(?<![.\s])[.!?](?!\.)(?=\s|$)""")
# Words allowed between a negation and its verb ("never blindly run", "do not ever pipe").
_FILLER = (r"(?:ever|blindly|directly|simply|automatically|any|remote|untrusted|unknown|"
           r"unverified)")
_NEG_CUE_RE = re.compile(
    r"\b(?:never|do\s+not|don['’]?t|refuse\s+to)"
    rf"(?:\s+{_FILLER})*\s+(?:run|pipe|execute|use)\b",
    re.IGNORECASE)
# Between the verb and the command: only quoting / markup and a short object phrase. A
# clause break means the cue governs something else ("Never use sudo; run …").
_GAP_OK_RE = re.compile(r"""^[\s`'"*(:]*$""")
# After the command: an optional short location phrase, then a verdict on it.
_POST_CUE_RE = re.compile(
    r"""^[\s`'"*)\]]*(?:(?:in|from|inside|within)\s+[\w\s-]{0,40}?)?"""
    r"""\s*(?:is\s+(?:an?\s+)?(?:attack|malicious|forbidden|unsafe)\b|"""
    r"""must\s+be\s+rejected\b)""",
    re.IGNORECASE)

WHY_PINNED = ("Pipes a script pinned to an exact commit to a shell. The bytes can't change "
              "after you review them, so read that script once before you run it.")

WHY_OFFICIAL = ("Pipes a well-known vendor's official installer (HTTPS) to a shell. It "
                "runs whatever that host serves at install time, so review it, or pin a "
                "version / checksum.")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host))  # decimal-encoded IPv4


def _sentence(line: str, start: int, end: int) -> tuple[str, str]:
    """The text before and after [start, end) within its sentence on ``line``."""
    s = 0
    for m in _SENTENCE_END_RE.finditer(line, 0, start):
        s = m.end()
    m = _SENTENCE_END_RE.search(line, end)
    e = m.start() if m else len(line)
    return line[s:start], line[end:e]


def _prohibited(line: str, start: int, end: int) -> bool:
    """The match at [start, end) sits in a sentence that forbids it."""
    before, after = _sentence(line, start, end)
    if _POST_CUE_RE.match(after):
        return True
    cues = list(_NEG_CUE_RE.finditer(before))
    return bool(cues) and bool(_GAP_OK_RE.match(before[cues[-1].end():]))


def _target(line: str, start: int, end: int) -> str:
    """The text that names what curl / wget fetches for the match at [start, end)."""
    seg = line[start:end]
    tm = _TOOL_RE.search(seg)
    if tm is None:
        return ""
    if "|" in seg[tm.end():]:
        return seg[tm.end():seg.rindex("|")]
    # `python3 <(curl …)`: the arguments run to the closing paren.
    rest = line[start + tm.end():]
    close = rest.find(")")
    return rest if close < 0 else rest[:close]


# curl / wget flags that take a value as the next token (or the rest of a short
# cluster). An unknown flag is assumed to take none, so its value counts as an extra
# argument (critical): the conservative direction.
_SHORT_WITH_VALUE = frozenset("oOHAmwuXdTUEbcrtPY")
_LONG_WITH_VALUE = frozenset({
    "--proto", "--proto-redir", "--header", "--user-agent", "--referer", "--retry",
    "--retry-delay", "--retry-max-time", "--max-time", "--connect-timeout", "--write-out",
    "--user", "--request", "--cacert", "--capath", "--limit-rate", "--max-redirs",
    "--tries", "--timeout", "--wait", "--output", "--output-document",
})
# Flags that read a config, add a URL / proxy / resolver, or name a URL list: the
# fetched script may not come from the URL on the line.
_SHORT_DANGEROUS = frozenset("Kx:iek")
_LONG_DANGEROUS = frozenset({
    "--config", "--next", "--url", "--proxy", "--preproxy", "--resolve", "--connect-to",
    "--doh-url", "--input-file", "--execute", "--socks4", "--socks4a", "--socks5",
    "--socks5-hostname", "--insecure", "--no-check-certificate", "--location-trusted",
})
_OUTPUT_FLAGS = frozenset({"-o", "-O", "--output", "--output-document"})
# Harmless stderr redirections.
_REDIRECT_OK_RE = re.compile(r"^(?:\d?>&\d|2>/dev/null)$")


def _args_clean(target: str) -> bool:
    """The target is flags plus exactly one URL, with no dangerous flag and no output
    to a file (`-o f`, `-O f`: a later `sh f` runs what was saved, not stdout)."""
    toks = [t.strip("'\"`") for t in target.split()]
    i, urls = 0, 0
    while i < len(toks):
        t = toks[i]
        i += 1
        if not t or _REDIRECT_OK_RE.match(t):
            continue
        if t.startswith("--"):
            name, eq, val = t.partition("=")
            if name in _LONG_DANGEROUS:
                return False
            if name in _LONG_WITH_VALUE:
                if not eq:
                    val = toks[i] if i < len(toks) else ""
                    i += 1
                if name in _OUTPUT_FLAGS and val.strip("'\"") != "-":
                    return False
            continue
        if t.startswith("-") and len(t) > 1:
            cluster = t[1:]
            for j, ch in enumerate(cluster):
                if ch in _SHORT_DANGEROUS:
                    return False
                if ch in _SHORT_WITH_VALUE:
                    val = cluster[j + 1:]
                    if not val:
                        val = toks[i] if i < len(toks) else ""
                        i += 1
                    if ch in "oO" and val.strip("'\"") != "-":
                        return False
                    break
            continue
        if _URL_RE.fullmatch(t):
            urls += 1
            continue
        return False  # a scheme-less host, a file, a shell word: not a plain fetch
    return urls == 1


def _is_official(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if parts.scheme.lower() != "https" or not host or _is_ip(host):
        return False
    path = (parts.path or "/").lower()
    return any(host == vhost and path.startswith(prefix)
               for vhost, prefix in VENDOR_INSTALLERS)


# Shell command separators. Only the command after the last one feeds the pipe.
_CMD_SEP_RE = re.compile(r";|&&|\|\||\n")


def _last_command_start(line: str, start: int, end: int) -> int:
    """Where the command that feeds the final ``|`` starts. ``a; curl X | bash`` pipes
    only ``curl X``, so a match that begins at an earlier curl / wget and crosses a
    command separator is read from the curl / wget after the last separator (gradio's
    minified ApiDocs: `curl --version` ... ; ... `curl -LsSf https://hf.co/... | bash`).
    With no separator in between, e.g. two literals that join into one command
    (`curl https://x` + ` | bash`), the start is unchanged: still the conservative read."""
    matched = line[start:end]
    pipe = matched.rfind("|")
    if pipe <= 0:
        return start
    pre = matched[:pipe]
    seps = list(_CMD_SEP_RE.finditer(pre))
    if not seps:
        return start
    tool = _TOOL_RE.search(pre, seps[-1].end())
    return start + tool.start() if tool else start


def classify_match(line: str, start: int, end: int, file_path: str) -> str:
    """Classify one pipe-to-shell match: DROP, OFFICIAL or CRITICAL."""
    start = _last_command_start(line, start, end)
    target = _target(line, start, end)
    matched = line[start:end]
    urls = _URL_RE.findall(target)
    pipe = matched.rfind("|")
    escaped_pipe = (pipe > 0 and matched[pipe - 1] == "\\"
                    and Path(file_path).suffix.lower() not in _JS_EXTS)
    if escaped_pipe or (not urls and _REGEX_SHAPE_RE.search(target)
                        and not _HOSTISH_RE.search(target)):
        return DROP
    has_var = bool(_VAR_RE.search(target))
    if not urls and not has_var:
        args = [a.strip("'\"`*") for a in target.split()]
        real = [a for a in args if a and not a.startswith("-")]
        if not real or all(_PLACEHOLDER_ARG_RE.match(a) for a in real):
            return DROP
    name = Path(file_path).name.lower()
    if Path(file_path).suffix.lower() in _PROSE_EXTS and _prohibited(line, start, end):
        return DROP
    if (has_var or len(urls) != 1 or name in _INSTALL_HOOK_NAMES
            or _BASE64_RE.search(line) or _INSECURE_FLAG_RE.search(target)
            or not _args_clean(target)):
        return CRITICAL
    if _is_official(urls[0]):
        return OFFICIAL
    if _PINNED_RAW_RE.match(urls[0]):
        return PINNED
    return CRITICAL


# RFC 2606 / RFC 6761 names that never reach a third party: the reserved TLDs never
# resolve publicly, and example.{com,net,org} are IANA's documentation hosts.
_RESERVED_TLDS = frozenset({"example", "invalid", "test", "localhost"})
_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_HOST_IN_URL_RE = re.compile(r"""^(?:https?|ftp)://(?:[^@/\s]*@)?([^/:?#\s]+)""", re.IGNORECASE)

WHY_RESERVED_TEST = (
    "A pipe-to-shell string in a test that names only a reserved domain (RFC 2606 / "
    "6761: .example, .invalid, .test, example.com). It cannot fetch anyone's script; it "
    "is sample input (likely a prompt-injection or refusal test)")


def _is_reserved_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return (h.rsplit(".", 1)[-1] in _RESERVED_TLDS
            or any(h == d or h.endswith("." + d) for d in _RESERVED_DOMAINS))


def reserved_hosts_only(line: str, pattern: re.Pattern[str], file_path: str) -> bool:
    """Every pipe-to-shell match on ``line`` fetches from a reserved host (and from
    nothing else): no variable, no extra URL, at least one host per match."""
    any_match = False
    for m in pattern.finditer(line):
        any_match = True
        start = _last_command_start(line, m.start(), m.end())
        target = _target(line, start, m.end())
        if not target or _VAR_RE.search(target):
            return False
        hosts = [hm.group(1) for u in _URL_RE.findall(target)
                 if (hm := _HOST_IN_URL_RE.match(u))]
        if not _URL_RE.search(target):
            hosts = [h.replace("\\.", ".") for h in _HOSTISH_RE.findall(target)]
        if not hosts or not all(_is_reserved_host(h) for h in hosts):
            return False
    return any_match


def why(cls: str | None) -> str:
    """The remediation text for a lowered class ("" for everything else)."""
    return {OFFICIAL: WHY_OFFICIAL, PINNED: WHY_PINNED}.get(cls or "", "")


def classify_line(line: str, pattern: re.Pattern[str], file_path: str) -> str:
    """The worst class over every pipe-to-shell match on ``line``."""
    worst = DROP
    for m in pattern.finditer(line):
        cls = classify_match(line, m.start(), m.end(), file_path)
        if _RANK[cls] > _RANK[worst]:
            worst = cls
    return worst
