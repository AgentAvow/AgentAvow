"""Precision for the critical "curl/wget piped to shell" rule (DNC sample, 2026-10-19).

The rule was the top finding on 44 of 57 Do-not-connect repos, and a false alarm or too
harsh in every sampled case. :func:`classify` looks at each match on a line and says
what it is:

* ``DROP``: not a command. No target at all or only a placeholder (``curl ... | sh``,
  ``curl <url> | bash``); a regex in a detection table
  (``curl.*\\| *sh``); or, in Markdown / agent-instruction / JSON text, a sentence that
  forbids it ("Refuse `curl ... | bash`", "`curl … | sh` in a bug report is an
  attack"). A negation must GOVERN the command: "Don't worry, just run curl … | sh"
  is an instruction and stays.
* ``OFFICIAL``: an HTTPS installer from a host on :data:`VENDOR_INSTALLERS` (uv from
  astral.sh, rustup, Docker, Claude Code …). Reported **high** (Review), not critical.
* ``OWN_CANDIDATE``: a clean HTTPS URL on an unlisted host. Critical from the per-file
  pass; :func:`lower_own_domain` lowers it to high when the host is the project's own
  (homepage / repository host, or the scanned repo's GitHub owner).
* ``CRITICAL``: everything else, kept as it was: ``http://``, ``--insecure``, raw IP
  hosts, paste / file-drop hosts and URL shorteners, a URL or target built from
  variables, base64 on the line, and unknown hosts.

A dev / CI script (``.github/``, ``build-docs.sh``) is handled by the existing
``shipped: false`` path in ``src.scanner.scan`` (``_is_unshipped_script``), not here.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

PIPE_TO_SHELL = "curl/wget piped to shell"

DROP = "drop"
OFFICIAL = "official"
OWN_CANDIDATE = "own_candidate"
CRITICAL = "critical"
_RANK = {DROP: 0, OFFICIAL: 1, OWN_CANDIDATE: 2, CRITICAL: 3}

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
)

# Never a project's "own" domain (shared platforms, paste / file-drop hosts, shorteners).
_PLATFORM_HOSTS = frozenset({
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org",
    "sourceforge.net", "npmjs.com", "npmjs.org", "pypi.org", "crates.io", "docs.rs",
    "huggingface.co", "readthedocs.org", "google.com", "googleusercontent.com",
    "x.com", "twitter.com", "discord.gg", "discord.com", "discordapp.com",
    "linkedin.com", "medium.com", "notion.site", "youtube.com",
    # paste / file-drop hosts
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "transfer.sh", "file.io",
    "0x0.st", "termbin.com", "ix.io", "sprunge.us", "dpaste.com", "dpaste.org",
    "rentry.co", "paste.rs", "catbox.moe",
    # URL shorteners
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "cutt.ly", "ow.ly",
    "shorturl.at", "tiny.cc", "git.io",
})
# Shared hosting suffixes: the project's own domain is the full subdomain.
_SHARED_SUFFIXES = (
    "github.io", "gitlab.io", "readthedocs.io", "vercel.app", "netlify.app", "pages.dev",
    "herokuapp.com", "web.app", "firebaseapp.com", "workers.dev", "fly.dev",
    "onrender.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "appspot.com",
)
_SLD_SUFFIXES = frozenset({"co", "com", "net", "org", "ac", "gov", "edu"})
# RFC 2606 / documentation hosts: never a project's own domain. (A pipe-to-shell of
# one is NOT dropped: tests and attack write-ups use them for real payload shapes.)
_PLACEHOLDER_HOST_RE = re.compile(
    r"^(?:[\w-]+\.)*example\.(?:com|org|net)$|^(?:[\w-]+\.)+(?:example|invalid|test)$"
    r"|^<.*>$")

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

_PROSE_EXTS = frozenset({".md", ".mdx", ".mdc", ".markdown", ".txt", ".rst",
                         ".json", ".jsonc"})
# A sentence break: . ! ? followed by whitespace, not part of an ellipsis.
_SENTENCE_END_RE = re.compile(r"""(?<![.\s])[.!?](?!\.)(?=\s|$)""")
# Words allowed between a negation and its verb ("never blindly run", "do not ever pipe").
_FILLER = (r"(?:ever|blindly|directly|simply|just|automatically|anything|any|commands?|"
           r"scripts?|code|like|such|as|this|that|these|the|a|an|remote|untrusted|"
           r"unknown|unverified|installers?|via|it|them|yourself)")
_ACTION = (r"(?:run|running|pipe|piping|execute|executing|exec|use|using|install|"
           r"installing|copy|paste|follow|trust|accept|allow|suggest|recommend|emit|"
           r"generate|output|do|curl|wget|fetch)")
_NEG_CUE_RE = re.compile(
    r"\b(?:(?:never|do\s+not|don['’]?t|must\s+not|mustn['’]?t|should\s+not|"
    r"shouldn['’]?t|cannot|can['’]?t|won['’]?t|will\s+not|may\s+not|refuse\s+to)"
    rf"(?:\s+{_FILLER})*\s+{_ACTION}\b"
    r"|(?:refuse[sd]?|reject(?:s|ed)?|block(?:s|ed)?|den(?:y|ies|ied)|forbid(?:s|den)?|"
    r"prohibit(?:s|ed)?|disallow(?:s|ed)?|avoid(?:s|ed)?|warn(?:s|ed)?\s+against|"
    r"flag(?:s|ged)?)\b)",
    re.IGNORECASE)
# Between the cue and the command: a clause break means the cue governs something else
# ("Don't worry, just run …", "Never use sudo; run …").
_CLAUSE_BREAK_RE = re.compile(
    r";|\b(?:but|just|instead|then|however|rather|otherwise|unless|except|now)\b|"
    r",\s*(?:and\s+)?(?:run|use|execute|type|paste|do|try|install)\b",
    re.IGNORECASE)
# After the command, a short prepositional phrase then a verdict on it.
_POST_CUE_RE = re.compile(
    r"""^[\s`'"*)\]]*(?:[-—–:]\s*)?(?:(?:in|from|inside|within|on|via|of|or)\b[^,;:]{0,40}?)?"""
    r"""\s*(?:must\s+(?:(?:always|never)\s+)?be\s+(?:rejected|refused|blocked|denied|"""
    r"""flagged)|must\s+never|(?:is|are)\s+(?:always\s+)?(?:an?\s+)?(?:attacks?|red\s+flags?|"""
    r"""anti-?patterns?|forbidden|prohibited|banned|blocked|not\s+allowed|never\s+allowed|"""
    r"""malicious|dangerous|unsafe)\b|should\s+(?:never|not)\s+be\b|(?:is|are)\s+never\b)""",
    re.IGNORECASE)
_ANTI_PATTERN_RE = re.compile(r"(?<!not an )(?<!not a )\banti-?pattern\b", re.IGNORECASE)

WHY_OFFICIAL = ("Pipes a well-known vendor's official installer (HTTPS) to a shell. It "
                "runs whatever that host serves at install time, so review it, or pin a "
                "version / checksum.")
WHY_OWN = ("Pipes the project's own installer (HTTPS, from its homepage / repository "
           "host) to a shell. It runs whatever that host serves at install time, so "
           "review it, or pin a version / checksum.")


def _registrable(host: str) -> str:
    h = host.lower().rstrip(".")
    for suf in _SHARED_SUFFIXES:
        if h.endswith("." + suf):
            labels = h.split(".")
            return ".".join(labels[-(suf.count(".") + 2):])
    labels = [x for x in h.split(".") if x]
    if len(labels) < 2:
        return h
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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
    if _ANTI_PATTERN_RE.search(before + " " + after):
        return True
    if _POST_CUE_RE.match(after):
        return True
    cues = list(_NEG_CUE_RE.finditer(before))
    if not cues:
        return False
    gap = before[cues[-1].end():]
    return len(gap) <= 100 and not _CLAUSE_BREAK_RE.search(gap)


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


def _url_class(url: str) -> tuple[str, str]:
    """(class, host) for one URL in a target."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return CRITICAL, ""
    if parts.scheme.lower() != "https" or not host or _is_ip(host):
        return CRITICAL, host
    if _registrable(host) in _PLATFORM_HOSTS and host != "raw.githubusercontent.com" \
            and host != "github.com":
        return CRITICAL, host
    path = (parts.path or "/").lower()
    for vhost, prefix in VENDOR_INSTALLERS:
        if host == vhost and path.startswith(prefix):
            return OFFICIAL, host
    return OWN_CANDIDATE, host


def classify_match(line: str, start: int, end: int, file_path: str) -> tuple[str, list[str]]:
    """Classify one pipe-to-shell match. Returns ``(class, urls)``; ``urls`` lists the
    candidate URLs for :func:`lower_own_domain` when the class is OWN_CANDIDATE."""
    target = _target(line, start, end)
    matched = line[start:end]
    urls = _URL_RE.findall(target)
    pipe = matched.rfind("|")
    if (pipe > 0 and matched[pipe - 1] == "\\") or (
            not urls and _REGEX_SHAPE_RE.search(target)):
        return DROP, []
    has_var = bool(_VAR_RE.search(target))
    if not urls and not has_var:
        args = [a.strip("'\"`*") for a in target.split()]
        real = [a for a in args if a and not a.startswith("-")]
        if not real or all(_PLACEHOLDER_ARG_RE.match(a) for a in real):
            return DROP, []
    if Path(file_path).suffix.lower() in _PROSE_EXTS and _prohibited(line, start, end):
        return DROP, []
    if has_var or not urls or _INSECURE_FLAG_RE.search(target) or _BASE64_RE.search(line):
        return CRITICAL, []
    worst, cands = OFFICIAL, []
    for u in urls:
        cls, _host = _url_class(u)
        if _RANK[cls] > _RANK[worst]:
            worst = cls
        if cls == OWN_CANDIDATE:
            cands.append(u)
    return worst, (cands if worst == OWN_CANDIDATE else [])


def classify_line(line: str, pattern: re.Pattern[str], file_path: str
                  ) -> tuple[str, list[str]]:
    """The worst class over every pipe-to-shell match on ``line``."""
    worst, cands = DROP, []
    for m in pattern.finditer(line):
        cls, urls = classify_match(line, m.start(), m.end(), file_path)
        if _RANK[cls] > _RANK[worst]:
            worst = cls
        cands.extend(urls)
    return worst, (cands if worst == OWN_CANDIDATE else [])


# --------------------------------------------------------------------------- #
# Own domain: lowers an OWN_CANDIDATE critical to high once the project is known.

_MANIFEST_URL_RE = re.compile(
    r"""^\s*["']?(?:homepage|home[-_]page|url|website|documentation|repository|source|"""
    r"""download[-_]url)["']?\s*[:=]\s*["']?(?:git\+)?(https://[^\s"'<>,]+)""",
    re.IGNORECASE | re.MULTILINE)
_MANIFEST_NAMES = frozenset({"package.json", "pyproject.toml", "setup.cfg", "setup.py",
                             "cargo.toml"})


def own_identity(texts: dict[str, str] | None = None, owner: str | None = None,
                 homepage: str | None = None) -> tuple[set[str], set[str]]:
    """``(own registrable domains, own GitHub owners)`` from the shallowest manifests in
    ``texts``, the repository's GitHub owner and its GitHub homepage."""
    domains: set[str] = set()
    owners: set[str] = {owner.lower()} if owner else set()
    urls: list[str] = [homepage] if homepage else []
    manifests = [p for p in (texts or {}) if Path(p).name.lower() in _MANIFEST_NAMES]
    if manifests:
        depth = min(p.count("/") for p in manifests)
        for p in manifests:
            if p.count("/") != depth:
                continue
            text = texts[p] or ""
            urls.extend(_MANIFEST_URL_RE.findall(text))
            if p.lower().endswith("package.json"):
                urls.extend(_package_json_urls(text))
    for u in urls:
        try:
            parts = urlsplit(u.strip())
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if parts.scheme.lower() != "https" or not host or _is_ip(host):
            continue
        if host == "github.com":
            seg = [s for s in parts.path.split("/") if s]
            if seg:
                owners.add(seg[0].lower())
            continue
        reg = _registrable(host)
        if reg in _PLATFORM_HOSTS or _PLACEHOLDER_HOST_RE.match(host):
            continue
        domains.add(reg)
    return domains, owners


def _package_json_urls(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out = []
    for key in ("homepage", "repository", "bugs"):
        v = data.get(key)
        if isinstance(v, dict):
            v = v.get("url")
        if isinstance(v, str):
            out.append(v.removeprefix("git+"))
    return out


def _is_own(url: str, domains: set[str], owners: set[str]) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    seg = [s.lower() for s in parts.path.split("/") if s]
    if host in ("raw.githubusercontent.com", "github.com"):
        return bool(seg) and seg[0] in owners
    if host.endswith(".github.io") and host[:-len(".github.io")] in owners:
        return True
    return _registrable(host) in domains


def lower_own_domain(findings: list, texts: dict[str, str] | None = None,
                     owner: str | None = None, homepage: str | None = None) -> None:
    """Lower each OWN_CANDIDATE pipe-to-shell critical whose every URL is the project's
    own to high (Review). Mutates ``findings``."""
    pending = [f for f in findings if getattr(f, "pipe_urls", None)
               and f.severity == "critical" and f.name == PIPE_TO_SHELL]
    if not pending:
        return
    domains, owners = own_identity(texts, owner, homepage)
    if not domains and not owners:
        return
    for f in pending:
        if all(_is_own(u, domains, owners) for u in f.pipe_urls):
            f.severity = "high"
            f.remediation = WHY_OWN
