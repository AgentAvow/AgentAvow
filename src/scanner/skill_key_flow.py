"""Where does a skill script send the API key it reads?

A bundled skill script that reads a secret-named environment variable used to be a
critical "exfiltration" finding on sight. That is right for an unknown secret
(``AWS_SECRET_ACCESS_KEY``, ``GITHUB_TOKEN``), but a skill that reads
``ANTHROPIC_API_KEY`` and calls the Anthropic API with it is doing its job.

Rule (Kenne, 2026-10-10): reading a known vendor's API key is critical only when the
key, or a value built from it, reaches a network call whose destination is not that
vendor's own API domain, or whose destination can't be resolved from the script.
Otherwise it is a low capability note: "uses your <Vendor> API key".

An unknown key counts as its own vendor's only in one strict case: its name minus the
key suffix, lowercased with underscores dropped (``BROWSER_ACT_API_KEY`` →
``browseract``, at least 4 characters), equals the registrable label of EVERY host the
key reaches (``api.browseract.com``), it reaches at least one, and none is unresolved.
Anything else about an unknown key stays critical.

The check follows the value, not proximity: it taints the variable the key is
assigned to (and values built from it, such as a headers dict), then looks at the
network calls that carry a tainted value and resolves their URL from string
literals in the call or from variables assigned a URL literal. It is deliberately
conservative: a call carrying the key to a destination it can't resolve counts as
leaving the vendor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Known vendor key names → (vendor display name, API domains the key belongs to).
VENDOR_KEYS: dict[str, tuple[str, tuple[str, ...]]] = {
    "ANTHROPIC_API_KEY": ("Anthropic", ("anthropic.com",)),
    "CLAUDE_API_KEY": ("Anthropic", ("anthropic.com",)),
    "OPENAI_API_KEY": ("OpenAI", ("openai.com",)),
    "GEMINI_API_KEY": ("Google Gemini", ("googleapis.com",)),
    "GOOGLE_API_KEY": ("Google", ("googleapis.com",)),
    "MISTRAL_API_KEY": ("Mistral", ("mistral.ai",)),
    "COHERE_API_KEY": ("Cohere", ("cohere.ai", "cohere.com")),
    "GROQ_API_KEY": ("Groq", ("groq.com",)),
    "OPENROUTER_API_KEY": ("OpenRouter", ("openrouter.ai",)),
    "PERPLEXITY_API_KEY": ("Perplexity", ("perplexity.ai",)),
    "DEEPSEEK_API_KEY": ("DeepSeek", ("deepseek.com",)),
    "TOGETHER_API_KEY": ("Together AI", ("together.xyz", "together.ai")),
    "XAI_API_KEY": ("xAI", ("x.ai",)),
    "ELEVENLABS_API_KEY": ("ElevenLabs", ("elevenlabs.io",)),
    "REPLICATE_API_TOKEN": ("Replicate", ("replicate.com",)),
    "HF_TOKEN": ("Hugging Face", ("huggingface.co",)),
    "HUGGINGFACE_API_KEY": ("Hugging Face", ("huggingface.co",)),
    "EXA_API_KEY": ("Exa", ("exa.ai",)),
    "TAVILY_API_KEY": ("Tavily", ("tavily.com",)),
    "FIRECRAWL_API_KEY": ("Firecrawl", ("firecrawl.dev",)),
}

# A secret-named env var READ through an accessor ($VAR, ${VAR}, os.environ[...] /
# .get(...), os.getenv(...), process.env.VAR / ["VAR"], ENV["VAR"], os.Getenv("VAR")).
# Case-sensitive on the name: env vars are UPPER_SNAKE.
SECRET_ENV_READ_RE = re.compile(
    r"(?:\$\{?|\benviron(?:\.get)?\s*[\[(]\s*[\"']|\bgetenv\s*\(\s*[\"']"
    r"|\bprocess\.env(?:\.|\[\s*[\"'])|\bENV\[\s*[\"']|\bGetenv\(\s*\")"
    r"([A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD))\b"
)

# Calls that send a request. Generic `<obj>.get/.post(...)` only count when the call
# also names a URL, a URL variable, or auth headers (see _is_request_call).
_NET_CALL_RE = re.compile(
    r"\b(?:curl|wget)\b"
    r"|requests\.(?:get|post|put|patch|delete|request|head)\s*\("
    r"|httpx\.(?:get|post|put|patch|delete|request|stream)\s*\("
    r"|urllib\.request\.(?:urlopen|Request)\s*\(|\burlopen\s*\(|\bRequest\s*\("
    r"|http\.client\.\w+\s*\(|\bfetch\s*\(|\baxios(?:\.\w+)?\s*\("
    r"|\bnew\s+WebSocket\s*\("
    r"|\b\w+\.(?:post|put|patch|request|get|send)\s*\("
)
_STRICT_NET_RE = re.compile(
    r"\b(?:curl|wget)\b|requests\.|httpx\.|urllib\.request|\burlopen\s*\("
    r"|http\.client|\bfetch\s*\(|\baxios\b|\bWebSocket\s*\("
)
_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_BASE_URL_RE = re.compile(r"\b(?:base_url|baseURL|api_base|base_path)\s*[=:]\s*([^,)\n]+)")
# Assignment targets may be dotted (``self.headers = {...}``, ``this.key = ...``).
_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|(?:const|let|var|local)\s+)?([A-Za-z_][\w.]*)\s*(?::\s*[^=]+)?"
    r"(?::=|=)(?!=)\s*(.+)$"
)
_ITEM_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\[[^\]]*\]\s*=(?!=)\s*(.+)$")


@dataclass
class KeyUse:
    env_name: str
    vendor: str | None            # None = not a known vendor key
    leaves_vendor: bool = False   # True = critical (or unknown key)
    destinations: list[str] = field(default_factory=list)  # offending hosts ("?" = unresolved)


_KEY_SUFFIX_RE = re.compile(
    r"_(?:API_KEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|SECRET_KEY|KEY|TOKEN|SECRET|PASSWORD)$")
# Second-level labels under which the registrable label sits one further left
# (example.co.uk, example.com.au).
_SLD_SUFFIXES = {"co", "com", "net", "org", "ac", "gov", "edu"}


def _name_prefix(env_name: str) -> str:
    """BROWSER_ACT_API_KEY -> "browseract"; "" when too short to trust (< 4 chars)."""
    stem = _KEY_SUFFIX_RE.sub("", env_name)
    if stem == env_name:
        return ""
    p = stem.replace("_", "").lower()
    return p if len(p) >= 4 else ""


def _registrable_label(host: str) -> str:
    labels = [x for x in host.lower().rstrip(".").split(".") if x]
    if len(labels) < 2:
        return ""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_SUFFIXES:
        return labels[-3]
    return labels[-2]


def _host_ok(host: str, domains: tuple[str, ...]) -> bool:
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def _logical_lines(text: str) -> list[str]:
    """Join shell/Python backslash continuations so a multi-line curl is one line."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        out.append(buf + raw)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _call_text(text: str, start: int) -> str:
    """The call starting at ``start``: through its balanced closing paren, or the
    rest of the line for a shell command (curl/wget)."""
    nl = text.find("\n", start)
    line_end = len(text) if nl == -1 else nl
    paren = text.find("(", start, line_end + 1)
    if paren == -1:
        return text[start:line_end]
    depth, i, quote = 0, paren, ""
    limit = min(len(text), paren + 4000)
    while i < limit:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return text[start:limit]


def _assignments(lines: list[str]) -> list[tuple[str, str]]:
    """(target, right-hand side) per assignment. A right-hand side that opens a
    bracket (``headers = {`` … ``}``) runs on until it balances, up to 30 lines."""
    out: list[tuple[str, str]] = []
    for i, ln in enumerate(lines):
        m = _ASSIGN_RE.match(ln) or _ITEM_ASSIGN_RE.match(ln)
        if not m:
            continue
        rhs = m.group(2)
        depth = sum(rhs.count(c) for c in "([{") - sum(rhs.count(c) for c in ")]}")
        j = i + 1
        while depth > 0 and j < min(len(lines), i + 30):
            rhs += "\n" + lines[j]
            depth += sum(lines[j].count(c) for c in "([{") - sum(lines[j].count(c) for c in ")]}")
            j += 1
        out.append((m.group(1), rhs))
    return out


def _mentions(chunk: str, tokens: set[str]) -> bool:
    return any(re.search(r"(?<![\w$])\$?\{?" + re.escape(t) + r"\b", chunk) for t in tokens)


def analyze(text: str) -> list[KeyUse]:
    """One KeyUse per distinct secret-named env var the script reads."""
    names = sorted(set(SECRET_ENV_READ_RE.findall(text or "")))
    if not names:
        return []
    joined = "\n".join(_logical_lines(text))
    lines = joined.splitlines()

    # URL-valued variables: NAME = "https://host/..." (first literal on the RHS).
    url_vars: dict[str, list[str]] = {}
    for ln in lines:
        m = _ASSIGN_RE.match(ln)
        if m:
            hosts = _URL_RE.findall(m.group(2))
            if hosts:
                url_vars.setdefault(m.group(1), []).extend(hosts)
    base_hosts = [h for m in _BASE_URL_RE.finditer(joined) for h in _URL_RE.findall(m.group(1))]
    for m in _BASE_URL_RE.finditer(joined):
        rhs = m.group(1).strip()
        if rhs in url_vars:
            base_hosts.extend(url_vars[rhs])

    calls = []
    for m in _NET_CALL_RE.finditer(joined):
        chunk = _call_text(joined, m.start())
        head = joined[m.start():m.end()]
        if head.startswith(("environ.", "env.", "os.")) or ".getenv" in head:
            continue  # os.environ.get(...) is the key read, not a request
        strict = bool(_STRICT_NET_RE.match(joined, m.start()))
        if not strict:
            named_url = _URL_RE.search(chunk) or any(
                re.search(r"\b" + re.escape(v) + r"\b", chunk) for v in url_vars)
            if not (named_url or re.search(r"(?i)headers|authorization|x-api-key|auth=", chunk)):
                continue
        calls.append(chunk)

    assigns = _assignments(lines)

    def reached(name: str) -> list[str]:
        """Every host the key (or a value built from it) is sent to; "?" = unresolved."""
        # Taint: the env name itself, the variables it is assigned to, and values
        # built from them (one assignment chain at a time, to a fixed point).
        tainted = {name}
        for _ in range(4):
            grew = False
            for target, rhs in assigns:
                if target not in tainted and _mentions(rhs, tainted):
                    tainted.add(target)
                    grew = True
            if not grew:
                break
        out: list[str] = []
        for chunk in calls:
            if not _mentions(chunk, tainted):
                continue
            hosts = list(_URL_RE.findall(chunk))
            for v, vh in url_vars.items():
                if re.search(r"\b" + re.escape(v) + r"\b", chunk):
                    hosts.extend(vh)
            out.extend(hosts or ["?"])
        # An SDK client pointed at a base URL sends the key there.
        out.extend(base_hosts)
        return out

    uses: list[KeyUse] = []
    for name in names:
        vendor = VENDOR_KEYS.get(name)
        if vendor is None:
            # Unknown key: its own vendor's only if every destination's registrable
            # label equals the key-name prefix (strict; see the module docstring).
            prefix = _name_prefix(name)
            hosts = reached(name) if prefix else []
            if hosts and "?" not in hosts and all(
                    _registrable_label(h) == prefix for h in hosts):
                labels = hosts[0].lower().rstrip(".").split(".")
                domain = ".".join(labels[labels.index(prefix):])
                uses.append(KeyUse(name, domain, leaves_vendor=False))
            else:
                uses.append(KeyUse(name, None, leaves_vendor=True))
            continue
        vname, domains = vendor
        bad = [h for h in reached(name) if h == "?" or not _host_ok(h, domains)]
        uses.append(KeyUse(name, vname, leaves_vendor=bool(bad),
                           destinations=sorted(set(bad))))
    return uses
