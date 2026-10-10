"""Where does a skill script send the API key it reads?

A bundled skill script that reads a secret-named environment variable used to be a
critical "exfiltration" finding on sight. That is right for an unknown secret
(``AWS_SECRET_ACCESS_KEY``, ``GITHUB_TOKEN``), but a skill that reads
``ANTHROPIC_API_KEY`` and calls the Anthropic API with it is doing its job.

Rule (Kenne, 2026-10-10): reading a known vendor's API key is critical only when the
key, or a value built from it, reaches a network call whose destination is not that
vendor's own API domain, or whose destination can't be resolved from the script.
Otherwise it is a low capability note: "uses your <Vendor> API key".

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
_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|(?:const|let|var|local)\s+)?([A-Za-z_]\w*)\s*(?::\s*[^=]+)?(?::=|=)(?!=)\s*(.+)$"
)
_ITEM_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=(?!=)\s*(.+)$")


@dataclass
class KeyUse:
    env_name: str
    vendor: str | None            # None = not a known vendor key
    leaves_vendor: bool = False   # True = critical (or unknown key)
    destinations: list[str] = field(default_factory=list)  # offending hosts ("?" = unresolved)


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

    uses: list[KeyUse] = []
    for name in names:
        vendor = VENDOR_KEYS.get(name)
        if vendor is None:
            uses.append(KeyUse(name, None, leaves_vendor=True))
            continue
        vname, domains = vendor
        # Taint: the env name itself, the variables it is assigned to, and values
        # built from them (one assignment chain at a time, to a fixed point).
        tainted = {name}
        for _ in range(4):
            grew = False
            for ln in lines:
                m = _ASSIGN_RE.match(ln) or _ITEM_ASSIGN_RE.match(ln)
                if m and m.group(1) not in tainted and _mentions(m.group(2), tainted):
                    tainted.add(m.group(1))
                    grew = True
            if not grew:
                break
        bad: list[str] = []
        for chunk in calls:
            if not _mentions(chunk, tainted):
                continue
            hosts = list(_URL_RE.findall(chunk))
            for v, vh in url_vars.items():
                if re.search(r"\b" + re.escape(v) + r"\b", chunk):
                    hosts.extend(vh)
            if not hosts:
                bad.append("?")
            bad.extend(h for h in hosts if not _host_ok(h, domains))
        # An SDK client pointed at a non-vendor base URL sends the key there.
        bad.extend(h for h in base_hosts if not _host_ok(h, domains))
        uses.append(KeyUse(name, vname, leaves_vendor=bool(bad),
                           destinations=sorted(set(bad))))
    return uses
