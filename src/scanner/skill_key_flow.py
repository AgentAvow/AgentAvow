"""Where does a skill script send the secret it reads?

A bundled skill script that reads a secret-named environment variable used to be a
critical "exfiltration" finding on sight, and later critical unless the key went only
to its own vendor. On the 2026-10-19 Do-not-connect sample that rule was the top
finding on 138 of 147 DNC skills and a false alarm in 8 of 8 sampled cases (comments,
keys read but never sent, keys sent to their own vendor through a ``BASE`` const, keys
sent to an endpoint the user configures). The rule now (Kenne approved, 2026-10-19):

1. Commented-out lines are not code (``#`` for sh / Python, ``//`` and ``/* */`` for
   JS / TS), see ``strip_comments``.
2. The secret has to be SENT: the value (or one built from it, or a function that
   returns it) must reach a network call in the same file. A key that is only read
   is not exfiltration.
3. A send to the key's own vendor is its intended use: the vendor comes from the key
   name (``SLACK_BOT_TOKEN`` -> slack.com, ``X_BEARER_TOKEN`` -> x.com,
   ``BROWSERACT_API_KEY`` -> browseract.*) and is matched against the destination's
   REGISTRABLE domain, never a substring (``api.x.com.evil.io`` is evil.io). URLs
   resolve through same-file consts and templates (``const BASE = "https://…";
   fetch(`${BASE}/x`)``).
4. A send to an endpoint the user configures (env var / config / argument, no
   hardcoded host; or a loopback / LAN default) is high: Review, not Do not connect.
5. A send to a hardcoded host that is not the key's vendor (a random domain, a paste
   or request-bin site, a raw IP, a shared-hosting subdomain) is critical. So is an
   destination decoded at run time (base64 / char codes: a hidden URL).

Credential FILES (~/.ssh, ~/.aws, browser profiles, wallets, other tools' configs)
are judged in ``skill_scan``; this module only follows values.

The check follows the value, not proximity: it taints the variable the key is
assigned to (and values built from it, such as a headers dict, and functions that
return it), then looks at the network calls that carry a tainted value and resolves
their URL from string literals in the call or from URL-valued variables.
"""
from __future__ import annotations

import ipaddress
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

# A vendor token in a key name → that vendor's registrable domains. A token listed
# here matches ONLY these domains (so ``openai.xyz`` is not OpenAI); a token of 3
# characters or fewer matches only through this table.
_TOKEN_DOMAINS: dict[str, tuple[str, ...]] = {
    "x": ("x.com", "twitter.com"),
    "twitter": ("twitter.com", "x.com"),
    "slack": ("slack.com",),
    "github": ("github.com", "githubusercontent.com", "ghcr.io"),
    "gh": ("github.com", "githubusercontent.com", "ghcr.io"),
    "gitlab": ("gitlab.com",),
    "openai": ("openai.com",),
    "anthropic": ("anthropic.com",),
    "claude": ("anthropic.com", "claude.ai"),
    "google": ("googleapis.com", "google.com"),
    "gemini": ("googleapis.com",),
    "gcp": ("googleapis.com",),
    "aws": ("amazonaws.com", "api.aws"),
    "azure": ("azure.com", "windows.net", "azure-api.net", "microsoft.com"),
    "hf": ("huggingface.co", "hf.co"),
    "huggingface": ("huggingface.co", "hf.co"),
    "npm": ("npmjs.org", "npmjs.com"),
    "pypi": ("pypi.org",),
    "discord": ("discord.com", "discordapp.com"),
    "telegram": ("telegram.org",),
    "tg": ("telegram.org",),
    "notion": ("notion.com", "notion.so"),
    "stripe": ("stripe.com",),
    "reddit": ("reddit.com",),
    "xai": ("x.ai",),
    "grok": ("x.ai",),
    "linear": ("linear.app",),
    "feishu": ("feishu.cn", "larksuite.com"),
    "lark": ("larksuite.com", "feishu.cn"),
    "cloudflare": ("cloudflare.com",),
    "cf": ("cloudflare.com",),
    "vercel": ("vercel.com",),
    "supabase": ("supabase.co", "supabase.com"),
    "jira": ("atlassian.net", "atlassian.com"),
    "atlassian": ("atlassian.net", "atlassian.com"),
    "dashscope": ("aliyuncs.com",),
    "qwen": ("aliyuncs.com",),
    "aliyun": ("aliyuncs.com", "aliyun.com"),
    "ark": ("volces.com", "volcengine.com"),
    "volcengine": ("volces.com", "volcengine.com"),
    "doubao": ("volces.com", "volcengine.com"),
    "minimax": ("minimax.chat", "minimaxi.com", "minimax.io"),
    "moonshot": ("moonshot.cn", "moonshot.ai"),
    "kimi": ("moonshot.cn", "moonshot.ai"),
    "zhipu": ("bigmodel.cn",),
    "glm": ("bigmodel.cn",),
    "baidu": ("baidu.com", "baidubce.com"),
    "qianfan": ("baidubce.com",),
    "ncbi": ("nih.gov",),
    "pubmed": ("nih.gov",),
    "siliconflow": ("siliconflow.cn", "siliconflow.com"),
    "dingtalk": ("dingtalk.com",),
    "fal": ("fal.run", "fal.ai", "fal.media"),
    "wechat": ("qq.com", "weixin.qq.com"),
}
# Secrets worth stealing whatever their vendor: infrastructure and money. A key named
# for one of these (or for a vendor above) sent to a stranger host is critical.
_HIGH_VALUE_TOKENS = frozenset({
    "postgres", "postgresql", "pg", "mysql", "mariadb", "database", "db", "redis", "mongo",
    "mongodb", "ssh", "gpg", "pgp", "wallet", "mnemonic", "seed", "stripe", "paypal",
    "twilio", "sendgrid", "mailgun", "shopify", "vault", "kube", "k8s", "digitalocean",
    "heroku", "netlify", "sentry", "datadog", "okta", "auth0", "smtp", "email", "mail",
    "bank", "plaid", "coinbase", "binance", "metamask", "eth", "solana", "sol", "btc",
})
# Messaging APIs double as exfil channels (a bot that posts to the author's chat).
_MESSAGING_DOMAINS = frozenset({"telegram.org", "discord.com", "discordapp.com",
                                "slack.com"})
for _name, (_v, _doms) in VENDOR_KEYS.items():
    _TOKEN_DOMAINS.setdefault(_name.split("_")[0].lower(), _doms)

# Words in a key name that name no vendor.
_GENERIC_TOKENS = frozenset({
    "api", "key", "keys", "token", "tokens", "secret", "secrets", "password", "passwd",
    "pass", "pwd", "access", "auth", "bearer", "client", "app", "bot", "user", "oauth",
    "refresh", "private", "public", "signing", "id", "my", "service", "server", "webhook",
    "hook", "hooks", "proxy", "base", "url", "host", "master", "admin", "account",
    "session", "cookie", "personal", "prod", "dev", "test", "live", "env", "default",
    "custom", "local", "remote", "read", "write", "consumer", "encryption", "jwt",
    "gateway", "trigger", "reply", "config", "site", "site", "data", "cloud", "web",
    "http", "https", "mcp", "agent", "skill", "openclaw", "the", "new", "old", "main",
    "site", "internal", "external", "global", "shared", "backup", "login", "code",
    "paste", "upload", "bin",
})

# Destinations that are never anyone's vendor API: request bins, paste sites,
# tunnels, OAST collectors (whatever the key is called).
_EXFIL_DOMAINS = frozenset({
    "webhook.site", "webhook.cool", "requestbin.com", "requestbin.net", "pipedream.net",
    "requestcatcher.com", "beeceptor.com", "hookbin.com", "ngrok.io", "ngrok.app",
    "ngrok-free.app", "ngrok.dev", "pastebin.com", "hastebin.com", "paste.ee",
    "ghostbin.com", "dpaste.com", "dpaste.org", "rentry.co", "termbin.com", "0x0.st",
    "transfer.sh", "file.io", "catbox.moe", "interact.sh", "oast.fun", "oast.pro",
    "oast.live", "oast.site", "oast.online", "oast.me", "burpcollaborator.net",
    "trycloudflare.com", "loca.lt", "serveo.net", "localtunnel.me",
})
# Suffixes under which anyone can own a subdomain (slack.vercel.app is not Slack).
_SHARED_SUFFIXES = (
    "vercel.app", "netlify.app", "herokuapp.com", "github.io", "workers.dev", "pages.dev",
    "glitch.me", "repl.co", "replit.app", "replit.dev", "onrender.com", "fly.dev",
    "deno.dev", "web.app", "firebaseapp.com", "appspot.com", "azurewebsites.net",
    "cloudfront.net", "surge.sh", "railway.app", "up.railway.app", "vercel.sh",
    "gitlab.io", "blogspot.com", "s3.amazonaws.com", "r2.dev", "ngrok-free.app",
)
# Second-level labels under which the registrable label sits one further left
# (example.co.uk, example.com.au).
_SLD_SUFFIXES = {"co", "com", "net", "org", "ac", "gov", "edu"}

# A secret-named env var READ through an accessor ($VAR, ${VAR}, os.environ[...] /
# .get(...), os.getenv(...), process.env.VAR / ["VAR"], ENV["VAR"], os.Getenv("VAR")).
# Case-sensitive on the name: env vars are UPPER_SNAKE.
SECRET_ENV_READ_RE = re.compile(
    r"(?:\$\{?|\benviron(?:\.get)?\s*[\[(]\s*[\"']|\bgetenv\s*\(\s*[\"']"
    r"|\bprocess\.env(?:\.|\[\s*[\"'])|\bENV\[\s*[\"']|\bGetenv\(\s*\")"
    r"([A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD))\b"
)
# Any secret-shaped name in the code (also inside strings / regexes): the keys a file
# deals in, used to tell a multi-provider file from a stranger host.
_SECRET_NAME_RE = re.compile(r"\b([A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD))\b")

# Calls that send a request. Generic `<obj>.get/.post(...)` only count when the call
# also names a URL, a URL variable, or auth headers (see _flow).
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
# A right-hand side that IS a request: its value is the response, not the key.
_RHS_IS_REQUEST_RE = re.compile(
    r"\s*(?:await\s+)?(?:(?:requests|httpx|axios|session|client|self\.\w+)\.(?:get|post|put|"
    r"patch|delete|request)\s*\(|fetch\s*\(|urlopen\s*\(|urllib\.request\.urlopen\s*\("
    r"|\"?\$\(\s*(?:curl|wget)\b|`\s*(?:curl|wget)\b)"
)
_URL_RE = re.compile(r"(?:https?|wss?)://(?:[^@/\s\"'`]*@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+)")
_BASE_URL_RE = re.compile(r"\b(?:base_url|baseURL|api_base|base_path)\s*[=:]\s*([^,)\n]+)")
# Assignment targets may be dotted (``self.headers = {...}``, ``this.key = ...``).
_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?((?:const|let|var|local|readonly|declare)\s+)?([A-Za-z_][\w.]*)"
    r"\s*(?::\s*[^=\"'`(]+)?(?::=|[-+*/|&]?=)(?![=>])\s*(.*)$"
)
_ITEM_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\[[^\]]*\]\s*=(?!=)\s*(.+)$")
# Decoding primitives: an unresolved destination in such a file may be a hidden URL.
_DECODE_RE = re.compile(
    r"\batob\s*\(|b64decode|base64\s+(?:-d|--decode|-D)\b|fromCharCode|bytes\.fromhex"
    r"|codecs\.decode|Buffer\.from\([^)]*,\s*['\"](?:base64|hex)['\"]\s*\)"
)


@dataclass
class KeyUse:
    env_name: str
    vendor: str | None            # vendor display name / domain; None = no vendor found
    leaves_vendor: bool = False   # True = critical
    destinations: list[str] = field(default_factory=list)  # offending hosts ("?" = unresolved)
    severity: str | None = None   # "critical" | "high" | None (no defect)
    sent: bool = False            # the value reaches at least one network call


# ---------------------------------------------------------------------------
# 1. Comments
# ---------------------------------------------------------------------------

_HASH_EXT = (".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".ps1")
_SLASH_EXT = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?")


def _js_regex_start(src: str, i: int) -> bool:
    k = i - 1
    while k >= 0 and src[k] in " \t":
        k -= 1
    if k < 0 or src[k] in "(,=:[!&|?{};+-*%<>~^\n":
        return True
    return src[max(0, k - 5):k + 1] in ("return", "typeof")


def strip_comments(text: str, path: str | None = None) -> str:
    """``text`` with comments blanked (strings and line breaks kept, so line numbers
    hold). ``path``'s extension picks the syntax; unknown: ``#`` and ``//`` both."""
    p = (path or "").lower()
    hash_ = not p.endswith(_SLASH_EXT)
    slash = not p.endswith(_HASH_EXT)
    python = p.endswith(".py")
    shell = p.endswith((".sh", ".bash", ".zsh"))
    out: list[str] = []
    n, i, quote = len(text), 0, ""
    heredoc = ""
    while i < n:
        c = text[i]
        if heredoc:
            j = text.find("\n", i)
            j = n if j < 0 else j
            line = text[i:j]
            out.append(line)
            if line.strip() == heredoc:
                heredoc = ""
            i = j
            if i < n:
                out.append("\n")
                i += 1
            continue
        if quote:
            out.append(c)
            if c == "\\" and quote != "'" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if text.startswith(quote, i):
                out.extend(text[i + 1:i + len(quote)])
                i += len(quote)
                quote = ""
                continue
            i += 1
            continue
        if python and text.startswith(('"""', "'''"), i):
            quote = text[i:i + 3]
            out.append(quote)
            i += 3
            continue
        if c in "\"'" or (c == "`" and not python):
            quote = c
            out.append(c)
            i += 1
            continue
        prev = text[i - 1] if i else "\n"
        if hash_ and c == "#" and (python or prev in " \t\n;(|&") and prev not in "${":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if slash and c == "/" and i + 1 < n and text[i + 1] == "/" and prev != ":":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if slash and c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if slash and not hash_ and c == "/" and _js_regex_start(text, i):
            # A regex literal (`/["']/g`): its quotes don't open a string.
            j, in_class = i + 1, False
            while j < n and text[j] != "\n":
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                elif text[j] == "/" and not in_class:
                    break
                j += 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if shell and c == "<":
            m = _HEREDOC_RE.match(text, i)
            if m:
                j = text.find("\n", i)
                j = n if j < 0 else j
                out.append(text[i:j])
                i = j
                heredoc = m.group(1)
                if i < n:
                    out.append("\n")
                    i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# 3 / 5. Hosts and vendors
# ---------------------------------------------------------------------------

def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def is_local_host(host: str) -> bool:
    """Loopback / LAN / container host: the user's own machine or network."""
    h = host.lower().rstrip(".")
    ip = _ip(h)
    if ip is not None:
        return ip.is_loopback or ip.is_private or ip.is_unspecified
    return (h == "localhost" or h.endswith(".localhost") or h == "host.docker.internal"
            or h.endswith(".local"))


def registrable_domain(host: str) -> str:
    """``api.x.com`` -> ``x.com``; ``api.acme.co.uk`` -> ``acme.co.uk``; shared
    hosting (``slack.vercel.app``) and IPs -> "" (never anyone's vendor)."""
    h = host.lower().rstrip(".")
    if _ip(h) is not None:
        return ""
    if any(h == s or h.endswith("." + s) for s in _SHARED_SUFFIXES):
        return ""
    labels = [x for x in h.split(".") if x]
    if len(labels) < 2:
        return ""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _key_tokens(env_name: str) -> list[str]:
    """Vendor-candidate tokens of a key name: each non-generic word, plus adjacent
    words glued (``BROWSER_ACT_API_KEY`` -> browser, act, browseract)."""
    words = [w for w in env_name.lower().split("_") if w]
    out: list[str] = []
    for i in range(len(words)):
        for j in range(i + 1, min(len(words), i + 3) + 1):
            part = words[i:j]
            if any(w in _GENERIC_TOKENS for w in part):
                continue
            out.append("".join(part))
    return list(dict.fromkeys(out))


def host_matches_key(host: str, env_name: str) -> bool:
    """True when ``host`` is the API of the vendor ``env_name`` belongs to."""
    reg = registrable_domain(host)
    if not reg or reg in _EXFIL_DOMAINS:
        return False
    known = VENDOR_KEYS.get(env_name)
    if known and reg in known[1]:
        return True
    label = reg.split(".")[0].replace("-", "")
    # An unknown vendor's name may sit in a subdomain (eutils.ncbi.nlm.nih.gov); only
    # for names that are not a known vendor's, whose domains are fixed above.
    sub = {x.replace("-", "") for x in host.lower().rstrip(".").split(".")[:-1]}
    for tok in _key_tokens(env_name):
        if tok in _TOKEN_DOMAINS:
            if reg in _TOKEN_DOMAINS[tok]:
                return True
        elif len(tok) >= 4 and (tok == label or tok in sub):
            return True
    return False


_KNOWN_API_DOMAINS = frozenset(d for doms in _TOKEN_DOMAINS.values() for d in doms)


def _key_class(env_name: str) -> str:
    """"vendor": the name names a well-known vendor or an infrastructure / money
    secret (OPENAI_API_KEY, GITHUB_TOKEN, DB_PASSWORD); "generic": it names nothing
    (API_KEY, ACCESS_TOKEN, BOT_TOKEN); "specific": it names something else, most
    often the skill's own service (EARTH2037_TOKEN, LITE_AGENT_API_KEY)."""
    if env_name in VENDOR_KEYS:
        return "vendor"
    words = [w for w in env_name.lower().split("_") if w]
    toks = _key_tokens(env_name)
    if any(t in _TOKEN_DOMAINS or t in _HIGH_VALUE_TOKENS for t in [*words, *toks]):
        return "vendor"
    return "specific" if toks else "generic"


def _vendor_name(env_name: str, hosts: list[str]) -> str | None:
    known = VENDOR_KEYS.get(env_name)
    if known:
        return known[0]
    for h in hosts:
        if host_matches_key(h, env_name):
            return registrable_domain(h)
    return None


DECODED = "(decoded URL)"


def classify(hosts: list[str], env_name: str | None, file_keys: set[str],
             ) -> tuple[str | None, list[str]]:
    """(severity, offending hosts) for a value that reaches ``hosts``.

    Per host, in order:

    * unresolved ("?") or loopback / LAN: an endpoint the user configures -> high
      a destination decoded at run time (``DECODED``) -> critical;
    * a request bin / paste site / tunnel, a public IP, a shared-hosting subdomain
      -> critical;
    * the key's own vendor, or the vendor of another key the same file handles (a
      multi-provider script) -> fine;
    * a key named for a well-known vendor or an infrastructure secret
      (``_key_class`` "vendor") going anywhere else -> critical;
    * a well-known vendor's API (not a messaging API) -> fine;
    * a messaging API (Telegram, Discord, Slack: also an exfil channel) -> high;
    * a key that names nothing (API_KEY, ACCESS_TOKEN) -> critical;
    * a skill-specific key (EARTH2037_TOKEN) to a host its name doesn't match ->
      high: most often the skill's own backend, worth a look.

    ``None`` = no defect."""
    names = ([env_name] if env_name else []) + sorted(file_keys - {env_name})
    # No name: a credential FILE's contents (every secret in it): strictest class.
    klass = _key_class(env_name) if env_name else "vendor"
    crit: list[str] = []
    high: list[str] = []
    for h in hosts:
        if h == DECODED:
            crit.append(h)
            continue
        if h == "?" or is_local_host(h):
            high.append(h)
            continue
        reg = registrable_domain(h)
        if not reg or reg in _EXFIL_DOMAINS:
            crit.append(h)
        elif any(host_matches_key(h, n) for n in names):
            continue
        elif klass == "vendor":
            crit.append(h)
        elif reg in _MESSAGING_DOMAINS:
            high.append(h)
        elif reg in _KNOWN_API_DOMAINS:
            continue
        elif klass == "generic":
            crit.append(h)
        else:
            high.append(h)
    if crit:
        return "critical", sorted(set(crit))
    if high:
        return "high", sorted(set(high))
    return None, []


# ---------------------------------------------------------------------------
# 2. Following the value
# ---------------------------------------------------------------------------

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


@dataclass
class _Assign:
    target: str
    rhs: str
    line: int
    declared: bool      # const / let / var / local: a new local name
    item: bool = False  # `x[k] = …` / `x.k = …` writes into an existing object


def _assignments(lines: list[str]) -> list[_Assign]:
    """One per assignment. A right-hand side that opens a bracket (``headers = {`` …
    ``}``) runs on until it balances, up to 30 lines; an empty one (``const HOST =``
    + newline) takes the next line."""
    out: list[_Assign] = []
    for i, ln in enumerate(lines):
        m = _ASSIGN_RE.match(ln)
        item = False
        if m:
            declared, target, rhs = bool(m.group(1)), m.group(2), m.group(3)
        else:
            m = _ITEM_ASSIGN_RE.match(ln)
            if not m:
                continue
            declared, target, rhs, item = False, m.group(1), m.group(2), True
        j = i + 1
        if not rhs.strip():
            if j >= len(lines):
                continue
            rhs, j = lines[j], j + 1
        depth = sum(rhs.count(c) for c in "([{") - sum(rhs.count(c) for c in ")]}")
        while depth > 0 and j < min(len(lines), i + 30):
            rhs += "\n" + lines[j]
            depth += sum(lines[j].count(c) for c in "([{") - sum(lines[j].count(c) for c in ")]}")
            j += 1
        out.append(_Assign(target, rhs, i, declared, item))
    return out


_STR_PREFIXES = {"f", "b", "r", "u", "rb", "br", "fr", "rf"}


def _mentions(chunk: str, tokens: set[str]) -> bool:
    # A string-prefix-shaped name directly followed by a quote (f"...", b'...') is a
    # string literal, not a use of a variable called ``f``.
    # Not an attribute of something else (`res.headers` is not `headers`).
    def pat(t: str) -> str:
        tail = r"(?![\"'])" if t.lower() in _STR_PREFIXES else ""
        return r"(?:(?<![\w$.])|(?<=env\.))\$?\{?" + re.escape(t) + r"\b" + tail
    return any(re.search(pat(t), chunk) for t in tokens)


# Function definitions, for "a function that returns the key".
_PY_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_JS_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
    r"(?:function\b|\([^)]*\)\s*(?::\s*[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)"
    r"|^\s*(?:public\s+|private\s+|protected\s+|static\s+)*(?:async\s+)?"
    r"(?!(?:if|for|while|switch|catch|return|function|with)\b)([A-Za-z_$][\w$]*)\s*\([^)]*\)"
    r"\s*(?::\s*[^{]+)?\{\s*$"
)
_RETURN_RE = re.compile(r"(?<![\w$.])return\b")
# Names too common to stand for one function across a file.
_COMMON_FUNCS = frozenset({"get", "post", "put", "run", "main", "call", "request", "fetch",
                           "send", "init", "load", "read", "handler", "default"})


def _functions(lines: list[str]) -> list[tuple[str, int, int]]:
    """(name, first line, last line) per function; Python by indent, JS / shell by
    braces."""
    out: list[tuple[str, int, int]] = []
    for i, ln in enumerate(lines):
        m = _PY_DEF_RE.match(ln)
        if m:
            ind = len(m.group(1))
            end = i
            for j in range(i + 1, min(len(lines), i + 2000)):
                nxt = lines[j]
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= ind:
                    break
                end = j
            out.append((m.group(2), i, end))
            continue
        m = _JS_DEF_RE.match(ln)
        if m:
            name = next(g for g in m.groups() if g)
            depth, opened, end = 0, False, i
            for j in range(i, min(len(lines), i + 2000)):
                depth += lines[j].count("{") - lines[j].count("}")
                opened = opened or "{" in lines[j]
                end = j
                if opened and depth <= 0:
                    break
            out.append((name, i, end))
    return out


# A variable named like an endpoint (`BASE`, `api_url`): resolves hosts for values
# built from it. Other names only resolve from their own literal.
_URLISH_NAME_RE = re.compile(r"(?i)(?:url|uri|host|base|endpoint|api|server|origin|domain)")


@dataclass
class _Flow:
    lines: list[str]
    joined: str
    url_vars: dict[str, list[str]]
    base_spans: list[tuple[str, list[str], int]]  # (surrounding text, hosts, line)
    calls: list[tuple[str, int]]                  # (call text, line)
    assigns: list[_Assign]
    functions: list[tuple[str, int, int]]
    scope_at: list[tuple[int, ...]]               # enclosing function ids per line
    python: bool
    locals_of: dict[int, set[str]] = field(default_factory=dict)  # JS / shell locals
    decoded_vars: set[str] = field(default_factory=set)  # assigned from base64 / hex …
    url_sites: dict[str, list[tuple[list[str], int | None]]] = field(default_factory=dict)

    def url_hosts(self, name: str, line: int | None) -> list[str]:
        """Hosts of URL variable ``name`` as seen from ``line``: its assignments in
        scope there, else every assignment (a URL passed in as a parameter)."""
        sites = self.url_sites.get(name, [])
        if line is not None:
            vis = [h for h, sc in sites if self.visible({sc}, line)]
            if vis:
                return [x for h in vis for x in h]
        return list(self.url_vars.get(name, []))

    def scope_of(self, line: int, declared: bool, name: str | None = None) -> int | None:
        """The scope a name assigned on ``line`` lives in: the innermost function for
        a Python assignment or a declared JS / shell local; for a JS / shell
        reassignment, the function that declares the name (``let x; … x = …``);
        else the module."""
        enclosing = self.scope_at[line] if line < len(self.scope_at) else ()
        if enclosing and (self.python or declared):
            return enclosing[-1]
        if name:
            for fid in reversed(enclosing):
                if name in self.locals_of.get(fid, ()):
                    return fid
        return None

    def visible(self, scopes: set[int | None], line: int) -> bool:
        if None in scopes:
            return True
        here = self.scope_at[line] if line < len(self.scope_at) else ()
        return any(s in here for s in scopes)


def _flow(text: str, path: str | None = None) -> _Flow:
    joined = "\n".join(_logical_lines(text or ""))
    lines = joined.splitlines()
    assigns = _assignments(lines)
    python = (path or "").lower().endswith(".py") or (
        not path and bool(re.search(r"^\s*(?:async\s+)?def \w+\(.*\):\s*$", joined, re.M)))
    functions = _functions(lines)
    scope_at: list[list[int]] = [[] for _ in lines]
    for fid, (_n, a, b) in sorted(enumerate(functions), key=lambda x: (x[1][1], -x[1][2])):
        for k in range(a, min(b, len(lines) - 1) + 1):
            scope_at[k].append(fid)

    # URL-valued variables: NAME = "https://host/..." (literals on the RHS), then
    # values built from an endpoint-named one (`const url = `${BASE}/x``).
    # ``url_sites`` keeps each assignment (hosts, assignment) so a call resolves a
    # name through the assignment in its own function first.
    url_vars: dict[str, list[str]] = {}
    url_sites: dict[str, list[tuple[list[str], _Assign]]] = {}
    for a in assigns:
        hosts = _URL_RE.findall(a.rhs)
        if hosts and not _RHS_IS_REQUEST_RE.match(a.rhs):  # `res = fetch(...)` is a response
            url_vars.setdefault(a.target, []).extend(hosts)
            url_sites.setdefault(a.target, []).append((hosts, a))
    for _ in range(4):
        grew = False
        for a in assigns:
            if a.target in url_vars or _RHS_IS_REQUEST_RE.match(a.rhs):
                continue
            src = [v for v in url_vars
                   if (_URLISH_NAME_RE.search(v) or _URLISH_NAME_RE.search(a.target))
                   and _mentions(a.rhs, {v})]
            if src:
                url_vars[a.target] = [h for v in src for h in url_vars[v]]
                url_sites.setdefault(a.target, []).append((url_vars[a.target], a))
                grew = True
        if not grew:
            break

    base_spans: list[tuple[str, list[str], int]] = []
    for m in _BASE_URL_RE.finditer(joined):
        rhs = m.group(1).strip()
        hosts = _URL_RE.findall(rhs) or list(url_vars.get(rhs, []))
        if hosts:
            a0 = joined.rfind("\n", 0, max(0, m.start() - 300))
            b0 = joined.find("\n", m.end() + 300)
            base_spans.append((joined[max(0, a0):(len(joined) if b0 < 0 else b0)], hosts,
                               joined.count("\n", 0, m.start())))

    calls: list[tuple[str, int]] = []
    for m in _NET_CALL_RE.finditer(joined):
        chunk = _call_text(joined, m.start())
        head = joined[m.start():m.end()]
        if head.startswith(("environ.", "env.", "os.")) or ".getenv" in head:
            continue  # os.environ.get(...) is the key read, not a request
        strict = bool(_STRICT_NET_RE.match(joined, m.start()))
        if not strict:
            # `<obj>.get/.post(...)`: a request only when its ARGUMENTS name a URL, a
            # URL variable or auth headers (`res.headers.get("x")`, `map.get(k)` are not).
            p = chunk.find("(")
            args = chunk[p + 1:] if p >= 0 else ""
            named_url = _URL_RE.search(args) or any(
                re.search(r"(?<![\w$.])" + re.escape(v) + r"\b", args) for v in url_vars)
            if not (named_url or re.search(
                    r"(?i)headers\s*[=:]|authorization|x-api-key|auth\s*=", args)):
                continue
        calls.append((chunk, joined.count("\n", 0, m.start())))
    locals_of: dict[int, set[str]] = {}
    if not python:
        for i, ln in enumerate(lines):
            if scope_at[i]:
                fid = scope_at[i][-1]
                names = set(_DECL_RE.findall(ln))
                if functions[fid][1] == i:          # the header: its parameters
                    p = ln.find("(")
                    q = ln.find(")", p + 1)
                    if p >= 0 and q > p:
                        names |= set(re.findall(r"[A-Za-z_$][\w$]*", ln[p + 1:q]))
                locals_of.setdefault(fid, set()).update(names)
    flow = _Flow(lines, joined, url_vars, base_spans, calls, assigns, functions,
                 [tuple(s) for s in scope_at], python, locals_of)
    flow.decoded_vars = {a.target for a in assigns if _DECODE_RE.search(a.rhs)}
    flow.url_sites = {
        v: [(h, flow.scope_of(a.line, a.declared, a.target)) for h, a in sites]
        for v, sites in url_sites.items()}
    return flow


_DECL_RE = re.compile(r"\b(?:let|const|var|local)\s+([A-Za-z_$][\w$]*)")


# ``with open(x) as f`` / ``for line in f`` (Python) and ``for (const x of y)`` (JS)
# bind a new name from a tainted value. (Not TypeScript's ``x as T`` cast.)
_BIND_RE = re.compile(r"\b(?:as|for)\s+([A-Za-z_]\w*)(?:\s*,\s*([A-Za-z_]\w*))?")
_BIND_LINE_RE = re.compile(r"^\s*(?:async\s+)?(?:with|for)\b.*:\s*$")
_JS_FOR_OF_RE = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+(?:of|in)\b")


def _bindings(line: str) -> list[str]:
    if _BIND_LINE_RE.match(line):
        return [n for m in _BIND_RE.finditer(line) for n in m.groups() if n]
    return [m.group(1) for m in _JS_FOR_OF_RE.finditer(line)]


def _func_called(chunk: str, funcs: set[str]) -> bool:
    return any(re.search(r"(?<![\w$])(?:self\.|this\.)?" + re.escape(f) + r"\s*\(", chunk)
               for f in funcs)


Taint = dict[str, set]   # name -> scopes it is tainted in (None = module-wide)


def _visible_names(flow: _Flow, tainted: Taint, line: int) -> set[str]:
    return {n for n, scopes in tainted.items() if flow.visible(scopes, line)}


def _taint(flow: _Flow, seeds: Taint) -> tuple[Taint, set[str]]:
    """(tainted names with their scopes, functions whose return value is tainted).

    Scoped: a local assigned in one function does not taint a same-named local in
    another (``body`` / ``data`` / ``text`` in a 2,700-line bot are many variables)."""
    tainted: Taint = {n: set(s) for n, s in seeds.items()}
    funcs: set[str] = set()

    def hit(s: str, line: int) -> bool:
        names = _visible_names(flow, tainted, line)
        return (bool(names) and _mentions(s, names)) or (
            bool(funcs) and _func_called(s, funcs))

    def add(name: str, scope: int | None) -> bool:
        cur = tainted.setdefault(name, set())
        if scope in cur or None in cur:
            return False
        cur.add(scope)
        return True

    for _ in range(6):
        grew = False
        for a in flow.assigns:
            if _RHS_IS_REQUEST_RE.match(a.rhs) or not hit(a.rhs, a.line):
                continue
            base = a.target.split(".")[0]
            if a.item or "." in a.target:
                # `self.key = …` is the object's state (module-wide); `headers.X = key`
                # / `headers["X"] = key` puts the key in the local `headers`.
                if base in ("self", "this", "cls"):
                    grew |= add(a.target, None)
                else:
                    grew |= add(a.target, flow.scope_of(a.line, True))
                    grew |= add(base, flow.scope_of(a.line, True))
            else:
                grew |= add(a.target, flow.scope_of(a.line, a.declared, a.target))
        for i, ln in enumerate(flow.lines):
            names = _bindings(ln)
            if names and hit(ln, i):
                for name in names:
                    if name not in ("in", "as"):
                        grew |= add(name, flow.scope_of(i, True))
        for name, a0, b0 in flow.functions:
            if name in funcs or name in _COMMON_FUNCS or len(name) < 3:
                continue
            for k in range(a0, min(b0, len(flow.lines) - 1) + 1):
                m = _RETURN_RE.search(flow.lines[k])
                if m and hit(flow.lines[k][m.end():], k):
                    funcs.add(name)
                    grew = True
                    break
        if not grew:
            break
    return tainted, funcs


_HTTP_METHOD_RE = re.compile(r"""^\s*['"](?:GET|POST|PUT|PATCH|DELETE|HEAD)['"]\s*$""", re.I)
_URL_OPTION_RE = re.compile(
    r"""(?<![\w$])['"]?(?:url|uri|baseURL|base_url)['"]?\s*[:=]\s*([^,\n}]+)""")


def _top_level_args(chunk: str) -> list[str]:
    """The call's arguments split at top-level commas (best effort)."""
    p = chunk.find("(")
    if p < 0:
        return [chunk]
    args, depth, cur, quote = [], 0, "", ""
    for c in chunk[p + 1:]:
        if quote:
            cur += c
            if c == quote:
                quote = ""
            continue
        if c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            args.append(cur)
            cur = ""
            continue
        cur += c
    args.append(cur)
    return args


def _hosts_in(flow: _Flow, part: str, line: int | None = None) -> list[str]:
    hosts = list(_URL_RE.findall(part))
    for v in flow.url_vars:
        if re.search(r"(?<![\w$.])\$?\{?" + re.escape(v) + r"\b(?!\s*[:=](?![:=]))", part):
            hosts.extend(flow.url_hosts(v, line))
    return hosts


_CURL_OPT_ARG_RE = re.compile(
    r"""(?<!\S)(?:-[HdFuAbeoTwXmE]|--(?:data(?:-raw|-binary|-urlencode|-ascii)?|header|user"""
    r"""|form(?:-string)?|output|request|user-agent|cookie|referer|write-out|max-time"""
    r"""|connect-timeout|retry|post-data|post-file|body-data|header-file))"""
    r"""(?:=|\s+)(?:"(?:\\.|[^"\\])*"|'[^']*'|\$\([^)]*\)|\S+)""")


def _decoded(flow: _Flow, part: str) -> bool:
    return bool(_DECODE_RE.search(part)) or (
        bool(flow.decoded_vars) and _mentions(part, flow.decoded_vars))


def _dest_hosts(flow: _Flow, chunk: str, line: int | None = None) -> list[str]:
    """Where a call sends to: a curl/wget line's URLs, else the URL argument (the
    first one, or the second after an HTTP-method string) or a ``url:`` option. The
    payload's own URLs and variables are not the destination."""
    if re.match(r"(?:curl|wget)\b", chunk):
        # The URL operand, not the values of -d / -H / -F … (a payload variable that
        # happens to hold another URL is not the destination).
        first = _CURL_OPT_ARG_RE.sub(" ", chunk)
        if _decoded(flow, first):
            return [DECODED]
        return _hosts_in(flow, first, line) or ["?"]
    args = _top_level_args(chunk)
    first = args[0] if args else ""
    if _HTTP_METHOD_RE.match(first) and len(args) > 1:
        first = args[1]
    if _decoded(flow, first):
        return [DECODED]
    hosts = _hosts_in(flow, first, line)
    if not hosts:
        for m in _URL_OPTION_RE.finditer(chunk):
            hosts.extend(_hosts_in(flow, m.group(1), line))
    return hosts or ["?"]


def _reached(flow: _Flow, tainted: Taint, funcs: set[str] | None = None,
             include_base: bool = True) -> list[str]:
    """Every host a tainted value is sent to; "?" = a call whose host is unresolved."""
    funcs = funcs or set()
    out: list[str] = []
    for chunk, line in flow.calls:
        names = _visible_names(flow, tainted, line)
        if not ((names and _mentions(chunk, names)) or (funcs and _func_called(chunk, funcs))):
            continue
        out.extend(_dest_hosts(flow, chunk, line))
    if include_base:
        # An SDK client pointed at a base URL sends the key there.
        for span, hosts, line in flow.base_spans:
            names = _visible_names(flow, tainted, line)
            if names and _mentions(span, names):
                out.extend(hosts)
    return out


def file_secret_names(text: str) -> set[str]:
    """Every secret-shaped name in the (comment-stripped) code."""
    return set(_SECRET_NAME_RE.findall(text or ""))


def analyze(text: str, path: str | None = None) -> list[KeyUse]:
    """One KeyUse per distinct secret-named env var the script reads (comments
    ignored; ``path`` picks the comment syntax)."""
    code = strip_comments(text or "", path)
    names = sorted(set(SECRET_ENV_READ_RE.findall(code)))
    if not names:
        return []
    flow = _flow(code, path)
    file_keys = file_secret_names(code)

    uses: list[KeyUse] = []
    for name in names:
        tainted, funcs = _taint(flow, {name: {None}})
        hosts = _reached(flow, tainted, funcs)
        known = VENDOR_KEYS.get(name)
        # An SDK reads a known vendor key from the environment by itself, so a
        # client pointed at a base URL counts for it even when the key isn't named.
        if known:
            for _span, bh, _line in flow.base_spans:
                hosts.extend(h for h in bh if h not in hosts)
        sev, bad = classify(hosts, name, file_keys) if hosts else (None, [])
        uses.append(KeyUse(
            name, _vendor_name(name, hosts), leaves_vendor=sev == "critical",
            destinations=bad, severity=sev, sent=bool(hosts)))
    return uses


# ---------------------------------------------------------------------------
# .env files (Kenne, 2026-10-11; send required since 2026-10-19)
#
# Loading a ``.env`` that sits next to the script (``Path(__file__).parent / ".env"``,
# ``os.path.dirname(__file__)``, ``$(dirname "$0")/.env``, ``__dirname``) is how a skill
# gets its own configuration. Any ``.env`` that is not anchored to the script's own
# directory (home dir, ``~``, a parent dir, an absolute path, or a bare relative path,
# which resolves against the user's current project) is "foreign". Either way the
# file's CONTENTS have to reach a network call to be exfiltration; the secret-named
# values a dotenv loader puts in the environment go through the key-flow rule above.

_ENV_FILE_RE = re.compile(r"(?<![\w\\])\.env\b")
_OWN_ANCHOR_RE = re.compile(
    r"__file__|__dirname|import\.meta|BASH_SOURCE|dirname\s+\\?\"?\$0|\$\{?0\b"
    r"|\b(?:script_?dir|SCRIPT_?DIR|scriptDir|SKILL_?DIR|skill_?dir|skillDir|HERE|here|BASE_DIR)\b"
)
_FOREIGN_RE = re.compile(
    r"~|\$HOME|\bHOME\b|expanduser|Path\.home|homedir|/root\b|/home/|/Users/|\.\./|\.\.[\\\"']"
    r"|getcwd|process\.cwd|Path\.cwd|\bcwd\b"
)
_COMMENT_RE = re.compile(r"^\s*(?:#|//|\*|/\*)")


def _strip_comment(line: str) -> str:
    """Drop a trailing ``# …`` / ``// …`` comment (outside quotes, best effort)."""
    quote = ""
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c == "#" or (c == "/" and line[i:i + 2] == "//" and (i == 0 or line[i - 1] != ":")):
            return line[:i]
    return line


def env_file_reads(text: str, path: str | None = None) -> str:
    """"none" (no .env file reference in code), "own" (every reference is anchored
    to the script's own directory) or "foreign" (any other .env)."""
    flow = _flow(text, path)
    anchored = {a.target for a in flow.assigns if _OWN_ANCHOR_RE.search(a.rhs)
                and not _FOREIGN_RE.search(a.rhs)}
    for _ in range(4):  # script_dir = Path(__file__).parent; env_file = script_dir / ".env"
        grew = False
        for a in flow.assigns:
            if a.target not in anchored and _mentions(a.rhs, anchored) \
                    and not _FOREIGN_RE.search(a.rhs):
                anchored.add(a.target)
                grew = True
        if not grew:
            break
    seen = False
    for raw in flow.lines:
        if _COMMENT_RE.match(raw):
            continue
        ln = _strip_comment(raw)
        if not _ENV_FILE_RE.search(ln):
            continue
        seen = True
        if _FOREIGN_RE.search(ln):
            return "foreign"
        if _OWN_ANCHOR_RE.search(ln) or _mentions(ln, anchored):
            continue
        return "foreign"
    return "own" if seen else "none"


def contents_reached(text: str, path_re: re.Pattern[str] = _ENV_FILE_RE,
                     path: str | None = None) -> list[str]:
    """Hosts the CONTENTS of a file whose path matches ``path_re`` reach ("?" =
    unresolved). A dotenv loader only writes os.environ; values read back from it are
    judged by the key-flow rule, so os.environ / load_dotenv calls are not a send."""
    flow = _flow(text, path)
    seeds: Taint = {}
    for a in flow.assigns:
        if path_re.search(_strip_comment(a.rhs)):
            seeds.setdefault(a.target, set()).add(flow.scope_of(a.line, a.declared))
    for i, ln in enumerate(flow.lines):
        if _COMMENT_RE.match(ln):
            continue
        if path_re.search(_strip_comment(ln)):
            for n in _bindings(ln):
                seeds.setdefault(n, set()).add(flow.scope_of(i, True))
    hosts: list[str] = []
    for chunk, line in flow.calls:
        if path_re.search(chunk):          # read inline inside the send
            hosts.extend(_dest_hosts(flow, chunk, line))
    if not seeds:
        return hosts
    tainted, funcs = _taint(flow, seeds)
    return hosts + _reached(flow, tainted, funcs, include_base=False)


_READ_PRIM_RE = re.compile(
    r"\bopen\s*\(|\.read_(?:text|bytes)\s*\(|\breadFile(?:Sync)?\s*\(|\bcreateReadStream\s*\("
    r"|\bexpanduser\s*\(|\b(?:cat|cp|tar|zip|scp|rsync|base64)\s")


def listed_paths_read_and_sent(text: str, path_re: re.Pattern[str],
                               path: str | None = None) -> bool:
    """Paths listed in a table (``TARGETS = ['~/.ssh/id_rsa', …]``) that the script
    then OPENS (a read on a value from the table) and whose result reaches a send."""
    flow = _flow(text, path)
    seeds: Taint = {}
    for a in flow.assigns:
        if path_re.search(a.rhs):
            seeds.setdefault(a.target, set()).add(flow.scope_of(a.line, a.declared))
    if not seeds:
        return False
    tainted, funcs = _taint(flow, seeds)
    opened = any(_READ_PRIM_RE.search(ln) and _mentions(ln, _visible_names(flow, tainted, i))
                 for i, ln in enumerate(flow.lines))
    return opened and bool(_reached(flow, tainted, funcs, include_base=False))


def own_env_contents_leave(text: str) -> bool:
    """True when the raw contents of the skill's .env reach any network call."""
    return bool(contents_reached(text))
