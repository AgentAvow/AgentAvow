"""Which environment variables does a package READ? (static, deterministic)

Feeds the credential canary: the exerciser fills each of these names with
``agentavow-canary-<id>`` before launching the server, so a tool that ships an env value
over DNS / plaintext HTTP, or echoes it in a tool result, is caught by name. Collected
from ``process.env.NAME`` / ``process.env["NAME"]`` / ``os.environ["NAME"]`` /
``os.environ.get("NAME")`` / ``os.getenv("NAME")`` over the artifact's text files.

A second, looser miner (:func:`env_names_from_text`) pulls credential-looking names
(``BRAVE_API_KEY``, ``SUPABASE_ACCESS_TOKEN``) out of prose — a README, or a server's own
usage/error text — for servers whose env reads static detection missed (a config library,
``process.env[name]`` with a computed name, a compiled bundle).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

MAX_ENV_NAMES = 32

# Names that are ambient on every machine, never a credential worth canarying.
_NOISE = {
    "PATH", "HOME", "USER", "SHELL", "PWD", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL",
    "TERM", "NODE_ENV", "NODE_OPTIONS", "NODE_PATH", "CI", "DEBUG", "PORT", "HOST",
    "HOSTNAME", "PYTHONPATH", "PYTHONUNBUFFERED", "VIRTUAL_ENV", "LOG_LEVEL", "LOGLEVEL",
    "NO_COLOR", "FORCE_COLOR", "COLORTERM", "EDITOR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "SYSTEMROOT", "COMSPEC",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "TZ", "DISPLAY", "SHLVL", "_",
}
_NOISE_PREFIXES = ("NPM_", "NODE_", "PYTHON", "GITHUB_ACTIONS", "RUNNER_", "LC_", "XDG_")

_IDENT = r"[A-Z][A-Z0-9_]{1,63}"
_PATTERNS = (
    re.compile(r"process\.env\.(" + _IDENT + r")\b"),
    re.compile(r"process\.env\[\s*['\"](" + _IDENT + r")['\"]\s*\]"),
    re.compile(r"os\.environ\[\s*['\"](" + _IDENT + r")['\"]\s*\]"),
    re.compile(r"os\.environ\.get\(\s*['\"](" + _IDENT + r")['\"]"),
    re.compile(r"os\.getenv\(\s*['\"](" + _IDENT + r")['\"]"),
)
_TEXT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".pyi")

# Prose miner: an uppercase identifier is a credential env var when it carries one of
# these words — as a substring (API_KEY, APIKEY, AUTHTOKEN, PASSWD-free PASSWORD) or, for
# the short ones that collide with ordinary words (PATH, CAPITAL), as a whole ``_`` token
# (GITHUB_PAT, API_VERSION is not a secret but API_KEY is caught by KEY anyway) — or a
# vendor prefix that near-always names a credential in a README.
_CRED_SUBSTRINGS = ("KEY", "TOKEN", "SECRET", "AUTH", "CREDENTIAL", "PASSWORD", "PASSWD")
_CRED_TOKENS = {"API", "PAT", "ACCESS"}
_CRED_PREFIXES = (
    "AWS_", "GITHUB_", "GH_", "GITLAB_", "OPENAI_", "ANTHROPIC_", "GEMINI_", "GOOGLE_",
    "AZURE_", "GCP_", "SLACK_", "DISCORD_", "TELEGRAM_", "STRIPE_", "TWILIO_", "SENDGRID_",
    "SUPABASE_", "BRAVE_", "NOTION_", "LINEAR_", "JIRA_", "ATLASSIAN_", "SENTRY_",
    "CLOUDFLARE_", "VERCEL_", "UPSTASH_", "TAVILY_", "EXA_", "FIRECRAWL_", "PERPLEXITY_",
    "MISTRAL_", "COHERE_", "GROQ_", "ELEVENLABS_", "REPLICATE_", "HF_", "HUGGINGFACE_",
    "DATABASE_", "POSTGRES_", "MONGODB_", "REDIS_", "SMITHERY_",
)
_PROSE_IDENT = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]{3,63})(?![A-Za-z0-9_])")


def _is_noise(name: str) -> bool:
    return name in _NOISE or name.startswith(_NOISE_PREFIXES)


def _env_names_from_source(text: str) -> set[str]:
    """Names read by code: ``process.env.X`` / ``os.environ["X"]`` … (exact, high signal)."""
    out: set[str] = set()
    if not isinstance(text, str) or not text:
        return out
    for pat in _PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            if not _is_noise(name):
                out.add(name)
    return out


def looks_like_credential(name: str) -> bool:
    """``BRAVE_API_KEY`` / ``GITHUB_PAT`` / ``SUPABASE_ACCESS_TOKEN`` → True; ``PATH`` /
    ``LOG_LEVEL`` / ``MCP_SERVER_PORT`` → False. Pure, no I/O."""
    if not name or _is_noise(name) or ("_" not in name and len(name) < 6):
        return False
    if any(w in name for w in _CRED_SUBSTRINGS):
        return True
    if any(tok in _CRED_TOKENS for tok in name.split("_")):
        return True
    return name.startswith(_CRED_PREFIXES)


def env_names_from_text(text: str) -> list[str]:
    """Credential-looking env var names mentioned in free text (a README, a server's usage
    or error output): sorted, de-duplicated, same noise filter and cap as
    :func:`env_names_from_files`. Names also read by code in the text (``process.env.X``)
    are included whether or not they look like credentials. Never raises."""
    try:
        if not isinstance(text, str) or not text:
            return []
        names = _env_names_from_source(text)
        for m in _PROSE_IDENT.finditer(text):
            name = m.group(1)
            if looks_like_credential(name):
                names.add(name)
        return sorted(names)[:MAX_ENV_NAMES]
    except Exception:  # noqa: BLE001 — a helper for a canary must never break a scan
        return []


def env_names_from_files(files: Mapping[str, object] | Iterable[tuple[str, object]] | None,
                         ) -> list[str]:
    """Sorted, de-duplicated env var names read by the artifact's source files (cap 32).
    ``files`` maps path → object with a ``.text`` attribute (``ArtifactFile``-like);
    binary/non-source files are skipped. Never raises."""
    names: set[str] = set()
    try:
        items = files.items() if isinstance(files, Mapping) else (files or [])
        for path, f in items:
            p = str(path).lower()
            if not p.endswith(_TEXT_SUFFIXES):
                continue
            if "/node_modules/" in p or p.startswith("node_modules/") or "/test" in p:
                continue
            text = getattr(f, "text", None)
            if isinstance(text, str) and text:
                names |= _env_names_from_source(text)
    except Exception:  # noqa: BLE001 — a helper for a canary must never break a scan
        return []
    return sorted(names)[:MAX_ENV_NAMES]
