"""Which environment variables does a package READ? (static, deterministic)

Feeds the credential canary: the exerciser fills each of these names with
``agentavow-canary-<id>`` before launching the server, so a tool that ships an env value
over DNS / plaintext HTTP, or echoes it in a tool result, is caught by name. Collected
from ``process.env.NAME`` / ``process.env["NAME"]`` / ``os.environ["NAME"]`` /
``os.environ.get("NAME")`` / ``os.getenv("NAME")`` over the artifact's text files.
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


def _is_noise(name: str) -> bool:
    return name in _NOISE or name.startswith(_NOISE_PREFIXES)


def env_names_from_text(text: str) -> set[str]:
    out: set[str] = set()
    if not isinstance(text, str) or not text:
        return out
    for pat in _PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            if not _is_noise(name):
                out.add(name)
    return out


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
                names |= env_names_from_text(text)
    except Exception:  # noqa: BLE001 — a helper for a canary must never break a scan
        return []
    return sorted(names)[:MAX_ENV_NAMES]
