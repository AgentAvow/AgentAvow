"""Scrub secrets and personal data out of log records before they are written.

Two passes, both applied by the formatters in src/observability/logs.py:

* **By field name.** A structured field (an ``extra=`` key, or a key anywhere inside a
  dict passed as one) whose name says it holds a secret or an email is replaced
  whole: Authorization, X-API-Key, X-Provider-Key, cookies, passwords, tokens,
  secrets, private keys, emails.
* **By shape.** Every string that reaches the output (the message, exception text,
  string field values) is searched for things that look like credentials wherever
  they appear: GitHub tokens (``ghp_`` / ``gho_`` / ``ghs_`` / ``ghu_`` / ``ghr_`` /
  ``github_pat_``), ``sk-`` keys, AWS access key ids, JWTs, our own API keys and
  webhook secrets (``ag_live_``, ``ag_org_``, ``whsec_``), ``Bearer`` / ``Basic``
  credentials, ``user:password@`` in URLs, ``key=value`` pairs whose key names a
  secret, and email addresses.

A GitHub token passed to a private scan is "never persisted"; a log line would
persist it, so it must not get that far. tests/test_observability_redaction.py logs
each shape and checks it never appears in the output.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"

# --- Field names ---------------------------------------------------------------------

# Matched against the lowercased name with "-" turned into "_", as whole "_" words.
_SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:"
    r"password|passwd|pwd|passphrase|secret|secrets|authorization|auth|cookie|cookies"
    r"|api_?key|apikey|provider_key|private_key|signing_key|access_key|credential|credentials"
    r"|jwt|session|email|emails|e_?mail"
    r")(?:$|_)"
)
# "token" only as the last word: access_token, github_token, token. Not token_budget
# or tokens_used, which are counts.
_TOKEN_NAME = re.compile(r"(?:^|_)token$")


def is_sensitive_key(name: object) -> bool:
    if not isinstance(name, str):
        return False
    n = name.strip().lower().replace("-", "_")
    return bool(_SENSITIVE_NAME.search(n) or _TOKEN_NAME.search(n))


# --- Shapes in free text --------------------------------------------------------------

_KEY_WORDS = (
    r"[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|apikey|provider[_-]?key"
    r"|private[_-]?key|access[_-]?key|authorization|session[_-]?id|credential)"
)

# Order matters: the specific shapes run first so their placeholder is what remains.
_TEXT_RULES: tuple[tuple[re.Pattern[str], Any], ...] = (
    # PEM private key blocks.
    (re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     REDACTED),
    # Credentials in a URL: scheme://user:password@host -> scheme://user:[REDACTED]@host
    (re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1" + REDACTED + "@"),
    # Authorization schemes. A credential has a digit or punctuation in it; a plain
    # word ("Bearer authentication failed") is left alone.
    (re.compile(r"\b(Bearer|Basic)\s+(?=\S*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{6,}", re.I),
     r"\1 " + REDACTED),
    # GitHub's "Authorization: token <value>". Needs a digit and some length so prose
    # like "token response missing" is left alone.
    (re.compile(r"\b([Tt]oken)\s+(?=\S*\d)[A-Za-z0-9._~+/=-]{16,}"), r"\1 " + REDACTED),
    # GitHub tokens: classic (ghp/gho/ghu/ghs/ghr) and fine-grained.
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    # OpenAI / Anthropic style keys (sk-..., sk-proj-..., sk-ant-...).
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), REDACTED),
    # AWS access key ids (long-lived AKIA, temporary ASIA).
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # Our own API keys and webhook secrets.
    (re.compile(r"\b(?:ag_live|ag_org)_[A-Za-z0-9]{16,}"), REDACTED),
    (re.compile(r"\bwhsec_[A-Za-z0-9_-]{16,}"), REDACTED),
    # Slack tokens.
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), REDACTED),
    # JWTs (three base64url segments, header starting with {" ).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+"), REDACTED),
    # Cookie headers in text: everything after the colon to the end of the line.
    (re.compile(r"(?i)\b((?:set-)?cookie[\"']?\s*[:=]\s*)[^\r\n]+"), r"\1" + REDACTED),
    # key=value / "key": "value" where the key names a secret.
    (re.compile(
        r"(?i)(\b" + _KEY_WORDS + r"[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED)[^\s\"'&,;}\]]+"),
     r"\1" + REDACTED),
)

_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")


def _email_sub(m: re.Match[str]) -> str:
    # git@github.com:owner/repo is an ssh remote, not a person.
    if m.group(1).lower() == "git":
        return m.group(0)
    return REDACTED_EMAIL


def redact_text(text: str) -> str:
    """Replace every secret- or email-shaped substring of ``text``."""
    if not text:
        return text
    for pattern, repl in _TEXT_RULES:
        text = pattern.sub(repl, text)
    return _EMAIL.sub(_email_sub, text)


_MAX_DEPTH = 8


def redact_value(value: Any, _depth: int = 0) -> Any:
    """Redact a structured value: secret-named keys whole, strings by shape."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if is_sensitive_key(k) else redact_value(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(v, _depth + 1) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # Anything else is written as its string form, so scrub that.
    return redact_text(str(value))


def redact_field(name: str, value: Any) -> Any:
    """Redact one named field."""
    if is_sensitive_key(name):
        return REDACTED
    return redact_value(value)
