"""Secrets and emails never reach a log line, in either format (#405).

Each test logs a secret through a real logger and handler, then checks that the
secret's distinctive part is absent from the written output. Values are built at run
time so this file holds no literal credential the secret scanners would flag.
"""
from __future__ import annotations

import io
import json
import logging

import pytest

from src.observability.logs import JSONFormatter, TextFormatter
from src.observability.redaction import (
    REDACTED,
    is_sensitive_key,
    redact_text,
    redact_value,
)

_A = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # 36 alnum chars
_UP = "ABCDEFGHIJ234567"  # 16 upper/digit chars

# (label, secret value, the part that must never appear)
SECRETS = [
    ("github classic pat", "ghp_" + _A, _A),
    ("github oauth token", "gho_" + _A, _A),
    ("github app installation token", "ghs_" + _A, _A),
    ("github user-to-server token", "ghu_" + _A, _A),
    ("github refresh token", "ghr_" + _A, _A),
    ("github fine-grained pat", "github_pat_11ABCDEFG0_" + _A, _A),
    ("openai key", "sk-" + _A, _A),
    ("openai project key", "sk-proj-" + _A, _A),
    ("anthropic key", "sk-ant-api03-" + _A, _A),
    ("aws access key id", "AKIA" + _UP, _UP),
    ("aws temporary key id", "ASIA" + _UP, _UP),
    ("agentavow api key", "ag_live_" + "0123456789abcdef" * 3, "0123456789abcdef" * 3),
    ("agentavow org key", "ag_org_" + "fedcba9876543210" * 3, "fedcba9876543210" * 3),
    ("webhook secret", "whsec_" + _A, _A),
    ("slack token", "xoxb-1234567890-" + _A, _A),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwia2luZCI6ImFjY2VzcyJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    ("email", "kenne.someone+tag@example.org", "kenne.someone+tag@example.org"),
]

# Free-text forms a secret shows up in: a header dump, a query string, a URL, JSON.
TEXT_TEMPLATES = [
    "plain mention {s} in a sentence",
    "Authorization: Bearer {s}",
    "headers={{'X-API-Key': '{s}', 'X-Provider-Key': '{s}'}}",
    "GET https://api.example.com/x?token={s}&page=2",
    "clone https://x-access-token:{s}@github.com/owner/private-repo.git failed",
    '{{"access_token": "{s}", "scope": "repo"}}',
    "github_token={s}",
]


def _logger(formatter: logging.Formatter) -> tuple[logging.Logger, io.StringIO]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(formatter)
    lg = logging.getLogger(f"test.redaction.{id(buf)}")
    lg.handlers = [handler]
    lg.propagate = False
    lg.setLevel(logging.DEBUG)
    return lg, buf


FORMATTERS = [pytest.param(JSONFormatter, id="json"), pytest.param(TextFormatter, id="text")]


@pytest.mark.parametrize("fmt", FORMATTERS)
@pytest.mark.parametrize("template", TEXT_TEMPLATES)
@pytest.mark.parametrize(("label", "secret", "core"), SECRETS, ids=[s[0] for s in SECRETS])
def test_secret_in_message_never_written(fmt, template, label, secret, core):
    lg, buf = _logger(fmt())
    lg.info(template.format(s=secret))
    out = buf.getvalue()
    assert core not in out, f"{label} leaked: {out}"


@pytest.mark.parametrize("fmt", FORMATTERS)
@pytest.mark.parametrize(("label", "secret", "core"), SECRETS, ids=[s[0] for s in SECRETS])
def test_secret_in_format_args_never_written(fmt, label, secret, core):
    lg, buf = _logger(fmt())
    lg.warning("scan failed for %s: %s", "owner/repo", secret)
    assert core not in buf.getvalue()


@pytest.mark.parametrize("fmt", FORMATTERS)
@pytest.mark.parametrize(("label", "secret", "core"), SECRETS, ids=[s[0] for s in SECRETS])
def test_secret_in_exception_never_written(fmt, label, secret, core):
    lg, buf = _logger(fmt())
    try:
        raise RuntimeError(f"upstream rejected credential {secret}")
    except RuntimeError:
        lg.exception("private scan failed")
    out = buf.getvalue()
    assert "private scan failed" in out
    assert core not in out


@pytest.mark.parametrize(
    "field",
    [
        "authorization", "Authorization", "x-api-key", "X-API-Key", "x_provider_key",
        "X-Provider-Key", "cookie", "set-cookie", "password", "github_token", "token",
        "access_token", "refresh_token", "webhook_secret", "client_secret", "secret",
        "api_key", "apiKey", "private_key", "email", "user_email", "jwt", "session_id",
    ],
)
@pytest.mark.parametrize("fmt", FORMATTERS)
def test_sensitive_structured_field_replaced(fmt, field):
    # A value with no secret shape, so only the field name can catch it.
    value = "plainvalue12345"
    lg, buf = _logger(fmt())
    # Top-level extra, and nested inside a dict extra (e.g. a headers mapping).
    lg.info("request", extra={field: value, "headers": {field: value}})
    assert value not in buf.getvalue()


def test_json_structured_fields_keep_harmless_values():
    lg, buf = _logger(JSONFormatter())
    lg.info(
        "scan done",
        extra={"repo": "owner/name", "token_budget": 4000, "tokens_used": 12, "score": 84},
    )
    entry = json.loads(buf.getvalue())
    assert entry["repo"] == "owner/name"
    assert entry["token_budget"] == 4000
    assert entry["tokens_used"] == 12
    assert entry["score"] == 84


def test_json_header_mapping_is_redacted_but_kept():
    lg, buf = _logger(JSONFormatter())
    headers = {
        "Authorization": "Bearer plain1234567",
        "Cookie": "session=abc123def456",
        "X-API-Key": "plainkey123456",
        "Accept": "application/json",
    }
    lg.info("outbound", extra={"headers": headers})
    entry = json.loads(buf.getvalue())
    assert entry["headers"] == {
        "Authorization": REDACTED,
        "Cookie": REDACTED,
        "X-API-Key": REDACTED,
        "Accept": "application/json",
    }


def test_cookie_header_text_redacted_to_end_of_line():
    out = redact_text("Cookie: ag_session=one1two2three3; csrftoken=four4five5")
    assert "one1two2three3" not in out
    assert "four4five5" not in out


def test_pem_private_key_redacted():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
    text = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    assert body not in redact_text(f"loaded key {text}")


def test_ssh_remote_and_plain_words_untouched():
    text = (
        "git@github.com:owner/repo.git token mint failed for 1234 tokens: 15; "
        "GitHub token response missing access_token; Bearer authentication failed"
    )
    assert redact_text(text) == text


def test_redact_value_handles_odd_types():
    class Obj:
        def __str__(self) -> str:
            return "ghp_" + _A

    out = redact_value({"nested": [Obj(), ("ghp_" + _A,), {"password": 1}], "n": 3})
    assert _A not in json.dumps(out)
    assert out["n"] == 3
    assert out["nested"][2] == {"password": REDACTED}


def test_is_sensitive_key_does_not_catch_counts():
    for name in ("token_budget", "tokens_used", "max_tokens", "author", "repo", "status"):
        assert not is_sensitive_key(name), name


def test_private_scan_token_never_logged_end_to_end():
    """The private-scan path's token, logged the ways code tends to log it."""
    token = "github_pat_11AAAAAAA0_" + _A
    lg, buf = _logger(JSONFormatter())
    lg.info("private scan start", extra={"github_token": token, "repo": "me/secret"})
    lg.info("private scan request headers %s", {"Authorization": f"token {token}"})
    lg.error("clone failed: https://oauth2:%s@github.com/me/secret.git", token)
    out = buf.getvalue()
    assert _A not in out
    assert "me/secret" in out
