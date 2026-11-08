"""Cloudflare Web Analytics must never receive a check page's address.

The beacon loads from web/src/lib/cloudflareBeacon.ts. On entering a /check/ page it adds a
stricter connect-src that leaves cloudflareinsights.com out. That list must cover every
other host nginx allows, or check pages would lose their own requests.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOADER = (ROOT / "web/src/lib/cloudflareBeacon.ts").read_text()
INDEX = (ROOT / "web/index.html").read_text()
MAIN = (ROOT / "web/src/main.tsx").read_text()
NGINX = (ROOT / "nginx/nginx.conf").read_text()

BEACON_HOST = "https://cloudflareinsights.com"
# Allowed only on /claude-code, for the Meta Pixel (tests/test_meta_pixel.py). The block
# list may drop it too: that page has no in-app link to a check page, and if one were
# followed, cutting the pixel off there is what we'd want.
META_EVENTS_HOST = "https://www.facebook.com"


def _csp_headers() -> list[str]:
    """The policies the web app is served under (the API docs pages have their own)."""
    every = re.findall(r'add_header Content-Security-Policy "([^"]+)"', NGINX)
    # Google sign-in runs only in the web app, so its script host marks the app's policies.
    return [csp for csp in every
            if "https://accounts.google.com" in _directive(csp, "script-src")]


def _directive(csp: str, name: str) -> set[str]:
    for part in csp.split(";"):
        words = part.split()
        if words and words[0] == name:
            return set(words[1:])
    raise AssertionError(f"{name} missing from {csp}")


def _blocking_list() -> set[str]:
    m = re.search(r'CONNECT_SRC_WITHOUT_BEACON =\s*"([^"]+)"', LOADER)
    assert m
    return set(m.group(1).split())


def test_beacon_is_not_in_the_html_shell():
    # A tag in index.html would also land in every prerendered page and run on /check.
    assert "cloudflareinsights" not in INDEX
    assert "data-cf-beacon" not in INDEX


def test_loader_turns_off_spa_tracking_and_runs_before_the_app():
    assert "spa: false" in LOADER
    assert "https://static.cloudflareinsights.com/beacon.min.js" in LOADER
    assert MAIN.index("startCloudflareAnalytics()") < MAIN.index("createRoot(")


def test_block_list_drops_only_cloudflare():
    blocking = _blocking_list()
    assert BEACON_HOST not in blocking
    headers = _csp_headers()
    assert headers
    for csp in headers:
        allowed = _directive(csp, "connect-src")
        assert BEACON_HOST in allowed
        extra = allowed - {BEACON_HOST, META_EVENTS_HOST} - blocking
        assert not extra, extra


def test_csp_still_allows_the_beacon_script_without_inline_code():
    for csp in _csp_headers():
        scripts = _directive(csp, "script-src")
        assert "https://static.cloudflareinsights.com" in scripts
        assert "'unsafe-inline'" not in scripts
