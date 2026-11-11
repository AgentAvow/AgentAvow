"""The Meta Pixel runs on /claude-code and nowhere else, and the privacy policy says so.

The pixel loads from web/src/lib/metaPixel.ts, called only by the /claude-code page. nginx
allows Meta's hosts only in the exact-match /claude-code location, so even a bug that loaded
the script elsewhere would be refused by the browser.
"""
from __future__ import annotations

import re
from pathlib import Path

from src.api.legal_router import _PRIVACY_CLAUSES

ROOT = Path(__file__).resolve().parent.parent
NGINX = (ROOT / "nginx/nginx.conf").read_text()
LOADER = (ROOT / "web/src/lib/metaPixel.ts").read_text()
INDEX = (ROOT / "web/index.html").read_text()
WEB_SRC = ROOT / "web/src"

PIXEL_ID = "1727269052296184"
META_HOSTS = ("https://connect.facebook.net", "https://www.facebook.com")


def _locations(conf: str) -> list[tuple[str, str]]:
    found = []
    for m in re.finditer(r"(?m)^\s*location [^{\n]*\{", conf):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(conf[i], 0)
            i += 1
        found.append((m.group().strip(), conf[m.end():i]))
    return found


def _directive(csp: str, name: str) -> set[str]:
    for part in csp.split(";"):
        words = part.split()
        if words and words[0] == name:
            return set(words[1:])
    return set()


def _csp(body: str) -> str:
    m = re.search(r'add_header Content-Security-Policy "([^"]+)"', body)
    assert m
    return m.group(1)


def _primary_server() -> str:
    return NGINX[NGINX.index("# AgentAvow (primary domain)"):]


def test_meta_hosts_appear_only_in_the_claude_code_location():
    with_meta = [head for head, body in _locations(NGINX)
                 if any(h in body for h in META_HOSTS)]
    assert with_meta == ["location = /claude-code {"]
    # Nothing at server level either.
    outside = NGINX
    for head, body in _locations(NGINX):
        outside = outside.replace(body, "")
    assert not any(h in outside for h in META_HOSTS)


def test_claude_code_csp_is_the_site_csp_plus_two_hosts():
    bodies = dict(_locations(_primary_server()))
    page = _csp(bodies["location = /claude-code {"])
    site = _csp(bodies["location / {"])
    assert _directive(page, "script-src") == _directive(site, "script-src") | {META_HOSTS[0]}
    assert _directive(page, "connect-src") == _directive(site, "connect-src") | {META_HOSTS[1]}
    for name in ("default-src", "style-src", "img-src", "font-src", "frame-src",
                 "frame-ancestors", "form-action", "base-uri"):
        assert _directive(page, name) == _directive(site, name), name
    assert "'unsafe-inline'" not in _directive(page, "script-src")


def test_claude_code_location_never_falls_through_to_the_strict_csp():
    bodies = dict(_locations(_primary_server()))
    body = bodies["location = /claude-code {"]
    # A file then =404: a URI fallback would redirect into location / internally.
    assert "try_files /prerender/claude-code/index.html /index.html =404;" in body


def test_pixel_loader_is_scoped_and_minimal():
    assert PIXEL_ID in LOADER
    assert "META_PIXEL_PATH = '/claude-code'" in LOADER
    assert "stub('set', 'autoConfig', false, META_PIXEL_ID)" in LOADER
    # init with the ID alone: no Advanced Matching data.
    assert "stub('init', META_PIXEL_ID)" in LOADER
    assert "stub.disablePushState = true" in LOADER
    assert "globalPrivacyControl" in LOADER
    assert "documentPath() !== META_PIXEL_PATH" in LOADER


def test_pixel_is_not_in_the_shell_and_only_the_landing_page_starts_it():
    assert "facebook" not in INDEX and "fbq" not in INDEX
    callers = [p.relative_to(WEB_SRC).as_posix() for p in WEB_SRC.rglob("*.ts*")
               if "startMetaPixel(" in p.read_text() and p.name != "metaPixel.ts"]
    assert callers == ["rebrand/pages/ClaudeCode.tsx"]
    users = {p.relative_to(WEB_SRC).as_posix() for p in WEB_SRC.rglob("*.ts*")
             if "lib/metaPixel" in p.read_text()}
    assert users == {"rebrand/pages/ClaudeCode.tsx"}


def test_privacy_policy_discloses_the_pixel():
    text = " ".join(b for _, b in _PRIVACY_CLAUSES)
    for phrase in ("Meta Pixel", "/claude-code only", "no other page", "_fbp",
                   "no Advanced Matching", "To opt out:", "Global Privacy Control",
                   "Meta Platforms"):
        assert phrase in text, phrase


def test_copy_button_falls_back_to_a_manual_copy():
    """In-app browsers (Reddit's) can refuse clipboard writes. Then the line is
    selected and the person is told to copy it by hand; the onCopy handler still
    tracks that copy, and nothing is counted for a copy that didn't happen."""
    src = (Path(__file__).resolve().parent.parent / "web" / "src" / "rebrand" / "pages"
           / "ClaudeCode.tsx").read_text()
    body = src[src.index("const copy = async"):]
    body = body[: body.index("\n  }\n")]
    assert "selectLine(" in body and "setManual(i)" in body
    assert body.index("return") < body.index("copied()")  # failure returns before tracking
    assert "onCopy={selectionCopied}" in src
    assert "press and hold" in src


def test_ad_visitors_get_the_normal_header_and_footer():
    """/claude-code keeps the site nav and footer for ad arrivals (Kenne, 2026-11-11)."""
    src = (Path(__file__).resolve().parent.parent / "web" / "src" / "rebrand"
           / "RebrandLayout.tsx").read_text()
    assert "const BARE_PAGES = new Set<string>([])" in src
