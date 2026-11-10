"""Legacy social pages send X-Robots-Tag: noindex; rebrand pages never do.

Reads the `$legacy_robots` map in nginx/nginx.conf and runs its regexes (PCRE syntax that
Python's `re` also accepts) against legacy routes, every sitemap URL, and the core rebrand
routes (docs/internal/seo-ai-audit-2026-11.md fix 6).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
SITEMAP = (ROOT / "web" / "public" / "sitemap.xml").read_text()


def _patterns() -> list[re.Pattern[str]]:
    block = re.search(r"map \$request_uri \$legacy_robots \{(.*?)\n    \}", NGINX, re.S)
    assert block, "legacy_robots map missing"
    out = []
    for line in block.group(1).splitlines():
        m = re.match(r'\s*~(\S+)\s+"noindex";', line)
        if m:
            out.append(re.compile(m.group(1)))
    assert out
    return out


def _noindex(uri: str) -> bool:
    return any(p.search(uri) for p in _patterns())


LEGACY = [
    "/feed", "/feed/", "/feed?utm_source=x", "/profile/abc", "/post/123", "/search",
    "/graph", "/marketplace", "/marketplace/42", "/marketplace/create", "/communities",
    "/m/general", "/leaderboard", "/trust/abc", "/evolution/abc", "/discover", "/agent/abc",
    "/badges", "/bot-onboarding", "/developers", "/scans", "/x402", "/register",
    "/onboarding", "/messages", "/dashboard", "/agents", "/legacy-home", "/auth/callback",
]

REBRAND = [
    "/", "/check", "/check/owner/repo", "/check/mcp", "/check/a2a?card=x", "/browse",
    "/index", "/claude-code", "/get", "/teams", "/faq", "/how-it-works", "/docs",
    "/docs/check-guide", "/legal/terms", "/login", "/badge", "/for-developers",
    "/state-of-agent-security-q3-2026", "/state-of-agent-security-2026", "/feedback",
    "/admin-dashboard", "/research", "/certified", "/claim",
]


def test_legacy_routes_are_noindex() -> None:
    missed = [u for u in LEGACY if not _noindex(u)]
    assert not missed


def test_rebrand_routes_stay_indexable() -> None:
    hit = [u for u in REBRAND if _noindex(u)]
    assert not hit


def test_no_sitemap_url_is_noindex() -> None:
    locs = re.findall(r"<loc>https://agentavow\.com([^<]*)</loc>", SITEMAP)
    assert locs
    assert not [u for u in locs if _noindex(u or "/")]


def test_header_sent_from_spa_locations() -> None:
    for name in ("location @spa_route {", "location / {\n            root"):
        start = NGINX.index(name)
        body = NGINX[start:NGINX.index("\n        }", start)]
        assert "add_header X-Robots-Tag $legacy_robots always;" in body, name
