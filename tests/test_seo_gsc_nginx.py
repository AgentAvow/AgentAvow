"""Search Console fixes (2026-11-10): old-URL redirects, favicon.ico, placeholder /check
pages sent noindex, no stale SearchAction, and a sitemap with no redirected URLs.

Reads nginx/nginx.conf statically, the same way tests/test_legacy_robots.py does.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
SITEMAP = (ROOT / "web" / "public" / "sitemap.xml").read_text()
DOCS_ROUTER = (ROOT / "src" / "api" / "docs_content_router.py").read_text()

# The agentavow.com server block (the agentgraph.co one redirects everything here).
AVOW = NGINX[NGINX.index("server_name agentavow.com www.agentavow.com;\n        set $backend"):]

REDIRECTS = {
    "/docs/getting-started": "/docs",
    "/docs/developer-guide": "/for-developers",
    "/docs/sdk": "/docs/gate-on-the-grade",
    "/docs/aip-spec": "/docs",
    "/docs/bot-onboarding": "/docs",
    "/verify": "/docs/verify-attestations",
    "/verify/": "/docs/verify-attestations",
    "/blog/openclaw-scan": "/research",
}


def _exact_redirects() -> dict[str, str]:
    out = {}
    for m in re.finditer(r"location = (\S+) \{\s*return 301 (\S+?);", AVOW):
        out[m.group(1)] = m.group(2)
    return out


def _doc_slugs() -> set[str]:
    return set(re.findall(r'\("([a-z0-9-]+)", "', DOCS_ROUTER))


def _spa_route_patterns() -> list[re.Pattern[str]]:
    block = re.search(r"map \$uri \$spa_known_route \{(.*?)\n    \}", NGINX, re.S)
    assert block
    return [re.compile(m) for m in re.findall(r"~(\S+) 1;", block.group(1))]


def _is_static_public(path: str) -> bool:
    """A static file nginx serves straight from web/public (a spec page or a PDF)."""
    public = ROOT / "web" / "public"
    rel = path.strip("/")
    return bool(rel) and ((public / rel).is_file() or (public / rel / "index.html").is_file())


def _is_live_target(path: str) -> bool:
    if _is_static_public(path):
        return True
    if path.startswith("/docs/"):
        return path.removeprefix("/docs/") in _doc_slugs()
    return any(p.search(path) for p in _spa_route_patterns())


@pytest.mark.parametrize(("src", "dst"), REDIRECTS.items())
def test_old_url_redirects_exactly(src: str, dst: str) -> None:
    assert _exact_redirects().get(src) == dst


@pytest.mark.parametrize("dst", sorted(set(REDIRECTS.values())))
def test_redirect_targets_are_live_pages(dst: str) -> None:
    assert _is_live_target(dst), dst


def test_redirect_targets_are_not_themselves_redirected() -> None:
    redirects = _exact_redirects()
    for dst in REDIRECTS.values():
        assert dst not in redirects, dst


def test_favicon_ico_served() -> None:
    ico = ROOT / "web" / "public" / "favicon.ico"
    assert ico.read_bytes()[:4] == b"\x00\x00\x01\x00"  # ICO header
    block = re.search(r"location = /favicon\.ico \{(.*?)\n        \}", AVOW, re.S)
    assert block and "try_files /favicon.ico =404;" in block.group(1)


def _check_robots() -> re.Pattern[str]:
    block = re.search(r"map \$request_uri \$check_robots \{(.*?)\n    \}", NGINX, re.S)
    assert block, "check_robots map missing"
    m = re.search(r'"~\*(\S+)"\s+"noindex";', block.group(1))
    assert m
    return re.compile(m.group(1), re.I)


PLACEHOLDERS = [
    "/check/owner/repo", "/check/OWNER/REPO", "/check/Owner/Repo", "/check/you/your-repo",
    "/check/owner/repo/", "/check/owner/repo?force=true", "/check/owner/name",
    "/check/your-org/your-repo", "/check/your-org/your-mcp-server", "/check/org/project",
    "/check/%7Bowner%7D/%7Brepo%7D", "/check/:owner/:repo", "/check/%3Cowner%3E/%3Crepo%3E",
]
REAL = [
    "/check/kieksme/mcp-listmonk", "/check/AgentAvow/AgentAvow",
    "/check/agentgraph-co/agentgraph", "/check/owner/repository", "/check/owners/repo",
    "/check/owner/repo-tools", "/check/you/your-repo2", "/check/modelcontextprotocol/servers",
    "/check", "/check/mcp", "/check/pkg/npm/owner", "/check/skill/owner/repo",
]


@pytest.mark.parametrize("uri", PLACEHOLDERS)
def test_placeholder_check_pages_are_noindex(uri: str) -> None:
    assert _check_robots().search(uri)


@pytest.mark.parametrize("uri", REAL)
def test_real_check_pages_stay_indexable(uri: str) -> None:
    assert not _check_robots().search(uri)


def test_check_robots_header_on_check_locations() -> None:
    check = re.search(r"location ~ \^/check/\(\[\^/\]\+\)/\(\[\^/\]\+\)\$ \{(.*?)\n        \}",
                      AVOW, re.S)
    assert check and "add_header X-Robots-Tag $check_robots always;" in check.group(1)
    spa = re.search(r"location @spa_route \{(.*?)\n        \}", AVOW, re.S)
    assert spa and "add_header X-Robots-Tag $check_robots always;" in spa.group(1)


def test_no_stale_searchaction() -> None:
    hits = []
    for base in ("web/src", "web/scripts", "web/public", "src"):
        for f in (ROOT / base).rglob("*"):
            if f.is_file() and f.suffix in {".ts", ".tsx", ".mjs", ".js", ".html", ".py", ".json"}:
                if "search_term_string" in f.read_text(errors="ignore"):
                    hits.append(str(f))
    hits += ["web/index.html"] if "search_term_string" in (ROOT / "web/index.html").read_text() else []
    assert not hits


def test_sitemap_has_no_redirected_or_unknown_urls() -> None:
    redirects = _exact_redirects()
    locs = re.findall(r"<loc>https://agentavow\.com([^<]*)</loc>", SITEMAP)
    assert locs
    for path in locs:
        path = path or "/"
        assert path not in redirects, path
        assert _is_live_target(path) or path.startswith("/legal/"), path


# Every sitemap URL must answer Googlebot with a 200 page it can index: not a redirect
# (nginx or client-side), not noindex, not disallowed in robots.txt (2026-11-10).
ROBOTS = (ROOT / "web" / "public" / "robots.txt").read_text()
PRERENDER = (ROOT / "web" / "src" / "prerender-entry.tsx").read_text()


def _sitemap_paths() -> list[str]:
    return [p or "/" for p in re.findall(r"<loc>https://agentavow\.com([^<]*)</loc>", SITEMAP)]


def _prerendered() -> set[str]:
    block = re.search(r"const PAGES: Record<string, ReactNode> = \{(.*?)\n\}", PRERENDER, re.S)
    assert block, "PAGES missing from prerender-entry.tsx"
    return set(re.findall(r"^\s*'(/[^']*)':", block.group(1), re.M))


def _disallowed(path: str) -> bool:
    allows = re.findall(r"^Allow:\s*(\S+)", ROBOTS, re.M)
    disallows = re.findall(r"^Disallow:\s*(\S+)", ROBOTS, re.M)
    longest_allow = max((len(a) for a in allows if path.startswith(a)), default=-1)
    longest_disallow = max((len(d) for d in disallows if path.startswith(d)), default=-1)
    return longest_disallow > longest_allow


def test_sitemap_urls_not_disallowed_in_robots_txt() -> None:
    assert not [p for p in _sitemap_paths() if _disallowed(p)]


def test_sitemap_urls_not_check_noindex() -> None:
    assert not [p for p in _sitemap_paths() if _check_robots().search(p)]


def test_sitemap_spa_urls_render_a_real_page() -> None:
    # A page in the prerender list is a real page with its own title and canonical. A
    # route that only redirects in the browser (like /claim) can't be in that list, so
    # it can't be in the sitemap either. Docs and legal pages are server-rendered for
    # crawlers by their own routers.
    pages = _prerendered()
    missing = [
        p for p in _sitemap_paths()
        if p != "/docs" and not p.startswith(("/docs/", "/legal/")) and p not in pages
        and not _is_static_public(p)
    ]
    assert not missing


def test_sitemap_every_url_has_a_lastmod() -> None:
    urls = re.findall(r"<url>(.*?)</url>", SITEMAP, re.S)
    assert urls
    for u in urls:
        m = re.search(r"<lastmod>(\d{4}-\d{2}-\d{2})</lastmod>", u)
        assert m, u


def test_sitemap_lists_both_reports_and_not_claim() -> None:
    paths = _sitemap_paths()
    assert "/state-of-agent-security-2026" in paths
    assert "/state-of-agent-security-q3-2026" in paths
    assert "/claim" not in paths
    assert {"/state-of-agent-security-2026", "/state-of-agent-security-q3-2026"} <= _prerendered()


def test_sitemap_has_no_duplicate_urls() -> None:
    paths = _sitemap_paths()
    assert len(paths) == len(set(paths))
