"""Meta description lengths on every prerendered page, and the IndexNow ping.

Bing flags descriptions outside 25-160 characters. The build enforces 50-160 too
(web/scripts/prerender.mjs, strict in CI); these tests catch it from the source without
a build, and check the built HTML when web/dist/prerender is there. File-only: run with
--noconftest.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
sys.path.insert(0, str(ROOT / "scripts"))

import indexnow_ping as ix  # noqa: E402

MIN_CHARS, MAX_CHARS = 50, 160
ENTRY = (WEB / "src/prerender-entry.tsx").read_text()


def _route_components() -> dict[str, Path]:
    imports = dict(re.findall(r"import (\w+) from '\./(rebrand/pages/\w+)'", ENTRY))
    block = ENTRY[ENTRY.index("const PAGES"):ENTRY.index("export const ROUTES")]
    return {
        route: WEB / "src" / f"{imports[name]}.tsx"
        for route, name in re.findall(r"'(/[^']*)': <(\w+) />", block)
    }


def _source_description(page: Path) -> str:
    """The page's own static description: the first SEOHead prop or Helmet meta."""
    m = re.search(r'description="([^"]+)"|name="description"\s+content="([^"]+)"', page.read_text())
    assert m, f"no static description in {page.name}"
    return m.group(1) or m.group(2)


ROUTES = _route_components()


def test_every_prerendered_route_is_covered():
    assert len(ROUTES) == 16  # /badge and /submit became redirects into /for-developers (11-11)
    assert all(p.exists() for p in ROUTES.values())


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_prerendered_page_description_length(route: str):
    text = _source_description(ROUTES[route])
    assert MIN_CHARS <= len(text) <= MAX_CHARS, f"{route}: {len(text)} chars: {text}"


def test_descriptions_keep_house_wording():
    for route, page in ROUTES.items():
        text = _source_description(page).lower()
        assert "letter grade" not in text, route
        assert "reputation" not in text, route


def test_shell_default_description_matches_everywhere_and_fits():
    shell = re.findall(r'description" data-static-seo content="([^"]+)"', (WEB / "index.html").read_text())
    default = re.search(r"DEFAULT_DESCRIPTION = '([^']+)'", (WEB / "src/components/SEOHead.tsx").read_text())
    vite = (WEB / "vite.config.ts").read_text()
    desc = "".join(re.findall(r"'([^']*)'", vite[vite.index("const DESC"):vite.index("return {")]))
    assert len(shell) == 3 and len(set(shell)) == 1
    assert shell[0] == default.group(1) == desc
    assert MIN_CHARS <= len(desc) <= MAX_CHARS


def test_prerender_build_enforces_the_same_range():
    script = (WEB / "scripts/prerender.mjs").read_text()
    assert f"DESCRIPTION_CHARS = [{MIN_CHARS}, {MAX_CHARS}]" in script


BUILT = sorted((WEB / "dist/prerender").glob("**/index.html")) if (WEB / "dist/prerender").exists() else []


@pytest.mark.skipif(not BUILT, reason="no prerender build in web/dist")
@pytest.mark.parametrize("page", BUILT, ids=lambda p: str(p.parent.name or "/"))
def test_built_page_descriptions(page: Path):
    text = page.read_text()
    found = {
        key: [html.unescape(v) for v in re.findall(rf'<meta[^>]*(?:name|property)="{key}"[^>]*content="([^"]*)"', text)]
        for key in ("description", "og:description", "twitter:description")
    }
    assert len(found["description"]) == 1
    desc = found["description"][0]
    assert MIN_CHARS <= len(desc) <= MAX_CHARS, f"{page}: {len(desc)} chars"
    assert found["og:description"] == found["twitter:description"] == [desc]


# --- IndexNow ---


def test_key_file_is_served_from_public_and_holds_its_key():
    key = ix.find_key()
    assert re.fullmatch(r"[0-9a-f]{32}", key)
    assert (WEB / "public" / f"{key}.txt").read_text().strip() == key


def test_key_file_is_not_intercepted_by_an_nginx_location():
    # Served by `location /` from the build (mime.types gives text/plain); nothing
    # may catch *.txt at the root and send it elsewhere.
    nginx = (ROOT / "nginx/nginx.conf").read_text()
    assert r"\.txt" not in nginx
    assert "include /etc/nginx/mime.types;" in nginx


def test_build_payload_shape():
    key = "0123456789abcdef0123456789abcdef"
    urls = ["https://agentavow.com/", "https://agentavow.com/check"]
    assert ix.build_payload(key, urls) == {
        "host": "agentavow.com",
        "key": key,
        "keyLocation": f"https://agentavow.com/{key}.txt",
        "urlList": urls,
    }
    json.dumps(ix.build_payload(key, urls))  # serializable as sent


SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://agentavow.com/</loc><lastmod>2026-11-10</lastmod></url>
  <url><loc>https://agentavow.com/check</loc><lastmod>2026-10-02</lastmod></url>
  <url><loc>https://agentavow.com/faq</loc></url>
  <url><loc>https://example.com/elsewhere</loc><lastmod>2026-11-10</lastmod></url>
</urlset>"""


def test_read_sitemap_keeps_order_and_this_host_only():
    assert ix.read_sitemap(SITEMAP) == {
        "https://agentavow.com/": "2026-11-10",
        "https://agentavow.com/check": "2026-10-02",
        "https://agentavow.com/faq": "",
    }


def test_real_sitemap_urls_all_go_in_the_payload():
    urls = ix.read_sitemap((WEB / "public/sitemap.xml").read_text())
    assert len(urls) >= 18
    assert all(u.startswith("https://agentavow.com/") for u in urls)


def test_changed_only_picks_new_and_moved_urls():
    current = ix.read_sitemap(SITEMAP)
    previous = {"https://agentavow.com/": "2026-11-01", "https://agentavow.com/check": "2026-10-02"}
    assert ix.changed(current, previous) == ["https://agentavow.com/", "https://agentavow.com/faq"]
    assert ix.changed(current, current) == []
    assert ix.changed(current, {}) == list(current)


def test_ping_failure_never_fails_and_prints_one_line(monkeypatch, capsys, tmp_path):
    def boom(_payload):
        raise TimeoutError("timed out\nafter 10s")

    monkeypatch.setattr(ix, "post", boom)
    assert ix.main(["--state", str(tmp_path / "s.json")]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and out.startswith("indexnow: skipped")
    assert not (tmp_path / "s.json").exists()


def test_successful_ping_records_state_for_changed_only(monkeypatch, capsys, tmp_path):
    sent: list[dict] = []
    monkeypatch.setattr(ix, "post", lambda payload: sent.append(payload) or 200)
    state = tmp_path / "s.json"
    assert ix.main(["--changed-only", "--state", str(state)]) == 0
    assert sent and sent[0]["urlList"]
    assert ix.main(["--changed-only", "--state", str(state)]) == 0
    assert len(sent) == 1  # nothing moved, nothing sent
    assert "no changed URLs" in capsys.readouterr().out
