"""Build-time prerender wiring, plus the small search fixes that shipped with it.

The pages themselves are checked by `npm run prerender` under PRERENDER_STRICT=1 in the
frontend CI job (title, description, canonical, one H1, word count, no invisible text).
These tests hold the parts around it that would fail quietly: nginx, the build scripts
and the static files.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gen_spa_routes as g  # noqa: E402

NGINX = (ROOT / "nginx/nginx.conf").read_text()
ENTRY = (ROOT / "web/src/prerender-entry.tsx").read_text()
SCRIPT = (ROOT / "web/scripts/prerender.mjs").read_text()


def _primary_server() -> str:
    return NGINX[NGINX.index("# AgentAvow (primary domain)"):]


def _prerendered_routes() -> list[str]:
    block = ENTRY[ENTRY.index("const PAGES"):ENTRY.index("export const ROUTES")]
    return re.findall(r"'(/[^']*)':", block)


def _locations(conf: str) -> list[tuple[str, str]]:
    """(location line, body) for every location block; these have no nested blocks
    apart from `if`, which the brace count steps over."""
    found = []
    for m in re.finditer(r"(?m)^\s*location [^{\n]*\{", conf):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(conf[i], 0)
            i += 1
        found.append((m.group().strip(), conf[m.end():i]))
    return found


def test_nginx_serves_prerendered_page_before_the_shell():
    # Before $uri: on / that matches the directory and serves the shell.
    assert "try_files /prerender$uri/index.html $uri $uri/ @spa_route;" in _primary_server()


def test_prerender_directory_is_not_a_public_url():
    bodies = dict(_locations(_primary_server()))
    assert "internal;" in bodies["location /prerender/ {"]


def test_pages_never_overwrite_the_shell_or_collide_with_it():
    # dist/index.html is the fallback for every route. /index is a real page, so it
    # must not be able to resolve to that file.
    assert "path.join(DIST, 'prerender')" in SCRIPT
    assert "path.join(OUT, route)" in SCRIPT
    assert "writeFile(path.join(DIST" not in SCRIPT


def test_prerendered_routes_are_real_routes_in_the_sitemap():
    known = [g.to_regex(p) for p in g.route_paths(g.APP.read_text())]
    sitemap = (ROOT / "web/public/sitemap.xml").read_text()
    routes = _prerendered_routes()
    assert len(routes) == 16  # /badge and /submit became redirects into /for-developers (11-11)
    for route in routes:
        assert any(re.match(p, route) for p in known), route
        assert f"<loc>https://agentavow.com{route if route != '/' else ''}" in sitemap, route


def test_login_is_never_prerendered():
    assert "/login" not in _prerendered_routes()


def test_build_runs_prerender_and_ci_is_strict():
    pkg = json.loads((ROOT / "web/package.json").read_text())
    assert pkg["scripts"]["build"].endswith("npm run prerender")
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert 'PRERENDER_STRICT: "1"' in ci


def test_prerender_failure_does_not_stop_a_deploy():
    assert "process.exit(STRICT && problems ? 1 : 0)" in SCRIPT


def test_nothing_inline_executes_under_the_csp():
    # script-src has no 'unsafe-inline': the snapshot may only carry data blocks.
    assert 'type="application/json" id="prerender-state"' in SCRIPT
    assert "<script>" not in SCRIPT


def test_tool_rows_stay_out_of_static_html():
    # Conflicting catalog rows must be resolved before tool answers reach search
    # results (audit fix 5). These queries are kept for their totals only.
    assert "TOTALS_ONLY_QUERIES = new Set(['rebrand-catalog', 'trust-index'])" in ENTRY


def test_build_does_not_touch_the_check_counter():
    # /public/scan/{owner}/{repo}/checks counts a check on every GET.
    fetched = re.search(r"const BUILD_QUERIES = new Set\(\[(.*?)\]\)", ENTRY).group(1)
    assert "home-ex-adopt" not in fetched


def test_api_noindex_is_keyed_on_the_requested_url():
    # $uri would also match docs and legal pages proxied to /api internally, and
    # tell search engines to drop them.
    assert re.search(r'map \$request_uri \$api_robots \{\s*default "";\s*~\^/api/ "noindex";',
                     NGINX)


def test_api_noindex_reaches_every_api_location():
    # A location with its own add_header inherits nothing from the server level.
    assert len(re.findall(r"(?m)^        add_header X-Robots-Tag \$api_robots always;$",
                          NGINX)) == 2
    for head, body in _locations(NGINX):
        if "/api" in head and "add_header" in body:
            assert "add_header X-Robots-Tag $api_robots always;" in body, head


def test_llms_txt_links_readable_pages():
    llms = (ROOT / "web/public/llms.txt").read_text()
    assert "/api/v1/docs" not in llms
    assert "https://agentavow.com/faq" in llms
    assert "https://agentavow.com/state-of-agent-security-q3-2026" in llms


def test_manifest_has_no_grade_wording():
    manifest = json.loads((ROOT / "web/public/manifest.json").read_text())
    assert "grade" not in manifest["description"].lower()


@pytest.mark.parametrize("data", [None, {"trust_score": 92, "findings": {}}])
def test_og_image_url_carries_no_letter_grade(data):
    from src.api.og_router import _og_image_url

    url = _og_image_url("x/y", 92, "t", data)
    assert "grade=" not in url and "score=92" in url
