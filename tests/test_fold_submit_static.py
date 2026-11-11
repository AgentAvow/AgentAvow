"""Static checks for folding /submit into /for-developers (#list) and linking the A2A
trust-verdict extension spec (2026-11-11). File-only: run with --noconftest."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web" / "src" / "rebrand"
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
AVOW = NGINX[NGINX.index("server_name agentavow.com www.agentavow.com;\n        set $backend"):]
SITEMAP = (ROOT / "web" / "public" / "sitemap.xml").read_text()
DEV = (WEB / "pages" / "ForDevelopers.tsx").read_text()
FORM = (WEB / "components" / "ListToolForm.tsx").read_text()
PARSE = (WEB / "lib" / "listCoordinate.ts").read_text()
LAYOUT = (WEB / "RebrandLayout.tsx").read_text()
PRERENDER = (ROOT / "web" / "src" / "prerender-entry.tsx").read_text()
EXT = "/ext/trust-verdict/v1/"


# ---- /submit folded into /for-developers#list ----

def test_submit_redirects_to_the_developer_page():
    for path in ("/submit", "/submit/"):
        assert f"location = {path} {{ return 301 /for-developers#list; }}" in AVOW


def test_submit_route_still_resolves_client_side():
    page = (WEB / "pages" / "Submit.tsx").read_text()
    assert "<Navigate" in page and "'#list'" in page
    assert 'path="submit"' in (ROOT / "web" / "src" / "App.tsx").read_text()


def test_developer_page_has_the_list_form():
    assert 'id="list"' in DEV and "<ListToolForm />" in DEV
    assert "Not listed yet? Add it." in DEV
    # The form still calls the submit endpoint with the parsed coordinate.
    assert "'/public/scan/submit', coord" in FORM
    assert "export function parseCoordinate" in PARSE and "parseCoordinate(value)" in FORM


def test_mcp_prefix_parses_as_an_endpoint():
    # "mcp:https://…" used to fall through to the owner/repo branch.
    assert r"v.match(/^mcp\s*:\s*(https?:\/\/\S+)$/i)" in PARSE


def test_submit_left_nav_sitemap_and_prerender():
    assert "/rebrand/submit" not in LAYOUT and "List your tool" not in LAYOUT
    assert "agentavow.com/submit<" not in SITEMAP
    assert "'/submit'" not in PRERENDER and "pages/Submit" not in PRERENDER


# ---- A2A trust-verdict extension spec ----

def test_extension_spec_page_exists():
    assert (ROOT / "web" / "public" / "ext" / "trust-verdict" / "v1" / "index.html").is_file()


def test_extension_spec_is_linked_with_plain_anchors():
    docs = (WEB / "pages" / "Docs.tsx").read_text()
    assert f"['A2A trust-verdict extension', '{EXT}']" in docs
    how = (WEB / "pages" / "HowItWorks.tsx").read_text()
    assert "Our agent card carries a pointer to its own signed verdict" in how and EXT in how
    teams = (WEB / "pages" / "Teams.tsx").read_text()
    assert f'<a href="{EXT}"' in teams and "Extension spec →" in teams
    for src in (docs, how, teams):
        assert f'to="{EXT}"' not in src and "rp('/ext" not in src


def test_extension_is_served_by_the_static_fallthrough():
    # No SPA route for /ext; with a slash, location / serves the file through $uri/.
    assert "try_files /prerender$uri/index.html $uri $uri/ @spa_route;" in AVOW
    # The declared URI has no slash: answered with a 200, not the directory 301.
    assert "location = /ext/trust-verdict/v1 { rewrite ^ /ext/trust-verdict/v1/index.html last; }" in AVOW
