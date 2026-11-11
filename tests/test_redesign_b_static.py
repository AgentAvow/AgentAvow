"""Static checks for the approved redesign, track B (2026-11-11): /get, the developer page
with /badge folded in, and the account shell. File-only: run with --noconftest."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web" / "src" / "rebrand"
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
SITEMAP = (ROOT / "web" / "public" / "sitemap.xml").read_text()
GET = (WEB / "pages" / "Get.tsx").read_text()
DEV = (WEB / "pages" / "ForDevelopers.tsx").read_text()
LAYOUT = (WEB / "RebrandLayout.tsx").read_text()
AVOW = NGINX[NGINX.index("server_name agentavow.com www.agentavow.com;\n        set $backend"):]


# ---- /badge folded into /for-developers ----

def test_badge_redirects_to_the_developer_page():
    for path in ("/badge", "/badge/"):
        assert f"location = {path} {{ return 301 /for-developers#badge; }}" in AVOW


def test_badge_route_still_resolves_client_side():
    badge = (WEB / "pages" / "Badge.tsx").read_text()
    assert "<Navigate" in badge and "'#badge'" in badge
    assert 'path="badge"' in (ROOT / "web" / "src" / "App.tsx").read_text()


def test_badge_page_left_the_sitemap_and_developers_has_the_maker():
    assert "agentavow.com/badge<" not in SITEMAP
    assert "agentavow.com/for-developers<" in SITEMAP
    assert 'id="badge"' in DEV and 'id="private"' in DEV and 'id="claim"' in DEV


def test_readme_badge_urls_are_untouched():
    # README embeds point at the API, never at the /badge page.
    target = (WEB / "lib" / "badgeTarget.ts").read_text()
    assert "/api/v1/public/scan/${owner}/${repo}/badge" in target
    assert "/api/v1/public/scan/package/${surface}/${name}/badge" in target
    assert "/api/v1/public/scan/mcp/badge?endpoint=" in target


def test_private_repo_copy_is_honest():
    # Kenne's pick: publish to get a badge; no private-README badge yet.
    assert "To get a badge, publish the result" in DEV
    assert "A badge for a private README without publishing" in DEV


# ---- /get ----

def test_get_order_claude_code_then_apps_then_codex():
    names = re.findall(r"\{ name: '([^']+)'", GET[GET.index("const GROUPS"):])
    assert names[:7] == [
        "Claude Code and Cowork plugin", "Claude and ChatGPT", "Codex", "Cursor",
        "VS Code", "Gemini CLI", "Any MCP client",
    ]
    for later in ("npm gates", "PyPI", "GitHub Action", "GitLab CI/CD Catalog", "API"):
        assert later in names
    assert names.index("PyPI") < names.index("GitHub Action") < names.index("GitLab CI/CD Catalog") < names.index("API")


def test_get_gitlab_row_matches_the_approved_text():
    assert "Gate merge requests on the answer. Runs in your own GitLab runner; nothing leaves your network." in GET
    assert "component: gitlab.com/agentavow/agentavow-scan/scan@0.1.0" in GET
    assert "fail_on: do_not_connect" in GET
    assert "https://gitlab.com/explore/catalog/agentavow/agentavow-scan" in GET
    assert "/rebrand/docs/run-locally#gitlab-ci" in GET


def test_get_vscode_is_one_click_with_https_fallback():
    assert "vscodeInstall(MCP)" in GET and "vscodeWebInstall(MCP)" in GET
    links = (WEB / "lib" / "installLinks.ts").read_text()
    assert "https://vscode.dev/redirect/mcp/install?" in links


def test_plugin_copy_never_says_blocks():
    for text in (GET, DEV):
        # The plugin warns or asks; it never "blocks" (CSS `block` is fine).
        assert not re.search(r"\bblocks\b|\bblocked\b|\bblocking\b", text, re.I)
        assert "letter grade" not in text.lower() and "reputation" not in text.lower()


# ---- nav, footer, account shell ----

def test_developers_in_nav_and_footer():
    assert "['/rebrand/for-developers', 'Developers']" in LAYOUT
    assert "['Check a private repo', '/rebrand/for-developers#private']" in LAYOUT
    assert "'/rebrand/badge'" not in LAYOUT


def test_account_pages_share_one_persistent_layout():
    # One parent route holds the header and tabs; only the <Outlet/> swaps (11-11).
    app = (ROOT / "web" / "src" / "App.tsx").read_text()
    block = app[app.index("<Route element={<RebrandAccountLayout />}>"):]
    block = block[:block.index("</Route>")]
    for path in ("tools", "account", "notifications", "settings"):
        assert f'<Route path="{path}" ' in block, path
        assert app.count(f'<Route path="{path}" element={{<Rebrand') == 1, path
    for page in ("MyTools", "Account", "Notifications", "Settings"):
        src = (WEB / "pages" / f"{page}.tsx").read_text()
        assert "AccountShell" not in src, page
    bits = (WEB / "components" / "AccountBits.tsx").read_text()
    assert "export function AccountLayout()" in bits and "<Outlet />" in bits
    assert "useRequireUser(user, isLoading)" in bits
    assert "max-w-[720px]" in bits
    assert "noindex" in bits
    # The route wrapper keeps one key for the whole account area, so tabs don't remount it.
    assert "key={accountTabFor(pathname) ? 'account' : pathname}" in LAYOUT


def test_api_keys_moved_to_settings_and_webhook_stayed():
    account = (WEB / "pages" / "Account.tsx").read_text()
    settings = (WEB / "pages" / "Settings.tsx").read_text()
    assert "/account/api-keys" not in account and "/account/api-keys" in settings
    assert "/account/alert-webhook" in account and "/account/alert-webhook" not in settings


def test_account_rows_show_adoption_artwork():
    for f in ("pages/Account.tsx", "pages/MyTools.tsx", "components/NotificationBits.tsx"):
        assert "<ToolArt" in (WEB / f).read_text(), f
    bits = (WEB / "components" / "AccountBits.tsx").read_text()
    # Always rendered, so a tool with no adoption signal shows the "New" state.
    assert "<AdoptionMini count={row.adoption_count} unit={row.adoption_unit} />" in bits


def test_no_blur_on_the_bell_dropdown():
    bell = LAYOUT[LAYOUT.index("{notifOpen && ("):LAYOUT.index("See all →")]
    assert "backdrop-blur" not in bell and "glass" not in bell


# ---- polish, 11-11 ----

def test_get_lines_up_with_the_1080_grid():
    # Outer 1080 container, inner 860 column with no auto margin: left edges match the logo.
    assert "max-w-[860px] mx-auto" not in GET
    assert GET.count("max-w-[1080px] mx-auto px-6") == 2
    assert '<div className="max-w-[860px]">' in GET


def test_section_dividers_are_contained():
    bits = (WEB / "components" / "PageBits.tsx").read_text()
    assert "before:w-[min(1080px,calc(100%-48px))]" in bits
    assert "${DIVIDER_CLASS}" in bits
    for f in ("Get", "Home", "ClaudeCode", "Teams", "ForDevelopers", "StateOfAgentSecurity2026",
              "Certified", "TrustIndex"):
        src = (WEB / "pages" / f"{f}.tsx").read_text()
        assert "py-[60px] border-t border-border/60" not in src, f
        assert 'pb-[60px] border-t border-border/60' not in src, f
        assert 'pb-[30px] border-t border-border/60' not in src, f
    # The footer keeps its full-width rule.
    assert '<footer className="relative z-10 bg-background border-t border-border/60' in LAYOUT


def test_home_certified_is_a_compact_row_under_the_answers():
    home = (WEB / "pages" / "Home.tsx").read_text()
    assert "CERT_ROWS" not in home and "CertifiedBand" not in home
    assert "every check passes, no averaging, and it comes off the moment one fails." in home
    answers = home.index('id="result"')
    where = home.index('id="where"')
    assert answers < home.index("<CertifiedRow") < where
    why = home[home.index("You don't have to take our word for it."):]
    assert "<BuiltInTheOpen" in why
