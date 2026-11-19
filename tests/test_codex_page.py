"""The /codex landing page: its commands come from the site's own source, its wording
is the Codex wording, and the route is wired everywhere /claude-code is.

Codex hooks can't ask, so on Do not connect the plugin stops the step and says why.
The page must not use the Claude Code wording ("asks before you install it") or claim
anything about calls to a server that's already connected.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
REBRAND = WEB / "src" / "rebrand"
PAGE = (REBRAND / "pages" / "Codex.tsx").read_text()


def _codex_plugin_cmds() -> list[str]:
    links = (REBRAND / "lib" / "installLinks.ts").read_text()
    m = re.search(r"export const CODEX_PLUGIN_COMMANDS = \[([^\]]+)\]", links)
    assert m, "CODEX_PLUGIN_COMMANDS not found in installLinks.ts"
    return re.findall(r"'([^']+)'", m.group(1))


def _visible_text() -> str:
    """The page's copy, roughly: JSX text and string literals, without the doc comments."""
    body = re.sub(r"/\*.*?\*/", " ", PAGE, flags=re.S)
    body = re.sub(r"(?m)^\s*//.*$", " ", body)
    return body


def test_install_box_uses_the_site_commands() -> None:
    cmds = _codex_plugin_cmds()
    assert cmds == ["codex plugin marketplace add AgentAvow/AgentAvow",
                    "codex plugin add agentavow-trust@agentavow"]
    # The commands are rendered from the shared constant, never retyped.
    assert "CODEX_PLUGIN_COMMANDS.join('\\n')" in PAGE
    assert "CODEX_PLUGIN_COMMANDS.map(" in PAGE
    for cmd in cmds:
        assert cmd not in PAGE, f"retyped command: {cmd}"
    # The connector-only line for the IDE extension comes from codexCmd() too.
    assert "codexCmd(AGENTAVOW_MCP)" in PAGE
    assert "codex mcp add agentavow --url" not in PAGE


def test_wording_is_the_codex_wording() -> None:
    text = _visible_text()
    # The one directory this page names is OpenAI's (the ChatGPT listing); any other
    # "plugin directory" (the Claude one) stays banned.
    low = text.lower().replace("openai&apos;s plugin directory", "")
    assert "CHATGPT_LISTING" in PAGE
    for banned in ("letter grade", "reputation", "open source", "open-source",
                   "plugin directory", "claude.ai/directory", "CLAUDE_LISTING".lower(),
                   "asks before you install", "already connected", "every day",
                   "machines connect", "rug-pull", "rug pull", "metapixel", "meta pixel"):
        assert banned not in low, banned
    for phrase in ("Safe to connect", "Review before you connect", "Do not connect"):
        assert phrase in text, phrase
    assert "Stops the step and says why" in text
    assert "run it yourself outside Codex" in text
    assert "again after each plugin update" in text
    assert "The IDE extension doesn&apos;t run plugins" in text
    assert "Knostic" in text


def test_no_pixel_and_no_claude_code_email() -> None:
    assert "metaPixel" not in PAGE and "startMetaPixel" not in PAGE
    # The emailed setup carries the Claude Code commands, so this page doesn't offer it.
    assert "EmailSetup" not in PAGE
    assert "page: '/codex'" in PAGE


def test_links_are_full_page_loads_and_point_at_the_docs() -> None:
    assert "<Link" not in PAGE and "from 'react-router-dom'" in PAGE
    assert "rp('/rebrand/docs/codex')" in PAGE
    assert (REBRAND / "docs" / "codex.md").exists()


def test_route_is_wired() -> None:
    app = (WEB / "src" / "App.tsx").read_text()
    assert "import('./rebrand/pages/Codex')" in app
    assert '<Route path="codex" element={<RebrandCodex />} />' in app
    entry = (WEB / "src" / "prerender-entry.tsx").read_text()
    assert "'/codex': <Codex />," in entry
    sitemap = (WEB / "public" / "sitemap.xml").read_text()
    assert "<loc>https://agentavow.com/codex</loc>" in sitemap
    llms = (WEB / "public" / "llms.txt").read_text()
    assert "(https://agentavow.com/codex)" in llms
    nginx = (ROOT / "nginx" / "nginx.conf").read_text()
    assert "~^/codex/?$ 1;" in nginx


def test_seo_is_about_codex() -> None:
    m = re.search(r'title="([^"]+)"\s+description="([^"]+)"\s+path="/codex"', PAGE)
    assert m, "SEOHead for /codex not found"
    title, desc = m.groups()
    assert "Codex" in title and "MCP servers" in title and "packages" in title
    assert "Codex" in desc and "MCP servers" in desc
