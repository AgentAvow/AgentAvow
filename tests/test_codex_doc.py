"""The /docs/codex page: its connector command comes from the same source as the site.

The page is Markdown (rendered by the SPA and by the SSR docs router), so it can't
call `codexCmd()` from web/src/rebrand/lib/installLinks.ts. This test builds the
command the way the site does and checks the page carries exactly that string.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web" / "src" / "rebrand"
DOC = (WEB / "docs" / "codex.md").read_text()


def _site_codex_cmd() -> str:
    links = (WEB / "lib" / "installLinks.ts").read_text()
    m = re.search(
        r"export function codexCmd\(t: McpTarget\): string \{\s*return `([^`]+)`", links
    )
    assert m, "codexCmd() not found in installLinks.ts"
    paths = (WEB / "lib" / "agentavowPaths.ts").read_text()
    t = re.search(r"AGENTAVOW_MCP = \{ name: '([^']+)', url: '([^']+)' \}", paths)
    assert t, "AGENTAVOW_MCP not found in agentavowPaths.ts"
    return m.group(1).replace("${t.name}", t.group(1)).replace("${t.url}", t.group(2))


def test_codex_doc_uses_the_site_command() -> None:
    cmd = _site_codex_cmd()
    assert cmd == "codex mcp add agentavow --url https://agentavow.com/mcp"
    assert f"\n{cmd}\n" in DOC


def test_get_page_uses_the_same_connector() -> None:
    get = (WEB / "pages" / "Get.tsx").read_text()
    assert "const MCP = { name: 'agentavow', url: 'https://agentavow.com/mcp' }" in get


def _site_codex_plugin_cmds() -> list[str]:
    links = (WEB / "lib" / "installLinks.ts").read_text()
    m = re.search(r"export const CODEX_PLUGIN_COMMANDS = \[([^\]]+)\]", links)
    assert m, "CODEX_PLUGIN_COMMANDS not found in installLinks.ts"
    return re.findall(r"'([^']+)'", m.group(1))


def test_codex_plugin_commands_match_the_doc() -> None:
    cmds = _site_codex_plugin_cmds()
    assert cmds == ["codex plugin marketplace add AgentAvow/AgentAvow",
                    "codex plugin add agentavow-trust@agentavow"]
    assert "\n" + "\n".join(cmds) + "\n" in DOC


def test_codex_row_leads_with_the_plugin_and_keeps_the_connector() -> None:
    for f in ("pages/Get.tsx", "lib/agentavowPaths.ts"):
        src = (WEB / f).read_text()
        row = src[src.index("'Codex'"):]
        row = row[:row.index("\n")] if f.startswith("pages") else row[:row.index("\n  },")]
        assert "tag: 'Checks by itself (CLI)'" in row, f
        assert "Checks when you ask" not in row, f
        assert "CODEX_PLUGIN_COMMANDS.join('\\n')" in row, f
        assert "Connector only" in row and "codexCmd(" in row, f


def test_codex_doc_config_block_matches_the_connector() -> None:
    assert '[mcp_servers.agentavow]\nurl = "https://agentavow.com/mcp"\n' in DOC


def test_codex_doc_is_wired() -> None:
    docs = (WEB / "pages" / "Docs.tsx").read_text()
    assert "{ slug: 'codex'," in docs
    router = (ROOT / "src" / "api" / "docs_content_router.py").read_text()
    assert '("codex", "Use AgentAvow in Codex")' in router
    for f in ("pages/Get.tsx", "lib/agentavowPaths.ts"):
        src = (WEB / f).read_text()
        codex_row = src[src.index("'Codex'"):][:400]
        assert "/rebrand/docs/codex'" in codex_row, f


def test_codex_doc_skill_paths_exist() -> None:
    rels = re.findall(r"AgentAvow/AgentAvow/(?:main|tree/main)/([\w./-]+)", DOC)
    assert rels
    for rel in rels:
        assert (ROOT / rel).exists(), rel


def test_codex_doc_wording() -> None:
    low = DOC.lower()
    for banned in ("letter grade", "reputation", "open source", "open-source"):
        assert banned not in low, banned
    assert "plugin directory" not in low and "claude.ai/directory" not in low
