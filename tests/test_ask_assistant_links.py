"""The "Ask about this in ChatGPT / Claude" row on a report page
(web/src/rebrand/lib/askAssistant.ts), run under node: the prompt names the public tool
identifier and our connector; ChatGPT gets it prefilled through ?q=, while Claude gets a
blank new chat plus the same prompt on the clipboard (claude.ai warns on a prefilled
prompt, which reads like a prompt-injection alert); nothing but the public identifier
ends up in a link."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "web" / "src" / "rebrand" / "lib" / "askAssistant.ts"
COMPONENT = ROOT / "web" / "src" / "rebrand" / "components" / "ResultPage.tsx"
CHECK = ROOT / "web" / "src" / "rebrand" / "pages" / "Check.tsx"

SCRIPT = (
    "const m = await import(process.argv[1]);"
    "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
    "const out=JSON.parse(s).map(t=>({text:m.askTargetText(t),links:m.askLinks(t)}));"
    "process.stdout.write(JSON.stringify(out));});"
)


def _run(cases: list) -> list[dict]:
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", SCRIPT, str(LIB)],
        input=json.dumps(cases), capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _q(href: str) -> str:
    return parse_qs(urlparse(href).query)["q"][0]


def test_package_prompt_and_both_links():
    [r] = _run([{"kind": "package", "surface": "npm", "name": "gadgethumans-mcp",
                 "version": "1.0.15"}])
    assert r["text"] == "npm package gadgethumans-mcp 1.0.15"
    prompt = ("Use AgentAvow to check npm package gadgethumans-mcp 1.0.15 "
              "and tell me if it's safe to connect.")
    chatgpt, claude = r["links"]
    assert chatgpt["label"] == "Ask about this in ChatGPT"
    assert chatgpt["href"].startswith("https://chatgpt.com/?q=")
    assert _q(chatgpt["href"]) == prompt
    assert "copy" not in chatgpt
    # Claude: no prefill in the URL; the same prompt goes by clipboard instead.
    assert claude["label"] == "Ask about this in Claude"
    assert claude["href"] == "https://claude.ai/new"
    assert "q=" not in claude["href"] and "?" not in claude["href"]
    assert claude["copy"] == prompt


def test_each_surface_names_the_tool_the_way_the_page_does():
    out = _run([
        {"kind": "package", "surface": "pypi", "name": "requests"},
        {"kind": "package", "surface": "huggingface", "name": "openai-community/gpt2"},
        {"kind": "repo", "owner": "makenotion", "repo": "notion-mcp-server"},
        {"kind": "skill", "owner": "acme", "repo": "skills", "skill": "pdf"},
        {"kind": "mcp", "endpoint": "https://mcp.example.com/mcp"},
    ])
    assert [r["text"] for r in out] == [
        "PyPI package requests",
        "Hugging Face model openai-community/gpt2",
        "GitHub repo makenotion/notion-mcp-server",
        "the Agent Skill pdf in GitHub repo acme/skills",
        "MCP server https://mcp.example.com/mcp",
    ]


def test_mcp_link_drops_query_fragment_and_userinfo():
    # Someone may paste a URL carrying a key; only scheme, host and path go out.
    [r] = _run([{"kind": "mcp",
                 "endpoint": "https://user:pw@mcp.example.com/sse?api_key=sk-secret#x"}])
    assert r["text"] == "MCP server https://mcp.example.com/sse"
    chatgpt, claude = r["links"]
    assert "secret" not in chatgpt["href"] and "pw" not in _q(chatgpt["href"])
    assert "secret" not in claude["copy"] and "pw" not in claude["copy"]


def test_nothing_to_name_gives_no_links():
    out = _run([{"kind": "mcp", "endpoint": "not a url"},
                {"kind": "mcp", "endpoint": "javascript:alert(1)"},
                {"kind": "package", "surface": "npm", "name": " "}])
    assert all(r["links"] == [] for r in out)


def test_row_opens_a_new_tab_and_private_scans_get_none():
    src = COMPONENT.read_text()
    assert 'target="_blank" rel="noopener noreferrer"' in src
    assert "props.ask && !privateScan && <AskAssistantRow" in src
    assert "Question copied — paste it into Claude" in src
    assert "navigator.clipboard.writeText(l.copy)" in src
    check = CHECK.read_text()
    assert "ask={isPrivate ? undefined : { kind: 'repo', owner, repo }}" in check
    # Never send people to the Claude plugin directory from this row.
    lib = LIB.read_text()
    assert "claude.ai/directory" not in lib and "claude.com/plugins" not in lib
