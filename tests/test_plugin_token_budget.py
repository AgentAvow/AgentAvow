"""The plugin's per-session token cost stays small.

The site, the plugin README and the FAQ say the checks cost Claude zero tokens and the
plugin costs "under 1,000 tokens a session" (tool names, connector instructions, the
scan command and the skill; Claude Code loads a tool's full definition only on use).
These budgets fail the build before that claim can drift. They count characters (about
4 per token) of what Claude reads. If you raise a budget, re-measure with /context and
update the FAQ (web/src/rebrand/pages/FAQ.tsx, #context-tokens) and the README.
"""
from __future__ import annotations

import json
import pathlib
import re

from src.bridges import mcp_streamable as m

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "agentavow-trust"

# Measured 12 Nov 2026: tools 5,189 chars; Claude Code instructions 2,491; skill and
# command front matter 440. Budgets leave about 15% headroom.
TOOLS_BUDGET_CHARS = 6_000
INSTRUCTIONS_BUDGET_CHARS = 2_900
FRONT_MATTER_BUDGET_CHARS = 600


def _front_matter(path: pathlib.Path) -> str:
    text = path.read_text()
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, f"{path} has no front matter"
    return match.group(1)


def test_tool_definitions_stay_within_budget():
    chars = sum(
        len(t.name) + len(t.description or "") + len(json.dumps(t.input_schema or {}))
        for t in m._TOOLS
    )
    assert chars <= TOOLS_BUDGET_CHARS, (
        f"connector tools are {chars} chars (~{chars // 4} tokens), over the "
        f"{TOOLS_BUDGET_CHARS} budget"
    )


def test_claude_code_instructions_stay_within_budget():
    chars = len(m._instructions_for("claude-code"))
    assert chars <= INSTRUCTIONS_BUDGET_CHARS, (
        f"Claude Code connector instructions are {chars} chars (~{chars // 4} tokens), "
        f"over the {INSTRUCTIONS_BUDGET_CHARS} budget"
    )


def test_skill_and_command_descriptions_stay_within_budget():
    files = [PLUGIN / "commands" / "scan.md", *sorted(PLUGIN.glob("skills/*/SKILL.md"))]
    chars = sum(len(_front_matter(f)) for f in files)
    assert chars <= FRONT_MATTER_BUDGET_CHARS, (
        f"skill and command front matter is {chars} chars, over the "
        f"{FRONT_MATTER_BUDGET_CHARS} budget"
    )
