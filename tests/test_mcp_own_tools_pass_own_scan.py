"""AgentAvow's own tools must pass AgentAvow's own MCP scan.

The read-only annotation check flags a tool whose name or description reads like it
executes or writes. A scan_package description that said "what a sandbox run observed"
tripped it on the word "run", so scanning agentavow.com/mcp graded our own server
"Review before you connect" — in front of an app-store reviewer.
"""
from __future__ import annotations

import pytest

from src.bridges.mcp_streamable import _TOOLS
from src.scanner.mcp_scan import _classify_tool


@pytest.mark.parametrize("tool", _TOOLS, ids=lambda t: t.name)
def test_no_read_only_tool_reads_like_it_executes_or_writes(tool):
    assert tool.annotations.readOnlyHint is True
    caps = _classify_tool(tool.name, tool.description)
    assert not caps & {"exec", "fs_write", "db_write"}, (tool.name, sorted(caps))
