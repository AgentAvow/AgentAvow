"""The MCP ``tools/list`` response and the ``initialize`` result (server name, version,
capabilities, instructions) must stay BYTE-IDENTICAL: a connector-directory review was
done against them. Only tool RESULT text may change. The fixture was captured from the
functions that build both, before any result-text change; regenerate it only on purpose
(a reviewed metadata change)."""
from __future__ import annotations

import asyncio
import json
import pathlib

from src.bridges import mcp_streamable as m

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "mcp_tools_list_snapshot.json"


def _current() -> str:
    tools = asyncio.run(m._list_tools())
    doc = {
        "initialize": m.server.create_initialization_options().model_dump(
            mode="json", exclude_none=True),
        "tools": [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools],
    }
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=1) + "\n"


def test_tools_list_and_initialize_are_byte_identical_to_the_snapshot():
    assert _current() == FIXTURE.read_text(encoding="utf-8")


def test_snapshot_covers_every_tool_and_the_instructions():
    snap = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert [t["name"] for t in snap["tools"]] == [t.name for t in m._TOOLS]
    assert snap["initialize"]["instructions"] == m._INSTRUCTIONS
