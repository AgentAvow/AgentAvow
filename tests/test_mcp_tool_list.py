"""MCP tool list: live/sandbox/source rows, declared annotations, digests."""
from __future__ import annotations

from src.scanner.behavioral.transcript import ExerciseTranscript, ToolSpec
from src.scanner.mcp_scan import compute_tool_digests
from src.scanner.mcp_tool_list import (
    build_tool_list,
    static_tool_list,
    tool_list_from_transcript,
)

_LIVE = [
    {"name": "read_wiki_structure", "description": "List topics",
     "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
    {"name": "ask_question", "description": "Ask", "inputSchema": {"type": "object"},
     "annotations": {"readOnlyHint": True, "openWorldHint": True, "title": "Ask DeepWiki"}},
    {"name": "delete_page", "description": "Delete", "annotations": {
        "readOnlyHint": False, "destructiveHint": True, "bogusHint": True}},
    {"name": "plain", "description": "no annotations"},
]


def test_live_rows_carry_declared_hints_only_and_signed_digest():
    rows = build_tool_list(_LIVE)
    by = {r["name"]: r for r in rows}
    assert [r["name"] for r in rows] == sorted(by)
    assert by["read_wiki_structure"]["annotations"] == {"readOnlyHint": True}
    assert by["delete_page"]["annotations"] == {"readOnlyHint": False, "destructiveHint": True}
    assert by["plain"]["annotations"] == {}  # undeclared stays unknown, not False
    assert by["ask_question"]["title"] == "Ask DeepWiki"
    assert all(r["source"] == "live" for r in rows)
    # The displayed digest is exactly the per-tool digest signed into the attestation.
    signed = compute_tool_digests(_LIVE)
    for r in rows:
        assert signed[f"tool:{r['name']}"] == r["digest"]


def test_bad_entries_and_duplicates_are_skipped():
    rows = build_tool_list([None, "x", {"name": ""}, {"name": "a"}, {"name": "a"}])
    assert [r["name"] for r in rows] == ["a"]


def test_sandbox_rows_from_transcript():
    tr = ExerciseTranscript(tools=[
        ToolSpec(name="write_file", description="Write a file",
                 annotations={"readOnlyHint": False, "destructiveHint": True},
                 input_schema={"type": "object"}),
        ToolSpec(name="read_file", description="Read", annotations=None),
    ])
    rows = tool_list_from_transcript(tr)
    assert [r["name"] for r in rows] == ["read_file", "write_file"]
    assert all(r["source"] == "sandbox" and r["digest"].startswith("sha256:") for r in rows)
    assert rows[1]["annotations"] == {"readOnlyHint": False, "destructiveHint": True}


_FS_JS = '''
server.registerTool(
  "read_text_file",
  {
    title: "Read Text File",
    description: "Read the complete contents of a file as text.",
    inputSchema: ReadTextFileArgsSchema,
    annotations: { readOnlyHint: true }
  },
  async (args) => { /* … */ }
);
server.registerTool("write_file", {
    description: "Create a new file or overwrite",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
}, handler);
server.tool('list_allowed_directories', 'Returns the allowed dirs', async () => ({}));
'''

_LIST_JS = '''
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: "search_files", description: "Recursively search", inputSchema: x },
  { name: "move_file", title: "Move", description: "Move or rename" },
]}));
const notATool = { name: "config", value: 3 };
'''

_PY = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def get_forecast(city: str) -> str:
    ...

@mcp.tool(name="send_email", annotations=ToolAnnotations(destructiveHint=True))
async def _send(to: str):
    ...

TOOLS = [Tool(name="legacy_tool", description="x")]
'''


def test_static_extraction_js_python_and_hints():
    files = {
        "package/dist/index.js": _FS_JS,
        "package/dist/list.js": _LIST_JS,
        "pkg/server.py": _PY,
        "package/dist/index.d.ts": 'server.tool("typedecl_only", …)',
        "package/test/index.test.js": 'server.tool("from_tests", x)',
        "package/README.md": 'server.tool("from_readme", x)',
    }
    rows = static_tool_list(files)
    by = {r["name"]: r for r in rows}
    assert set(by) == {
        "read_text_file", "write_file", "list_allowed_directories", "search_files",
        "move_file", "get_forecast", "send_email", "legacy_tool",
    }
    assert by["read_text_file"]["annotations"] == {"readOnlyHint": True}
    assert by["write_file"]["annotations"] == {
        "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True}
    assert by["send_email"]["annotations"] == {"destructiveHint": True}
    # A tool's hints never leak into the NEXT registration's window.
    assert by["list_allowed_directories"]["annotations"] == {}
    assert all(r["source"] == "source" and "digest" not in r for r in rows)


def test_static_extraction_fails_open():
    assert static_tool_list(None) == []
    assert static_tool_list({"a.js": None, "b.py": b"bytes"}) == []
