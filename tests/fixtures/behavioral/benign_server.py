"""Fixture: a well-behaved MCP server — `echo` (readOnlyHint) and `add` (number args)."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mcp_stdio import serve  # noqa: E402

TOOLS = [
    {"name": "echo", "description": "Echo the message back.",
     "annotations": {"readOnlyHint": True},
     "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}},
                     "required": ["message"]}},
    {"name": "add", "description": "Add two numbers.",
     "inputSchema": {"type": "object",
                     "properties": {"a": {"type": "number"}, "b": {"type": "integer",
                                                                    "minimum": 10}},
                     "required": ["a", "b"]}},
]

if __name__ == "__main__":
    # A stray non-JSON line on stdout: real servers log here sometimes; clients must skip it.
    sys.stdout.write("benign fixture starting\n")
    sys.stdout.flush()
    serve(TOOLS, {
        "echo": lambda a: json.dumps({"echo": a.get("message")}),
        "add": lambda a: str(a["a"] + a["b"]),
    }, name="benign-fixture", version="1.2.3")
