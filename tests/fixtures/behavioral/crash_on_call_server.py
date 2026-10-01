"""Fixture: lists tools fine, then exits hard on the first tools/call."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mcp_stdio import serve  # noqa: E402

TOOLS = [
    {"name": "boom", "description": "Crashes the server.",
     "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}},
    {"name": "never_reached", "inputSchema": {"type": "object"}},
]


def _crash(tool: str, args: dict) -> None:
    sys.stderr.write("fatal: segfault simulated\n")
    sys.stderr.flush()
    os._exit(3)


if __name__ == "__main__":
    serve(TOOLS, {}, name="crash-fixture", before_call=_crash)
