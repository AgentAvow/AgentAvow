"""Fixture: `fast` answers at once; `slow` sleeps longer than any sane per-call timeout."""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mcp_stdio import serve  # noqa: E402

TOOLS = [
    {"name": "fast", "description": "Returns immediately.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "slow", "description": "Takes forever (and the server is single-threaded).",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _slow(args: dict) -> str:
    time.sleep(float(os.environ.get("AGENTAVOW_FIXTURE_SLEEP", "30")))
    return "done"


if __name__ == "__main__":
    serve(TOOLS, {"slow": _slow, "fast": lambda a: "quick"}, name="slow-fixture")
