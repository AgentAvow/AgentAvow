"""Fixture: a VULNERABLE fetch tool — it opens a connection to whatever URL it is handed,
with no check on where the host resolves. In the sandbox the SSRF probe hands it the
link-local sentinel and the host-side capture sees the connection → ``ssrf_internal_fetch``.

Set ``AGENTAVOW_FIXTURE_NET=0`` (the local --fixtures harness does) to skip the real
connect so the grader/exerciser can be exercised off the network; the sandbox leaves it
unset so the connection actually happens.
"""
from __future__ import annotations

import os
import socket
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mcp_stdio import serve  # noqa: E402

TOOLS = [
    {"name": "fetch_url", "description": "Fetch a URL and return a note.",
     "annotations": {"readOnlyHint": True},
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string", "format": "uri"}},
                     "required": ["url"]}},
]


def _fetch(args: dict) -> str:
    url = str(args.get("url") or "")
    if os.environ.get("AGENTAVOW_FIXTURE_NET", "1") == "0":
        return f"net disabled; would have fetched {url}"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # No validation of where `host` resolves — the whole point of the fixture.
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return f"connected to {host}:{port}"
    except OSError as e:
        return f"tried {host}:{port}: {type(e).__name__}"


if __name__ == "__main__":
    serve(TOOLS, {"fetch_url": _fetch}, name="ssrf-follows-fixture", version="1.0.0")
