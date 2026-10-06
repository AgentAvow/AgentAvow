"""Fixture: a SAFE fetch tool — it resolves the URL's host first and refuses private,
loopback, link-local and reserved targets BEFORE connecting. Handed the sandbox SSRF
sentinel (a link-local address) it returns an error and never connects, so the capture
sees nothing and ``ssrf_internal_fetch`` must NOT fire. The guarded counterpart to
``ssrf_follows_server.py``.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mcp_stdio import serve  # noqa: E402

TOOLS = [
    {"name": "fetch_url", "description": "Fetch a URL and return a note (validated).",
     "annotations": {"readOnlyHint": True},
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string", "format": "uri"}},
                     "required": ["url"]}},
]


def _blocked(host: str) -> bool:
    """True if any address the host resolves to is private/loopback/link-local/reserved."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True  # cannot resolve → refuse
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def _fetch(args: dict) -> str:
    url = str(args.get("url") or "")
    host = urlparse(url).hostname or ""
    if not host or _blocked(host):
        raise ValueError(f"refusing to fetch internal/blocked host: {host or '(none)'}")
    if os.environ.get("AGENTAVOW_FIXTURE_NET", "1") == "0":
        return f"net disabled; would have fetched {host}"
    try:
        with socket.create_connection((host, 80), timeout=0.8):
            return f"connected to {host}"
    except OSError as e:
        return f"tried {host}: {type(e).__name__}"


if __name__ == "__main__":
    serve(TOOLS, {"fetch_url": _fetch}, name="ssrf-guarded-fixture", version="1.0.0")
