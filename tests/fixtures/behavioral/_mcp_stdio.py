"""Minimal stdlib MCP stdio server used by the behavioral fixture servers next to it.

Newline-delimited JSON-RPC 2.0 on stdin/stdout, per the MCP stdio transport. Each fixture
passes its tool list and a ``{tool_name: handler(args) -> str}`` map; ``serve`` answers
``initialize`` / ``tools/list`` / ``tools/call`` and ignores notifications.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Callable


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve(tools: list[dict], handlers: dict[str, Callable[[dict], str]],
          *, name: str = "agentavow-fixture", version: str = "0.1.0",
          before_call: Callable[[str, dict], None] | None = None) -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if rid is None:
            continue  # notification
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": version}}})
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
        elif method == "tools/call":
            tool, args = params.get("name"), params.get("arguments") or {}
            if before_call:
                before_call(tool, args)
            handler = handlers.get(tool)
            if handler is None:
                _send({"jsonrpc": "2.0", "id": rid,
                       "error": {"code": -32602, "message": f"unknown tool {tool}"}})
                continue
            try:
                text, is_error = handler(args), False
            except Exception as e:  # noqa: BLE001 — tool errors are MCP isError results
                text, is_error = f"{type(e).__name__}: {e}", True
            _send({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text}], "isError": is_error}})
        else:
            _send({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32601, "message": f"method not found: {method}"}})
