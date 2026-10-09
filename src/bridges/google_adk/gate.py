"""Google ADK ``before_tool_callback`` that gates every tool call on the AgentAvow grade.

``AgentAvowToolGate`` is a callable ADK accepts as ``LlmAgent(before_tool_callback=...)``
(``google-adk`` 1.x / 2.x; the callback takes ``tool, args, tool_context`` and skips
the tool when it returns a dict, which the model then sees as the tool's result).
Before a tool runs it maps the tool to the MCP server (or repo / package) it came
from, fetches that server's signed grade from AgentAvow's free API, and allows the
call only when the tool's answer is Safe to connect (``fail_on``, default ``review``),
the score clears ``min_score`` (default 51), no critical / high finding is on the
grade, and the definition the agent was served recomputes to the per-tool digest
signed into the attestation (``scan.toolDigests["tool:<name>"]``). Anything else is a
fail, handled per ``on_fail``:

* ``block`` (default) — return ``{"error": <why>, "agentavow": {...}}`` in place of
  the tool result. Nothing is raised.
* ``confirm`` — ask first. With a ``confirm`` callable, that decides; without one
  the gate uses ADK's own confirmation flow (``tool_context.request_confirmation``)
  and lets the call through once ``tool_context.tool_confirmation.confirmed``.
* ``warn`` — run the tool, report the verdict through ``on_warn`` (default: log).
* ``raise`` — raise :class:`~src.bridges.tool_gate.ToolGateBlockedError`.

Mapping is automatic for ``McpToolset`` tools over Streamable HTTP / SSE: the gate
reads the server URL off the tool's session manager and the served definition off
the raw ``mcp.types.Tool`` it wraps, so drift is checked against exactly what the
agent was served. A stdio server has no URL; give it a coordinate with
``tool_to_server`` (``{"tool": "npm:@scope/server"}``) — drift is then not
checked, as nothing was served over the wire. Local function tools map to no
server and are not gated.

Usage::

    from google.adk.agents import LlmAgent
    from src.bridges.google_adk import AgentAvowToolGate

    agent = LlmAgent(
        name="assistant", model="gemini-2.5-flash",
        tools=[McpToolset(connection_params=StreamableHTTPConnectionParams(url=URL))],
        before_tool_callback=AgentAvowToolGate(),
    )

``google-adk`` is optional (``pip install agentgraph[adk]``); this module imports
without it, since the callback is plain Python.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from src.bridges.tool_gate import (
    DEFAULT_BASE_URL,
    DEFAULT_BLOCK_ON,
    DEFAULT_CACHE_TTL,
    DEFAULT_FAIL_ON,
    DEFAULT_MIN_SCORE,
    DEFAULT_TIMEOUT,
    GateDecision,
    ToolGate,
    ToolGateBlockedError,
)

logger = logging.getLogger(__name__)

__all__ = ["AgentAvowToolGate", "GateDecision", "ToolGateBlockedError"]


def _served_definition(tool: Any) -> dict | None:
    """The raw ``mcp.types.Tool`` an ``McpTool`` wraps, as the server served it."""
    raw = getattr(tool, "_mcp_tool", None)
    if raw is None:
        return None
    dump = getattr(raw, "model_dump", None)
    if callable(dump):
        try:
            d = dump(by_alias=True, exclude_unset=True)
            return d if isinstance(d, dict) else None
        except Exception:
            return None
    return raw if isinstance(raw, dict) else None


def _endpoint(tool: Any) -> str | None:
    """The URL of the MCP server behind an ``McpTool`` (Streamable HTTP / SSE)."""
    manager = getattr(tool, "_mcp_session_manager", None)
    params = getattr(manager, "_connection_params", None)
    url = getattr(params, "url", None)
    return url if isinstance(url, str) and url else None


class AgentAvowToolGate:
    """Gate ADK tool calls on the AgentAvow grade. See the module docstring."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        min_score: int = DEFAULT_MIN_SCORE,
        block_on: tuple[str, ...] | list[str] = DEFAULT_BLOCK_ON,
        fail_on: str = DEFAULT_FAIL_ON,
        on_fail: str = "block",
        cache_ttl: float = DEFAULT_CACHE_TTL,
        fail_closed: bool = True,
        tool_to_server: dict[str, str] | None = None,
        servers: dict[str, str] | None = None,
        resolve_server: Callable[[str, dict], str | None] | None = None,
        served_tools: Any = None,
        fetch_served: bool = True,
        unmapped: str = "allow",
        confirm: Callable[[GateDecision], bool] | None = None,
        on_warn: Callable[[str], Any] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Any = None,
        headers: dict[str, str] | None = None,
        server_headers: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.gate = ToolGate(
            base_url=base_url, min_score=min_score, block_on=block_on, fail_on=fail_on,
            on_fail=on_fail,
            cache_ttl=cache_ttl, fail_closed=fail_closed, tool_to_server=tool_to_server,
            servers=servers, resolve_server=resolve_server, served_tools=served_tools,
            fetch_served=fetch_served, unmapped=unmapped, confirm=confirm, on_warn=on_warn,
            timeout=timeout, transport=transport, headers=headers,
            server_headers=server_headers,
        )

    # mapping -------------------------------------------------------------

    @staticmethod
    def _hint(tool: Any) -> dict:
        hint: dict[str, Any] = {}
        endpoint = _endpoint(tool)
        if endpoint:
            hint["endpoint"] = endpoint
        meta = getattr(tool, "custom_metadata", None)
        if isinstance(meta, dict):
            for key in ("agentavow_server", "server_url", "mcp_endpoint"):
                if isinstance(meta.get(key), str):
                    hint["endpoint"] = meta[key]
                    break
            if isinstance(meta.get("server_name"), str):
                hint["server_name"] = meta["server_name"]
        raw = getattr(tool, "_mcp_tool", None)
        raw_name = getattr(raw, "name", None)
        if isinstance(raw_name, str) and raw_name:
            hint["mcp_name"] = raw_name
        return hint

    def resolve(self, tool: Any) -> tuple[str | None, str]:
        """``(server coordinate or None, the tool's name on that server)``."""
        return self.gate.resolve(str(getattr(tool, "name", "") or ""), self._hint(tool))

    # responses -----------------------------------------------------------

    @staticmethod
    def _blocked(decision: GateDecision) -> dict:
        g = decision.grade
        return {
            "error": decision.reason,
            "agentavow": {
                "outcome": decision.outcome,
                "server": decision.server,
                "score": g.score if g else None,
                "tier": g.tier if g else None,
                "report_url": g.report_url if g else None,
                "served_digest": decision.served_digest,
                "signed_digest": decision.signed_digest,
            },
        }

    def _confirm_via_adk(self, tool_context: Any, decision: GateDecision) -> dict | None:
        """ADK's confirmation flow: ask once, run on ``confirmed``, refuse otherwise."""
        confirmation = getattr(tool_context, "tool_confirmation", None)
        if confirmation is None:
            request = getattr(tool_context, "request_confirmation", None)
            if not callable(request):
                return self._blocked(decision)
            try:
                request(hint=decision.reason + " Approve to run it anyway.",
                        payload=decision.as_dict())
            except Exception as e:  # outside a tool context: nothing to ask
                logger.debug("request_confirmation failed: %s", e)
                return self._blocked(decision)
            actions = getattr(tool_context, "actions", None)
            if actions is not None:
                try:
                    actions.skip_summarization = True
                except Exception:
                    pass
            out = self._blocked(decision)
            out["error"] += " This call needs your confirmation."
            return out
        if getattr(confirmation, "confirmed", False):
            return None
        out = self._blocked(decision)
        out["error"] += " The confirmation was rejected."
        return out

    def _apply(self, decision: GateDecision, tool_context: Any) -> dict | None:
        action = self.gate.action(decision)
        if action == "confirm":
            return self._confirm_via_adk(tool_context, decision)
        if action == "block":
            return self._blocked(decision)
        return None

    # the callbacks -------------------------------------------------------

    async def __call__(self, tool: Any, args: dict[str, Any], tool_context: Any) -> dict | None:
        """The async ``before_tool_callback``: None runs the tool, a dict replaces it."""
        server, mcp_name = self.resolve(tool)
        tool_name = str(getattr(tool, "name", "") or "")
        if server is None:
            return self._apply(self.gate.unmapped_decision(tool_name), tool_context)
        decision = await self.gate.acheck(
            tool_name, server, mcp_name=mcp_name, served_definition=_served_definition(tool))
        return self._apply(decision, tool_context)

    def before_tool_callback_sync(self, tool: Any, args: dict[str, Any],
                                  tool_context: Any) -> dict | None:
        """The same gate, blocking — for a sync callback slot."""
        server, mcp_name = self.resolve(tool)
        tool_name = str(getattr(tool, "name", "") or "")
        if server is None:
            return self._apply(self.gate.unmapped_decision(tool_name), tool_context)
        decision = self.gate.check(
            tool_name, server, mcp_name=mcp_name, served_definition=_served_definition(tool))
        return self._apply(decision, tool_context)
