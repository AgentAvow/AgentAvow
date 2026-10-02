"""LangChain agent middleware that gates every tool call on the AgentAvow grade.

``AgentAvowGate`` is a LangChain 1.x ``AgentMiddleware`` (``langchain.agents.middleware``)
implementing ``wrap_tool_call`` / ``awrap_tool_call``. Before a tool runs it maps the
tool to the MCP server (or repo / package) it came from, fetches that server's
signed grade from AgentAvow's free API, and allows the call only when the score
clears ``min_score`` (default 81), no critical / high finding is on the grade, and
the definition the agent was served for the tool recomputes to the per-tool digest
signed into the attestation (``scan.toolDigests["tool:<name>"]``). Anything else
is a fail, handled per ``on_fail``:

* ``block`` (default) — the model receives a ``ToolMessage`` saying why the tool
  was not run, instead of a tool result. Nothing is raised.
* ``confirm`` — ask first. With a ``confirm`` callable, that decides; without one
  the middleware calls ``langgraph.types.interrupt`` (requires a checkpointer) and
  resumes on ``True`` / ``"approve"`` / ``{"decision": "approve"}``.
* ``warn`` — run the tool, report the verdict through ``on_warn`` (default: log).
* ``raise`` — raise :class:`~src.bridges.tool_gate.ToolGateBlockedError`.

Mapping a tool to its server: tools built by ``langchain-mcp-adapters`` carry no
server identity (``metadata`` holds only the MCP annotations and ``_meta``);
tools from ``langchain.mcp.MCPAdapter`` (1.4+) carry the server's self-declared
name under ``metadata["mcp"]["server"]["name"]`` but not its URL. So the map is
yours to give, by whichever is easiest:

* ``tool_to_server={"ask_wiki_question": "https://mcp.deepwiki.com/mcp"}``
* ``servers={"deepwiki": "https://mcp.deepwiki.com/mcp"}`` — matched against the
  ``MCPAdapter`` server name, or a ``deepwiki_`` tool-name prefix when the adapters
  client was built with ``tool_name_prefix=True``.
* ``resolve_server=lambda tool_name, hint: ...`` for anything else.

A tool that maps to no server (a local function tool) is not gated. The served
definition for the drift check comes from ``served_tools`` (the ``tools/list`` you
loaded the tools from, keyed by coordinate) or, by default, is fetched from the
https server itself and cached for ``cache_ttl``.

Usage::

    from langchain.agents import create_agent
    from src.bridges.langchain.middleware import AgentAvowGate

    gate = AgentAvowGate(servers={"deepwiki": "https://mcp.deepwiki.com/mcp"})
    agent = create_agent(model, tools=mcp_tools, middleware=[gate])

LangChain is an optional dependency (``pip install agentgraph[langchain]``); the
module imports without it so the gate's configuration can be inspected, but the
middleware class is only usable when ``langchain>=1.0`` is installed.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from src.bridges.tool_gate import (
    DEFAULT_BASE_URL,
    DEFAULT_BLOCK_ON,
    DEFAULT_CACHE_TTL,
    DEFAULT_MIN_SCORE,
    DEFAULT_TIMEOUT,
    GateDecision,
    ToolGate,
    ToolGateBlockedError,
)

try:
    from langchain.agents.middleware import AgentMiddleware
    from langchain_core.messages import ToolMessage

    HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover - depends on the install
    HAS_LANGCHAIN = False
    AgentMiddleware = object  # type: ignore[assignment,misc]
    ToolMessage = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

__all__ = ["AgentAvowGate", "GateDecision", "ToolGateBlockedError", "HAS_LANGCHAIN"]

_APPROVE = ("approve", "approved", "allow", "yes", "accept", "y")


def _approved(resume: Any) -> bool:
    """Whether an ``interrupt`` resume value approves the call."""
    if resume is True:
        return True
    if isinstance(resume, str):
        return resume.strip().lower() in _APPROVE
    if isinstance(resume, dict):
        for key in ("decision", "action", "type"):
            v = resume.get(key)
            if isinstance(v, str):
                return v.strip().lower() in _APPROVE
        return bool(resume.get("approved"))
    return False


class AgentAvowGate(AgentMiddleware):  # type: ignore[misc]
    """Gate tool calls on the AgentAvow grade. See the module docstring."""

    name = "agentavow_gate"

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        min_score: int = DEFAULT_MIN_SCORE,
        block_on: tuple[str, ...] | list[str] = DEFAULT_BLOCK_ON,
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
        if not HAS_LANGCHAIN:
            raise ImportError(
                "AgentAvowGate needs langchain>=1.0: pip install 'agentgraph[langchain]'")
        super().__init__()
        self.gate = ToolGate(
            base_url=base_url, min_score=min_score, block_on=block_on, on_fail=on_fail,
            cache_ttl=cache_ttl, fail_closed=fail_closed, tool_to_server=tool_to_server,
            servers=servers, resolve_server=resolve_server, served_tools=served_tools,
            fetch_served=fetch_served, unmapped=unmapped, confirm=confirm, on_warn=on_warn,
            timeout=timeout, transport=transport, headers=headers,
            server_headers=server_headers,
        )

    # mapping -------------------------------------------------------------

    @staticmethod
    def _hint(request: Any) -> dict:
        """What the request tells us about the serving server."""
        hint: dict[str, Any] = {}
        tool = getattr(request, "tool", None)
        meta = getattr(tool, "metadata", None) or {}
        mcp = meta.get("mcp") if isinstance(meta, dict) else None
        if isinstance(mcp, dict):
            server = mcp.get("server")
            if isinstance(server, dict) and isinstance(server.get("name"), str):
                hint["server_name"] = server["name"]
            if isinstance(mcp.get("endpoint"), str):
                hint["endpoint"] = mcp["endpoint"]
        for key in ("agentavow_server", "server_url", "mcp_endpoint"):
            if isinstance(meta, dict) and isinstance(meta.get(key), str):
                hint["endpoint"] = meta[key]
                break
        if isinstance(meta, dict) and isinstance(meta.get("server_name"), str):
            hint.setdefault("server_name", meta["server_name"])
        return hint

    def resolve(self, request: Any) -> tuple[str | None, str]:
        """``(server coordinate or None, the tool's name on that server)``."""
        tool_name = str(request.tool_call.get("name") or "")
        return self.gate.resolve(tool_name, self._hint(request))

    # decisions -----------------------------------------------------------

    def _blocked_message(self, request: Any, decision: GateDecision) -> Any:
        return ToolMessage(
            content=decision.reason,
            tool_call_id=str(request.tool_call.get("id") or ""),
            name=str(request.tool_call.get("name") or "") or None,
            status="error",
        )

    def _interrupt(self, request: Any, decision: GateDecision) -> bool:
        """Pause the graph and ask; resume with True / "approve" to run the tool."""
        from langgraph.types import interrupt

        resume = interrupt({
            "type": "agentavow_gate",
            "tool": request.tool_call.get("name"),
            "args": request.tool_call.get("args"),
            "reason": decision.reason,
            "decision": decision.as_dict(),
        })
        return _approved(resume)

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        server, mcp_name = self.resolve(request)
        tool_name = str(request.tool_call.get("name") or "")
        if server is None:
            decision = self.gate.unmapped_decision(tool_name)
        else:
            decision = self.gate.check(tool_name, server, mcp_name=mcp_name)
        action = self.gate.action(decision)
        if action == "confirm":
            action = "allow" if self._interrupt(request, decision) else "block"
        if action == "block":
            return self._blocked_message(request, decision)
        return handler(request)

    async def awrap_tool_call(
        self, request: Any, handler: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        server, mcp_name = self.resolve(request)
        tool_name = str(request.tool_call.get("name") or "")
        if server is None:
            decision = self.gate.unmapped_decision(tool_name)
        else:
            decision = await self.gate.acheck(tool_name, server, mcp_name=mcp_name)
        action = self.gate.action(decision)
        if action == "confirm":
            action = "allow" if self._interrupt(request, decision) else "block"
        if action == "block":
            return self._blocked_message(request, decision)
        return await handler(request)
