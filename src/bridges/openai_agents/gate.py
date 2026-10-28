"""OpenAI Agents SDK gate: AgentAvow decides every MCP server the agent connects to.

``AgentAvowMCPGate.wrap(server)`` takes an ``agents.mcp`` server
(``MCPServerStreamableHttp``, ``MCPServerSse``, ``MCPServerStdio``) and wraps three
of its methods on that instance:

* ``connect()`` grades the server first (cached) and, when its answer fails
  ``fail_on`` (default ``review``), raises
  :class:`~src.bridges.tool_gate.ToolGateBlockedError` without opening the
  connection. ``async with server`` goes through ``connect()``, so it is covered.
  :meth:`AgentAvowMCPGate.connect_all` connects the servers that pass and returns
  the rest as refused, for an agent that should start without them.
* ``list_tools()`` checks every served definition against the per-tool digest
  signed into the attestation and drops a drifted or unknown tool, so the model is
  never shown it.
* ``call_tool()`` re-checks the call (the cached grade plus the drift check against
  what ``list_tools`` recorded) and, on a fail, returns an MCP ``CallToolResult``
  with ``isError: true`` and the reason in place of running the tool; the SDK hands
  that text to the model and the run continues.

The coordinate AgentAvow grades is the server's own https URL (``params["url"]``)
or ``coordinate=`` / ``servers={name: coordinate}`` for a stdio server or one
graded as a package or repo. A server with neither is decided by ``unmapped``
(default allow, with a warning).

``on_fail``: ``block`` (default), ``warn`` (run and report), ``raise`` (raise from
``call_tool`` too), ``confirm`` (needs a ``confirm`` callable; MCP server tools have
no SDK approval pause, so without one ``confirm`` blocks).

Usage::

    from agents import Agent, Runner
    from agents.mcp import MCPServerStreamableHttp
    from src.bridges.openai_agents import AgentAvowMCPGate

    gate = AgentAvowMCPGate()
    async with gate.wrap(MCPServerStreamableHttp(
            name="deepwiki", params={"url": "https://mcp.deepwiki.com/mcp"})) as server:
        agent = Agent(name="Assistant", mcp_servers=[server])
        await Runner.run(agent, "...")

``openai-agents`` is optional; this module imports without it (the server shape is
structural).
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
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
    evaluate,
    parse_coordinate,
)

logger = logging.getLogger(__name__)

__all__ = ["AgentAvowMCPGate"]

_WRAPPED = "_agentavow_gated"


def _server_url(server: Any) -> str | None:
    params = getattr(server, "params", None)
    candidates = [params.get("url") if isinstance(params, dict) else getattr(params, "url", None),
                  getattr(server, "url", None)]
    for v in candidates:
        if isinstance(v, str) and v.lower().startswith(("https://", "http://")):
            return v
    return None


def _as_dict(tool: Any) -> dict | None:
    if isinstance(tool, dict):
        return tool
    dump = getattr(tool, "model_dump", None)
    if callable(dump):
        try:
            d = dump(by_alias=True, exclude_unset=True)
            return d if isinstance(d, dict) else None
        except Exception:  # noqa: BLE001
            return None
    return None


def _error_result(text: str) -> Any:
    """An MCP ``CallToolResult`` with ``isError`` set (a plain dict without ``mcp``)."""
    try:
        from mcp.types import CallToolResult, TextContent
    except Exception:  # noqa: BLE001 — mcp not installed (tests, other runtimes)
        return {"content": [{"type": "text", "text": text}], "isError": True}
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=True)


class AgentAvowMCPGate:
    """Gate OpenAI Agents SDK MCP servers. See the module docstring."""

    def __init__(
        self,
        *,
        servers: dict[str, str] | None = None,
        base_url: str = DEFAULT_BASE_URL,
        min_score: int = DEFAULT_MIN_SCORE,
        block_on: tuple[str, ...] | list[str] = DEFAULT_BLOCK_ON,
        fail_on: str = DEFAULT_FAIL_ON,
        on_fail: str = "block",
        cache_ttl: float = DEFAULT_CACHE_TTL,
        fail_closed: bool = True,
        unmapped: str = "allow",
        confirm: Callable[[GateDecision], bool] | None = None,
        on_warn: Callable[[str], Any] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        # fetch_served=False: the gate checks the definitions list_tools() returns,
        # which are exactly what the agent is served.
        self.gate = ToolGate(
            base_url=base_url, min_score=min_score, block_on=block_on, fail_on=fail_on,
            on_fail=on_fail, cache_ttl=cache_ttl, fail_closed=fail_closed,
            fetch_served=False, unmapped=unmapped, confirm=confirm, on_warn=on_warn,
            timeout=timeout, transport=transport, headers=headers,
        )
        self.servers = dict(servers or {})

    def coordinate_of(self, server: Any) -> str | None:
        name = getattr(server, "name", None)
        coord = (self.servers.get(name) if isinstance(name, str) else None) or _server_url(server)
        if coord:
            parse_coordinate(coord)
        return coord

    def _action(self, decision: GateDecision) -> str:
        action = self.gate.action(decision)  # raises under on_fail="raise"
        return "block" if action == "confirm" else action  # no SDK pause for MCP tools

    async def server_decision(self, coord: str, label: str) -> GateDecision:
        grade = await self.gate.client.agrade(coord)
        d = evaluate(f"server {label}", coord, grade, min_score=self.gate.min_score,
                     block_on=self.gate.block_on, fail_closed=self.gate.fail_closed,
                     fail_on=self.gate.fail_on)
        d.warnings = [w for w in d.warnings if not w.startswith("no served definition")]
        return d

    def wrap(self, server: Any, coordinate: str | None = None) -> Any:
        """Wrap ``connect`` / ``list_tools`` / ``call_tool`` on this server; same object back."""
        if getattr(server, _WRAPPED, False):
            return server
        coord = coordinate or self.coordinate_of(server)
        label = str(getattr(server, "name", "") or coord or "MCP server")
        connect, list_tools, call_tool = server.connect, server.list_tools, server.call_tool
        served: dict[str, dict] = {}
        setattr(server, _WRAPPED, True)

        if coord is None:
            async def connect_unmapped(*args: Any, **kwargs: Any) -> Any:
                d = self.gate.unmapped_decision(f"server {label}")
                if not d.allow:
                    raise ToolGateBlockedError(d)
                self.gate.on_warn(f"AgentAvow: MCP server '{label}' has no https URL and no "
                                  "coordinate (wrap(server, coordinate=...)); not gated.")
                return await connect(*args, **kwargs)
            server.connect = connect_unmapped
            return server

        async def gated_connect(*args: Any, **kwargs: Any) -> Any:
            d = await self.server_decision(coord, label)
            if self._action(d) == "block":
                d.reason = f"AgentAvow refused MCP server '{label}' ({coord}): {d.reason}"
                raise ToolGateBlockedError(d)
            return await connect(*args, **kwargs)

        async def gated_list_tools(*args: Any, **kwargs: Any) -> Any:
            tools = await list_tools(*args, **kwargs)
            keep = []
            for t in tools or []:
                definition = _as_dict(t)
                name = str((definition or {}).get("name") or getattr(t, "name", ""))
                if definition is not None:
                    served[name] = definition
                d = await self.gate.acheck(name, coord, served_definition=definition)
                if not d.allow and d.outcome in ("drift", "unknown_tool"):
                    if self._action(d) == "block":
                        self.gate.on_warn(d.reason)
                        continue
                keep.append(t)
            return keep

        async def gated_call_tool(tool_name: str, arguments: Any = None, *args: Any,
                                  **kwargs: Any) -> Any:
            d = await self.gate.acheck(tool_name, coord, served_definition=served.get(tool_name))
            if self._action(d) == "block":
                return _error_result(d.reason)
            return await call_tool(tool_name, arguments, *args, **kwargs)

        server.connect = gated_connect
        server.list_tools = gated_list_tools
        server.call_tool = gated_call_tool
        return server

    async def connect_all(self, servers: Sequence[Any]) -> tuple[list[Any], list[GateDecision]]:
        """Wrap and connect each server; ``(connected, refused decisions)``."""
        ok: list[Any] = []
        refused: list[GateDecision] = []
        for s in servers:
            self.wrap(s)
            try:
                await s.connect()
            except ToolGateBlockedError as e:
                refused.append(e.decision)
                continue
            ok.append(s)
        return ok, refused
