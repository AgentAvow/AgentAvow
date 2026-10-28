"""LiteLLM proxy guardrail: AgentAvow decides every MCP tool call the gateway makes.

LiteLLM's MCP gateway runs ``pre_mcp_call`` guardrails before it forwards a
``tools/call`` to an MCP server. :class:`AgentAvowGuardrail` is one: it looks up the
server's signed AgentAvow grade (cached) and refuses the call when the server's
answer is Do not connect (``fail_on="do_not_connect"``, the default) or also Review
before you connect (``fail_on="review"``). For an https server it also fetches the
server's own ``tools/list`` (cached) and refuses a tool whose definition no longer
matches the per-tool digest signed into the scan, or that the scan never saw (the
rug-pull).

A refusal is raised as an HTTP 400 with the reason, which LiteLLM returns to the
caller as an MCP tool error (``isError: true``); the model sees the reason and the
run continues. ``on_fail="warn"`` lets the call through and logs the reason.

Configure it in the proxy's ``config.yaml`` (see ``integrations/litellm/``)::

    guardrails:
      - guardrail_name: agentavow
        litellm_params:
          guardrail: agentavow_guardrail.AgentAvowGuardrail
          mode: pre_mcp_call
          default_on: true
          fail_on: do_not_connect
          servers: {local_files: "npm:@modelcontextprotocol/server-filesystem"}

Which coordinate AgentAvow grades: the server's ``url`` from LiteLLM's MCP server
registry (an https endpoint), else ``servers[<server name>]`` (needed for stdio
servers, or to grade a server as its published package). A server with neither is
decided by ``unmapped`` (default allow, with a warning).

Requires ``litellm`` (tested with 1.105). The decision itself is
:mod:`src.bridges.tool_gate`, shared with the LangChain, ADK, Claude Agent SDK and
OpenAI Agents SDK gates.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from src.bridges.tool_gate import (
    DEFAULT_BASE_URL,
    DEFAULT_BLOCK_ON,
    DEFAULT_CACHE_TTL,
    DEFAULT_MIN_SCORE,
    DEFAULT_TIMEOUT,
    GateDecision,
    ToolGate,
    evaluate,
    parse_coordinate,
)

logger = logging.getLogger(__name__)

__all__ = ["AgentAvowGuardrail", "MCP_CALL_TYPES"]

# LiteLLM's call types for an MCP tool call (proxy/utils.py MCP_GUARDRAIL_CALL_TYPES
# plus the older "mcp_call" name).
MCP_CALL_TYPES = ("call_mcp_tool", "mcp_call")

try:  # pragma: no cover - exercised by the real-litellm smoke test
    from litellm.integrations.custom_guardrail import CustomGuardrail as _Base
    from litellm.types.guardrails import GuardrailEventHooks as _Hooks

    _PRE_MCP = _Hooks.pre_mcp_call
except Exception:  # noqa: BLE001 - litellm not installed (unit tests, other runtimes)

    class _Base:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            self.guardrail_name = kwargs.get("guardrail_name")
            self.event_hook = kwargs.get("event_hook")
            self.default_on = kwargs.get("default_on", False)

        def should_run_guardrail(self, data: dict, event_type: Any) -> bool:
            return True

    _PRE_MCP = "pre_mcp_call"


def _blocked(detail: str) -> Exception:
    """The exception LiteLLM turns into a refused MCP call (FastAPI's HTTPException,
    as LiteLLM's own MCP guardrails raise)."""
    try:
        from fastapi import HTTPException
    except Exception:  # noqa: BLE001 - fastapi missing outside the proxy
        return PermissionError(detail)
    return HTTPException(status_code=400, detail={"error": detail, "guardrail": "agentavow"})


def _split_prefixed(name: str) -> tuple[str | None, str]:
    """LiteLLM prefixes gateway tool names with the server (``deepwiki-read_wiki``)."""
    try:
        from litellm.proxy._experimental.mcp_server.utils import split_server_prefix_from_name
    except Exception:  # noqa: BLE001
        return None, name
    try:
        unprefixed, server = split_server_prefix_from_name(name)
    except Exception:  # noqa: BLE001
        return None, name
    return (server or None), (unprefixed or name)


def _registry_server(name: str) -> Any:
    try:
        from litellm.proxy._experimental.mcp_server.mcp_server_manager import (
            global_mcp_server_manager,
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        return (global_mcp_server_manager.get_mcp_server_by_name(name)
                or global_mcp_server_manager.get_mcp_server_by_id(name))
    except Exception:  # noqa: BLE001
        return None


class AgentAvowGuardrail(_Base):
    """A LiteLLM ``CustomGuardrail`` for ``mode: pre_mcp_call``. See the module docstring.

    Options (``litellm_params`` in ``config.yaml``, or keyword arguments):
        fail_on: ``do_not_connect`` (default) or ``review``.
        on_fail: ``block`` (default) or ``warn``.
        servers: ``{LiteLLM server name: AgentAvow coordinate}``.
        fail_closed: refuse when AgentAvow cannot answer (default True).
        check_drift: compare served definitions with the signed digests (default True).
        server_headers: ``{coordinate: {header: value}}`` for fetching a private
            server's ``tools/list`` for the drift check.
        unmapped: ``allow`` (default) or ``block`` a server with no coordinate.
        cache_ttl, timeout, base_url: lookup tuning.
        min_score, block_on: extra floors (default: none under ``do_not_connect``;
            51 and critical/high findings under ``review``, as the other gates).
    """

    def __init__(
        self,
        *,
        fail_on: str = "do_not_connect",
        on_fail: str = "block",
        servers: dict[str, str] | None = None,
        fail_closed: bool = True,
        check_drift: bool = True,
        server_headers: dict[str, dict[str, str]] | None = None,
        unmapped: str = "allow",
        cache_ttl: float = DEFAULT_CACHE_TTL,
        timeout: float | None = None,
        base_url: str = DEFAULT_BASE_URL,
        min_score: int | None = None,
        block_on: Iterable[str] | None = None,
        transport: Any = None,
        **kwargs: Any,
    ) -> None:
        if fail_on not in ("do_not_connect", "review"):
            raise ValueError("fail_on must be 'do_not_connect' or 'review'")
        if on_fail not in ("block", "warn"):
            raise ValueError("on_fail must be 'block' or 'warn'")
        if unmapped not in ("allow", "block"):
            raise ValueError("unmapped must be 'allow' or 'block'")
        strict = fail_on == "review"
        self.fail_on = fail_on
        self.on_fail = on_fail
        self.check_drift = bool(check_drift)
        self.servers = dict(servers or {})
        for coord in self.servers.values():
            parse_coordinate(coord)
        self.gate = ToolGate(
            base_url=base_url,
            min_score=DEFAULT_MIN_SCORE if (min_score is None and strict) else (min_score or 0),
            block_on=tuple(block_on) if block_on is not None else (
                DEFAULT_BLOCK_ON if strict else ()),
            fail_on=fail_on,
            on_fail="warn" if on_fail == "warn" else "block",
            cache_ttl=float(cache_ttl),
            fail_closed=bool(fail_closed),
            fetch_served=self.check_drift,
            unmapped=unmapped,
            on_warn=lambda m: logger.warning("AgentAvow guardrail: %s", m),
            timeout=float(timeout) if timeout else DEFAULT_TIMEOUT,
            transport=transport,
            server_headers=server_headers,
        )
        kwargs.setdefault("supported_event_hooks", [_PRE_MCP])
        super().__init__(**kwargs)

    @classmethod
    def get_supported_event_hooks(cls) -> list:
        return [_PRE_MCP]

    # ── resolution ───────────────────────────────────────────────────────────

    def coordinate_for(self, server_name: str | None) -> str | None:
        if not server_name:
            return None
        if server_name in self.servers:
            return self.servers[server_name]
        server = _registry_server(server_name)
        url = getattr(server, "url", None) if server is not None else None
        if isinstance(url, str) and url.lower().startswith(("https://", "http://")):
            return url
        for alias in (getattr(server, "alias", None), getattr(server, "server_name", None)):
            if isinstance(alias, str) and alias in self.servers:
                return self.servers[alias]
        return None

    async def check_call(self, server_name: str | None, tool_name: str) -> GateDecision:
        """Decide one MCP tool call (no LiteLLM objects needed; used by the hook)."""
        coordinate = self.coordinate_for(server_name)
        if coordinate is None:
            return self.gate.unmapped_decision(tool_name)
        if self.check_drift:
            return await self.gate.acheck(tool_name, coordinate, mcp_name=tool_name)
        grade = await self.gate.client.agrade(coordinate)
        return evaluate(tool_name, coordinate, grade, min_score=self.gate.min_score,
                        block_on=self.gate.block_on, fail_closed=self.gate.fail_closed,
                        served_definition=None, fail_on=self.gate.fail_on)

    # ── the LiteLLM hook ─────────────────────────────────────────────────────

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: Any,
    ) -> Exception | str | dict | None:
        kind = getattr(call_type, "value", call_type)
        if str(kind) not in MCP_CALL_TYPES:
            return data
        raw_tool = data.get("mcp_tool_name")
        if not isinstance(raw_tool, str) or not raw_tool:
            return data
        try:
            if self.should_run_guardrail(data=data, event_type=_PRE_MCP) is not True:
                return data
        except Exception:  # noqa: BLE001 - older signatures; run by default
            pass
        prefix_server, tool = _split_prefixed(raw_tool)
        server_name = data.get("mcp_server_name") or prefix_server
        if isinstance(server_name, str) and raw_tool.startswith(server_name + "-"):
            tool = raw_tool[len(server_name) + 1:]
        name = server_name if isinstance(server_name, str) else None
        decision = await self.check_call(name, tool)
        for w in decision.warnings:
            logger.warning("AgentAvow guardrail: %s", w)
        if decision.allow:
            return data
        if self.on_fail == "warn":
            logger.warning("AgentAvow guardrail (warn only): %s", decision.reason)
            return data
        raise _blocked(decision.reason)
