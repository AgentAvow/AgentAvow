"""Claude Agent SDK gate: AgentAvow decides every MCP server and ``mcp__…`` tool call.

``AgentAvowClaudeGate`` plugs into ``claude-agent-sdk`` (Python) at two seams:

* :meth:`AgentAvowClaudeGate.check_mcp_servers` runs before the session. Each entry
  of ``ClaudeAgentOptions.mcp_servers`` is mapped to the coordinate AgentAvow grades
  (its own https URL for ``http`` / ``sse`` servers; ``servers={name: coordinate}`` for
  a stdio server or one graded as a package or repo) and checked. A server whose
  answer fails ``fail_on`` (default ``review``) is left out of the returned config,
  so the session never connects to it.
* :meth:`AgentAvowClaudeGate.hooks` returns ``{"PreToolUse": [HookMatcher(...)]}`` for
  every ``mcp__<server>__<tool>`` call. The hook grades the serving server (cached),
  checks the definition the server serves against the per-tool digest signed into
  the attestation, and on a fail returns ``permissionDecision: "deny"`` with the
  reason, which the SDK hands the model as the tool result. A PreToolUse deny holds
  in every permission mode, including ``bypassPermissions``; ``can_use_tool`` is not
  reached for auto-approved tools, so the hook is the seam that always runs.
  :meth:`AgentAvowClaudeGate.can_use_tool` gives the same decision as a callback.

``on_fail``: ``block`` (default) denies; ``confirm`` returns ``permissionDecision:
"ask"`` (the SDK's own approval flow) unless you pass a ``confirm`` callable;
``warn`` runs the tool and reports; ``raise`` raises
:class:`~src.bridges.tool_gate.ToolGateBlockedError` from the hook.

Usage::

    from claude_agent_sdk import ClaudeAgentOptions, query
    from src.bridges.claude_agent_sdk import AgentAvowClaudeGate

    gate = AgentAvowClaudeGate()
    servers = await gate.check_mcp_servers(
        {"deepwiki": {"type": "http", "url": "https://mcp.deepwiki.com/mcp"}})
    options = ClaudeAgentOptions(mcp_servers=servers, hooks=gate.hooks())

``claude-agent-sdk`` is optional; this module imports without it (``hooks()`` and
``can_use_tool`` import its types lazily).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from src.bridges.tool_gate import (
    DECISION_PHRASES,
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

__all__ = ["AgentAvowClaudeGate", "claude_tool_name", "normalize_server_name"]


def normalize_server_name(name: str) -> str:
    """Claude Code's server segment of ``mcp__<server>__<tool>``."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def claude_tool_name(server_name: str, tool_name: str) -> str:
    return f"mcp__{normalize_server_name(server_name)}__{tool_name}"


def _config_url(config: Any) -> str | None:
    if isinstance(config, dict) and config.get("type") in ("http", "sse"):
        url = config.get("url")
        return url if isinstance(url, str) and url else None
    return None


def headline(decision: GateDecision) -> str:
    """"Do not connect", "Safe to connect · Certified", … (the mark only beside Safe)."""
    g = decision.grade
    if g is None or g.decision not in DECISION_PHRASES:
        return "Do not connect" if not decision.allow else "Safe to connect"
    mark = " · Certified" if g.certified and g.decision == "safe" else ""
    return DECISION_PHRASES[g.decision] + mark


class AgentAvowClaudeGate:
    """Gate Claude Agent SDK MCP servers and tool calls. See the module docstring."""

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
            on_fail=on_fail, cache_ttl=cache_ttl, fail_closed=fail_closed,
            fetch_served=fetch_served, unmapped=unmapped, confirm=confirm,
            on_warn=on_warn, timeout=timeout, transport=transport, headers=headers,
            server_headers=server_headers,
        )
        self._coords: dict[str, str] = {}
        self._warned: set[str] = set()
        for name, coord in (servers or {}).items():
            self.register(name, coord)

    # mapping -------------------------------------------------------------

    def register(self, server_name: str, coordinate: str) -> None:
        """Tell the gate which coordinate a server name is graded under."""
        parse_coordinate(coordinate)  # raises on an unusable coordinate
        self._coords[normalize_server_name(server_name)] = coordinate

    def parse_tool_name(self, tool_name: str) -> tuple[str, str] | None:
        """``(server, tool)`` behind ``mcp__<server>__<tool>``, or None."""
        if not tool_name.startswith("mcp__"):
            return None
        rest = tool_name[5:]
        for s in sorted(self._coords, key=len, reverse=True):  # a name may contain "__"
            if rest.startswith(s + "__") and len(rest) > len(s) + 2:
                return s, rest[len(s) + 2:]
        server, sep, tool = rest.partition("__")
        return (server, tool) if sep and server and tool else None

    # decisions -----------------------------------------------------------

    async def decide(self, tool_name: str) -> GateDecision:
        """The decision for one ``mcp__<server>__<tool>`` call."""
        ref = self.parse_tool_name(tool_name)
        coord = self._coords.get(ref[0]) if ref else None
        if ref is None or coord is None:
            d = self.gate.unmapped_decision(tool_name)
            if d.allow and tool_name not in self._warned:
                self._warned.add(tool_name)
                self.gate.on_warn(f"AgentAvow: '{tool_name}' comes from a server the gate was "
                                  "not given (check_mcp_servers or servers=); not gated.")
            return d
        return await self.gate.acheck(tool_name, coord, mcp_name=ref[1])

    async def check_mcp_servers(self, mcp_servers: dict[str, Any]) -> dict[str, Any]:
        """The servers that pass, for ``ClaudeAgentOptions(mcp_servers=...)``.

        The decision per server is kept on :attr:`server_decisions`.
        """
        self.server_decisions: dict[str, GateDecision] = {}
        allowed: dict[str, Any] = {}
        for name, config in mcp_servers.items():
            coord = self._coords.get(normalize_server_name(name)) or _config_url(config)
            if coord is None:
                d = self.gate.unmapped_decision(f"server {name}")
                self.server_decisions[name] = d
                if d.allow:
                    allowed[name] = config
                    self.gate.on_warn(f"AgentAvow: MCP server '{name}' has no https URL and "
                                      "no coordinate (servers={...}); not gated.")
                continue
            self.register(name, coord)
            headers = config.get("headers") if isinstance(config, dict) else None
            if isinstance(headers, dict) and headers:
                self.gate.server_headers.setdefault(coord, headers)
            grade = await self.gate.client.agrade(coord)
            d = evaluate(f"server {name}", coord, grade, min_score=self.gate.min_score,
                         block_on=self.gate.block_on, fail_closed=self.gate.fail_closed,
                         fail_on=self.gate.fail_on)
            d.warnings = [w for w in d.warnings if not w.startswith("no served definition")]
            self.server_decisions[name] = d
            action = self._action(d)
            if action == "block":
                logger.info("AgentAvow refused MCP server %r (%s): %s", name, coord, d.reason)
                continue
            allowed[name] = config
        return allowed

    def _action(self, decision: GateDecision) -> str:
        """allow | block | confirm. ``confirm`` without a callable means: let the SDK ask."""
        return self.gate.action(decision)

    # the seams -----------------------------------------------------------

    async def pre_tool_use(self, input_data: dict, tool_use_id: str | None = None,
                           context: Any = None) -> dict:
        """The PreToolUse hook: ``{}`` lets the call run."""
        tool_name = str((input_data or {}).get("tool_name") or "")
        if not tool_name.startswith("mcp__"):
            return {}
        d = await self.decide(tool_name)
        action = self._action(d)
        if action == "allow":
            return {}
        ask = action == "confirm"
        reason = (f"{headline(d)} — {d.reason} Approve to run it anyway." if ask
                  else f"{headline(d)} — {d.reason}")
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask" if ask else "deny",
            "permissionDecisionReason": reason,
        }}

    def hooks(self) -> dict:
        """``ClaudeAgentOptions(hooks=...)``: the PreToolUse hook on every ``mcp__`` tool."""
        from claude_agent_sdk.types import HookMatcher  # optional dependency

        return {"PreToolUse": [HookMatcher(matcher="mcp__.*", hooks=[self.pre_tool_use])]}

    async def can_use_tool(self, tool_name: str, input_data: dict, context: Any = None) -> Any:
        """The same decision as a ``can_use_tool`` callback."""
        from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny

        if not tool_name.startswith("mcp__"):
            return PermissionResultAllow(updated_input=input_data)
        d = await self.decide(tool_name)
        try:
            action = self._action(d)
        except ToolGateBlockedError as e:
            return PermissionResultDeny(message=f"{headline(d)} — {e.decision.reason}")
        if action == "allow":
            return PermissionResultAllow(updated_input=input_data)
        return PermissionResultDeny(message=f"{headline(d)} — {d.reason}")
