"""Trust verification guard for CrewAI tools.

Provides a CrewAI-compatible tool wrapper that checks AgentGraph trust
scores before allowing tool execution.  Works with any CrewAI BaseTool subclass.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_GATEWAY_URL = "https://agentavow.com/api/v1/gateway/check"
_TIMEOUT = 30.0


@dataclass
class TrustResult:
    """Result of a trust check."""

    repo: str
    allowed: bool
    score: int  # 0-100
    grade: str  # A+/A/B/C/D/F
    tier: str  # verified/trusted/standard/minimal/restricted/blocked
    reason: str
    category_scores: dict[str, int]


class TrustGuard:
    """Pre-execution trust verification for CrewAI tools.

    Checks an agent or tool's trust score via the AgentGraph gateway
    before allowing execution.  Can be used standalone or as a wrapper
    around CrewAI tools.

    Args:
        min_tier: Minimum trust tier required (default: "standard").
        api_url: AgentGraph gateway URL override.
        timeout: HTTP request timeout in seconds.
        on_block: Optional callback invoked when a tool is blocked.
                  Receives ``(tool_name, TrustResult)``.

    Example::

        guard = TrustGuard(min_tier="standard")

        result = await guard.check("owner/repo")
        if not result.allowed:
            print(f"Blocked: {result.reason}")
    """

    def __init__(
        self,
        min_tier: str = "standard",
        api_url: str | None = None,
        timeout: float = _TIMEOUT,
        on_block: Callable[[str, TrustResult], Any] | None = None,
    ) -> None:
        self.min_tier = min_tier
        self._gateway_url = api_url or _GATEWAY_URL
        self._timeout = timeout
        self._on_block = on_block

    async def check(self, repo: str) -> TrustResult:
        """Check trust for a repository/tool before execution.

        Args:
            repo: GitHub repo in "owner/repo" format.

        Returns:
            TrustResult with allowed/blocked decision.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._gateway_url,
                    json={"repo": repo, "min_tier": self.min_tier},
                )
                resp.raise_for_status()
                data = resp.json()

                return TrustResult(
                    repo=repo,
                    allowed=data.get("allowed", False),
                    score=data.get("trust_score", 0),
                    grade=data.get("grade", "F"),
                    tier=data.get("trust_tier", "blocked"),
                    reason=data.get("decision_reason", ""),
                    category_scores=data.get("category_scores", {}),
                )
        except Exception as e:
            logger.warning("Trust check failed for %s: %s", repo, e)
            return TrustResult(
                repo=repo,
                allowed=False,
                score=0,
                grade="F",
                tier="blocked",
                reason=f"Trust check failed: {e}",
                category_scores={},
            )


def trust_gated_tool(
    tool: Any,
    repo: str,
    guard: TrustGuard | None = None,
    min_tier: str = "standard",
) -> Any:
    """Wrap a CrewAI BaseTool with a trust gate.

    Returns a new tool that checks trust before every invocation.
    If the trust check fails, the tool returns an error message
    instead of executing.

    Args:
        tool: A CrewAI ``BaseTool`` instance.
        repo: The GitHub repo to check trust for (e.g. "owner/repo").
        guard: Optional pre-configured TrustGuard instance.
        min_tier: Minimum trust tier if no guard is provided.

    Returns:
        A wrapped tool that performs trust checks before execution.

    Example::

        from crewai.tools import BaseTool
        from agentgraph_bridge_crewai import trust_gated_tool

        my_tool = MyCustomTool()
        safe_tool = trust_gated_tool(my_tool, "owner/repo")
    """
    try:
        from crewai.tools import BaseTool as _BaseTool
    except ImportError:
        raise ImportError(
            "crewai is required for trust_gated_tool. "
            "Install with: pip install agentgraph-bridge-crewai[crewai]"
        )

    if not isinstance(tool, _BaseTool):
        raise TypeError(
            f"Expected a CrewAI BaseTool, got {type(tool).__name__}"
        )

    _guard = guard or TrustGuard(min_tier=min_tier)

    from crewai.tools import BaseTool

    # Preserve original metadata
    orig_name = tool.name
    orig_description = tool.description
    orig_run = tool._run

    class TrustGatedTool(BaseTool):
        """A CrewAI tool wrapped with AgentGraph trust verification."""

        name: str = orig_name
        description: str = orig_description

        def _run(self, *args: Any, **kwargs: Any) -> str:
            """Synchronous execution with trust check."""
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    logger.warning(
                        "Cannot run async trust check in sync context "
                        "for tool %s; blocking execution",
                        orig_name,
                    )
                    return (
                        f"[AgentGraph] Trust check could not run for "
                        f"{orig_name}. Use async invocation instead."
                    )
            except RuntimeError:
                pass

            result = asyncio.run(_guard.check(repo))
            if not result.allowed:
                msg = (
                    f"[AgentGraph] Tool '{orig_name}' blocked — "
                    f"repo '{repo}' scored {result.grade} "
                    f"(tier: {result.tier}). {result.reason}"
                )
                if _guard._on_block:
                    _guard._on_block(orig_name, result)
                return msg

            return orig_run(*args, **kwargs)

    return TrustGatedTool()


def trust_gate_tools(
    tools: Sequence[Any],
    repo: str,
    guard: TrustGuard | None = None,
    min_tier: str = "standard",
) -> list[Any]:
    """Wrap multiple CrewAI tools with trust gates.

    Convenience function for gating an entire tool list at once.

    Args:
        tools: Sequence of CrewAI BaseTool instances.
        repo: GitHub repo to check trust for.
        guard: Optional shared TrustGuard instance.
        min_tier: Minimum trust tier if no guard provided.

    Returns:
        List of trust-gated tools.

    Example::

        tools = [MySearchTool(), MyAnalysisTool()]
        safe_tools = trust_gate_tools(tools, "owner/repo")
    """
    _guard = guard or TrustGuard(min_tier=min_tier)
    return [trust_gated_tool(t, repo, guard=_guard) for t in tools]


async def check_trust(
    repo: str,
    min_tier: str = "standard",
) -> TrustResult:
    """Quick trust check — convenience function.

    Args:
        repo: GitHub repo in "owner/repo" format.
        min_tier: Minimum acceptable tier (default: standard).

    Returns:
        TrustResult with allowed/blocked decision.

    Example::

        result = await check_trust("crewai/crewai")
        print(f"{result.grade} ({result.score}/100) — {result.reason}")
    """
    guard = TrustGuard(min_tier=min_tier)
    return await guard.check(repo)
