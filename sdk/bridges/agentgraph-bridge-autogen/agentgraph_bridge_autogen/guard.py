"""Trust verification guard for AutoGen tools.

Provides an AutoGen-compatible tool wrapper that checks AgentGraph trust
scores before allowing tool execution.  Works with AutoGen's function-based
tool registration pattern (``register_function``).
"""
from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable
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
    """Pre-execution trust verification for AutoGen tools.

    Checks an agent or tool's trust score via the AgentGraph gateway
    before allowing execution.  Can be used standalone or as a wrapper
    around AutoGen tool functions.

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
    func: Callable[..., Any],
    repo: str,
    guard: TrustGuard | None = None,
    min_tier: str = "standard",
) -> Callable[..., Any]:
    """Wrap a plain function with a trust gate for use with AutoGen.

    Returns a new function that checks trust before every invocation.
    If the trust check fails, the function returns an error message
    instead of executing.  The wrapper preserves the original function's
    name, docstring, and signature for AutoGen's function registration.

    Args:
        func: A callable to be registered as an AutoGen tool.
        repo: The GitHub repo to check trust for (e.g. "owner/repo").
        guard: Optional pre-configured TrustGuard instance.
        min_tier: Minimum trust tier if no guard is provided.

    Returns:
        A wrapped function that performs trust checks before execution.

    Example::

        from agentgraph_bridge_autogen import trust_gated_tool

        def search(query: str) -> str:
            return f"Results for {query}"

        safe_search = trust_gated_tool(search, "owner/repo")

        # Register with AutoGen
        from autogen import register_function
        register_function(
            safe_search,
            caller=assistant,
            executor=user_proxy,
            description="Search the web",
        )
    """
    if not callable(func):
        raise TypeError(
            f"Expected a callable, got {type(func).__name__}"
        )

    _guard = guard or TrustGuard(min_tier=min_tier)
    func_name = getattr(func, "__name__", str(func))

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        """Synchronous execution with trust check."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                logger.warning(
                    "Cannot run async trust check in sync context "
                    "for tool %s; blocking execution",
                    func_name,
                )
                return (
                    f"[AgentGraph] Trust check could not run for "
                    f"{func_name}. Use async invocation instead."
                )
        except RuntimeError:
            pass

        result = asyncio.run(_guard.check(repo))
        if not result.allowed:
            msg = (
                f"[AgentGraph] Tool '{func_name}' blocked — "
                f"repo '{repo}' scored {result.grade} "
                f"(tier: {result.tier}). {result.reason}"
            )
            if _guard._on_block:
                _guard._on_block(func_name, result)
            return msg

        return func(*args, **kwargs)

    return wrapper


def trust_gated_function(
    repo: str,
    guard: TrustGuard | None = None,
    min_tier: str = "standard",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator version of trust_gated_tool for AutoGen functions.

    Use as a decorator on functions before registering them with AutoGen.

    Args:
        repo: The GitHub repo to check trust for.
        guard: Optional pre-configured TrustGuard instance.
        min_tier: Minimum trust tier if no guard is provided.

    Returns:
        A decorator that wraps functions with trust checks.

    Example::

        from agentgraph_bridge_autogen import trust_gated_function

        @trust_gated_function("owner/repo", min_tier="trusted")
        def calculator(expression: str) -> str:
            return str(eval(expression))

        # Register with AutoGen
        register_function(
            calculator,
            caller=assistant,
            executor=user_proxy,
            description="Evaluate math expressions",
        )
    """
    _guard = guard or TrustGuard(min_tier=min_tier)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        return trust_gated_tool(func, repo, guard=_guard)

    return decorator


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

        result = await check_trust("microsoft/autogen")
        print(f"{result.grade} ({result.score}/100) — {result.reason}")
    """
    guard = TrustGuard(min_tier=min_tier)
    return await guard.check(repo)
