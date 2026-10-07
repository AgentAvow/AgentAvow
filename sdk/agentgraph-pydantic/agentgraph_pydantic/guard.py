"""Trust verification guard for PydanticAI agents.

Provides pre-execution trust checks against AgentGraph's public API
and trust gateway. No AgentGraph account needed for basic scanning.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

_GATEWAY_URL = "https://agentavow.com/api/v1/gateway/check"
_SCAN_URL = "https://agentavow.com/api/v1/public/scan"
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
    is_mcp_server: bool = False


class TrustGuard:
    """Pre-execution trust verification guard.

    Usage with PydanticAI::

        from agentgraph_pydantic import TrustGuard

        guard = TrustGuard(min_tier="standard")

        # Before calling an external tool
        result = await guard.check("owner/repo")
        if not result.allowed:
            raise ValueError(f"Tool blocked: {result.reason}")
    """

    def __init__(
        self,
        min_tier: str = "standard",
        api_url: str | None = None,
        timeout: float = _TIMEOUT,
    ):
        self.min_tier = min_tier
        self._gateway_url = api_url or _GATEWAY_URL
        self._timeout = timeout

    async def check(self, repo: str) -> TrustResult:
        """Check trust for a repository before execution.

        Args:
            repo: GitHub repo in "owner/repo" format

        Returns:
            TrustResult with allowed/blocked decision
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
                    is_mcp_server=False,
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


async def check_trust(
    repo: str,
    min_tier: str = "standard",
) -> TrustResult:
    """Quick trust check — convenience function.

    Args:
        repo: GitHub repo in "owner/repo" format
        min_tier: Minimum acceptable tier (default: standard)

    Returns:
        TrustResult with allowed/blocked decision

    Example::

        result = await check_trust("crewAIInc/crewAI")
        print(f"{result.grade} {result.score} — {result.reason}")
    """
    guard = TrustGuard(min_tier=min_tier)
    return await guard.check(repo)
