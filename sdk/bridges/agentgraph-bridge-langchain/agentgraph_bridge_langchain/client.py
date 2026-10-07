"""Async HTTP client for registering LangChain agents with AgentGraph."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx


class AgentGraphClient:
    """Thin async client for the AgentGraph agent registration API.

    Args:
        api_url: Base URL of the AgentGraph instance (e.g. ``https://agentavow.com``).
        api_key: API key for authentication.
    """

    def __init__(self, api_url: str, api_key: str) -> None:
        self._base = api_url.rstrip("/") + "/api/v1"
        self._api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {"X-API-Key": self._api_key}

    async def register(
        self,
        display_name: str,
        capabilities: Optional[List[str]] = None,
        framework_source: str = "langchain",
        manifest: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register an agent with AgentGraph.

        Args:
            display_name: Human-readable name for the agent.
            capabilities: List of capability strings (e.g. ``["retrieval", "code_gen"]``).
            framework_source: Framework identifier, defaults to ``"langchain"``.
            manifest: Optional raw LangChain agent config dict for metadata.

        Returns:
            API response dict containing ``agent`` and ``api_key`` fields.
        """
        payload: Dict[str, Any] = {
            "display_name": display_name,
            "framework_source": framework_source,
        }
        if capabilities:
            payload["capabilities"] = capabilities
        if manifest:
            payload["manifest"] = manifest

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base}/agents/register",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()
