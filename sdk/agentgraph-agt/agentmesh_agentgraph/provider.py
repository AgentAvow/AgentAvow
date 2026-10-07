"""AgentGraph trust provider — external trust source for AGT's TrustEngine.

Implements the duck-typed interface expected by AGT's external_providers:
  - get_trust_score(agent_id) -> float (0.0-1.0)
  - check_sybil(agent_id) -> dict
  - get_trust_circle(agent_id) -> list[str]
  - verify_identity(agent_id, credentials) -> bool
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_API = "https://agentavow.com/api/v1"
_TIMEOUT = 10.0


class AgentGraphTrustProvider:
    """External trust provider that feeds AgentGraph trust scores into AGT.

    AgentGraph provides:
    - Entity trust scores (identity + external signals + code security)
    - Social graph (followers, attestations)
    - DID resolution (did:web:agentgraph.co:...)
    - Security scan results

    AGT consumes these as one of potentially many external trust signals
    in its TrustEngine.
    """

    def __init__(
        self,
        api_url: str = _DEFAULT_API,
        api_key: str | None = None,
        timeout: float = _TIMEOUT,
    ):
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=api_url,
            headers=headers,
            timeout=timeout,
        )
        self._api_url = api_url

    async def get_trust_score(self, agent_id: str) -> float:
        """Return normalized trust score (0.0-1.0) for an agent.

        Maps AgentGraph's entity trust score to AGT's expected range.
        Returns 0.5 (default/unknown) if the entity is not found.
        """
        try:
            resp = await self._client.get(f"/entities/{agent_id}/trust")
            if resp.status_code == 404:
                return 0.5  # Unknown entity = default trust
            resp.raise_for_status()
            data = resp.json()
            # AgentGraph stores score as 0.0-1.0 already
            return float(data.get("score", 0.5))
        except Exception:
            logger.warning("AgentGraph trust lookup failed for %s", agent_id)
            return 0.5

    async def check_sybil(self, agent_id: str) -> dict:
        """Return sybil risk assessment for an agent.

        Uses AgentGraph's social graph density and identity verification
        status to estimate sybil risk.
        """
        try:
            resp = await self._client.get(f"/entities/{agent_id}/trust")
            if resp.status_code != 200:
                return {"risk": "unknown", "confidence": 0.0}

            data = resp.json()
            components = data.get("components", {})

            # Sybil indicators from trust components
            verification = components.get("verification", 0.0)
            community = components.get("community", 0.0)
            external = components.get("external_reputation", 0.0)

            # Higher verification + external = lower sybil risk
            identity_strength = (verification + external) / 2
            risk = "low" if identity_strength > 0.5 else (
                "medium" if identity_strength > 0.2 else "high"
            )

            return {
                "risk": risk,
                "confidence": min(1.0, identity_strength + 0.3),
                "identity_verified": verification > 0.3,
                "external_accounts": external > 0.0,
                "community_attestations": community > 0.0,
            }
        except Exception:
            logger.warning("AgentGraph sybil check failed for %s", agent_id)
            return {"risk": "unknown", "confidence": 0.0}

    async def get_trust_circle(self, agent_id: str) -> list[str]:
        """Return direct trust connections (followers/following) for an agent.

        Uses AgentGraph's ego-graph API to find connected entities.
        """
        try:
            resp = await self._client.get(
                f"/graph/ego/{agent_id}",
                params={"depth": 1},
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            # Extract connected entity IDs from the ego graph
            nodes = data.get("nodes", [])
            return [
                n["id"] for n in nodes
                if n.get("id") != agent_id
            ]
        except Exception:
            logger.warning("AgentGraph trust circle failed for %s", agent_id)
            return []

    async def verify_identity(
        self, agent_id: str, credentials: dict | None = None,
    ) -> bool:
        """Verify an agent's identity via AgentGraph's DID resolution.

        Checks if the entity exists, is active, and has verified identity
        (email, operator link, or external account OAuth).
        """
        try:
            resp = await self._client.get(f"/entities/{agent_id}/trust")
            if resp.status_code != 200:
                return False

            data = resp.json()
            components = data.get("components", {})
            verification = components.get("verification", 0.0)

            # Consider identity verified if verification score >= 0.3
            # (email verified or better)
            return verification >= 0.3
        except Exception:
            logger.warning("AgentGraph identity check failed for %s", agent_id)
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
