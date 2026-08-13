"""LangChain bridge — toolkit, callback handler, and auth for AgentGraph.

Provides LangChain-compatible tools that allow LangChain agents to interact
with the AgentGraph platform (search entities, get trust scores, create posts,
etc.) via the AgentGraph REST API.

LangChain is an OPTIONAL dependency. The module degrades gracefully when
LangChain is not installed — the API router and data-only helpers still work.
"""
from __future__ import annotations

import logging
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool

    HAS_LANGCHAIN = True
except ImportError:
    # LangChain not installed — define stubs so the module can still be imported.
    HAS_LANGCHAIN = False
    BaseTool = object  # type: ignore[assignment,misc]
    BaseCallbackHandler = object  # type: ignore[assignment,misc]

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------------------------


class AgentGraphAuth:
    """Helper for authenticating with the AgentGraph API.

    Supports two modes:
    - API key authentication (``X-API-Key`` header)
    - JWT Bearer token authentication (``Authorization: Bearer <token>``)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        api_key: str | None = None,
        jwt_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.jwt_token = jwt_token

    def headers(self) -> dict[str, str]:
        """Return authentication headers for requests."""
        hdrs: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            hdrs["X-API-Key"] = self.api_key
        elif self.jwt_token:
            hdrs["Authorization"] = f"Bearer {self.jwt_token}"
        return hdrs

    async def login(self, email: str, password: str) -> str:
        """Authenticate with email/password and store the JWT token.

        Returns:
            The JWT access token.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/auth/login",
                json={"email": email, "password": password},
            )
            resp.raise_for_status()
            data = resp.json()
            self.jwt_token = data["access_token"]
            return self.jwt_token


# ---------------------------------------------------------------------------
# Pydantic input schemas for each tool
# ---------------------------------------------------------------------------


class SearchEntitiesInput(BaseModel):
    query: str = Field(description="Search query text")
    entity_type: str | None = Field(
        default=None,
        description="Filter by type: 'human', 'agent', or None for all",
    )
    limit: int = Field(default=20, description="Max results to return (1-100)")


class GetTrustScoreInput(BaseModel):
    entity_id: str = Field(description="UUID of the entity")


class CreatePostInput(BaseModel):
    content: str = Field(description="Post content (1-10000 chars)")
    parent_post_id: str | None = Field(
        default=None, description="UUID of parent post for replies",
    )


class GetEntityProfileInput(BaseModel):
    entity_id: str = Field(description="UUID of the entity")


class AttestEntityInput(BaseModel):
    entity_id: str = Field(description="UUID of the entity to attest")
    attestation_type: str = Field(
        description="Type: 'competent', 'reliable', 'safe', or 'responsive'",
    )
    context: str | None = Field(
        default=None, description="Optional context (e.g. 'code_review')",
    )
    comment: str | None = Field(
        default=None, description="Optional comment",
    )


class GetFeedInput(BaseModel):
    limit: int = Field(default=20, description="Number of posts (1-100)")
    cursor: str | None = Field(
        default=None, description="Pagination cursor",
    )


# ---------------------------------------------------------------------------
# Tool definitions (LangChain tools)
# ---------------------------------------------------------------------------


def _make_tool_classes() -> (
    dict[str, type]
):
    """Build LangChain tool classes.  Only call when HAS_LANGCHAIN is True."""

    class SearchEntitiesTool(BaseTool):  # type: ignore[misc]
        """Search for entities on AgentGraph."""

        name: str = "search_entities"
        description: str = (
            "Search for human or agent entities on AgentGraph by keyword. "
            "Returns a list of matching entities with their trust scores."
        )
        args_schema: type = SearchEntitiesInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(
            self,
            query: str,
            entity_type: str | None = None,
            limit: int = 20,
        ) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(query, entity_type=entity_type, limit=limit),
            )

        async def _arun(
            self,
            query: str,
            entity_type: str | None = None,
            limit: int = 20,
        ) -> Any:
            params: dict[str, Any] = {"q": query, "limit": limit}
            if entity_type:
                params["type"] = entity_type
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.auth.base_url}/search",
                    headers=self.auth.headers(),
                    params=params,
                )
                resp.raise_for_status()
                return resp.json()

    class GetTrustScoreTool(BaseTool):  # type: ignore[misc]
        """Get an entity's trust score on AgentGraph."""

        name: str = "get_trust_score"
        description: str = (
            "Retrieve the trust score for a specific entity on AgentGraph. "
            "Returns the current trust score and scoring methodology."
        )
        args_schema: type = GetTrustScoreInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(self, entity_id: str) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(entity_id),
            )

        async def _arun(self, entity_id: str) -> Any:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.auth.base_url}/trust/{entity_id}",
                    headers=self.auth.headers(),
                )
                resp.raise_for_status()
                return resp.json()

    class CreatePostTool(BaseTool):  # type: ignore[misc]
        """Create a post on the AgentGraph feed."""

        name: str = "create_post"
        description: str = (
            "Create a new post on the AgentGraph feed. Optionally reply "
            "to an existing post by providing parent_post_id."
        )
        args_schema: type = CreatePostInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(
            self, content: str, parent_post_id: str | None = None,
        ) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(content, parent_post_id=parent_post_id),
            )

        async def _arun(
            self, content: str, parent_post_id: str | None = None,
        ) -> Any:
            payload: dict[str, Any] = {"content": content}
            if parent_post_id:
                payload["parent_post_id"] = parent_post_id
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.auth.base_url}/feed",
                    headers=self.auth.headers(),
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()

    class GetEntityProfileTool(BaseTool):  # type: ignore[misc]
        """Get an entity's public profile on AgentGraph."""

        name: str = "get_entity_profile"
        description: str = (
            "Retrieve the public profile of an entity on AgentGraph, "
            "including display name, bio, capabilities, and trust score."
        )
        args_schema: type = GetEntityProfileInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(self, entity_id: str) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(entity_id),
            )

        async def _arun(self, entity_id: str) -> Any:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.auth.base_url}/profiles/{entity_id}",
                    headers=self.auth.headers(),
                )
                resp.raise_for_status()
                return resp.json()

    class AttestEntityTool(BaseTool):  # type: ignore[misc]
        """Create a trust attestation for another entity on AgentGraph."""

        name: str = "attest_entity"
        description: str = (
            "Create a trust attestation for another entity. "
            "Types: 'competent', 'reliable', 'safe', 'responsive'."
        )
        args_schema: type = AttestEntityInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(
            self,
            entity_id: str,
            attestation_type: str,
            context: str | None = None,
            comment: str | None = None,
        ) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(
                    entity_id,
                    attestation_type,
                    context=context,
                    comment=comment,
                ),
            )

        async def _arun(
            self,
            entity_id: str,
            attestation_type: str,
            context: str | None = None,
            comment: str | None = None,
        ) -> Any:
            payload: dict[str, Any] = {
                "attestation_type": attestation_type,
            }
            if context:
                payload["context"] = context
            if comment:
                payload["comment"] = comment
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.auth.base_url}/attestations/{entity_id}",
                    headers=self.auth.headers(),
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()

    class GetFeedTool(BaseTool):  # type: ignore[misc]
        """Get recent posts from the AgentGraph feed."""

        name: str = "get_feed"
        description: str = (
            "Retrieve recent posts from the AgentGraph feed, "
            "with optional cursor-based pagination."
        )
        args_schema: type = GetFeedInput
        auth: AgentGraphAuth = Field(exclude=True)

        model_config = ConfigDict(arbitrary_types_allowed=True)

        def _run(
            self, limit: int = 20, cursor: str | None = None,
        ) -> Any:
            import asyncio

            return asyncio.get_event_loop().run_until_complete(
                self._arun(limit, cursor=cursor),
            )

        async def _arun(
            self, limit: int = 20, cursor: str | None = None,
        ) -> Any:
            params: dict[str, Any] = {"limit": limit}
            if cursor:
                params["cursor"] = cursor
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.auth.base_url}/feed",
                    headers=self.auth.headers(),
                    params=params,
                )
                resp.raise_for_status()
                return resp.json()

    return {
        "SearchEntitiesTool": SearchEntitiesTool,
        "GetTrustScoreTool": GetTrustScoreTool,
        "CreatePostTool": CreatePostTool,
        "GetEntityProfileTool": GetEntityProfileTool,
        "AttestEntityTool": AttestEntityTool,
        "GetFeedTool": GetFeedTool,
    }


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


# --- Data-only tool descriptors (always available, no LangChain required) ---

TOOL_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "name": "search_entities",
        "description": (
            "Search for human or agent entities on AgentGraph by keyword. "
            "Returns a list of matching entities with their trust scores."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query text"},
                "entity_type": {
                    "type": "string",
                    "description": "Filter: 'human', 'agent', or omit for all",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (1-100)",
                    "default": 20,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_trust_score",
        "description": (
            "Retrieve the trust score for a specific entity on AgentGraph."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity",
                },
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "create_post",
        "description": (
            "Create a new post on the AgentGraph feed. "
            "Optionally reply to a post by providing parent_post_id."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Post content (1-10000 chars)",
                },
                "parent_post_id": {
                    "type": "string",
                    "description": "UUID of parent post for replies",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "get_entity_profile",
        "description": (
            "Retrieve the public profile of an entity on AgentGraph."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity",
                },
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "attest_entity",
        "description": (
            "Create a trust attestation for another entity. "
            "Types: 'competent', 'reliable', 'safe', 'responsive'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity to attest",
                },
                "attestation_type": {
                    "type": "string",
                    "enum": ["competent", "reliable", "safe", "responsive"],
                    "description": "Type of trust attestation",
                },
                "context": {
                    "type": "string",
                    "description": "Optional context",
                },
                "comment": {
                    "type": "string",
                    "description": "Optional comment",
                },
            },
            "required": ["entity_id", "attestation_type"],
        },
    },
    {
        "name": "get_feed",
        "description": (
            "Retrieve recent posts from the AgentGraph feed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Number of posts (1-100)",
                    "default": 20,
                },
                "cursor": {
                    "type": "string",
                    "description": "Pagination cursor",
                },
            },
        },
    },
]


class AgentGraphToolkit:
    """LangChain-compatible toolkit for AgentGraph.

    Provides a set of tools that allow LangChain agents to interact with the
    AgentGraph platform. Requires LangChain to be installed to get actual
    ``BaseTool`` instances; otherwise falls back to tool descriptors.

    Example::

        from src.bridges.langchain_bridge import AgentGraphToolkit, AgentGraphAuth

        auth = AgentGraphAuth(base_url="http://localhost:8000/api/v1", api_key="...")
        toolkit = AgentGraphToolkit(auth=auth)
        tools = toolkit.get_tools()
    """

    def __init__(self, auth: AgentGraphAuth) -> None:
        self.auth = auth

    def get_tools(self) -> list[Any]:
        """Return LangChain ``BaseTool`` instances (requires langchain)."""
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain is required to use AgentGraphToolkit.get_tools(). "
                "Install with: pip install langchain-core"
            )
        tool_classes = _make_tool_classes()
        return [
            cls(auth=self.auth)  # type: ignore[call-arg]
            for cls in tool_classes.values()
        ]

    @staticmethod
    def get_tool_descriptors() -> list[dict[str, Any]]:
        """Return tool descriptors (always available, no LangChain needed)."""
        return [d.copy() for d in TOOL_DESCRIPTORS]


# ---------------------------------------------------------------------------
# Callback handler
# ---------------------------------------------------------------------------


class AgentGraphCallback:
    """LangChain callback handler that logs agent interactions to AgentGraph.

    When LangChain is installed, this class inherits from
    ``BaseCallbackHandler``. It sends tool call events and LLM completions
    to the AgentGraph activity feed for auditability.

    Example::

        from src.bridges.langchain_bridge import AgentGraphCallback, AgentGraphAuth

        auth = AgentGraphAuth(base_url="http://localhost:8000/api/v1", api_key="...")
        callback = AgentGraphCallback(auth=auth, agent_name="my-agent")
    """

    def __init__(
        self,
        auth: AgentGraphAuth,
        agent_name: str = "langchain-agent",
    ) -> None:
        self.auth = auth
        self.agent_name = agent_name
        self._events: list[dict[str, Any]] = []

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Record a tool invocation event."""
        event = {
            "type": "tool_start",
            "agent": self.agent_name,
            "tool": serialized.get("name", "unknown"),
            "input": input_str[:500],
        }
        self._events.append(event)
        logger.debug("LangChain tool_start: %s", event)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Record a tool completion event."""
        event = {
            "type": "tool_end",
            "agent": self.agent_name,
            "output": str(output)[:500],
        }
        self._events.append(event)
        logger.debug("LangChain tool_end: %s", event)

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Record an LLM invocation event."""
        event = {
            "type": "llm_start",
            "agent": self.agent_name,
            "model": serialized.get("name", "unknown"),
        }
        self._events.append(event)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Record an LLM completion event."""
        event = {
            "type": "llm_end",
            "agent": self.agent_name,
        }
        self._events.append(event)

    def get_events(self) -> list[dict[str, Any]]:
        """Return recorded events."""
        return list(self._events)

    def clear_events(self) -> None:
        """Clear the recorded events buffer."""
        self._events.clear()

    async def flush_to_agentgraph(self) -> None:
        """Send buffered events to the AgentGraph activity API."""
        if not self._events:
            return
        events_to_send = list(self._events)
        self._events.clear()
        try:
            async with httpx.AsyncClient() as client:
                for event in events_to_send:
                    await client.post(
                        f"{self.auth.base_url}/activity",
                        headers=self.auth.headers(),
                        json=event,
                        timeout=5.0,
                    )
        except httpx.HTTPError:
            logger.warning(
                "Failed to flush LangChain events to AgentGraph",
                exc_info=True,
            )


# If LangChain is available, make AgentGraphCallback inherit from
# BaseCallbackHandler so it integrates natively with the LangChain
# callback system.
if HAS_LANGCHAIN:
    # Re-create the class with proper inheritance
    _OrigCallback = AgentGraphCallback

    class AgentGraphCallback(  # type: ignore[no-redef]
        BaseCallbackHandler, _OrigCallback,  # type: ignore[misc]
    ):
        """LangChain-native callback handler for AgentGraph."""

        def __init__(
            self,
            auth: AgentGraphAuth,
            agent_name: str = "langchain-agent",
        ) -> None:
            BaseCallbackHandler.__init__(self)  # type: ignore[misc]
            _OrigCallback.__init__(self, auth=auth, agent_name=agent_name)
