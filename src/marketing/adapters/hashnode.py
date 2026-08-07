"""Hashnode adapter — blog publishing via GraphQL API."""
from __future__ import annotations

import logging
from datetime import datetime

import httpx

from src.marketing.adapters.base import (
    AbstractPlatformAdapter,
    EngagementMetrics,
    ExternalPostResult,
    Mention,
)
from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)

_API_URL = "https://gql.hashnode.com"
_TIMEOUT = 30.0


class HashnodeAdapter(AbstractPlatformAdapter):
    platform_name = "hashnode"
    max_content_length = 50000
    supports_replies = False
    supports_monitoring = False
    rate_limit_posts_per_hour = 2

    async def is_configured(self) -> bool:
        return bool(
            marketing_settings.hashnode_api_key
            and marketing_settings.hashnode_publication_id
        )

    def _headers(self) -> dict:
        return {
            "Authorization": marketing_settings.hashnode_api_key or "",
            "Content-Type": "application/json",
        }

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        meta = metadata or {}
        title = meta.get("title", "AgentAvow Update")
        tags = meta.get("tags", [])

        mutation = """
        mutation PublishPost($input: PublishPostInput!) {
            publishPost(input: $input) {
                post { id url title }
            }
        }
        """

        tag_ids = [{"slug": t, "name": t} for t in tags[:5]]
        variables = {
            "input": {
                "title": title,
                "contentMarkdown": content,
                "publicationId": marketing_settings.hashnode_publication_id,
                "tags": tag_ids,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    _API_URL,
                    json={"query": mutation, "variables": variables},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            errors = data.get("errors")
            if errors:
                return ExternalPostResult(
                    success=False, error=str(errors[0].get("message", errors)),
                )

            post_data = data.get("data", {}).get("publishPost", {}).get("post", {})
            return ExternalPostResult(
                success=True,
                external_id=post_data.get("id", ""),
                url=post_data.get("url"),
            )
        except Exception as exc:
            logger.exception("Hashnode post failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        return ExternalPostResult(success=False, error="Hashnode replies not supported")

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        return []

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        return EngagementMetrics()  # Hashnode API doesn't expose analytics

    async def health_check(self) -> bool:
        if not await self.is_configured():
            return False
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    _API_URL,
                    json={"query": "{ me { id } }"},
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception:
            return False
