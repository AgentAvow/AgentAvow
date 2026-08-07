"""Hacker News adapter — read-only monitoring + draft queue.

HN actively bans bots. This adapter ONLY monitors for relevant
discussions and generates drafts for human submission.
"""
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

logger = logging.getLogger(__name__)

_API_BASE = "https://hn.algolia.com/api/v1"
_TIMEOUT = 15.0

# Keywords to monitor
MONITOR_KEYWORDS = [
    "agent identity",
    "agent trust",
    "AI agent security",
    "agent framework",
    "MCP protocol",
    "agent social",
    "agent verification",
    "decentralized identity",
    "DID",
    "OpenClaw",
    "Moltbook",
]


class HackerNewsAdapter(AbstractPlatformAdapter):
    platform_name = "hackernews"
    max_content_length = 2000
    supports_replies = False
    supports_monitoring = True
    requires_human_approval = True
    rate_limit_posts_per_hour = 0  # Never auto-post

    async def is_configured(self) -> bool:
        # Always available for monitoring (public API)
        return True

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        return ExternalPostResult(
            success=False, error="HN requires human submission — use draft queue",
        )

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        return ExternalPostResult(
            success=False, error="HN requires human submission",
        )

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        return await self.search_keywords(["agentavow"], since)

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/items/{post_external_id}",
                )
                resp.raise_for_status()
                data = resp.json()

            return EngagementMetrics(
                likes=data.get("points", 0),
                comments=data.get("num_comments", 0),
            )
        except Exception:
            return EngagementMetrics()

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(f"{_API_BASE}/search?query=test&hitsPerPage=1")
                return resp.status_code == 200
        except Exception:
            return False

    async def search_keywords(
        self, keywords: list[str], since: datetime | None = None,
    ) -> list[Mention]:
        """Search HN via Algolia API for relevant discussions."""
        mentions: list[Mention] = []
        query = " OR ".join(f'"{kw}"' for kw in keywords)

        params: dict = {
            "query": query,
            "hitsPerPage": 20,
            "tags": "(story,comment)",
        }

        if since:
            params["numericFilters"] = f"created_at_i>{int(since.timestamp())}"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/search_by_date", params=params,
                )
                resp.raise_for_status()
                hits = resp.json().get("hits", [])

            for hit in hits:
                text = hit.get("comment_text") or hit.get("title") or ""
                matched = [
                    kw for kw in keywords
                    if kw.lower() in text.lower()
                ]
                mentions.append(Mention(
                    platform="hackernews",
                    external_id=str(hit.get("objectID", "")),
                    author=hit.get("author", ""),
                    content=text,
                    url=f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}",
                    keywords_matched=matched,
                ))
        except Exception:
            logger.debug("HN search failed")

        return mentions
