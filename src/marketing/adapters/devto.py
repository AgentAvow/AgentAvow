"""Dev.to adapter — technical blog publishing via REST API."""
from __future__ import annotations

import logging
import re
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

_API_BASE = "https://dev.to/api"
_TIMEOUT = 30.0

# Match the first Markdown heading (# or ##) to extract a title
_HEADING_RE = re.compile(r"^#{1,2}\s+(.+)", re.MULTILINE)


def _extract_title(content: str) -> tuple[str, str]:
    """Extract a title from Markdown content.

    If the content starts with a heading, use it as the title and strip
    it from the body (Dev.to renders its own title separately).
    Returns (title, body).
    """
    match = _HEADING_RE.search(content)
    if match:
        title = match.group(1).strip()
        # Remove the heading line from the body
        body = content[:match.start()] + content[match.end():]
        body = body.lstrip("\n")
        return title, body
    return "", content


class DevtoAdapter(AbstractPlatformAdapter):
    platform_name = "devto"
    max_content_length = 50000
    supports_replies = False
    supports_monitoring = False
    rate_limit_posts_per_hour = 2

    async def is_configured(self) -> bool:
        return bool(marketing_settings.devto_api_key)

    def _headers(self) -> dict:
        return {
            "api-key": marketing_settings.devto_api_key or "",
            "Content-Type": "application/json",
        }

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        meta = metadata or {}
        tags = meta.get("tags", ["ai", "agents", "security", "webdev"])
        published = meta.get("published", True)

        # Extract title from content if not provided in metadata
        explicit_title = meta.get("title", "")
        if explicit_title:
            title = explicit_title
            body_markdown = content
        else:
            extracted, body_markdown = _extract_title(content)
            title = extracted or "AgentAvow Update"

        body = {
            "article": {
                "title": title,
                "body_markdown": body_markdown,
                "tags": tags[:4],  # Dev.to max 4 tags
                "published": published,
                "canonical_url": meta.get("canonical_url"),
            },
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_API_BASE}/articles", json=body, headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            return ExternalPostResult(
                success=True,
                external_id=str(data.get("id", "")),
                url=data.get("url"),
            )
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            logger.error(
                "Dev.to post failed: HTTP %s — %s",
                exc.response.status_code,
                body,
            )
            return ExternalPostResult(success=False, error=f"{exc}: {body}")
        except Exception as exc:
            logger.exception("Dev.to post failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        return ExternalPostResult(success=False, error="Dev.to replies not supported via API")

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        return []

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/articles/{post_external_id}",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()

            return EngagementMetrics(
                likes=data.get("positive_reactions_count", 0),
                comments=data.get("comments_count", 0),
                impressions=data.get("page_views_count", 0),
            )
        except Exception:
            return EngagementMetrics()

    async def health_check(self) -> bool:
        if not await self.is_configured():
            return False
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/users/me", headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception:
            return False
