"""Reddit adapter using httpx (no asyncpraw dependency).

Posts to relevant subreddits with value-first content.
Reddit's API is free but requires OAuth app registration.
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
from src.marketing.config import marketing_settings

logger = logging.getLogger(__name__)

_AUTH_URL = "https://www.reddit.com/api/v1/access_token"
_API_BASE = "https://oauth.reddit.com"
_TIMEOUT = 15.0

# Target subreddits with subscriber counts for context
TARGET_SUBREDDITS = [
    "AgentAvow",           # our own community — primary home base
    "artificial",          # 2.3M — general AI
    "MachineLearning",     # 3.2M — ML research
    "LangChain",           # 45K — LangChain
    "LocalLLaMA",          # 300K — local AI
    "programming",         # 6.7M — general programming
    "SideProject",         # small — indie projects
]


class RedditAdapter(AbstractPlatformAdapter):
    platform_name = "reddit"
    max_content_length = 10000
    supports_replies = True
    supports_monitoring = True
    rate_limit_posts_per_hour = 5
    rate_limit_replies_per_hour = 10

    _access_token: str | None = None
    _token_expires: float = 0

    async def is_configured(self) -> bool:
        return bool(
            marketing_settings.reddit_client_id
            and marketing_settings.reddit_client_secret
            and marketing_settings.reddit_username
            and marketing_settings.reddit_password
        )

    async def _ensure_token(self) -> str | None:
        """Get or refresh OAuth2 access token."""
        import time

        if self._access_token and time.time() < self._token_expires:
            return self._access_token

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    _AUTH_URL,
                    auth=(
                        marketing_settings.reddit_client_id or "",
                        marketing_settings.reddit_client_secret or "",
                    ),
                    data={
                        "grant_type": "password",
                        "username": marketing_settings.reddit_username,
                        "password": marketing_settings.reddit_password,
                    },
                    headers={"User-Agent": marketing_settings.reddit_user_agent},
                )
                resp.raise_for_status()
                data = resp.json()

            self._access_token = data["access_token"]
            self._token_expires = time.time() + data.get("expires_in", 3600) - 60
            return self._access_token
        except Exception:
            logger.exception("Reddit OAuth failed")
            return None

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "User-Agent": marketing_settings.reddit_user_agent,
        }

    async def post(self, content: str, metadata: dict | None = None) -> ExternalPostResult:
        token = await self._ensure_token()
        if not token:
            return ExternalPostResult(success=False, error="Reddit auth failed")

        subreddit = (metadata or {}).get("subreddit", "AgentAvow")
        title = (metadata or {}).get("title", content[:200])

        body = {
            "sr": subreddit,
            "kind": "self",
            "title": title,
            "text": self.truncate(content),
            "resubmit": True,
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_API_BASE}/api/submit",
                    data=body,
                    headers=self._headers(token),
                )

            if resp.status_code == 429:
                return ExternalPostResult(
                    success=False, error="Rate limited", rate_limited=True,
                )

            resp.raise_for_status()
            data = resp.json()

            # Reddit returns errors in json.errors
            errors = data.get("json", {}).get("errors", [])
            if errors:
                error_msg = "; ".join(str(e) for e in errors)
                return ExternalPostResult(success=False, error=error_msg)

            result_data = data.get("json", {}).get("data", {})
            post_url = result_data.get("url", "")
            post_id = result_data.get("id", "")

            return ExternalPostResult(
                success=True, external_id=post_id, url=post_url,
            )
        except httpx.HTTPStatusError as exc:
            logger.warning("Reddit post failed: %s", exc.response.text[:200])
            return ExternalPostResult(
                success=False, error=f"HTTP {exc.response.status_code}",
            )
        except Exception as exc:
            logger.exception("Reddit post failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def reply(
        self, parent_id: str, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        token = await self._ensure_token()
        if not token:
            return ExternalPostResult(success=False, error="Reddit auth failed")

        # parent_id should be a fullname like t3_xxx or t1_xxx
        thing_id = parent_id if parent_id.startswith("t") else f"t1_{parent_id}"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_API_BASE}/api/comment",
                    data={"thing_id": thing_id, "text": content},
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                data = resp.json()

            errors = data.get("json", {}).get("errors", [])
            if errors:
                return ExternalPostResult(
                    success=False, error="; ".join(str(e) for e in errors),
                )

            things = (
                data.get("json", {}).get("data", {}).get("things", [])
            )
            comment_id = things[0]["data"]["id"] if things else None

            return ExternalPostResult(success=True, external_id=comment_id)
        except Exception as exc:
            logger.exception("Reddit reply failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def fetch_mentions(self, since: datetime | None = None) -> list[Mention]:
        """Search for AgentAvow mentions across target subreddits."""
        token = await self._ensure_token()
        if not token:
            return []

        mentions: list[Mention] = []
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/search",
                    params={
                        "q": "agentavow OR agent+graph+trust",
                        "sort": "new",
                        "limit": 25,
                        "t": "week",
                    },
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                posts = resp.json().get("data", {}).get("children", [])

            for post in posts:
                pd = post.get("data", {})
                mentions.append(Mention(
                    platform="reddit",
                    external_id=pd.get("id", ""),
                    author=pd.get("author", ""),
                    content=pd.get("selftext", pd.get("title", "")),
                    url=f"https://reddit.com{pd.get('permalink', '')}",
                ))
        except Exception:
            logger.debug("Reddit mention search failed")

        return mentions

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        token = await self._ensure_token()
        if not token:
            return EngagementMetrics()

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/api/info",
                    params={"id": f"t3_{post_external_id}"},
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                children = resp.json().get("data", {}).get("children", [])

            if not children:
                return EngagementMetrics()

            data = children[0].get("data", {})
            return EngagementMetrics(
                likes=data.get("ups", 0),
                comments=data.get("num_comments", 0),
                shares=data.get("num_crossposts", 0),
            )
        except Exception:
            return EngagementMetrics()

    async def health_check(self) -> bool:
        token = await self._ensure_token()
        return token is not None

    async def search_keywords(
        self, keywords: list[str], since: datetime | None = None,
    ) -> list[Mention]:
        token = await self._ensure_token()
        if not token:
            return []

        query = " OR ".join(keywords)
        mentions: list[Mention] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"{_API_BASE}/search",
                    params={"q": query, "sort": "new", "limit": 25, "t": "day"},
                    headers=self._headers(token),
                )
                resp.raise_for_status()
                posts = resp.json().get("data", {}).get("children", [])

            for post in posts:
                pd = post.get("data", {})
                matched = [kw for kw in keywords if kw.lower() in
                           (pd.get("title", "") + pd.get("selftext", "")).lower()]
                mentions.append(Mention(
                    platform="reddit",
                    external_id=pd.get("id", ""),
                    author=pd.get("author", ""),
                    content=pd.get("selftext", pd.get("title", "")),
                    url=f"https://reddit.com{pd.get('permalink', '')}",
                    keywords_matched=matched,
                ))
        except Exception:
            logger.debug("Reddit keyword search failed")

        return mentions
