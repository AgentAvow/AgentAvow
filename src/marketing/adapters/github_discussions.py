"""GitHub Discussions adapter — engage in relevant open-source repos.

Searches target AI/agent repos for relevant discussions, monitors for
keyword mentions, and replies with helpful context about AgentAvow.
All posts require human approval before publishing.

Uses the GitHub GraphQL API v4 exclusively.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from src.marketing.adapters.base import (
    AbstractPlatformAdapter,
    EngagementMetrics,
    ExternalPostResult,
    Mention,
)

logger = logging.getLogger(__name__)

_API_URL = "https://api.github.com/graphql"
_TIMEOUT = 15.0

# Target repos for engagement — popular AI/agent framework repos where
# AgentAvow's trust + identity layer is most relevant.
TARGET_REPOS: list[dict[str, str]] = [
    {"owner": "langchain-ai", "name": "langchain"},
    {"owner": "microsoft", "name": "autogen"},
    {"owner": "modelcontextprotocol", "name": "servers"},
    {"owner": "AgentAvow", "name": "AgentAvow"},
]

# Keywords to monitor across discussions
MONITOR_KEYWORDS: list[str] = [
    "agentavow",
    "agent trust",
    "agent identity",
    "agent verification",
    "decentralized identity",
    "agent social",
    "agent reputation",
    "agent safety",
    "MCP trust",
]

# GraphQL: fetch recent discussions from a repo
_REPO_DISCUSSIONS_QUERY = """
query RepoDiscussions($owner: String!, $name: String!, $first: Int!) {
    repository(owner: $owner, name: $name) {
        discussions(first: $first, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
                id
                title
                body
                url
                createdAt
                updatedAt
                author { login }
                comments { totalCount }
                reactions { totalCount }
                category { name }
            }
        }
    }
}
"""

# GraphQL: search discussions globally
_SEARCH_DISCUSSIONS_QUERY = """
query SearchDiscussions($query: String!, $first: Int!) {
    search(query: $query, type: DISCUSSION, first: $first) {
        nodes {
            ... on Discussion {
                id
                title
                body
                url
                createdAt
                updatedAt
                author { login }
                comments { totalCount }
                reactions { totalCount }
                repository { nameWithOwner }
            }
        }
    }
}
"""

# GraphQL: fetch discussion categories for a repo (needed to create discussions)
_REPO_CATEGORIES_QUERY = """
query RepoCategories($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
        id
        discussionCategories(first: 20) {
            nodes {
                id
                name
                isAnswerable
            }
        }
    }
}
"""

# GraphQL: create a new discussion
_CREATE_DISCUSSION_MUTATION = """
mutation CreateDiscussion($input: CreateDiscussionInput!) {
    createDiscussion(input: $input) {
        discussion {
            id
            url
        }
    }
}
"""

# GraphQL: add a comment to a discussion
_ADD_COMMENT_MUTATION = """
mutation AddComment($input: AddDiscussionCommentInput!) {
    addDiscussionComment(input: $input) {
        comment {
            id
            url
            createdAt
        }
    }
}
"""

# GraphQL: fetch a discussion node by ID (for metrics)
_DISCUSSION_NODE_QUERY = """
query DiscussionNode($id: ID!) {
    node(id: $id) {
        ... on Discussion {
            id
            title
            url
            comments { totalCount }
            reactions { totalCount }
            upvoteCount
        }
        ... on DiscussionComment {
            id
            url
            reactions { totalCount }
            upvoteCount
            replies { totalCount }
        }
    }
}
"""

# GraphQL: verify authentication
_VIEWER_QUERY = """
query Viewer {
    viewer {
        login
        id
    }
    rateLimit {
        remaining
        resetAt
    }
}
"""


class GitHubDiscussionsAdapter(AbstractPlatformAdapter):
    """GitHub Discussions adapter for engaging in open-source AI repo discussions.

    Strategy:
    - Monitor target repos for relevant discussions about agent trust,
      identity, safety, and interoperability.
    - Reply to existing discussions with helpful, non-spammy context.
    - Never create new discussions — only comment on existing ones.
    - All posts go through human approval before publishing.
    """

    platform_name = "github_discussions"
    max_content_length = 10000  # GitHub supports up to 65536 but we keep it concise
    supports_replies = True
    supports_monitoring = True
    requires_human_approval = True  # All platforms require human review
    rate_limit_posts_per_hour = 5
    rate_limit_replies_per_hour = 10

    def _token(self) -> str | None:
        """Get GitHub token — falls back to main config."""
        from src.config import settings

        return settings.github_token

    async def is_configured(self) -> bool:
        """Check if GitHub token is available."""
        return bool(self._token())

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query against the GitHub API.

        Returns the full response JSON.  Raises ``httpx.HTTPStatusError``
        on non-2xx responses and logs rate-limit headers.
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _API_URL,
                json=payload,
                headers=self._headers(),
            )
            # Log rate-limit info for diagnostics
            remaining = resp.headers.get("x-ratelimit-remaining")
            if remaining is not None and int(remaining) < 100:
                logger.warning(
                    "GitHub GraphQL rate limit low: %s remaining", remaining,
                )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # Posting
    # ------------------------------------------------------------------

    async def post(
        self, content: str, metadata: dict | None = None,
    ) -> ExternalPostResult:
        """Post to GitHub Discussions.

        If ``discussion_id`` is in metadata, replies to that discussion.
        Otherwise creates a new discussion in AgentAvow/AgentAvow.
        All posts go through human approval via HUMAN_APPROVAL_PLATFORMS.
        """
        meta = metadata or {}
        discussion_id = meta.get("discussion_id")
        if discussion_id:
            return await self.reply(discussion_id, content, metadata)

        return await self._create_discussion(content, meta)

    async def _create_discussion(
        self, content: str, meta: dict,
    ) -> ExternalPostResult:
        """Create a new discussion on the AgentAvow/AgentAvow repo."""
        if not await self.is_configured():
            return ExternalPostResult(success=False, error="GitHub token not configured")

        owner, name = "AgentAvow", "AgentAvow"
        try:
            # Fetch repo ID and discussion categories
            cat_data = await self._graphql(
                _REPO_CATEGORIES_QUERY,
                {"owner": owner, "name": name},
            )
            repo_node = cat_data.get("data", {}).get("repository", {})
            repo_id = repo_node.get("id")
            categories = repo_node.get("discussionCategories", {}).get("nodes", [])

            if not repo_id or not categories:
                return ExternalPostResult(
                    success=False,
                    error="Could not fetch repo categories",
                )

            # Prefer "General" or "Ideas" category; fall back to first non-answerable
            category_id = None
            for cat in categories:
                if cat["name"].lower() in ("general", "ideas"):
                    category_id = cat["id"]
                    break
            if not category_id:
                for cat in categories:
                    if not cat.get("isAnswerable"):
                        category_id = cat["id"]
                        break
            if not category_id:
                category_id = categories[0]["id"]

            # Extract title from first line or metadata
            title = meta.get("title", "")
            body = content
            if not title:
                lines = content.strip().split("\n", 1)
                first_line = lines[0].lstrip("#").strip()
                title = first_line[:128] if first_line else "AgentAvow Update"
                body = lines[1].strip() if len(lines) > 1 else content

            data = await self._graphql(
                _CREATE_DISCUSSION_MUTATION,
                {"input": {
                    "repositoryId": repo_id,
                    "categoryId": category_id,
                    "title": title,
                    "body": self.truncate(body),
                }},
            )

            errors = data.get("errors")
            if errors:
                msg = errors[0].get("message", "Unknown GraphQL error")
                logger.warning("GitHub Discussions create error: %s", msg)
                return ExternalPostResult(success=False, error=msg)

            discussion = (
                data.get("data", {})
                .get("createDiscussion", {})
                .get("discussion", {})
            )
            logger.info(
                "GitHub Discussion created: %s", discussion.get("url"),
            )
            return ExternalPostResult(
                success=True,
                external_id=discussion.get("id", ""),
                url=discussion.get("url"),
            )
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "GitHub Discussions create HTTP %s: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return ExternalPostResult(
                success=False,
                error=f"HTTP {exc.response.status_code}",
                rate_limited=exc.response.status_code in (403, 429),
            )
        except Exception as exc:
            logger.exception("GitHub Discussions create failed")
            return ExternalPostResult(success=False, error=str(exc))

    async def reply(
        self,
        parent_id: str,
        content: str,
        metadata: dict | None = None,
    ) -> ExternalPostResult:
        """Reply to an existing discussion with a comment.

        ``parent_id`` must be a GitHub GraphQL node ID for a Discussion.
        """
        if not await self.is_configured():
            return ExternalPostResult(success=False, error="GitHub token not configured")

        body = self.truncate(content)

        variables = {
            "input": {
                "discussionId": parent_id,
                "body": body,
            },
        }

        try:
            data = await self._graphql(_ADD_COMMENT_MUTATION, variables)

            errors = data.get("errors")
            if errors:
                msg = errors[0].get("message", "Unknown GraphQL error")
                logger.warning("GitHub Discussions reply error: %s", msg)
                return ExternalPostResult(
                    success=False,
                    error=msg,
                    rate_limited="rate limit" in msg.lower(),
                )

            comment = (
                data.get("data", {})
                .get("addDiscussionComment", {})
                .get("comment", {})
            )
            return ExternalPostResult(
                success=True,
                external_id=comment.get("id", ""),
                url=comment.get("url"),
            )
        except httpx.HTTPStatusError as exc:
            rate_limited = exc.response.status_code in (403, 429)
            logger.warning(
                "GitHub Discussions reply HTTP %s: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return ExternalPostResult(
                success=False,
                error=f"HTTP {exc.response.status_code}",
                rate_limited=rate_limited,
            )
        except Exception as exc:
            logger.exception("GitHub Discussions reply failed")
            return ExternalPostResult(success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    async def fetch_mentions(
        self, since: datetime | None = None,
    ) -> list[Mention]:
        """Search for AgentAvow-relevant discussions across target repos.

        Combines two strategies:
        1. Global search for keyword mentions in discussions.
        2. Per-repo recent discussions scan for topic relevance.
        """
        if not await self.is_configured():
            return []

        mentions: list[Mention] = []

        # Strategy 1: Global keyword search
        mentions.extend(await self._search_global_mentions(since))

        # Strategy 2: Per-repo recent discussions
        for repo in TARGET_REPOS:
            # Skip our own repo for mention monitoring
            if repo["owner"] == "AgentAvow":
                continue
            mentions.extend(await self._fetch_repo_discussions(repo, since))

        # Deduplicate by external_id
        seen: set[str] = set()
        unique: list[Mention] = []
        for m in mentions:
            if m.external_id not in seen:
                seen.add(m.external_id)
                unique.append(m)

        return unique

    async def _search_global_mentions(
        self, since: datetime | None = None,
    ) -> list[Mention]:
        """Search GitHub Discussions globally for keyword matches."""
        mentions: list[Mention] = []

        # Build search query — combine key terms with OR
        search_terms = "agentavow OR \"agent trust\" OR \"agent identity verification\""
        search_query = f"{search_terms} type:discussions"

        try:
            data = await self._graphql(
                _SEARCH_DISCUSSIONS_QUERY,
                {"query": search_query, "first": 15},
            )

            nodes = data.get("data", {}).get("search", {}).get("nodes", [])
            for node in nodes:
                if not node:
                    continue

                created_str = node.get("createdAt")
                created_at = None
                if created_str:
                    try:
                        created_at = datetime.fromisoformat(
                            created_str.replace("Z", "+00:00"),
                        )
                    except (ValueError, TypeError):
                        pass

                # Skip if older than since
                if since and created_at and created_at < since:
                    continue

                body = node.get("body", "")
                title = node.get("title", "")
                matched = _match_keywords(f"{title} {body}")

                mentions.append(Mention(
                    platform="github_discussions",
                    external_id=node.get("id", ""),
                    author=node.get("author", {}).get("login", "unknown"),
                    content=f"{title}\n\n{body[:500]}",
                    url=node.get("url"),
                    created_at=created_at,
                    keywords_matched=matched,
                ))
        except Exception:
            logger.debug("GitHub Discussions global search failed", exc_info=True)

        return mentions

    async def _fetch_repo_discussions(
        self,
        repo: dict[str, str],
        since: datetime | None = None,
    ) -> list[Mention]:
        """Fetch recent discussions from a specific repo."""
        mentions: list[Mention] = []

        try:
            data = await self._graphql(
                _REPO_DISCUSSIONS_QUERY,
                {"owner": repo["owner"], "name": repo["name"], "first": 10},
            )

            nodes = (
                data.get("data", {})
                .get("repository", {})
                .get("discussions", {})
                .get("nodes", [])
            )
            for node in nodes:
                if not node:
                    continue

                created_str = node.get("createdAt")
                created_at = None
                if created_str:
                    try:
                        created_at = datetime.fromisoformat(
                            created_str.replace("Z", "+00:00"),
                        )
                    except (ValueError, TypeError):
                        pass

                if since and created_at and created_at < since:
                    continue

                body = node.get("body", "")
                title = node.get("title", "")
                matched = _match_keywords(f"{title} {body}")
                if not matched:
                    continue  # Only surface discussions matching our keywords

                repo_label = f"{repo['owner']}/{repo['name']}"
                mentions.append(Mention(
                    platform="github_discussions",
                    external_id=node.get("id", ""),
                    author=node.get("author", {}).get("login", "unknown"),
                    content=f"[{repo_label}] {title}\n\n{body[:500]}",
                    url=node.get("url"),
                    created_at=created_at,
                    keywords_matched=matched,
                ))
        except Exception:
            logger.debug(
                "GitHub Discussions repo fetch failed for %s/%s",
                repo["owner"],
                repo["name"],
                exc_info=True,
            )

        return mentions

    # ------------------------------------------------------------------
    # Keyword search
    # ------------------------------------------------------------------

    async def search_keywords(
        self,
        keywords: list[str],
        since: datetime | None = None,
    ) -> list[Mention]:
        """Search GitHub Discussions for specific keywords."""
        if not await self.is_configured():
            return []

        mentions: list[Mention] = []
        # Build OR-joined search query from provided keywords
        terms = " OR ".join(f'"{kw}"' for kw in keywords[:5])
        search_query = f"{terms} type:discussions"

        try:
            data = await self._graphql(
                _SEARCH_DISCUSSIONS_QUERY,
                {"query": search_query, "first": 20},
            )

            nodes = data.get("data", {}).get("search", {}).get("nodes", [])
            for node in nodes:
                if not node:
                    continue

                created_str = node.get("createdAt")
                created_at = None
                if created_str:
                    try:
                        created_at = datetime.fromisoformat(
                            created_str.replace("Z", "+00:00"),
                        )
                    except (ValueError, TypeError):
                        pass

                if since and created_at and created_at < since:
                    continue

                body = node.get("body", "")
                title = node.get("title", "")
                matched = [
                    kw for kw in keywords
                    if kw.lower() in f"{title} {body}".lower()
                ]

                mentions.append(Mention(
                    platform="github_discussions",
                    external_id=node.get("id", ""),
                    author=node.get("author", {}).get("login", "unknown"),
                    content=f"{title}\n\n{body[:500]}",
                    url=node.get("url"),
                    created_at=created_at,
                    keywords_matched=matched,
                ))
        except Exception:
            logger.debug("GitHub Discussions keyword search failed", exc_info=True)

        return mentions

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    async def fetch_metrics(self, post_external_id: str) -> EngagementMetrics:
        """Fetch engagement metrics for a discussion or comment by node ID."""
        if not await self.is_configured():
            return EngagementMetrics()

        try:
            data = await self._graphql(
                _DISCUSSION_NODE_QUERY,
                {"id": post_external_id},
            )

            errors = data.get("errors")
            if errors:
                logger.debug("GitHub metrics query error: %s", errors[0].get("message"))
                return EngagementMetrics()

            node = data.get("data", {}).get("node", {})
            if not node:
                return EngagementMetrics()

            reactions = node.get("reactions", {}).get("totalCount", 0)
            upvotes = node.get("upvoteCount", 0)

            # Discussion nodes have .comments, DiscussionComment nodes have .replies
            comments = (
                node.get("comments", {}).get("totalCount", 0)
                or node.get("replies", {}).get("totalCount", 0)
            )

            return EngagementMetrics(
                likes=reactions + upvotes,
                comments=comments,
                extra={
                    "reactions": reactions,
                    "upvotes": upvotes,
                    "node_type": "Discussion" if "comments" in node else "DiscussionComment",
                },
            )
        except Exception:
            logger.debug("GitHub Discussions metrics fetch failed", exc_info=True)
            return EngagementMetrics()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Verify GitHub token is valid and rate limit is healthy."""
        if not await self.is_configured():
            return False
        try:
            data = await self._graphql(_VIEWER_QUERY)

            errors = data.get("errors")
            if errors:
                logger.warning("GitHub health check errors: %s", errors)
                return False

            viewer = data.get("data", {}).get("viewer", {})
            rate_limit = data.get("data", {}).get("rateLimit", {})

            login = viewer.get("login", "")
            remaining = rate_limit.get("remaining", 0)

            logger.info(
                "GitHub Discussions health OK: user=%s, rate_limit_remaining=%s",
                login,
                remaining,
            )
            return bool(login)
        except Exception:
            logger.debug("GitHub Discussions health check failed", exc_info=True)
            return False


def _match_keywords(text: str) -> list[str]:
    """Return which monitor keywords appear in the given text."""
    lower = text.lower()
    return [kw for kw in MONITOR_KEYWORDS if kw.lower() in lower]
