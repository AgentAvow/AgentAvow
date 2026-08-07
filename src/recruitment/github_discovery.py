"""GitHub repo discovery pipeline for operator recruitment.

Searches GitHub for MCP servers, AI agent repos, and AI tool repos,
then stores them as recruitment prospects for outreach.
"""
from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import RecruitmentProspect

logger = logging.getLogger(__name__)

_TIMEOUT = 15  # seconds

# Star ceiling — repos above this are too established and treat unsolicited
# issues as spam.  Target the 50-5000 sweet spot.
_MAX_STARS = 5000

# Search queries with minimum star thresholds and template keys.
# Focused on *actual* MCP servers and agent framework projects — NOT general
# AI-adjacent tools (search engines, workflow automation, curated lists, etc.).
_SEARCH_QUERIES: list[tuple[str, int, str]] = [
    ("topic:mcp-server", 10, "mcp_server"),
    ("topic:mcp topic:server", 10, "mcp_server"),
    ('"model context protocol" in:readme', 10, "mcp_server"),
    ("topic:crewai", 20, "ai_agent"),
    ("topic:autogen", 20, "ai_agent"),
    ("topic:langchain topic:agent", 30, "ai_agent"),
]

# Repos to skip (our own, forks of huge projects, etc.)
# Both the old (agentgraph-co) and current (agentavow) org handles are skipped so
# our own repos never surface in discovery. Compared against owner.lower().
_SKIP_OWNERS = {"agentavow", "agentgraph-co", "agentgraph"}

# Name patterns that indicate curated lists / aggregators, not actual projects
_SKIP_NAME_PREFIXES = ("awesome-", "awesome_")
_SKIP_NAME_KEYWORDS = {"awesome", "list", "curated", "collection", "resources"}


async def _github_headers() -> dict[str, str]:
    """Build GitHub API headers with optional auth."""
    from src.github_auth import get_github_token
    headers = {"Accept": "application/vnd.github+json"}
    token = await get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _detect_framework(topics: list[str], description: str) -> str | None:
    """Detect agent framework from repo topics and description."""
    text = " ".join(topics) + " " + (description or "")
    text_lower = text.lower()
    if "mcp" in text_lower or "model context protocol" in text_lower:
        return "mcp"
    if "langchain" in text_lower:
        return "langchain"
    if "crewai" in text_lower:
        return "crewai"
    if "autogen" in text_lower:
        return "autogen"
    if "semantic-kernel" in text_lower:
        return "semantic_kernel"
    return None


def _should_skip_repo(item: dict) -> bool:
    """Return True if this repo should be skipped based on name/metadata."""
    owner = item.get("owner", {}).get("login", "")
    if owner.lower() in _SKIP_OWNERS:
        return True
    if item.get("fork", False):
        return True

    name = (item.get("name") or "").lower()
    # Skip curated lists / awesome repos — they aren't actual projects
    if name.startswith(_SKIP_NAME_PREFIXES):
        return True
    if name in _SKIP_NAME_KEYWORDS:
        return True

    # Skip repos above star ceiling — too established, treat issues as spam
    stars = item.get("stargazers_count", 0)
    if stars > _MAX_STARS:
        return True

    # Skip repos with no description (low quality / abandoned)
    if not item.get("description"):
        return True

    return False


async def _search_github(
    query: str, min_stars: int,
) -> list[dict]:
    """Search GitHub for repos matching query with at least min_stars."""
    results = []
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        url = "https://api.github.com/search/repositories"
        params = {
            "q": f"{query} stars:>={min_stars} stars:<={_MAX_STARS}",
            "sort": "stars",
            "order": "desc",
            "per_page": 100,
        }
        resp = await client.get(url, headers=await _github_headers(), params=params)

        if resp.status_code == 403:
            logger.warning("GitHub rate limit hit during discovery")
            return results
        if resp.status_code != 200:
            logger.warning(
                "GitHub search returned %d for query: %s",
                resp.status_code, query,
            )
            return results

        data = resp.json()
        for item in data.get("items", []):
            if _should_skip_repo(item):
                continue
            results.append(item)

    return results


async def run_discovery_cycle(db: AsyncSession) -> int:
    """Run one discovery cycle, storing new prospects. Returns count added."""
    added = 0

    # Pre-load all known platform_ids to avoid per-row SELECTs and
    # autoflush issues with AsyncSession on Python 3.9.
    existing_rows = await db.execute(
        select(RecruitmentProspect.platform_id).where(
            RecruitmentProspect.platform == "github",
        )
    )
    known_ids: set[str] = {row[0] for row in existing_rows}

    for query, min_stars, template_key in _SEARCH_QUERIES:
        try:
            repos = await _search_github(query, min_stars)
        except Exception:
            logger.exception("Discovery search failed: %s", query)
            continue

        for repo in repos:
            full_name = repo["full_name"]
            owner = repo["owner"]["login"]

            if full_name in known_ids:
                continue

            topics = repo.get("topics", [])
            framework = _detect_framework(
                topics, repo.get("description", "") or "",
            )

            prospect = RecruitmentProspect(
                platform="github",
                platform_id=full_name,
                owner_login=owner,
                repo_name=repo["name"],
                stars=repo.get("stargazers_count", 0),
                description=(repo.get("description") or "")[:2000],
                framework_detected=framework or template_key.replace("_", " "),
                status="discovered",
            )
            db.add(prospect)
            known_ids.add(full_name)
            added += 1

    # Flush in batches to handle any remaining duplicates gracefully.
    # The pre-loaded known_ids should catch most, but edge cases
    # (concurrent cycles, stale cache) can still produce duplicates.
    if added > 0:
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            logger.info(
                "Bulk flush hit duplicate — skipping cycle, "
                "duplicates will be filtered next run",
            )
            return 0

    return added
