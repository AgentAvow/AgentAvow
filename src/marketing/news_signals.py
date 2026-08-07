"""Gather trending news signals for campaign planning.

Sources:
1. Local news-digest project (digest_history.json) — recent articles
2. HN Algolia API — AI agent and security stories

All signals are relevance-filtered to AgentAvow's domain before
being returned, so off-topic personal-interest articles from the
user's news digest don't leak into marketing content.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# Path to the news-digest history file:
# - Local (Mac Mini): ~/projects/news-digest/digest_history.json
# - EC2 (prod): ~/agentgraph/digest_history.json (synced via scp)
_DIGEST_PATHS = [
    Path("/app/digest_history.json"),  # Docker container mount
    Path.home() / "projects" / "news-digest" / "digest_history.json",
    Path.home() / "agentgraph" / "digest_history.json",
    Path("/home/ec2-user/agentgraph/digest_history.json"),
]

_HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search_by_date"
_HN_QUERIES = [
    "AI agent",
    "agent security",
    "decentralized identity",
    "multi-agent",
    "LLM framework",
    "bot trust",
    "AI safety",
    "agent protocol",
]
_HN_TIMEOUT = 10.0

# Keywords that indicate an article is relevant to AgentAvow's
# domain.  Checked case-insensitively against the title.
_RELEVANCE_KEYWORDS = re.compile(
    r"agent|multi.?agent|llm|large language|gpt|claude|"
    r"trust|identity|did |decentrali[sz]|verif|"
    r"bot|autonom|ai safety|ai security|"
    r"mcp|protocol|framework|langchain|autogen|crewai|"
    r"open.?claw|moltbook|marketplace|"
    r"scraping|api|sdk|developer|open.?source|"
    r"social.?network|graph|federat|fediverse",
    re.IGNORECASE,
)


def _find_digest_file() -> Path | None:
    """Find the digest history file from known paths."""
    for p in _DIGEST_PATHS:
        if p.exists():
            return p
    return None


def _is_relevant(title: str) -> bool:
    """Check if an article title is relevant to AgentAvow's domain."""
    return bool(_RELEVANCE_KEYWORDS.search(title))


def _parse_digest_history(
    limit: int = 10,
    days: int = 1,
) -> list[dict]:
    """Read recent articles from the news-digest history file.

    Supports two formats:
    1. Hash-keyed: ``{"sent_articles": {"<hash>": {"title": ..., "sent_at": ...}}}``
    2. Title-keyed: ``{"<title>": {"url": ..., "published": ..., "source": ..., "summary": ...}}``

    Args:
        limit: Max articles to return.
        days: How far back to look (1 for daily posts, 7 for weekly
              campaign planning).
    """
    digest_path = _find_digest_file()
    if not digest_path:
        logger.info("News digest history not found in any path")
        return []

    try:
        data = json.loads(digest_path.read_text())
    except (json.JSONDecodeError, OSError):
        logger.warning(
            "Failed to parse digest_history.json", exc_info=True,
        )
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    recent: list[dict] = []

    # Format 1: hash-keyed with sent_articles wrapper
    sent = data.get("sent_articles", {})
    if sent:
        for _hash, article in sent.items():
            sent_at = article.get("sent_at", "")
            try:
                ts = datetime.fromisoformat(
                    sent_at.replace("Z", "+00:00"),
                )
            except (ValueError, AttributeError):
                continue

            if ts < cutoff:
                continue

            title = article.get("title", "")
            if not _is_relevant(title):
                continue

            recent.append({
                "title": title,
                "source": article.get("source", "news-digest"),
                "url": article.get("link", ""),
                "relevance": "news_digest",
                "timestamp": ts.isoformat(),
            })

    # Format 2: title-keyed (keys are article titles, values have
    # url, published, source, summary)
    if not sent:
        for title, article in data.items():
            if not isinstance(article, dict):
                continue
            pub = article.get("published", "")
            try:
                ts = datetime.fromisoformat(
                    pub.replace("Z", "+00:00"),
                )
            except (ValueError, AttributeError):
                continue

            if ts < cutoff:
                continue

            if not _is_relevant(title):
                continue

            recent.append({
                "title": title,
                "source": article.get("source", "news-digest"),
                "url": article.get("url", ""),
                "summary": article.get("summary", ""),
                "relevance": "news_digest",
                "timestamp": ts.isoformat(),
            })

    recent.sort(key=lambda a: a["timestamp"], reverse=True)
    return recent[:limit]


async def _fetch_hn_stories(
    query: str, limit: int = 5, days: int = 3,
) -> list[dict]:
    """Fetch recent HN stories matching a query via Algolia."""
    params = {
        "query": query,
        "tags": "story",
        "numericFilters": (
            "created_at_i>"
            + str(
                int(
                    (
                        datetime.now(timezone.utc)
                        - timedelta(days=days)
                    ).timestamp(),
                ),
            )
        ),
        "hitsPerPage": limit,
    }
    try:
        async with httpx.AsyncClient(
            timeout=_HN_TIMEOUT,
        ) as client:
            resp = await client.get(
                _HN_SEARCH_URL, params=params,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        logger.warning(
            "HN Algolia query failed for %r", query, exc_info=True,
        )
        return []

    results: list[dict] = []
    for hit in data.get("hits", []):
        title = hit.get("title", "")
        url = hit.get("url") or (
            f"https://news.ycombinator.com/item?id="
            f"{hit.get('objectID', '')}"
        )
        results.append({
            "title": title,
            "source": "hackernews",
            "url": url,
            "relevance": query,
            "timestamp": hit.get(
                "created_at", "",
            ),
        })
    return results


def _deduplicate(
    signals: list[dict],
) -> list[dict]:
    """Remove near-duplicate signals by normalised title."""
    seen: set[str] = set()
    unique: list[dict] = []
    for sig in signals:
        key = sig["title"].lower().strip()[:80]
        if key and key not in seen:
            seen.add(key)
            unique.append(sig)
    return unique


async def gather_news_signals(
    limit: int = 20,
    days: int = 1,
) -> list[dict]:
    """Gather and merge news signals from all sources.

    Args:
        limit: Max signals to return.
        days: Lookback window.  Use 1 for daily proactive posts,
              7 for weekly campaign planning.

    Returns a deduplicated, relevance-filtered list sorted by
    recency, capped at *limit* items.  Each item is::

        {
            "title": str,
            "source": str,
            "url": str,
            "relevance": str,
            "summary": str | None,  # present for digest items with summaries
        }
    """
    signals: list[dict] = _parse_digest_history(
        limit=limit, days=days,
    )

    hn_days = max(days, 3)  # HN minimum 3 days for enough signal
    for query in _HN_QUERIES:
        hn = await _fetch_hn_stories(
            query, limit=5, days=hn_days,
        )
        signals.extend(hn)

    signals = _deduplicate(signals)

    # Sort by timestamp descending (missing → bottom)
    def _ts(item: dict) -> str:
        return item.get("timestamp", "")

    signals.sort(key=_ts, reverse=True)

    # Strip internal timestamp before returning
    cleaned: list[dict] = []
    for sig in signals[:limit]:
        item: dict = {
            "title": sig["title"],
            "source": sig["source"],
            "url": sig["url"],
            "relevance": sig["relevance"],
        }
        if sig.get("summary"):
            item["summary"] = sig["summary"]
        cleaned.append(item)
    return cleaned
