"""crates.io fetcher for Rust agent packages.

crates.io is the canonical Rust package registry. Newly relevant to
AgentGraph's scan corpus via the Vauban (serde_jcs) substrate work + the
growing Rust agent ecosystem. Added to the Q3 2026 scan corpus per
docs/internal/execution-plan-rebalance.md week of Jun 22 (#111).

Scaffold: URL parsing + fetch contract matching the huggingface_fetcher
pattern. crates.io's API is well-documented and stable (https://crates.io/api/v1).

Discovery query for batch scan: filter by keywords like "agent", "mcp",
"a2a", "llm", "ai-agent" plus the canonical agent-framework crates we
know of (e.g. tcp, rig, etc.) — implemented in the discovery query when
batch scan kicks off.
"""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.http import fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# URL forms:
#   https://crates.io/crates/<name>
#   https://crates.io/crates/<name>/<version>
_CRATES_URL_RE = re.compile(
    r"https?://crates\.io/crates/(?P<name>[A-Za-z0-9_-]+)",
)

_REQUEST_TIMEOUT = 15.0
# Budget for the whole fetch, retries included.
_TOTAL_DEADLINE = 25.0


def parse_crates_url(url: str) -> str:
    """Extract crate name from a crates.io URL.

    Raises:
        SourceParseError: if the URL does not match the expected shape.
    """
    match = _CRATES_URL_RE.search(url)
    if not match:
        raise SourceParseError(
            f"Cannot parse crate name from URL: {url}",
        )
    return match.group("name")


async def fetch_crates(crate_name: str, url: str) -> SourceImportResult:
    """Fetch crates.io package metadata and return a SourceImportResult.

    Args:
        crate_name: identifier returned by ``parse_crates_url``.
        url: original URL provided by the caller (preserved as ``source_url``).

    Raises:
        SourceFetchError: if crates.io returns non-200.
    """
    api_url = f"https://crates.io/api/v1/crates/{crate_name}"
    try:
        async with fetch_client(
            total=_TOTAL_DEADLINE, attempt_timeout=_REQUEST_TIMEOUT,
        ) as client:
            resp = await client.get(
                api_url,
                headers={
                    "Accept": "application/json",
                    # crates.io requires a User-Agent per their crawl policy
                    "User-Agent": "agentgraph.co scanner (kenne@agentgraph.co)",
                },
            )
    except httpx.RequestError as exc:
        raise SourceFetchError(f"crates.io fetch failed: {exc}") from exc

    if resp.status_code != 200:
        raise SourceFetchError(
            f"crates.io returned HTTP {resp.status_code} for {crate_name}",
        )

    data = resp.json()
    crate = data.get("crate", {})
    versions = data.get("versions", [])
    latest = versions[0] if versions else {}

    display_name = crate.get("name") or crate_name
    bio = crate.get("description") or ""
    keywords = crate.get("keywords") or []
    categories = crate.get("categories") or []

    return SourceImportResult(
        source_type="crates",
        source_url=url,
        display_name=display_name,
        bio=bio,
        capabilities=keywords,  # crate keywords are the closest thing to capabilities
        detected_framework=None,  # framework detection lives in the scanner pass
        community_signals={
            "crates_downloads": crate.get("downloads", 0),
            "crates_recent_downloads": crate.get("recent_downloads", 0),
            "crates_categories": categories,
        },
        raw_metadata={"crate": crate, "latest_version": latest},
        readme_excerpt="",  # crates.io README requires a separate API call; skip for scaffold
        version=latest.get("num"),
    )
