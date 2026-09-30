"""Moltbook profile fetcher for source imports.

Moltbook is a competitor platform with known security issues.
Profiles imported from Moltbook receive a trust penalty modifier.
"""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# Trust modifier applied to Moltbook-sourced agents due to platform
# security track record (35K emails + 1.5M API tokens leaked).
_MOLTBOOK_TRUST_MODIFIER = 0.65


async def fetch_moltbook(profile_url: str) -> SourceImportResult:
    """Fetch basic data from a Moltbook profile URL.

    This is a thin scraper that extracts name and bio from the HTML
    page. No official API is used.

    Raises:
        ValueError: If the profile cannot be fetched.
    """
    from src.ssrf import ssrf_safe_async_client, ssrf_safe_follow

    # The URL comes from the caller: pin it, and validate each redirect hop.
    async with ssrf_safe_async_client(timeout=10, follow_redirects=False) as client:
        try:
            resp, _ = await ssrf_safe_follow(client, "GET", profile_url)
        except httpx.HTTPError as exc:
            raise ValueError("Failed to fetch Moltbook profile") from exc
        if resp.status_code != 200:
            raise ValueError(
                f"Failed to fetch Moltbook profile: HTTP {resp.status_code}"
            )

    html = resp.text

    # Extract name from <title> or og:title
    name = _extract_meta(html, "og:title") or _extract_title(html) or "Unknown Agent"

    # Extract bio from og:description or meta description
    bio = (
        _extract_meta(html, "og:description")
        or _extract_meta_name(html, "description")
        or ""
    )

    # Extract avatar from og:image
    avatar_url = _extract_meta(html, "og:image") or None

    return SourceImportResult(
        source_type="moltbook",
        source_url=profile_url,
        display_name=name,
        bio=bio,
        capabilities=[],
        detected_framework=None,
        community_signals={},
        raw_metadata={
            "moltbook_trust_modifier": _MOLTBOOK_TRUST_MODIFIER,
            "import_warning": (
                "Moltbook has known security vulnerabilities. "
                "Agent identity cannot be independently verified."
            ),
        },
        avatar_url=avatar_url,
    )


def _extract_meta(html: str, property_name: str) -> str:
    """Extract content from <meta property="..." content="...">."""
    pattern = re.compile(
        rf'<meta\s+[^>]*property=["\']?{re.escape(property_name)}["\']?'
        rf'\s+[^>]*content=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if match:
        return match.group(1).strip()

    # Try reversed attribute order
    pattern2 = re.compile(
        rf'<meta\s+[^>]*content=["\']([^"\']*)["\']'
        rf'\s+[^>]*property=["\']?{re.escape(property_name)}["\']?',
        re.IGNORECASE,
    )
    match2 = pattern2.search(html)
    if match2:
        return match2.group(1).strip()

    return ""


def _extract_meta_name(html: str, name: str) -> str:
    """Extract content from <meta name="..." content="...">."""
    pattern = re.compile(
        rf'<meta\s+[^>]*name=["\']?{re.escape(name)}["\']?'
        rf'\s+[^>]*content=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if match:
        return match.group(1).strip()
    return ""


def _extract_title(html: str) -> str:
    """Extract text from <title> tag."""
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""
