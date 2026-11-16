"""PyPI package metadata fetcher for source imports."""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.http import fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# Budget for the whole PyPI fetch, retries included.
_TOTAL_DEADLINE = 20.0

_FRAMEWORK_PATTERNS: list[tuple[str, str]] = [
    ("langchain", "langchain"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("mcp", "mcp"),
]

# Classifier topic fragments → short capability labels
_CLASSIFIER_CAPABILITY_MAP: list[tuple[str, str]] = [
    ("Artificial Intelligence", "ai"),
    ("Machine Learning", "ml"),
    ("Natural Language", "nlp"),
    ("Neural Networks", "neural-networks"),
    ("Deep Learning", "deep-learning"),
    ("Computer Vision", "computer-vision"),
    ("Data Science", "data-science"),
    ("Internet :: WWW/HTTP", "web"),
    ("Databases", "databases"),
    ("Security", "security"),
]

_PYPI_URL_RE = re.compile(
    r"https?://pypi\.org/project/(?P<name>[^/?#]+)"
)


def parse_pypi_url(url: str) -> str:
    """Extract package name from a pypi.org URL.

    Raises:
        SourceParseError: If the URL does not match the expected format.
    """
    match = _PYPI_URL_RE.search(url)
    if not match:
        raise SourceParseError(f"Cannot parse PyPI package name from URL: {url}")
    # Strip trailing slash that pypi URLs often have
    return match.group("name").rstrip("/")


async def fetch_pypi(package_name: str, url: str) -> SourceImportResult:
    """Fetch PyPI package metadata and return a SourceImportResult.

    Args:
        package_name: The PyPI package name (e.g. ``langchain``).
        url: The original URL provided by the user.

    Raises:
        SourceFetchError: If the package is not found or a network error occurs.
    """
    try:
        async with fetch_client(total=_TOTAL_DEADLINE, attempt_timeout=10) as client:
            resp = await client.get(
                f"https://pypi.org/pypi/{package_name}/json"
            )
            if resp.status_code == 404:
                raise SourceFetchError(f"Package not found: {package_name}")
            if resp.status_code != 200:
                raise SourceFetchError(
                    f"PyPI returned status {resp.status_code} for {package_name}"
                )
            package_data = resp.json()
    except SourceFetchError:
        raise
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Network error fetching PyPI package {package_name}: {exc}"
        ) from exc

    info = package_data.get("info", {})
    classifiers = info.get("classifiers", []) or []
    requires_dist = info.get("requires_dist", []) or []
    project_urls = info.get("project_urls") or {}

    # Capabilities from classifiers
    capabilities = _classifiers_to_capabilities(classifiers)

    # Detect framework from requires_dist
    detected_framework = _detect_framework(requires_dist)

    # Bio = summary
    bio = info.get("summary", "") or ""

    # Readme excerpt from the long description
    description_body = info.get("description", "") or ""
    readme_excerpt = description_body[:2000] if description_body else ""

    # Try to find an avatar/logo URL from project_urls
    avatar_url = _extract_avatar_url(project_urls)

    community_signals = {
        "classifiers": classifiers,
        "requires_python": info.get("requires_python"),
        "author": info.get("author") or info.get("author_email"),
    }

    return SourceImportResult(
        source_type="pypi",
        source_url=url,
        display_name=info.get("name", package_name),
        bio=bio,
        capabilities=capabilities,
        detected_framework=detected_framework,
        community_signals=community_signals,
        raw_metadata={
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "license": info.get("license"),
            "home_page": info.get("home_page"),
            "project_urls": project_urls,
            "python_requires": info.get("requires_python"),
        },
        readme_excerpt=readme_excerpt,
        avatar_url=avatar_url,
        version=info.get("version"),
    )


def _classifiers_to_capabilities(classifiers: list[str]) -> list[str]:
    """Extract meaningful capability labels from PyPI classifiers."""
    capabilities: list[str] = []
    for classifier in classifiers:
        for fragment, label in _CLASSIFIER_CAPABILITY_MAP:
            if fragment in classifier and label not in capabilities:
                capabilities.append(label)
    # Also keep raw Topic leaf nodes for extra detail
    for classifier in classifiers:
        if classifier.startswith("Topic ::"):
            parts = classifier.split(" :: ")
            if len(parts) >= 3:
                leaf = parts[-1]
                if leaf not in capabilities:
                    capabilities.append(leaf)
    return capabilities[:20]


def _detect_framework(requires_dist: list[str]) -> str | None:
    """Detect framework from requires_dist entries."""
    if not requires_dist:
        return None
    joined = " ".join(requires_dist).lower()
    for pattern, framework in _FRAMEWORK_PATTERNS:
        if pattern in joined:
            return framework
    return None


def _extract_avatar_url(project_urls: dict) -> str | None:
    """Try to find an avatar or logo URL from project_urls."""
    if not project_urls:
        return None
    # Check common keys that might hold a logo/avatar
    for key in ("Avatar", "Logo", "avatar", "logo"):
        if key in project_urls:
            return project_urls[key]
    return None
