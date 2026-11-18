"""npm package metadata fetcher for source imports."""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.http import fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# Budget for the whole fetch (registry metadata + download count), retries included.
_TOTAL_DEADLINE = 25.0

# Framework detection: dependency name substring → framework label
_FRAMEWORK_PATTERNS: list[tuple[str, str]] = [
    ("langchain", "langchain"),
    ("@modelcontextprotocol", "mcp"),
    ("openai", "openai"),
    ("@anthropic-ai", "anthropic"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
]

# URL pattern: handles scoped (@org/name) and unscoped packages
_NPM_URL_RE = re.compile(
    r"https?://(?:www\.)?npmjs\.com/package/(?P<name>(?:@[^/]+/)?[^/?#]+)"
)


def parse_npm_url(url: str) -> str:
    """Extract package name from an npmjs.com URL.

    Handles scoped packages like ``@modelcontextprotocol/sdk``.

    Raises:
        SourceParseError: If the URL does not match the expected format.
    """
    match = _NPM_URL_RE.search(url)
    if not match:
        raise SourceParseError(f"Cannot parse npm package name from URL: {url}")
    return match.group("name")


async def fetch_npm(package_name: str, url: str) -> SourceImportResult:
    """Fetch npm package metadata and return a SourceImportResult.

    Args:
        package_name: The npm package name (e.g. ``@modelcontextprotocol/sdk``).
        url: The original URL provided by the user.

    Raises:
        SourceFetchError: If the package is not found or a network error occurs.
    """
    try:
        async with fetch_client(total=_TOTAL_DEADLINE, attempt_timeout=10) as client:
            # Registry metadata
            reg_resp = await client.get(
                f"https://registry.npmjs.org/{package_name}"
            )
            if reg_resp.status_code == 404:
                raise SourceFetchError(f"Package not found: {package_name}")
            if reg_resp.status_code != 200:
                raise SourceFetchError(
                    f"npm registry returned status {reg_resp.status_code} "
                    f"for {package_name}"
                )
            package_data = reg_resp.json()

            # Download counts (best-effort)
            downloads_monthly = 0
            try:
                dl_resp = await client.get(
                    f"https://api.npmjs.org/downloads/point/last-month/"
                    f"{package_name}"
                )
                if dl_resp.status_code == 200:
                    downloads_monthly = dl_resp.json().get("downloads", 0)
            except Exception:
                logger.debug(
                    "Failed to fetch npm download stats for %s", package_name
                )
    except SourceFetchError:
        raise
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Network error fetching npm package {package_name}: {exc}"
        ) from exc

    # Extract latest version info
    latest_tag = package_data.get("dist-tags", {}).get("latest")
    versions = package_data.get("versions", {})
    latest_data = versions.get(latest_tag, {}) if latest_tag else {}

    keywords = package_data.get("keywords", []) or []
    description = package_data.get("description", "") or ""
    maintainers = package_data.get("maintainers", [])

    # Map keywords to capabilities
    capabilities = [kw for kw in keywords if kw][:20]

    # Detect framework from latest version dependencies
    all_deps = {
        **latest_data.get("dependencies", {}),
        **latest_data.get("devDependencies", {}),
    }
    detected_framework = _detect_framework(all_deps)

    community_signals = {
        "downloads_monthly": downloads_monthly,
        "maintainers": len(maintainers),
        "keywords": keywords,
    }

    return SourceImportResult(
        source_type="npm",
        source_url=url,
        display_name=package_data.get("name", package_name),
        bio=description,
        capabilities=capabilities,
        detected_framework=detected_framework,
        community_signals=community_signals,
        raw_metadata={
            "latest_version": latest_tag,
            "license": latest_data.get("license"),
            "homepage": package_data.get("homepage"),
            "repository": package_data.get("repository"),
            "maintainers": [
                m.get("name") or m.get("email") for m in maintainers
            ],
        },
        version=latest_tag,
    )


def _detect_framework(deps: dict) -> str | None:
    """Detect framework from npm dependency names."""
    if not deps:
        return None
    dep_str = " ".join(deps.keys()).lower()
    for pattern, framework in _FRAMEWORK_PATTERNS:
        if pattern in dep_str:
            return framework
    return None
