"""Docker Hub repository metadata fetcher for source imports."""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.http import fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# Budget for the whole Docker Hub fetch, retries included.
_TOTAL_DEADLINE = 20.0

# URL patterns: hub.docker.com/r/{namespace}/{name} and hub.docker.com/_/{name} (official)
_DOCKER_URL_RE = re.compile(
    r"https?://hub\.docker\.com/(?:r/(?P<ns>[^/]+)/(?P<name>[^/?#]+)"
    r"|_/(?P<official>[^/?#]+))"
)


def parse_docker_url(url: str) -> tuple[str, str]:
    """Extract namespace/name from a Docker Hub URL.

    Returns (namespace, name). Official images use "library" as namespace.

    Raises:
        SourceParseError: If the URL does not match the expected format.
    """
    match = _DOCKER_URL_RE.search(url)
    if not match:
        raise SourceParseError(f"Cannot parse Docker Hub repo from URL: {url}")
    if match.group("official"):
        return "library", match.group("official")
    return match.group("ns"), match.group("name")


async def fetch_docker(namespace: str, name: str, url: str) -> SourceImportResult:
    """Fetch Docker Hub repository metadata and return a SourceImportResult.

    Args:
        namespace: Docker Hub namespace (or "library" for official images).
        name: Repository name.
        url: The original URL provided by the user.

    Raises:
        SourceFetchError: If the repository is not found or a network error occurs.
    """
    try:
        async with fetch_client(total=_TOTAL_DEADLINE, attempt_timeout=10) as client:
            resp = await client.get(
                f"https://hub.docker.com/v2/repositories/{namespace}/{name}"
            )
            if resp.status_code == 404:
                raise SourceFetchError(
                    f"Docker Hub repository not found: {namespace}/{name}"
                )
            if resp.status_code != 200:
                raise SourceFetchError(
                    f"Docker Hub API returned status {resp.status_code} "
                    f"for {namespace}/{name}"
                )
            data = resp.json()
    except SourceFetchError:
        raise
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Network error fetching Docker Hub repo {namespace}/{name}: {exc}"
        ) from exc

    pull_count = data.get("pull_count", 0)
    star_count = data.get("star_count", 0)
    description = data.get("description", "") or ""
    full_description = data.get("full_description", "") or ""
    is_official = namespace == "library"

    community_signals = {
        "pulls": pull_count,
        "stars": star_count,
    }

    return SourceImportResult(
        source_type="docker",
        source_url=url,
        display_name=f"{namespace}/{name}" if not is_official else name,
        bio=description,
        capabilities=[],
        detected_framework=None,
        community_signals=community_signals,
        raw_metadata={
            "namespace": namespace,
            "name": name,
            "is_official": is_official,
            "last_updated": data.get("last_updated"),
            "pull_count": pull_count,
            "star_count": star_count,
        },
        readme_excerpt=full_description[:2000],
        avatar_url=None,
        version=None,
    )
