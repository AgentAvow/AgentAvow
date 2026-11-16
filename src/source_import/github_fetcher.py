"""GitHub repository metadata fetcher for source imports."""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.http import FetchClient, fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds, per attempt
# Budget for the whole fetch (repo, README, four dependency files), retries included.
_TOTAL_DEADLINE = 45.0

# Framework detection: dependency string → framework name
_FRAMEWORK_PATTERNS: list[tuple[str, str]] = [
    ("langchain", "langchain"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
    ("@modelcontextprotocol", "mcp"),
    ("mcp", "mcp"),
    ("anthropic", "anthropic"),
    ("openai", "native"),
]

# Dependency files to fetch for framework detection
_DEP_FILES = ["requirements.txt", "pyproject.toml", "setup.py", "package.json"]


class SourceFetchError(Exception):
    """Error fetching data from a source."""


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner/repo from a GitHub URL.

    Handles formats:
      - https://github.com/owner/repo
      - https://github.com/owner/repo/
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/tree/main/subdir
      - https://github.com/owner/repo/blob/main/file.py
      - git@github.com:owner/repo.git
    """
    url = url.strip().rstrip("/")

    # SSH format: git@github.com:owner/repo.git
    ssh_match = re.match(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    # HTTP(S) format
    match = re.match(
        r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
        url,
    )
    if match:
        return match.group(1), match.group(2)

    raise SourceFetchError(f"Cannot parse GitHub owner/repo from URL: {url}")


async def fetch_github(owner: str, repo: str, url: str) -> SourceImportResult:
    """Fetch GitHub repo metadata and return a SourceImportResult.

    Uses GITHUB_TOKEN from settings for authenticated requests (5000 req/hr)
    when available, otherwise falls back to unauthenticated (60 req/hr).

    Raises:
        SourceFetchError: If the repository is not found, rate-limited,
            or a network error occurs.
    """
    from src.github_auth import get_github_token

    api_base = f"https://api.github.com/repos/{owner}/{repo}"
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}

    token = await get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with fetch_client(total=_TOTAL_DEADLINE, attempt_timeout=_TIMEOUT) as client:
            # 1. Fetch repo metadata
            repo_resp = await client.get(api_base, headers=headers)

            if repo_resp.status_code == 404:
                raise SourceFetchError(
                    f"GitHub repository not found: {owner}/{repo}"
                )
            if repo_resp.status_code == 403:
                remaining = repo_resp.headers.get("x-ratelimit-remaining", "?")
                raise SourceFetchError(
                    f"GitHub API rate limit exceeded (remaining: {remaining}). "
                    "Set GITHUB_TOKEN for higher limits."
                )
            if repo_resp.status_code != 200:
                raise SourceFetchError(
                    f"GitHub API error {repo_resp.status_code} for {owner}/{repo}"
                )

            repo_data = repo_resp.json()

            # 2. Fetch README (raw)
            readme_text = ""
            readme_resp = await client.get(
                f"{api_base}/readme",
                headers={**headers, "Accept": "application/vnd.github.raw"},
            )
            if readme_resp.status_code == 200:
                readme_text = readme_resp.text

            # 3. Fetch dependency files for framework detection
            dep_files = await _fetch_dependency_files(client, api_base, headers)
            dep_contents = "\n".join(dep_files.values())

    except SourceFetchError:
        raise
    except httpx.TimeoutException:
        raise SourceFetchError(
            f"Timeout fetching GitHub repo {owner}/{repo} (>{_TIMEOUT}s)"
        )
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Network error fetching GitHub repo {owner}/{repo}: {exc}"
        )

    # Extract capabilities from README, fallback to topics
    topics = repo_data.get("topics", [])
    capabilities = _extract_capabilities(readme_text)
    if not capabilities and topics:
        capabilities = topics[:10]

    # Detect framework from dependencies
    detected_framework = _detect_framework(dep_contents)

    # Bio: repo description, fallback to first paragraph of README
    bio = repo_data.get("description") or ""
    if not bio and readme_text:
        bio = _first_paragraph(readme_text)

    # Community signals
    owner_data = repo_data.get("owner", {})
    community_signals = {
        "stars": repo_data.get("stargazers_count", 0),
        "forks": repo_data.get("forks_count", 0),
        "watchers": repo_data.get("subscribers_count", 0),
        "open_issues": repo_data.get("open_issues_count", 0),
        "language": repo_data.get("language"),
    }

    return SourceImportResult(
        source_type="github",
        source_url=url,
        display_name=repo_data.get("full_name", f"{owner}/{repo}"),
        bio=bio,
        capabilities=capabilities,
        detected_framework=detected_framework,
        community_signals=community_signals,
        raw_metadata={
            "owner": owner,
            "repo": repo,
            "default_branch": repo_data.get("default_branch"),
            "license": (repo_data.get("license") or {}).get("spdx_id"),
            "created_at": repo_data.get("created_at"),
            "updated_at": repo_data.get("updated_at"),
            "topics": topics,
            "dep_files": dep_files,
        },
        readme_excerpt=readme_text[:2000],
        avatar_url=owner_data.get("avatar_url"),
        version=None,
    )


async def _fetch_dependency_files(
    client: FetchClient,
    api_base: str,
    headers: dict[str, str],
) -> dict[str, str]:
    """Fetch common dependency files and return a filename→content dict."""
    files: dict[str, str] = {}

    for fname in _DEP_FILES:
        resp = await client.get(
            f"{api_base}/contents/{fname}",
            headers={**headers, "Accept": "application/vnd.github.raw"},
        )
        if resp.status_code == 200:
            files[fname] = resp.text

    return files


def _extract_capabilities(readme: str) -> list[str]:
    """Extract capability bullet points from README sections.

    Looks for ## Features, ## Capabilities, ## What it does, etc.
    Returns up to 10 items.
    """
    capabilities: list[str] = []
    if not readme:
        return capabilities

    section_pattern = re.compile(
        r"##\s*(?:Features|Capabilities|What it does)\s*\n(.*?)(?=\n##|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    match = section_pattern.search(readme)
    if match:
        section_text = match.group(1)
        for line in section_text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("- ", "* ", "• ")):
                # Remove the bullet prefix
                cap = stripped.lstrip("-*• ").strip()
                if cap:
                    capabilities.append(cap)

    return capabilities[:10]


def _first_paragraph(readme: str) -> str:
    """Extract the first real paragraph from a README, truncated to 500 chars.

    Skips headings, badges, and blank lines at the top.
    """
    lines: list[str] = []
    in_paragraph = False

    for line in readme.splitlines():
        stripped = line.strip()

        # Skip headings and badge lines
        if stripped.startswith("#") or stripped.startswith("![") or stripped.startswith("[!"):
            if in_paragraph:
                break
            continue

        # Skip blank lines before paragraph starts
        if not stripped:
            if in_paragraph:
                break
            continue

        in_paragraph = True
        lines.append(stripped)

    text = " ".join(lines)
    return text[:500]


def _detect_framework(dep_contents: str) -> str | None:
    """Detect the primary agent framework from dependency file contents."""
    if not dep_contents:
        return None
    lower = dep_contents.lower()
    for pattern, framework in _FRAMEWORK_PATTERNS:
        if pattern in lower:
            return framework
    return None
