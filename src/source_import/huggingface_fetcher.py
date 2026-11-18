"""HuggingFace model metadata fetcher for source imports."""
from __future__ import annotations

import logging
import re

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.http import fetch_client
from src.source_import.types import SourceImportResult

logger = logging.getLogger(__name__)

# Budget for the whole Hugging Face fetch, retries included.
_TOTAL_DEADLINE = 20.0

_HF_URL_RE = re.compile(
    r"https?://huggingface\.co/(?P<org>[^/]+)/(?P<model>[^/?#]+)"
)


def parse_huggingface_url(url: str) -> str:
    """Extract ``org/model`` identifier from a HuggingFace URL.

    Raises:
        SourceParseError: If the URL does not match the expected format.
    """
    match = _HF_URL_RE.search(url)
    if not match:
        raise SourceParseError(
            f"Cannot parse HuggingFace model ID from URL: {url}"
        )
    return f"{match.group('org')}/{match.group('model')}"


async def fetch_huggingface(model_id: str, url: str) -> SourceImportResult:
    """Fetch HuggingFace model metadata and return a SourceImportResult.

    Args:
        model_id: The model identifier in ``org/model`` format.
        url: The original URL provided by the user.

    Raises:
        SourceFetchError: If the model is not found or a network error occurs.
    """
    try:
        async with fetch_client(total=_TOTAL_DEADLINE, attempt_timeout=10) as client:
            resp = await client.get(
                f"https://huggingface.co/api/models/{model_id}"
            )
            if resp.status_code == 404:
                raise SourceFetchError(f"Model not found: {model_id}")
            if resp.status_code != 200:
                raise SourceFetchError(
                    f"HuggingFace API returned status {resp.status_code} "
                    f"for {model_id}"
                )
            model_data = resp.json()
    except SourceFetchError:
        raise
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Network error fetching HuggingFace model {model_id}: {exc}"
        ) from exc

    pipeline_tag = model_data.get("pipeline_tag", "") or ""
    tags = model_data.get("tags", []) or []
    card_data = model_data.get("cardData", {}) or {}

    # Primary capability from pipeline_tag (human-readable)
    capabilities: list[str] = []
    if pipeline_tag:
        capabilities.append(pipeline_tag.replace("-", " "))

    # Additional capabilities from tags
    for tag in tags[:15]:
        normalised = tag.replace("-", " ")
        if normalised not in capabilities:
            capabilities.append(normalised)
    capabilities = capabilities[:20]

    # Bio from cardData description/summary, fallback to model ID
    bio = ""
    if isinstance(card_data, dict):
        bio = (
            card_data.get("description", "")
            or card_data.get("summary", "")
            or ""
        )
    if not bio:
        bio = f"HuggingFace model: {model_id}"

    # Derive org from model_id for avatar URL
    org = model_id.split("/")[0] if "/" in model_id else model_id
    avatar_url = f"https://huggingface.co/{org}/avatar"

    community_signals = {
        "downloads": model_data.get("downloads", 0),
        "likes": model_data.get("likes", 0),
        "pipeline_tag": pipeline_tag,
        "tags": tags,
    }

    return SourceImportResult(
        source_type="huggingface",
        source_url=url,
        display_name=model_data.get("modelId", model_id),
        bio=bio,
        capabilities=capabilities,
        detected_framework=None,
        community_signals=community_signals,
        raw_metadata={
            "pipeline_tag": pipeline_tag,
            "library_name": model_data.get("library_name"),
            "tags": tags,
            "sha": model_data.get("sha"),
            "created_at": model_data.get("createdAt"),
            "last_modified": model_data.get("lastModified"),
        },
        avatar_url=avatar_url,
        version=model_data.get("sha"),
    )
