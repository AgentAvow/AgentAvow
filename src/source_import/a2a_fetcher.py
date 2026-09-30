"""A2A (Agent-to-Agent) agent card fetcher for source imports."""
from __future__ import annotations

import logging

import httpx

from src.source_import.errors import SourceFetchError, SourceParseError
from src.source_import.types import SourceImportResult
from src.ssrf import validate_url

logger = logging.getLogger(__name__)


def _resolve_card_url(url: str) -> str:
    """Resolve the final agent card URL.

    If the URL doesn't end with ``.json`` and doesn't already contain
    ``agent.json``, append ``/.well-known/agent.json``.
    """
    if url.endswith(".json") or "agent.json" in url:
        return url
    return url.rstrip("/") + "/.well-known/agent.json"


async def fetch_a2a(card_url: str) -> SourceImportResult:
    """Fetch an A2A agent card and return a SourceImportResult.

    The A2A spec defines agent cards at ``/.well-known/agent.json`` with
    fields: name, description, url, capabilities, version, provider.

    Accepts either a direct URL to the JSON card or a base URL where
    ``/.well-known/agent.json`` can be appended.

    Args:
        card_url: URL to the A2A agent card (or base URL of the agent).

    Returns:
        Populated SourceImportResult with source_type ``a2a_card``.

    Raises:
        SourceFetchError: If the card cannot be fetched.
        SourceParseError: If the response is not a valid A2A agent card.
    """
    resolved_url = _resolve_card_url(card_url)

    # SSRF protection — reject private/internal IPs
    try:
        validate_url(resolved_url, field_name="card_url")
    except ValueError as exc:
        raise SourceFetchError(str(exc)) from exc

    from src.ssrf import ssrf_safe_async_client

    try:
        async with ssrf_safe_async_client(timeout=10, follow_redirects=False) as client:
            resp = await client.get(resolved_url)
    except (httpx.HTTPError, ValueError) as exc:
        raise SourceFetchError(
            f"Failed to fetch A2A agent card: {exc}"
        ) from exc

    if resp.status_code != 200:
        raise SourceFetchError(
            f"Failed to fetch A2A agent card: HTTP {resp.status_code}"
        )

    try:
        data = resp.json()
    except Exception as exc:
        raise SourceParseError(
            "A2A agent card URL did not return valid JSON"
        ) from exc

    if not isinstance(data, dict):
        raise SourceParseError("A2A agent card must be a JSON object")

    name = data.get("name")
    if not name:
        raise SourceParseError("A2A agent card must contain a 'name' field")

    description = data.get("description") or ""

    # Extract capability names from the capabilities array
    raw_caps = data.get("capabilities", [])
    capabilities: list[str] = []
    if isinstance(raw_caps, list):
        for cap in raw_caps:
            if isinstance(cap, str):
                capabilities.append(cap)
            elif isinstance(cap, dict):
                cap_name = cap.get("name", "")
                if cap_name:
                    capabilities.append(str(cap_name))
    capabilities = capabilities[:20]

    return SourceImportResult(
        source_type="a2a_card",
        source_url=card_url,
        display_name=str(name),
        bio=description,
        capabilities=capabilities,
        detected_framework="a2a",
        community_signals={"provider": data.get("provider", {})},
        raw_metadata=data,
        avatar_url=data.get("avatar_url") or data.get("iconUrl"),
        version=data.get("version"),
    )
