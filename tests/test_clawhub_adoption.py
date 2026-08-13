"""ClawHub (OpenClaw skill registry) adoption collector — owner-matched, fail-open."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scanner.adoption_sources import fetch_clawhub_stats


def _client(payload: dict, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


_SEARCH = {
    "results": [
        {"slug": "github", "ownerHandle": "steipete",
         "sourceIdentity": {"owner": "steipete", "repo": None},
         "stats": {"installs": 7625, "downloads": 195389, "stars": 662},
         "metrics": {"rolling60DayInstalls": 87}, "downloads": 195389},
        {"slug": "github", "ownerHandle": "someoneelse",
         "sourceIdentity": {"owner": "someoneelse"},
         "stats": {"installs": 3, "downloads": 5, "stars": 0},
         "metrics": {"rolling60DayInstalls": 0}, "downloads": 5},
    ]
}


@pytest.mark.asyncio
async def test_matches_the_right_owner():
    with patch("httpx.AsyncClient", return_value=_client(_SEARCH)):
        got = await fetch_clawhub_stats("steipete", "github")
    assert got is not None
    assert got["installs"] == 7625
    assert got["stars"] == 662
    assert got["trend_60d_installs"] == 87
    assert got["source"] == "clawhub"


@pytest.mark.asyncio
async def test_never_returns_a_different_owners_skill():
    # 'github' skill exists on ClawHub, but not for owner 'acme' → no fabricated number.
    with patch("httpx.AsyncClient", return_value=_client(_SEARCH)):
        assert await fetch_clawhub_stats("acme", "github") is None


@pytest.mark.asyncio
async def test_search_top_level_downloads_when_stats_absent():
    payload = {"results": [
        {"ownerHandle": "acme", "sourceIdentity": {"owner": "acme"},
         "stats": None, "metrics": {"rolling60DayInstalls": 4}, "downloads": 42},
    ]}
    with patch("httpx.AsyncClient", return_value=_client(payload)):
        got = await fetch_clawhub_stats("acme", "thing")
    assert got["downloads"] == 42
    assert got["installs"] == 0
    assert got["trend_60d_installs"] == 4


@pytest.mark.asyncio
async def test_fail_open_on_non_200():
    with patch("httpx.AsyncClient", return_value=_client({}, status=503)):
        assert await fetch_clawhub_stats("steipete", "github") is None


@pytest.mark.asyncio
async def test_blank_coordinate_short_circuits():
    assert await fetch_clawhub_stats("", "github") is None
    assert await fetch_clawhub_stats("steipete", "") is None
