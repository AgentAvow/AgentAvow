"""The cache-only /public/scan/{owner}/{repo}/collection endpoint the Check page
asks before requesting a full repo scan."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from src.api import public_scan_router as psr

_COLL = {
    "trust_score": 67,
    "surface_detail": {"collection": True, "worst_skill": "skill-creator", "skills_total": 19,
                       "skills": [{}] * 19},
    "findings": {"critical": 0, "high": 1, "items": []},
}


@pytest.mark.asyncio
async def test_known_collection_returns_summary():
    with patch.object(psr, "_skill_collection_data", AsyncMock(return_value=_COLL)):
        out = await psr.scan_skill_collection("anthropics", "skills")
    assert out["trust_score"] == 67
    assert out["worst_skill"] == "skill-creator"
    assert out["report_url"].endswith("/check/skill/anthropics/skills")


@pytest.mark.asyncio
async def test_unknown_repo_is_404_and_never_scans():
    lookup = AsyncMock(return_value=None)
    with patch.object(psr, "_skill_collection_data", lookup), \
            patch.object(psr, "scan_repo", AsyncMock(side_effect=AssertionError("scanned")),
                         create=True):
        with pytest.raises(HTTPException) as e:
            await psr.scan_skill_collection("vercel", "next.js")
    assert e.value.status_code == 404
    lookup.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("owner,repo", [("a b", "x"), ("o", "../etc"), ("", "x")])
async def test_bad_names_are_404_without_lookup(owner, repo):
    lookup = AsyncMock(return_value=_COLL)
    with patch.object(psr, "_skill_collection_data", lookup):
        with pytest.raises(HTTPException) as e:
            await psr.scan_skill_collection(owner, repo)
    assert e.value.status_code == 404
    lookup.assert_not_awaited()
