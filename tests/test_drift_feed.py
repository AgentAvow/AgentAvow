"""Tests for the recompute-on-release drift feed (ScanHistory + _drift_payload)."""
from __future__ import annotations

import pytest

from src.api.preflight_router import _drift_payload
from src.models import ScanHistory


async def _seed(db, full_name: str, points: list[dict]) -> None:
    for p in points:
        db.add(ScanHistory(
            surface="github", owner="acme", repo="tool", full_name=full_name,
            trust_score=p["score"], grade=p.get("grade", "A"),
            certified=p.get("certified", False),
            critical=p.get("critical", 0), high=p.get("high", 0),
            tool_manifest_digest=p.get("digest"),
            score_delta=p.get("delta"), manifest_drift=p.get("drift", False),
        ))
    await db.flush()


@pytest.mark.asyncio
async def test_drift_payload_builds_signed_timeline(db):
    await _seed(db, "acme/tool", [
        {"score": 88, "digest": "d1"},
        {"score": 40, "digest": "d2", "delta": -48, "drift": True},
    ])
    out = await _drift_payload("acme/tool", "github:acme/tool", db)
    assert out["full_name"] == "acme/tool"
    assert out["current_score"] in (88, 40)          # newest first (order by time desc)
    assert out["summary"]["points"] == 2
    assert out["summary"]["drift_events"] >= 1        # the -48 / manifest drift point
    assert out["signed"]["jws"].count(".") == 2       # compact JWS header.payload.sig
    assert out["signed"]["kid"] == "agentgraph-security-v1"


@pytest.mark.asyncio
async def test_drift_payload_404_when_no_history(db):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        await _drift_payload("nobody/here", "github:nobody/here", db)
    assert ei.value.status_code == 404
