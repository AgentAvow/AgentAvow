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


async def _seed_at(db, full_name: str, points: list[dict]) -> None:
    from datetime import datetime, timedelta, timezone
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    for i, p in enumerate(points):
        db.add(ScanHistory(
            surface="mcp", owner="mcp", repo="x", full_name=full_name,
            trust_score=p["score"], tool_manifest_digest=p.get("digest"),
            tool_digests=p.get("tools"), manifest_drift=p.get("drift", False),
            scanned_at=t0 + timedelta(days=i),
        ))
    await db.flush()


@pytest.mark.asyncio
async def test_drift_points_say_which_tools_changed(db):
    await _seed_at(db, "mcp:https://x.example/mcp", [
        {"score": 88, "digest": "aaa", "tools": {"read": "1", "list": "2"}},
        {"score": 88, "digest": "bbb", "drift": True,
         "tools": {"read": "1", "list": "9", "delete_all": "3"}},
    ])
    out = await _drift_payload("mcp:https://x.example/mcp", "mcp:https://x.example/mcp", db)
    newest, oldest = out["history"]
    assert newest["tool_manifest_digest"] == "bbb"
    assert newest["tool_changes"] == {"added": ["delete_all"], "removed": [], "changed": ["list"]}
    assert oldest["tool_changes"] is None            # nothing older to compare with
    # The signed payload keeps its shape: no per-tool detail inside it.
    import base64
    import json
    body = out["signed"]["jws"].split(".")[1]
    signed = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert set(signed["history"][0]) == {"scannedAt", "trustScore", "scoreDelta", "manifestDrift"}


@pytest.mark.asyncio
async def test_points_from_before_per_tool_digests_show_no_detail(db):
    await _seed_at(db, "acme/old", [
        {"score": 80, "digest": "aaa"},                      # written before t33
        {"score": 80, "digest": "bbb", "drift": True, "tools": {"a": "1"}},
    ])
    out = await _drift_payload("acme/old", "github:acme/old", db)
    assert out["history"][0]["tool_changes"] is None


def test_history_tool_digests_are_strings_and_capped():
    from src.api.public_scan_router import _HISTORY_MAX_TOOLS, _history_tool_digests
    assert _history_tool_digests(None) is None
    assert _history_tool_digests({}) is None
    assert _history_tool_digests({"t": 1}) == {"t": "1"}
    big = {f"t{i}": "d" for i in range(_HISTORY_MAX_TOOLS + 50)}
    assert len(_history_tool_digests(big)) == _HISTORY_MAX_TOOLS


@pytest.mark.asyncio
async def test_a_scan_writes_its_per_tool_digests_into_history(db):
    from sqlalchemy import select

    from src.api.public_scan_router import _record_scan_history
    data = {"trust_score": 90, "tool_manifest_digest": "m1",
            "tool_digests": {"scan_repo": "d1", "scan_package": "d2"}, "findings": {}}
    await _record_scan_history("mcp:https://w.example/mcp", "mcp", "mcp", "w", data, db)
    row = (await db.execute(select(ScanHistory).where(
        ScanHistory.full_name == "mcp:https://w.example/mcp"))).scalar_one()
    assert row.tool_digests == {"scan_repo": "d1", "scan_package": "d2"}
    assert row.tool_manifest_digest == "m1"
