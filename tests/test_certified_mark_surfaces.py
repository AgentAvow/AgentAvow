"""The Certified MARK on the API + badge surfaces: one rule (verdict.certified_mark),
never the raw provenance gate. Eligible-but-Review shows no mark anywhere."""
from __future__ import annotations

import pytest

from src.api import public_scan_router as psr

CERT = {"eligible": True, "checks": {}}


def _cached(score=92, files=120, **extra):
    return {"trust_score": score, "trust_tier": "verified", "scan_result": "clean",
            "recommended_limits": psr.recommended_limits(score),
            "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0,
                         "categories": {}, "items": []},
            "metadata": {"files_scanned": files}, "certified": CERT,
            "scanned_at": "2026-10-09T00:00:00+00:00", **extra}


@pytest.mark.asyncio
async def test_badge_view_mark_only_beside_safe(monkeypatch):
    async def none(_d):
        return None
    monkeypatch.setattr(psr, "_cached_behavioral_for", none)
    assert await psr._badge_view(_cached(), 92) == ("safe", True)
    # eligible but deprecated → Review, no mark
    assert await psr._badge_view(_cached(deprecation="use y"), 92) == ("review", False)
    # eligible, Safe, but thin / under 81 → no mark
    assert (await psr._badge_view(_cached(files=4), 82))[1] is False
    assert (await psr._badge_view(_cached(score=80), 80))[1] is False
    # no scan → a bare score never carries the mark
    assert (await psr._badge_view(None, 99))[1] is False
    # an API response's own fields win
    assert await psr._badge_view({"decision": "review", "certified_mark": False}, 90) \
        == ("review", False)


@pytest.mark.asyncio
async def test_badge_view_folds_in_a_cached_sandbox_block(monkeypatch):
    async def leak(_d):
        return {"ran": True, "attestation": {"jws": "x"},
                "findings": [{"rule": "credential_canary_exfiltrated", "severity": "critical"}]}
    monkeypatch.setattr(psr, "_cached_behavioral_for", leak)
    dec, mark = await psr._badge_view(_cached(), 92)
    assert dec == "do_not_connect" and mark is False


def test_package_response_carries_the_mark_and_why_not():
    ok = psr._package_response("npm:x", _cached(), "jws", False)
    assert ok.certified_mark is True and ok.certified_mark_reason == ""
    assert ok.certified["eligible"] is True
    dep = psr._package_response("npm:x", _cached(deprecation="use y"), "jws", False)
    assert dep.decision == "review"
    assert dep.certified_mark is False and dep.certified_mark_reason == "not_safe"
    assert dep.certified["eligible"] is True  # the signed gate is unchanged
    pending = psr._package_response("npm:x", _cached(), "jws", False,
                                    behavioral={"ran": False, "pending": True})
    assert pending.certified_mark is False
    assert pending.certified_mark_reason == "sandbox_pending"


def test_mcp_struct_mark_follows_the_rule():
    from src.bridges.mcp_streamable import _certified_mark_of
    assert _certified_mark_of(_cached()) is True
    assert _certified_mark_of(_cached(deprecation="use y")) is False
    assert _certified_mark_of({**_cached(), "certified_mark": False}) is False


def test_tool_gate_reads_the_mark_not_eligibility():
    from src.bridges.tool_gate import _certified_mark_of
    assert _certified_mark_of({"certified": CERT}) is False  # no score/files → closed
    assert _certified_mark_of({"certified": CERT, "certified_mark": True}) is True
    assert _certified_mark_of(_cached()) is True
