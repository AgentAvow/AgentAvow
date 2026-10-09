"""The trust gateway denies on the tool's answer, not just its tier.

A Do not connect tool (a critical finding, a canary leak, a known-malicious package) is
denied by /gateway/check and /gateway/re-verify whatever its score or tier; ``fail_on``
("do_not_connect" default | "review") is the same knob the other gates use, and
``min_tier`` stays an extra floor.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app

CHECK_URL = "/api/v1/gateway/check"
RE_VERIFY_URL = "/api/v1/gateway/re-verify"


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


def _limits():
    return SimpleNamespace(dict=lambda: {
        "requests_per_minute": 60, "max_tokens_per_call": 4000,
        "require_user_confirmation": False,
    })


def _scan_result(score: int, tier: str, decision: str, reason: str = "x"):
    return SimpleNamespace(
        trust_score=score, trust_tier=tier, recommended_limits=_limits(),
        category_scores={}, decision=decision, decision_final=True,
        decision_reason=reason,
    )


def _cached(score: int, tier: str, items: list | None = None) -> dict:
    items = items or []
    return {
        "trust_score": score, "trust_tier": tier,
        "findings": {"critical": sum(1 for i in items if i["severity"] == "critical"),
                     "high": 0, "medium": 0, "total": len(items),
                     "categories": {}, "items": items},
        "metadata": {"files_scanned": 50},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


async def _check(client, result, **body):
    with patch("src.api.public_scan_router.public_scan", new=AsyncMock(return_value=result)):
        return await client.post(CHECK_URL, json={"repo": "o/r", **body})


@pytest.mark.asyncio
async def test_check_denies_do_not_connect_even_at_a_passing_tier(client):
    r = await _check(client, _scan_result(72, "standard", "do_not_connect",
                                          "a planted credential left the sandbox"))
    body = r.json()
    assert r.status_code == 200
    assert body["allowed"] is False
    assert body["decision_reason"].startswith("Do not connect")
    assert body["scan_decision"]["decision"] == "do_not_connect"


@pytest.mark.asyncio
async def test_check_allows_review_by_default_and_denies_with_fail_on_review(client):
    res = _scan_result(70, "standard", "review", "one high finding")
    assert (await _check(client, res)).json()["allowed"] is True
    body = (await _check(client, res, fail_on="review")).json()
    assert body["allowed"] is False
    assert body["decision_reason"].startswith("Review before you connect")


@pytest.mark.asyncio
async def test_check_min_tier_is_still_a_floor(client):
    body = (await _check(client, _scan_result(55, "minimal", "safe"),
                         min_tier="standard")).json()
    assert body["allowed"] is False
    assert "below minimum" in body["decision_reason"]


@pytest.mark.asyncio
async def test_check_rejects_unknown_fail_on(client):
    r = await _check(client, _scan_result(90, "trusted", "safe"), fail_on="maybe")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_check_signed_payload_carries_the_answer(client):
    import base64
    import json
    body = (await _check(client, _scan_result(90, "trusted", "safe"))).json()
    payload = body["jws"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    signed = json.loads(base64.urlsafe_b64decode(payload))
    assert signed["decision"] == "safe" and signed["fail_on"] == "do_not_connect"


@pytest.mark.asyncio
async def test_re_verify_denies_a_do_not_connect_cached_scan(client):
    crit = {"severity": "critical", "category": "secret", "name": "AWS key",
            "shipped": True, "kind": "defect"}
    with patch("src.api.public_scan_router._get_cached",
               new=AsyncMock(return_value=_cached(60, "standard", [crit]))):
        r = await client.post(RE_VERIFY_URL, json={"repo": "o/r"})
    body = r.json()
    assert body["verified"] is False
    assert body["decision"] == "do_not_connect"
    assert body["reason"].startswith("answer_do_not_connect")


@pytest.mark.asyncio
async def test_re_verify_passes_a_safe_cached_scan(client):
    with patch("src.api.public_scan_router._get_cached",
               new=AsyncMock(return_value=_cached(90, "trusted"))):
        body = (await client.post(RE_VERIFY_URL, json={"repo": "o/r"})).json()
    assert body["verified"] is True and body["decision"] == "safe"


@pytest.mark.asyncio
async def test_stats_drops_the_letter_scale(client):
    body = (await client.get("/api/v1/gateway/stats")).json()
    assert "grade_scale" not in body
    assert "by_grade" not in body["metrics"]
    assert body["docs"].endswith("/docs/gate-on-the-grade")
