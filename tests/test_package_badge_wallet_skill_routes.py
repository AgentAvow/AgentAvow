"""Package badges for names with a slash, package-badge cache misses, per-skill
routes, fresh package scans recording history, wallet → repo, crates claims."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import src.api.public_scan_router as psr
from src.database import get_db
from src.main import app


def _scan_dict(score: int = 88) -> dict:
    return {
        "trust_score": score, "trust_tier": "trusted", "scan_result": "clean",
        "recommended_limits": {"requests_per_minute": 60, "max_tokens_per_call": 4000,
                               "require_user_confirmation": False},
        "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0, "categories": {},
                     "suppressed_lines": 0, "items": []},
        "positive_signals": [], "category_scores": {},
        "metadata": {"files_scanned": 30, "primary_language": "javascript", "has_readme": True,
                     "has_license": True, "has_tests": False, "is_mcp_server": False},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def no_sandbox():
    with patch("src.api.public_scan_router._behavioral_block", new=AsyncMock(return_value=None)):
        yield


# ── package badges ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scoped_npm_badge_reads_the_package_result(client):
    seen = []

    async def fake_cached(owner, repo):
        seen.append((owner, repo))
        return _scan_dict(88) if (owner, repo) == ("npm", "@scope/pkg") else None

    with patch.object(psr, "_get_cached", new=fake_cached), \
         patch.object(psr, "public_scan", new=AsyncMock(side_effect=AssertionError("no repo scan"))):
        r = await client.get("/api/v1/public/scan/package/npm/@scope/pkg/badge")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "88" in r.text
    assert ("npm", "@scope/pkg") in seen


@pytest.mark.asyncio
async def test_hf_badge_with_slash_and_query_options(client):
    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=_scan_dict(71))):
        r = await client.get("/api/v1/public/scan/package/hf/org/model/badge",
                             params={"metric": "trust"})
    assert r.status_code == 200 and "71" in r.text


@pytest.mark.asyncio
async def test_package_badge_rejects_bad_input(client):
    r = await client.get("/api/v1/public/scan/package/gopher/x/badge")
    assert r.status_code == 404
    r = await client.get("/api/v1/public/scan/package/npm/a..b/badge")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_old_package_badge_miss_uses_stale_package_not_github_repo(client):
    scheduled = []
    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=None)), \
         patch.object(psr, "_get_stale_cached", new=AsyncMock(return_value=_scan_dict(64))), \
         patch.object(psr, "_schedule_package_refresh", new=lambda *a: scheduled.append(a)), \
         patch.object(psr, "public_scan", new=AsyncMock(side_effect=AssertionError("no repo scan"))):
        r = await client.get("/api/v1/public/scan/npm/semver/badge")
    assert r.status_code == 200 and "64" in r.text
    assert scheduled and scheduled[0][:2] == ("npm", "semver")


@pytest.mark.asyncio
async def test_package_badge_full_miss_scans_the_package(client):
    class R:
        error = None

    async def fake_scan(surface, name, version=None):
        assert (surface, name) == ("pypi", "boto3")
        return R()

    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=None)), \
         patch.object(psr, "_get_stale_cached", new=AsyncMock(return_value=None)), \
         patch("src.scanner.scan.scan_package", new=fake_scan), \
         patch.object(psr, "_scan_result_to_dict", new=lambda r: _scan_dict(90)), \
         patch.object(psr, "_set_cached", new=AsyncMock()):
        r = await client.get("/api/v1/public/scan/package/pypi/boto3/badge")
    assert r.status_code == 200 and "90" in r.text


# ── fresh package scans record history ───────────────────────────────────────

@pytest.mark.asyncio
async def test_fresh_package_scan_records_catalog_and_history(client, no_sandbox):
    captured = []

    class R:
        error = None

    async def fake_scan(surface, name, version=None):
        return R()

    async def fake_capture(owner, repo, data, db, surface="github"):
        captured.append((owner, repo, surface, data["trust_score"]))

    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=None)), \
         patch("src.scanner.scan.scan_package", new=fake_scan), \
         patch.object(psr, "_scan_result_to_dict", new=lambda r: _scan_dict(83)), \
         patch.object(psr, "_set_cached", new=AsyncMock()), \
         patch.object(psr, "_capture_community_scan", new=fake_capture), \
         patch("src.api.rate_limit.enforce_fresh_scan_limit", new=AsyncMock()):
        r = await client.get("/api/v1/public/scan/package/npm/left-pad")
        assert r.status_code == 200
        r = await client.get("/api/v1/public/scan/package/npm/left-pad", params={"version": "1.0.0"})
        assert r.status_code == 200
    assert captured == [("npm", "left-pad", "npm", 83)]  # pinned versions aren't recorded


# ── per-skill route ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_per_skill_route_and_collection_caching(client, no_sandbox):
    from src.scanner.scan import ScanResult

    def mk(repo, score, extra=None):
        r = ScanResult(repo=repo, stars=0, description="", framework="")
        r.trust_score = score
        r.files_scanned = 9
        r.artifact_scan = {"surface": "openclaw", **(extra or {})}
        return r

    sub_a = mk("skill:acme/skills/skills/a", 90)
    coll = mk("skill:acme/skills", 70, {"collection": True, "skills": []})
    coll.per_skill = {"skills/a": sub_a}
    calls, cached = [], {}

    async def fake_scan_skill(owner, repo, skill=None):
        calls.append(skill)
        return coll if skill is None else mk(f"skill:{owner}/{repo}/{skill}", 90)

    async def fake_set(owner, repo, data):
        cached[(owner, repo)] = data

    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=None)), \
         patch("src.scanner.scan.scan_skill", new=fake_scan_skill), \
         patch.object(psr, "_set_cached", new=fake_set), \
         patch("src.api.rate_limit.enforce_fresh_scan_limit", new=AsyncMock()):
        r = await client.get("/api/v1/public/scan/skill/acme/skills")
        assert r.status_code == 200
        assert ("skill", "acme/skills") in cached
        assert ("skill", "acme/skills/skills/a") in cached  # each skill cached for its page
        r = await client.get("/api/v1/public/scan/skill/acme/skills/skills/b")
        assert r.status_code == 200
        r = await client.get("/api/v1/public/scan/skill/acme/skills/..%2Fetc")
        assert r.status_code in (400, 404)
    assert calls == [None, "skills/b"]


# ── wallet ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_wallet_unknown_is_not_found(client):
    r = await client.get("/api/v1/public/scan/wallet/0x" + "ab" * 20, params={"chain": "ethereum"})
    assert r.status_code == 200
    assert r.json()["found"] is False


# ── crates claims ────────────────────────────────────────────────────────────

def test_claim_coord_accepts_crates():
    from src.api.account_claims_router import _claim_coord

    assert _claim_coord("crates", "", "serde") == ("crates", "serde", "crates:serde")
    assert _claim_coord("crates", "", "bad name") is None


@pytest.mark.asyncio
async def test_crates_declared_repo_and_keyword(monkeypatch):
    import httpx

    import src.api.account_claims_router as acr

    def handler(request):
        assert "AgentAvow" in request.headers.get("user-agent", "")
        return httpx.Response(200, json={
            "crate": {"repository": "https://github.com/Acme/Demo", "keywords": ["fast"]},
            "keywords": [{"id": "agentavow-verify-abc123", "keyword": "agentavow-verify-abc123"}],
        })

    real = httpx.AsyncClient

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    assert await acr._declared_repo("crates", "demo") == "acme/demo"
    assert await acr._keyword_challenge_ok("crates", "demo", "abc123") is True
    assert await acr._keyword_challenge_ok("crates", "demo", "zzz") is False
