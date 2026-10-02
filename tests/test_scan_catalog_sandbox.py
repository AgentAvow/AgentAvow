"""/public/scan-catalog rows carry a read-only ``sandbox`` summary of the cached
behavioral block (npm/pypi/docker only), fetched for the whole page in ONE Redis
MGET — never a round trip per row — and never mutating the shared in-memory catalog.
"""
from __future__ import annotations

import json

import pytest

import src.api.scan_catalog_router as m
from src.api.public_scan_router import _behavioral_cache_key
from src.api.scan_catalog_router import CatalogRow, _attach_sandbox, _sandbox_candidate_keys


class _FakeRedis:
    def __init__(self, store: dict[str, str]):
        self.store = store
        self.calls: list[list[str]] = []

    async def mget(self, keys):
        self.calls.append(list(keys))
        return [self.store.get(k) for k in keys]

    async def get(self, key):  # a per-row GET would be the bug under test
        raise AssertionError("per-row GET used instead of a batched MGET")


def _block(findings=0, unexpected=0, launch_ok=True, ran=True, exercise=True) -> str:
    return json.dumps({
        "ran": ran,
        "findings": [{"rule": f"r{i}"} for i in range(findings)],
        "unexpected_egress": [f"h{i}.net" for i in range(unexpected)],
        "exercise": {"launch_ok": launch_ok, "calls": []} if exercise else None,
    })


@pytest.fixture
def redis(monkeypatch):
    store: dict[str, str] = {}
    fake = _FakeRedis(store)
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


def test_candidate_keys_follow_the_scan_cache_key():
    npm = CatalogRow(surface="npm", name="chalk")
    assert _sandbox_candidate_keys(npm) == [_behavioral_cache_key("npm", "chalk")]
    mcp = CatalogRow(surface="npm", name="@acme/mcp", is_mcp_server=True)
    assert _sandbox_candidate_keys(mcp) == [
        _behavioral_cache_key("npm", "@acme/mcp"),
        _behavioral_cache_key("npm", "@acme/mcp", None, "npm-mcp"),
    ]
    assert _sandbox_candidate_keys(CatalogRow(surface="docker", name="acme/img")) == [
        _behavioral_cache_key("docker", "acme/img"),
        _behavioral_cache_key("docker", "acme/img", None, "docker"),
    ]
    # surfaces without a sandbox tier never hit Redis
    assert _sandbox_candidate_keys(CatalogRow(surface="mcp", name="https://x")) == []
    assert _sandbox_candidate_keys(CatalogRow(surface="openclaw", name="a/b")) == []
    assert _sandbox_candidate_keys(CatalogRow(surface="npm", name="")) == []


async def test_page_is_decorated_with_one_mget(redis):
    redis.store[_behavioral_cache_key("npm", "clean")] = _block()
    redis.store[_behavioral_cache_key("pypi", "dirty")] = _block(findings=2, unexpected=1)
    redis.store[_behavioral_cache_key("npm", "srv", None, "npm-mcp")] = _block(launch_ok=False)
    redis.store[_behavioral_cache_key("npm", "pending")] = json.dumps(
        {"ran": False, "pending": True})
    rows = [
        CatalogRow(surface="npm", name="clean"),
        CatalogRow(surface="pypi", name="dirty"),
        CatalogRow(surface="npm", name="srv", is_mcp_server=True),
        CatalogRow(surface="npm", name="pending"),
        CatalogRow(surface="npm", name="never-run"),
        CatalogRow(surface="mcp", name="https://mcp.example"),
    ]
    out = await _attach_sandbox(rows)
    assert len(redis.calls) == 1
    assert len(redis.calls[0]) == 1 + 1 + 2 + 1 + 1  # keys for the 5 package rows only
    assert out[0].sandbox.model_dump() == {
        "ran": True, "exercised": True, "findings": 0, "unexpected_egress": 0}
    assert out[1].sandbox.model_dump() == {
        "ran": True, "exercised": True, "findings": 2, "unexpected_egress": 1}
    assert out[2].sandbox.exercised is False
    assert out[3].sandbox is None  # pending is not a run
    assert out[4].sandbox is None
    assert out[5].sandbox is None
    # the input rows (shared catalog cache) are untouched — decorated rows are copies
    assert all(r.sandbox is None for r in rows)


async def test_install_plan_without_exercise_has_null_exercised(redis):
    redis.store[_behavioral_cache_key("pypi", "lib")] = _block(exercise=False)
    (row,) = await _attach_sandbox([CatalogRow(surface="pypi", name="lib")])
    assert row.sandbox.model_dump() == {
        "ran": True, "exercised": None, "findings": 0, "unexpected_egress": 0}


async def test_no_package_rows_means_no_redis_call(redis):
    rows = [CatalogRow(surface="mcp", name="https://a"), CatalogRow(surface="x402", name="u")]
    assert await _attach_sandbox(rows) is rows
    assert redis.calls == []


async def test_redis_failure_and_bad_json_leave_rows_undecorated(monkeypatch):
    class _Down:
        async def mget(self, keys):
            raise ConnectionError("redis down")

    monkeypatch.setattr("src.redis_client.get_redis", lambda: _Down())
    rows = [CatalogRow(surface="npm", name="x")]
    assert (await _attach_sandbox(rows))[0].sandbox is None

    bad = _FakeRedis({_behavioral_cache_key("npm", "x"): "{not json"})
    monkeypatch.setattr("src.redis_client.get_redis", lambda: bad)
    assert (await _attach_sandbox(rows))[0].sandbox is None


async def test_catalog_endpoint_serves_sandbox_on_the_page(monkeypatch, redis):
    rows = [m._normalize_row("npm", {"name": "chalk", "full_name": "chalk/chalk",
                                     "trust_score": 95, "critical": 0, "high": 0})]
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(rows))

    async def _no_community(db):
        return []

    monkeypatch.setattr(m, "_community_rows", _no_community)
    redis.store[_behavioral_cache_key("npm", "chalk")] = _block(findings=1)
    resp = await m.scan_catalog(
        surface="npm", q=None, severity=None, grade=None, category=None,
        sort="default", limit=50, offset=0, db=None,
    )
    assert resp.rows[0].sandbox.findings == 1
    # the cached catalog row itself stays clean
    assert m._CATALOG_CACHE["rows"][0].sandbox is None
