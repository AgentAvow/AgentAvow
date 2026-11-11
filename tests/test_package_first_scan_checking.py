"""A slow first package scan answers 202 {state: checking} instead of a 503.

claude-mem and hyperframes took ~100 s on their first scan and hit the old 90 s cap as a
503. The scan now runs in the background: the request waits up to ``wait`` seconds, then
answers 202 with retry_after; asking again joins the same scan (no second scan, no second
fresh-scan charge) and returns the cached result once it lands.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from src.api import public_scan_router as psr


def _data(score=88):
    return {"trust_score": score, "trust_tier": "trusted", "scan_result": "clean",
            "recommended_limits": psr.recommended_limits(score),
            "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0,
                         "categories": {}, "items": []},
            "metadata": {"files_scanned": 40, "total_scannable_files": 40, "sampled": False,
                         "primary_language": "Rust"},
            "positive_signals": [], "certified": {"eligible": False, "checks": {}},
            "scanned_at": "2026-11-11T00:00:00+00:00"}


class Harness:
    """A cache dict, a controllable scanner and a counted fresh-scan limiter."""

    def __init__(self, delay=0.0, error=None):
        self.cache: dict = {}
        self.scans = 0
        self.charges = 0
        self.delay = delay
        self.error = error
        self.release = asyncio.Event()

    async def get_cached(self, owner, repo):
        return self.cache.get(f"{owner}/{repo}")

    async def set_cached(self, owner, repo, data):
        self.cache[f"{owner}/{repo}"] = data

    async def scan_package(self, surface, name, version=None):
        self.scans += 1
        if self.delay:
            await self.release.wait()
        return SimpleNamespace(error=self.error)

    async def charge(self, request):
        self.charges += 1

    def patches(self, redis=None):
        return [
            patch.object(psr, "_get_cached", new=self.get_cached),
            patch.object(psr, "_set_cached", new=self.set_cached),
            patch.object(psr, "_scan_result_to_dict", new=lambda r: _data()),
            patch.object(psr, "_capture_community_scan", new=AsyncMock()),
            patch.object(psr, "_track_checker", new=AsyncMock()),
            patch.object(psr, "create_jws", new=lambda b: "jws"),
            patch.object(psr, "_redis_or_none", new=AsyncMock(return_value=redis)),
            patch("src.scanner.scan.scan_package", new=self.scan_package),
            patch("src.api.rate_limit.enforce_fresh_scan_limit", new=self.charge),
        ]


async def _call(wait=None, force=False):
    return await psr.scan_package_endpoint(
        surface="crates", name="slowpkg", request=object(), force=force, behavioral=False,
        version=None, wait=wait, stored=False, db=None)


def _enter(ps):
    for p in ps:
        p.start()


def _exit(ps):
    for p in reversed(ps):
        p.stop()
    psr._first_scans.clear()


@pytest.mark.asyncio
async def test_slow_first_scan_answers_checking_then_the_result():
    h = Harness(delay=1)
    ps = h.patches()
    _enter(ps)
    try:
        first = await _call(wait=0)
        assert isinstance(first, JSONResponse) and first.status_code == 202
        body = json.loads(first.body)
        assert body["state"] == "checking" and body["status"] == "checking"
        assert body["retry_after"] == psr._FIRST_SCAN_RETRY_AFTER
        assert first.headers["retry-after"] == str(psr._FIRST_SCAN_RETRY_AFTER)

        # asking again while it runs joins the same scan: no new scan, no new charge
        again = await _call(wait=0)
        assert again.status_code == 202
        assert h.scans == 1 and h.charges == 1

        h.release.set()
        await asyncio.sleep(0.05)
        done = await _call(wait=0)
        assert done.trust_score == 88 and done.decision
        assert h.scans == 1
    finally:
        _exit(ps)


@pytest.mark.asyncio
async def test_a_waiting_call_gets_the_result_when_it_lands_inside_the_wait():
    h = Harness(delay=1)
    ps = h.patches()
    _enter(ps)
    try:
        async def finish_soon():
            await asyncio.sleep(0.05)
            h.release.set()
        asyncio.get_running_loop().create_task(finish_soon())
        r = await _call(wait=5)
        assert r.trust_score == 88
    finally:
        _exit(ps)


@pytest.mark.asyncio
async def test_fast_scan_is_answered_inline_as_before():
    h = Harness()
    ps = h.patches()
    _enter(ps)
    try:
        r = await _call()
        assert r.trust_score == 88 and h.scans == 1 and h.charges == 1
        assert h.cache["crates/slowpkg"]["trust_score"] == 88
    finally:
        _exit(ps)


@pytest.mark.asyncio
@pytest.mark.parametrize("error,code", [("Package not found on crates.io", 404),
                                        ("registry returned 500", 502)])
async def test_scanner_errors_keep_their_status(error, code):
    h = Harness(error=error)
    ps = h.patches()
    _enter(ps)
    try:
        with pytest.raises(HTTPException) as e:
            await _call()
        assert e.value.status_code == code
    finally:
        _exit(ps)


class FakeRedis:
    """Another worker holds the scan lock; this worker polls the cache."""

    def __init__(self, error=None):
        self.error = error

    async def exists(self, key):
        return 1

    async def get(self, key):
        return self.error if key.startswith(psr._FIRST_SCAN_ERROR_PREFIX) else None


@pytest.mark.asyncio
async def test_a_call_on_another_worker_polls_the_cache_instead_of_scanning():
    h = Harness()
    ps = h.patches(redis=FakeRedis())
    _enter(ps)
    try:
        assert (await _call(wait=0)).status_code == 202
        h.cache["crates/slowpkg"] = _data(91)
        r = await _call(wait=0)
        assert r.trust_score == 91
        assert h.scans == 0 and h.charges == 0
    finally:
        _exit(ps)


@pytest.mark.asyncio
async def test_another_workers_failed_scan_is_reported():
    h = Harness()
    ps = h.patches(redis=FakeRedis(error="Package not found"))
    _enter(ps)
    try:
        with pytest.raises(HTTPException) as e:
            await _call(wait=0)
        assert e.value.status_code == 404
    finally:
        _exit(ps)


@pytest.mark.asyncio
async def test_mcp_connector_reads_a_202_as_still_checking(monkeypatch):
    from src.bridges import mcp_streamable as ms

    def handler(request):
        return httpx.Response(202, json={"state": "checking", "retry_after": 15})
    real = httpx.AsyncClient
    monkeypatch.setattr(ms.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    with pytest.raises(httpx.TimeoutException):
        await ms._get("/public/scan/package/npm/claude-mem")
    with pytest.raises(ms.ScanStillChecking):
        await ms._get("/public/scan/package/npm/claude-mem")
