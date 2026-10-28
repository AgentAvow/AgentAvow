"""The public-scan cache refresh routes each key to its own surface.

Package keys (``npm/react-dom``, ``pypi/uvicorn``, ``crates/syn``, ``docker/postgres``)
used to be handed to ``scan_repo`` as GitHub repos: every one 404'd and burned a GitHub
API call, and nothing was written back to the cache.
"""
from __future__ import annotations

import pytest

from src.scanner.behavioral.trigger import coords_from_cache_key, scan_cache_coords


@pytest.mark.parametrize(
    "key, expected",
    [
        ("npm/react-dom", ("npm", "npm", "react-dom")),
        ("npm/@babel/core", ("npm", "npm", "@babel/core")),
        ("pypi/uvicorn", ("pypi", "pypi", "uvicorn")),
        ("crates/syn", ("crates", "crates", "syn")),
        ("docker/postgres", ("docker", "docker", "postgres")),
        ("huggingface/sentence-transformers/all-MiniLM-L6-v2",
         ("huggingface", "huggingface", "sentence-transformers/all-MiniLM-L6-v2")),
        ("mcp/https://mcp.deepwiki.com/mcp", ("mcp", "mcp", "https://mcp.deepwiki.com/mcp")),
        ("skill/anthropics/skills", ("openclaw", "anthropics", "skills")),
        ("vercel/next.js", ("github", "vercel", "next.js")),
    ],
)
def test_cache_key_maps_to_its_surface(key, expected):
    assert coords_from_cache_key(key) == expected


@pytest.mark.parametrize(
    "key", ["", "npm", "npm/", "/x", "skill/anthropics/skills/skills/pdf", "a/b/c"],
)
def test_unroutable_keys_are_skipped(key):
    assert coords_from_cache_key(key) is None


@pytest.mark.parametrize(
    "surface, owner, repo",
    [
        ("npm", "npm", "react-dom"),
        ("pypi", "pypi", "uvicorn"),
        ("crates", "crates", "syn"),
        ("docker", "docker", "postgres"),
        ("mcp", "mcp", "https://mcp.deepwiki.com/mcp"),
        ("openclaw", "anthropics", "skills"),
        ("github", "vercel", "next.js"),
    ],
)
def test_round_trips_with_scan_cache_coords(surface, owner, repo):
    o, r = scan_cache_coords(surface, owner, repo)
    assert coords_from_cache_key(f"{o}/{r}") == (surface, owner, repo)


class _FakeRedis:
    def __init__(self, ttls: dict[str, int]):
        self._ttls = ttls

    async def scan_iter(self, match: str):
        for k in self._ttls:
            yield k.encode()

    async def ttl(self, key):
        key = key.decode() if isinstance(key, bytes) else key
        return self._ttls[key]


@pytest.mark.asyncio
async def test_refresh_routes_package_keys_to_the_package_path(monkeypatch):
    from src.jobs import scheduler
    from src.scanner import service

    ttls = {
        "ag:cache:public_scan:npm/react-dom": 120,
        "ag:cache:public_scan:pypi/uvicorn": 300,
        "ag:cache:public_scan:vercel/next.js": 60,
        "ag:cache:public_scan:crates/syn": 3000,  # not expiring: left alone
    }

    async def fake_get_redis():
        return _FakeRedis(ttls)

    calls: list[tuple[str, str, str]] = []

    async def fake_rescan(surface, owner, repo, db):
        calls.append((surface, owner, repo))
        return True

    async def no_github(*a, **kw):  # the old path; must never run
        raise AssertionError("scan_repo must not be called for a cache refresh")

    import src.redis_client as redis_client
    import src.scanner.scan as scan_mod

    monkeypatch.setattr(redis_client, "get_redis", fake_get_redis)
    monkeypatch.setattr(scheduler, "_rescan_catalog_row", fake_rescan)
    monkeypatch.setattr(scan_mod, "scan_repo", no_github)
    from src.config import settings

    monkeypatch.setattr(settings, "catalog_rescan_spacing_seconds", 0, raising=False)

    refreshed = await service.refresh_public_scan_cache(limit=10)

    assert refreshed == 3
    assert sorted(calls) == sorted([
        ("npm", "npm", "react-dom"),
        ("pypi", "pypi", "uvicorn"),
        ("github", "vercel", "next.js"),
    ])
