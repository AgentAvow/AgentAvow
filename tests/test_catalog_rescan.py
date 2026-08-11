"""Catalog re-scan/growth loop — surface-aware dispatch + fail-open behavior."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.jobs import scheduler as sch


@pytest.mark.asyncio
async def test_rescan_github_uses_public_scan(monkeypatch):
    called = {}

    async def fake_public_scan(owner, repo, force, db):
        called["args"] = (owner, repo, force)
        return SimpleNamespace(trust_score=90)

    monkeypatch.setattr("src.api.public_scan_router.public_scan", fake_public_scan)
    ok = await sch._rescan_catalog_row("github", "torvalds", "linux", db=None)
    assert ok is True
    assert called["args"] == ("torvalds", "linux", True)  # force re-scan


@pytest.mark.asyncio
async def test_rescan_npm_captures_with_surface(monkeypatch):
    cap = {}

    async def fake_scan_package(surface, name):
        return SimpleNamespace(error=None, trust_score=94)

    async def fake_capture(owner, repo, data, db, surface="github"):
        cap["surface"] = surface
        cap["repo"] = repo

    def fake_dict(result):
        return {"trust_score": result.trust_score, "grade": "A"}

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    monkeypatch.setattr("src.api.public_scan_router._capture_community_scan", fake_capture)
    monkeypatch.setattr("src.api.public_scan_router._scan_result_to_dict", fake_dict)
    ok = await sch._rescan_catalog_row("npm", "npm", "chalk", db=None)
    assert ok is True
    assert cap == {"surface": "npm", "repo": "chalk"}


@pytest.mark.asyncio
async def test_rescan_skill_surface(monkeypatch):
    cap = {}

    async def fake_scan_skill(owner, repo):
        return SimpleNamespace(error=None, trust_score=82)

    async def fake_capture(owner, repo, data, db, surface="github"):
        cap["surface"] = surface

    monkeypatch.setattr("src.scanner.scan.scan_skill", fake_scan_skill)
    monkeypatch.setattr("src.api.public_scan_router._capture_community_scan", fake_capture)
    monkeypatch.setattr("src.api.public_scan_router._scan_result_to_dict", lambda r: {"grade": "B"})
    ok = await sch._rescan_catalog_row("openclaw", "acme", "skill", db=None)
    assert ok is True
    assert cap["surface"] == "openclaw"


@pytest.mark.asyncio
async def test_rescan_skips_on_scan_error(monkeypatch):
    async def fake_scan_package(surface, name):
        return SimpleNamespace(error="registry 500", trust_score=None)

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    ok = await sch._rescan_catalog_row("npm", "npm", "broken", db=None)
    assert ok is False  # errored scan → no capture, fail-open


@pytest.mark.asyncio
async def test_rescan_unknown_surface_returns_false():
    assert await sch._rescan_catalog_row("crates", "x", "y", db=None) is False


def test_backfill_targets_are_openclaw_coordinates():
    targets = sch._openclaw_backfill_targets()
    assert isinstance(targets, list)
    # Every target is (surface, owner, repo) with surface=openclaw and a real repo.
    for surface, owner, repo in targets[:20]:
        assert surface == "openclaw"
        assert owner and repo
