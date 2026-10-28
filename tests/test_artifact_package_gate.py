"""The repo artifact scan (and the provenance check that rides on it) uses a published
package ONLY when that package's own registry entry points back at the scanned repo.
A same-named package that declares no repo, or a different one, is never scanned or
run as the repo — the repo is graded from its source and the result says so."""
from __future__ import annotations

import types

import pytest

import src.scanner.scan as scan_mod
from src.scanner.scan import (
    PACKAGE_UNCONFIRMED_NOTE,
    ScanResult,
    _maybe_scan_artifact,
    _maybe_verify_provenance,
    _package_points_back,
)


def _registry(slugs):
    async def fake(ecosystem, name):
        return list(slugs), None
    return fake


def _flags(monkeypatch, **kw):
    from src.config import settings
    for k, v in kw.items():
        monkeypatch.setattr(settings, k, v, raising=False)


def _spy_artifact(monkeypatch):
    calls = []

    async def fake_scan(ecosystem, name, version=None, **kw):
        calls.append((ecosystem, name))
        return types.SimpleNamespace(
            ok=True, findings=[], drift={}, ecosystem=ecosystem, name=name,
            version="1.0.0", kind="tarball", digest="sha256:x", download_url="u",
            files_scanned=3, file_count=3, unpacked_size=10, registry_snapshot=None,
        )
    import src.scanner.artifact_scan as art_mod
    monkeypatch.setattr(art_mod, "scan_published_artifact", fake_scan)
    return calls


def _result():
    return ScanResult(repo="vercel/next.js", stars=0, description="", framework="")


async def _run(monkeypatch, slugs, coord=("npm", "nextjs-project", None)):
    _flags(monkeypatch, scanner_scan_artifact=True)
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(slugs))

    async def fake_coord(*a, **k):
        return coord
    monkeypatch.setattr(scan_mod, "_accurate_artifact_coord", fake_coord)
    calls = _spy_artifact(monkeypatch)
    res = _result()
    await _maybe_scan_artifact(res, "vercel", "next.js", [], None, None, None, {})
    return res, calls


@pytest.mark.asyncio
async def test_package_declaring_no_repo_is_skipped(monkeypatch):
    res, calls = await _run(monkeypatch, [])
    assert calls == []
    assert res.artifact_scan["ok"] is False
    assert res.artifact_scan["skipped"] == "unconfirmed"
    assert res.artifact_scan["note"] == PACKAGE_UNCONFIRMED_NOTE


@pytest.mark.asyncio
async def test_package_declaring_another_repo_is_skipped(monkeypatch):
    res, calls = await _run(monkeypatch, ["someone/else"])
    assert calls == []
    assert res.artifact_scan["skipped"] == "unconfirmed"


@pytest.mark.asyncio
async def test_matching_package_is_scanned(monkeypatch):
    res, calls = await _run(monkeypatch, ["vercel/next.js"], ("npm", "next", None))
    assert calls == [("npm", "next")]
    assert res.artifact_scan["ok"] is True
    assert res.coverage.get("scan_depth") == "artifact"


@pytest.mark.asyncio
async def test_case_insensitive_match(monkeypatch):
    _flags(monkeypatch)
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["vercel/next.js"]))
    assert await _package_points_back("Vercel", "Next.js", "npm", "next") is True


@pytest.mark.asyncio
async def test_monorepo_subpath_matches(monkeypatch):
    # _github_slug reduces a monorepo subpath URL to owner/repo before matching.
    async def fake_get(self, url, **kw):
        class R:
            status_code = 200

            @staticmethod
            def json():
                return {"repository": {
                    "url": "git+https://github.com/vercel/next.js.git",
                    "directory": "packages/next"},
                    "homepage": "https://github.com/vercel/next.js/tree/canary/packages/next"}
        return R()
    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    assert await _package_points_back("vercel", "next.js", "npm", "next") is True


@pytest.mark.asyncio
async def test_registry_outage_fails_closed_and_scan_continues(monkeypatch):
    async def boom(*a, **k):
        import httpx
        raise httpx.ConnectError("down")
    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    _flags(monkeypatch, scanner_scan_artifact=True)

    async def fake_coord(*a, **k):
        return ("npm", "next", None)
    monkeypatch.setattr(scan_mod, "_accurate_artifact_coord", fake_coord)
    calls = _spy_artifact(monkeypatch)
    res = _result()
    await _maybe_scan_artifact(res, "vercel", "next.js", [], None, None, None, {})
    assert calls == []
    assert res.artifact_scan["skipped"] == "unconfirmed"


@pytest.mark.asyncio
async def test_no_manifest_package_leaves_no_note(monkeypatch):
    res, calls = await _run(monkeypatch, [], coord=None)
    assert calls == []
    assert not res.artifact_scan


@pytest.mark.asyncio
async def test_provenance_ignores_unconfirmed_explicit_artifact(monkeypatch):
    _flags(monkeypatch, scanner_verify_provenance=True)
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry([]))
    seen = []

    async def fake_prov(*a, **k):
        seen.append(a)
        raise AssertionError("must not verify an unconfirmed package")
    import src.scanner.provenance as prov_mod
    monkeypatch.setattr(prov_mod, "analyze_provenance", fake_prov)
    res = _result()
    await _maybe_verify_provenance(
        res, "vercel", "next.js", [], None, None, ("npm", "nextjs-project", "1.0.0"))
    assert seen == []
