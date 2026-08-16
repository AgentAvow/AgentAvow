"""Package-identity guard for the artifact scan (_accurate_artifact_coord).

Ensures the artifact scan resolves the package from the repo's OWN manifest name
(not the bare repo-folder name), and refuses to resolve a private/unnamed one — so
`owner/servers` is never diffed against an unrelated npm `servers`.
"""
from __future__ import annotations

import pytest

from src.scanner import scan as scanmod


def _tree(*names):
    return [{"path": n, "type": "blob"} for n in names]


async def _coord(monkeypatch, tree, files):
    async def fake_content(owner, repo, path, token, ref=None, *a, **k):
        return files.get(path)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    return await scanmod._accurate_artifact_coord("owner", "servers", tree, None, "main")


@pytest.mark.asyncio
async def test_uses_manifest_name_not_repo_name(monkeypatch):
    # repo is "servers" but the package.json declares a scoped name
    coord = await _coord(
        monkeypatch,
        _tree("package.json", "index.js"),
        {"package.json": '{"name": "@modelcontextprotocol/sdk", "version": "1.0.0"}'},
    )
    assert coord == ("npm", "@modelcontextprotocol/sdk", None)


@pytest.mark.asyncio
async def test_private_package_is_not_scanned(monkeypatch):
    # a workspace root marked private is never published → no artifact to diff
    coord = await _coord(
        monkeypatch,
        _tree("package.json"),
        {"package.json": '{"name": "servers", "private": true}'},
    )
    assert coord is None


@pytest.mark.asyncio
async def test_unnamed_manifest_returns_none(monkeypatch):
    coord = await _coord(
        monkeypatch,
        _tree("package.json"),
        {"package.json": '{"version": "1.0.0"}'},
    )
    assert coord is None


@pytest.mark.asyncio
async def test_pyproject_name(monkeypatch):
    coord = await _coord(
        monkeypatch,
        _tree("pyproject.toml"),
        {"pyproject.toml": '[project]\nname = "mcp"\nversion = "0.1"\n'},
    )
    assert coord == ("pypi", "mcp", None)


@pytest.mark.asyncio
async def test_no_manifest_returns_none(monkeypatch):
    # a Go repo (go.mod only) publishes no npm/pypi artifact — nothing to diff
    coord = await _coord(monkeypatch, _tree("go.mod", "main.go"), {})
    assert coord is None
