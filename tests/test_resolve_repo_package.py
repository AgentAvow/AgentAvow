"""_resolve_repo_package — resolve the published (surface, registry-name) a repo
maps to from its root manifest, so the UI can offer 1-click package/MCP install."""
from __future__ import annotations

import pytest

import src.scanner.scan as scan_mod
from src.scanner.scan import _resolve_repo_package


def _tree(*paths):
    return [{"path": p, "type": "blob"} for p in paths]


@pytest.mark.asyncio
async def test_pypi_name_from_pyproject(monkeypatch):
    async def fake_content(owner, repo, path, token=None, ref=None):
        return '[project]\nname = "academia-mcp"\nversion = "1.0"\n'
    monkeypatch.setattr(scan_mod, "_fetch_file_content", fake_content)
    pc = await _resolve_repo_package(
        "IlyaGusev", "academia_mcp", _tree("pyproject.toml"), None, None)
    assert pc == {"surface": "pypi", "name": "academia-mcp"}


@pytest.mark.asyncio
async def test_npm_name_from_package_json(monkeypatch):
    async def fake_content(owner, repo, path, token=None, ref=None):
        return '{"name": "@scope/my-mcp", "version": "2.0.0"}'
    monkeypatch.setattr(scan_mod, "_fetch_file_content", fake_content)
    pc = await _resolve_repo_package("o", "repo", _tree("package.json"), None, None)
    assert pc == {"surface": "npm", "name": "@scope/my-mcp"}


@pytest.mark.asyncio
async def test_falls_back_to_repo_name_on_unparseable(monkeypatch):
    async def fake_content(owner, repo, path, token=None, ref=None):
        return "not valid json"
    monkeypatch.setattr(scan_mod, "_fetch_file_content", fake_content)
    pc = await _resolve_repo_package("o", "cool-tool", _tree("package.json"), None, None)
    assert pc == {"surface": "npm", "name": "cool-tool"}


@pytest.mark.asyncio
async def test_no_manifest_returns_empty(monkeypatch):
    async def fake_content(owner, repo, path, token=None, ref=None):
        return None
    monkeypatch.setattr(scan_mod, "_fetch_file_content", fake_content)
    pc = await _resolve_repo_package("o", "r", _tree("README.md", "src/main.go"), None, None)
    assert pc == {}


@pytest.mark.asyncio
async def test_fetch_error_falls_open(monkeypatch):
    async def boom(owner, repo, path, token=None, ref=None):
        raise RuntimeError("network")
    monkeypatch.setattr(scan_mod, "_fetch_file_content", boom)
    pc = await _resolve_repo_package("o", "r", _tree("setup.py"), None, None)
    assert pc == {"surface": "pypi", "name": "r"}
