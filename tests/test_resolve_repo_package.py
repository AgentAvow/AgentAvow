"""_resolve_repo_package — the published package a repo maps to, used for the 1-click
install, the sandbox target and the supply-chain root. A coordinate is attached only
when the package's own registry entry points back at the scanned repo."""
from __future__ import annotations

import pytest

import src.scanner.scan as scan_mod
from src.scanner.scan import _github_slug, _resolve_repo_package


def _tree(*paths):
    return [{"path": p, "type": "blob"} for p in paths]


def _content(text):
    async def fake(owner, repo, path, token=None, ref=None):
        return text
    return fake


def _registry(slugs, manifest=None):
    calls = []

    async def fake(ecosystem, name):
        calls.append((ecosystem, name))
        return list(slugs), manifest
    fake.calls = calls
    return fake


@pytest.mark.asyncio
async def test_pypi_name_from_pyproject_when_registry_points_back(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content",
                        _content('[project]\nname = "academia-mcp"\nversion = "1.0"\n'))
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["ilyagusev/academia_mcp"]))
    pc = await _resolve_repo_package(
        "IlyaGusev", "academia_mcp", _tree("pyproject.toml"), None, None)
    assert pc == {"surface": "pypi", "name": "academia-mcp", "is_mcp_server": True}


@pytest.mark.asyncio
async def test_npm_name_from_package_json(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content",
                        _content('{"name": "@scope/tool", "version": "2.0.0"}'))
    monkeypatch.setattr(scan_mod, "_published_pkg_meta",
                        _registry(["o/repo"], {"name": "@scope/tool", "dependencies": {}}))
    pc = await _resolve_repo_package("o", "repo", _tree("package.json"), None, None)
    assert pc == {"surface": "npm", "name": "@scope/tool", "is_mcp_server": False}


@pytest.mark.asyncio
async def test_npm_mcp_server_detected_from_registry_manifest(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content", _content('{"name": "tool"}'))
    manifest = {"name": "tool", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["o/repo"], manifest))
    pc = await _resolve_repo_package("o", "repo", _tree("package.json"), None, None)
    assert pc["is_mcp_server"] is True


@pytest.mark.asyncio
async def test_unrelated_package_with_same_name_is_dropped(monkeypatch):
    """vercel/next.js: a non-private root named like a stranger's npm package. The
    stranger's registry entry declares no repo (or another one) — no coordinate."""
    monkeypatch.setattr(scan_mod, "_fetch_file_content", _content('{"name": "nextjs-project"}'))
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry([]))
    assert await _resolve_repo_package(
        "vercel", "next.js", _tree("package.json"), None, None) == {}
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["mhjack/other"]))
    assert await _resolve_repo_package(
        "vercel", "next.js", _tree("package.json"), None, None) == {}


@pytest.mark.asyncio
async def test_private_workspace_root_is_never_resolved(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content",
                        _content('{"name": "nextjs-project", "private": true}'))
    reg = _registry(["vercel/next.js"])
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", reg)
    assert await _resolve_repo_package(
        "vercel", "next.js", _tree("package.json"), None, None) == {}
    assert reg.calls == []


@pytest.mark.asyncio
async def test_no_repo_name_guess_on_unparseable_manifest(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content", _content("not valid json"))
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["o/cool-tool"]))
    assert await _resolve_repo_package(
        "o", "cool-tool", _tree("package.json"), None, None) == {}


@pytest.mark.asyncio
async def test_no_manifest_returns_empty(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content", _content(None))
    pc = await _resolve_repo_package("o", "r", _tree("README.md", "src/main.go"), None, None)
    assert pc == {}


@pytest.mark.asyncio
async def test_fetch_error_falls_open_to_nothing(monkeypatch):
    async def boom(owner, repo, path, token=None, ref=None):
        raise RuntimeError("network")
    monkeypatch.setattr(scan_mod, "_fetch_file_content", boom)
    assert await _resolve_repo_package("o", "r", _tree("setup.py"), None, None) == {}


@pytest.mark.asyncio
async def test_repo_match_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(scan_mod, "_fetch_file_content", _content('{"name": "x"}'))
    monkeypatch.setattr(scan_mod, "_published_pkg_meta", _registry(["agentavow/agentavow"]))
    pc = await _resolve_repo_package("AgentAvow", "AgentAvow", _tree("package.json"), None, None)
    assert pc["name"] == "x"


@pytest.mark.parametrize("url,shorthand,expected", [
    ("git+https://github.com/vercel/next.js.git", False, "vercel/next.js"),
    ("https://github.com/Vercel/Next.js/tree/canary/packages/next", False, "vercel/next.js"),
    ("git@github.com:o/r.git", False, "o/r"),
    ("https://github.com/o/r#readme", False, "o/r"),
    ("https://github.com/o/r?tab=x", False, "o/r"),
    ("o/r", True, "o/r"),
    ("github:o/r", True, "o/r"),
    ("o/r", False, None),
    ("gitlab:o/r", True, None),
    ("https://gitlab.com/o/r", False, None),
    ("", False, None),
])
def test_github_slug(url, shorthand, expected):
    assert _github_slug(url, allow_shorthand=shorthand) == expected
