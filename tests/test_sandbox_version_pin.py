"""The sandbox installs the exact release the static scan resolved, and says so.

No database: run with ``--noconftest``. Route-level checks are in test_pinned_sandbox.py.
"""
from __future__ import annotations

import contextlib
import json
from unittest.mock import AsyncMock, patch

import pytest

import src.api.public_scan_router as psr
from src.scanner import artifact_fetch
from src.scanner.behavioral import runner

_OK = json.dumps({"exit_code": 0, "egress_hosts": [], "fs_writes": []})


async def _cmd(surface: str, coord: str, version: str | None, *, plan: str | None = None,
               v2: str = "") -> tuple[list[str] | None, object]:
    ex = AsyncMock(return_value=(_OK, None))
    with patch.object(runner, "_execute", new=ex), \
         patch("src.config.settings.scanner_behavioral_sandbox_runner_v2", v2):
        res = await runner.run_behavioral(surface, coord, version=version, plan=plan)
    return (ex.await_args.args[0] if ex.await_count else None), res


@pytest.mark.asyncio
async def test_npm_installs_the_exact_release_and_requires_the_bare_name():
    args, _ = await _cmd("npm", "left-pad", "1.3.0")
    cmd = args[-2]
    assert "npm install --no-audit --no-fund left-pad@1.3.0 " in cmd
    assert "require(\"left-pad\")" in cmd


@pytest.mark.asyncio
async def test_pip_installs_the_exact_release():
    args, _ = await _cmd("pypi", "requests", "2.32.3")
    cmd = args[-2]
    assert "pip install --no-input --user requests==2.32.3 " in cmd
    assert "import requests" in cmd


@pytest.mark.asyncio
async def test_mcp_plan_installs_the_exact_release():
    args, _ = await _cmd("npm", "@modelcontextprotocol/server-everything", "2.2.1",
                         plan="npm-mcp", v2="v2")
    cmd = args[-2]
    assert "npm install --no-audit --no-fund @modelcontextprotocol/server-everything@2.2.1 " in cmd


@pytest.mark.asyncio
async def test_docker_runs_the_tag():
    args, _ = await _cmd("docker", "mcp/fetch", "1.2.0", v2="v2")
    assert args[-3] == "mcp/fetch:1.2.0"
    args, _ = await _cmd("docker", "mcp/fetch:latest", "1.2.0", v2="v2")
    assert args[-3] == "mcp/fetch:latest"


@pytest.mark.asyncio
async def test_no_version_keeps_todays_command():
    args, _ = await _cmd("npm", "left-pad", None)
    assert "npm install --no-audit --no-fund left-pad " in args[-2]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["1.0.0;rm -rf /", "1.0.0 && x", "$(id)", "^1.0.0", ">=1",
                                 "1.0.0\n", "`id`", "-1.0"])
async def test_a_version_that_is_not_an_exact_release_never_runs(bad):
    args, res = await _cmd("npm", "left-pad", bad)
    assert args is None
    assert res.ran is False and res.error == "bad_version"


def test_observation_subject_names_the_release():
    p = psr._behavioral_observation_payload("npm", "x", {"version": "2.2.1"})
    assert p["subject"] == {"id": "pkg:npm/x@2.2.1", "surface": "npm", "name": "x",
                            "version": "2.2.1"}
    assert psr._behavioral_observation_payload("npm", "x", {})["subject"]["id"] == "pkg:npm/x"


def test_run_kwargs_carry_the_resolved_version_for_packages_only():
    pkg = {"package_coordinate": {"surface": "npm", "name": "x"}, "package_version": "2.2.1"}
    assert psr._behavioral_run_kwargs(pkg, "npm-mcp")["version"] == "2.2.1"
    repo = {"repo_full_name": "o/r", "primary_language": "python", "package_version": "1"}
    assert "version" not in psr._behavioral_run_kwargs(repo, "pypi-git")


class _Redis:
    def __init__(self, block):
        self.raw = json.dumps(block) if block is not None else None

    async def get(self, _key):
        return self.raw


@pytest.mark.asyncio
async def test_cached_block_for_another_release_is_a_miss():
    block = {"ran": True, "version": "2.2.1"}
    with patch("src.redis_client.get_redis", return_value=_Redis(block)):
        assert await psr._get_cached_behavioral("npm", "x", None, None, "2.2.2") is None
        assert await psr._get_cached_behavioral("npm", "x", None, None, "2.2.1") == block
        assert await psr._get_cached_behavioral("npm", "x", None, None) == block
    with patch("src.redis_client.get_redis", return_value=_Redis({"ran": True})):
        # unstamped (pre-change) blocks still serve the unpinned view until they expire
        assert await psr._get_cached_behavioral("npm", "x", None, None, "2.2.2") == {"ran": True}


@pytest.mark.asyncio
async def test_latest_is_the_dist_tag_not_the_highest_version():
    # server-everything: latest = 2.2.1, while deprecated date releases sort higher.
    packument = {"dist-tags": {"latest": "2.2.1"},
                 "versions": {v: {"version": v, "dist": {"tarball": f"https://t/{v}.tgz"}}
                              for v in ("2.0.0", "2.2.1", "2025.4.25", "2026.8.31")}}
    seen = {}

    def _fake_result(name, version, raw, **kw):
        seen["version"] = version
        return "ok"

    with patch.object(artifact_fetch, "_get_json", new=AsyncMock(return_value=packument)), \
         patch.object(artifact_fetch, "_download_spooled",
                      new=AsyncMock(return_value=contextlib.nullcontext(b""))), \
         patch.object(artifact_fetch, "npm_result_from_tarball", new=_fake_result):
        await artifact_fetch.fetch_npm_artifact("@modelcontextprotocol/server-everything",
                                                client=object())
    assert seen["version"] == "2.2.1"
