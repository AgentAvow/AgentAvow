"""The repo-advisory rescan selector: read-only list building (no network, no DB)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_P = Path(__file__).resolve().parent.parent / "scripts" / "select_repo_advisory_rescans.py"
_spec = importlib.util.spec_from_file_location("select_repo_advisory_rescans", _P)
sel = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = sel  # dataclasses look the module up while defining
_spec.loader.exec_module(sel)

ADV = {"ghsa_id": "GHSA-mvf5-2qqv-rg3c", "cve_id": None, "summary": "x", "severity": "high",
       "state": "published", "withdrawn_at": None,
       "vulnerabilities": [{"package": {"ecosystem": "npm",
                                        "name": "@modelcontextprotocol/server-everything"},
                            "vulnerable_version_range": "< 2.0.1",
                            "patched_versions": "2.0.1"}]}


def test_dedupe_keeps_first_and_normalises_pypi_names():
    got = sel.dedupe([("npm", "A"), ("npm", "a"), ("pypi", "Foo_Bar"), ("pypi", "foo-bar"),
                      ("docker", "x"), ("crates", "serde")])
    assert got == [("npm", "A"), ("pypi", "Foo_Bar"), ("crates", "serde")]


def test_coords_from_files(tmp_path):
    (tmp_path / "npm-agents-results.json").write_text(json.dumps(
        {"results": [{"name": "a"}, {"full_name": "o/r"}, "junk"]}))
    assert sel.coords_from_files(tmp_path) == [("npm", "a")]


@pytest.mark.asyncio
@pytest.mark.parametrize("version,affected", [("2.0.0", True), ("2.2.1", False)])
async def test_lists_packages_the_repo_advisories_name(tmp_path, version, affected):
    async def _resolve(c, _client):
        c.version, c.slug = version, "modelcontextprotocol/servers"

    fetch = AsyncMock(return_value={"checked": True, "advisories": [ADV]})
    args = sel.argparse.Namespace(
        source="none", coord=["npm:@modelcontextprotocol/server-everything",
                              "npm:@modelcontextprotocol/server-memory"],
        data_dir=str(tmp_path), out_dir=str(tmp_path / "o"), limit=0, concurrency=2,
        delay=0, gh_delay=0, github_token="t")
    with patch.object(sel, "resolve", new=_resolve), \
         patch("src.scanner.incident_history.fetch_repo_advisories", new=fetch):
        summary = await sel.run(args)
    assert fetch.await_count == 1  # one lookup per distinct repo
    lines = (tmp_path / "o" / "repo-advisory-rescan.txt").read_text().splitlines()
    assert lines == ["npm:@modelcontextprotocol/server-everything"]  # sibling not named
    assert summary["affected_at_latest"] == (1 if affected else 0)


@pytest.mark.asyncio
async def test_a_failed_repo_lookup_is_reported_not_listed(tmp_path):
    async def _resolve(c, _client):
        c.version, c.slug = "1.3.0", "stevemao/left-pad"

    fetch = AsyncMock(return_value={"checked": False, "reason": "http_301"})
    args = sel.argparse.Namespace(
        source="none", coord=["npm:left-pad"], data_dir=str(tmp_path),
        out_dir=str(tmp_path / "o"), limit=0, concurrency=1, delay=0, gh_delay=0,
        github_token="t")
    with patch.object(sel, "resolve", new=_resolve), \
         patch("src.scanner.incident_history.fetch_repo_advisories", new=fetch):
        summary = await sel.run(args)
    assert summary["repo_lookup_failed"] == ["stevemao/left-pad"]
    assert summary["rescan"] == 0
