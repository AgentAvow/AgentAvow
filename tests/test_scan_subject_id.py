"""The signed ``subject.id`` names the surface that was actually scanned.

Every surface shares one payload builder. It used to prefix every coordinate with
``github:``, so an npm package was signed as ``github:npm:left-pad`` and a live MCP
endpoint as ``github:mcp:https://…``. A gate's subject check compares this field,
so it has to say what was scanned.
"""
from __future__ import annotations

import pytest

from src.api.public_scan_router import _build_scan_payload, _subject_id


def _result_data():
    return {
        "trust_score": 80,
        "trust_tier": "standard",
        "scan_result": "clean",
        "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0},
        "positive_signals": [],
        "recommended_limits": {},
        "category_scores": {},
        "metadata": {"files_scanned": 3, "primary_language": "python"},
        "scanned_at": "2026-07-01T00:00:00+00:00",
    }


def test_github_repo_keeps_its_subject_id():
    subject = _build_scan_payload("github/github-mcp-server", _result_data())["subject"]
    assert subject == {
        "id": "github:github/github-mcp-server", "repo": "github/github-mcp-server"}


@pytest.mark.parametrize("coordinate", [
    "npm:left-pad",
    "npm:@scope/pkg@1.2.3",
    "pypi:requests",
    "crates:serde",
    "huggingface:org/model",
    "docker:library/nginx",
    "skill:acme/my-skill",
    "mcp:https://mcp.example.com/mcp",
])
def test_surfaced_coordinate_is_not_relabelled_as_github(coordinate):
    subject = _build_scan_payload(coordinate, _result_data())["subject"]
    assert subject["id"] == coordinate
    assert subject["repo"] == coordinate


def test_github_owner_named_like_a_surface_is_still_github():
    # "npm/cli" is a GitHub repository, not an npm coordinate.
    assert _subject_id("npm/cli") == "github:npm/cli"
    assert _subject_id("docker/compose") == "github:docker/compose"
