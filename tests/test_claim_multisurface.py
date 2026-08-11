"""Multi-surface claim — coordinate mapping, GitHub-repo normalization, and the
npm/PyPI repo-linked auto-grant dispatch (provenance/declared → keyword fallback)."""
from __future__ import annotations

import pytest

from src.api import account_claims_router as cr

# ---- _claim_coord: request → stored (owner, repo, full_name) per surface ----

def test_coord_github():
    assert cr._claim_coord("github", "chalk", "chalk") == ("chalk", "chalk", "chalk/chalk")


def test_coord_openclaw_like_github():
    assert cr._claim_coord("openclaw", "acme", "my-skill") == ("acme", "my-skill", "acme/my-skill")


def test_coord_npm_forces_surface_owner():
    # npm/pypi: owner=surface, repo=package, full_name='surface:pkg'
    assert cr._claim_coord("npm", "ignored", "chalk") == ("npm", "chalk", "npm:chalk")
    assert cr._claim_coord("pypi", "", "requests") == ("pypi", "requests", "pypi:requests")


def test_coord_npm_scoped_package():
    assert cr._claim_coord("npm", "", "@scope/pkg") == ("npm", "@scope/pkg", "npm:@scope/pkg")


def test_coord_mcp_url():
    got = cr._claim_coord("mcp", "", "https://mcp.example.com/sse")
    assert got == ("mcp", "https://mcp.example.com/sse", "https://mcp.example.com/sse")


def test_coord_mcp_rejects_non_url():
    assert cr._claim_coord("mcp", "", "not-a-url") is None


def test_coord_rejects_bad_github():
    assert cr._claim_coord("github", "", "") is None
    assert cr._claim_coord("github", "a b", "c") is None


# ---- _norm_github_repo: any GitHub URL/spec → lowercase owner/repo ----

@pytest.mark.parametrize("url,expected", [
    ("git+https://github.com/chalk/chalk.git", "chalk/chalk"),
    ("https://github.com/facebook/React", "facebook/react"),
    ("git@github.com:sindresorhus/is.git", "sindresorhus/is"),
    ("github.com/psf/requests", "psf/requests"),
    ("psf/requests", "psf/requests"),
    ("https://gitlab.com/foo/bar", None),  # non-GitHub host → None
    ("", None),
    (None, None),
])
def test_norm_github_repo(url, expected):
    assert cr._norm_github_repo(url) == expected


# ---- _package_grant: repo-linked auto-grant dispatch (mocked network + DB) ----

@pytest.mark.asyncio
async def test_grant_via_declared_repo(monkeypatch):
    async def fake_declared(surface, name):
        return "chalk/chalk"

    async def fake_prov(surface, name):
        return None

    async def fake_owns(db, entity_id, full_name):
        return full_name == "chalk/chalk"

    monkeypatch.setattr(cr, "_declared_repo", fake_declared)
    monkeypatch.setattr(cr, "_provenance_repo", fake_prov)
    monkeypatch.setattr(cr, "_user_owns_repo", fake_owns)
    granted, method = await cr._package_grant(db=None, entity_id="e", surface="npm", name="chalk")
    assert granted is True
    assert method == "declared-repo"


@pytest.mark.asyncio
async def test_grant_via_provenance_when_no_declared_match(monkeypatch):
    async def fake_declared(surface, name):
        return "someone/else"  # user doesn't own this

    async def fake_prov(surface, name):
        return "me/mine"  # provenance binds a repo the user owns

    async def fake_owns(db, entity_id, full_name):
        return full_name == "me/mine"

    monkeypatch.setattr(cr, "_declared_repo", fake_declared)
    monkeypatch.setattr(cr, "_provenance_repo", fake_prov)
    monkeypatch.setattr(cr, "_user_owns_repo", fake_owns)
    granted, method = await cr._package_grant(db=None, entity_id="e", surface="npm", name="mine")
    assert granted is True
    assert method == "provenance"


@pytest.mark.asyncio
async def test_no_grant_when_repo_not_owned(monkeypatch):
    async def fake_declared(surface, name):
        return "facebook/react"

    async def fake_prov(surface, name):
        return None

    async def fake_owns(db, entity_id, full_name):
        return False  # owns nothing

    monkeypatch.setattr(cr, "_declared_repo", fake_declared)
    monkeypatch.setattr(cr, "_provenance_repo", fake_prov)
    monkeypatch.setattr(cr, "_user_owns_repo", fake_owns)
    granted, method = await cr._package_grant(db=None, entity_id="e", surface="npm", name="react")
    assert granted is False
    assert method is None
