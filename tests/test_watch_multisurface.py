"""Multi-surface watch dispatch — scan_watch_target routes each surface to the
right scanner and fails open (None) so the re-scan loop never false-alerts on a
transient scan failure."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.api import watch_router


@pytest.mark.asyncio
async def test_npm_dispatches_to_scan_package(monkeypatch):
    called = {}

    async def fake_scan_package(surface, name):
        called["args"] = (surface, name)
        return SimpleNamespace(error=None, trust_score=94)

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    score, digest = await watch_router.scan_watch_target("npm", "npm", "sigstore", db=None)
    assert called["args"] == ("npm", "sigstore")
    assert score == 94
    assert digest is None


@pytest.mark.asyncio
async def test_pypi_dispatches_to_scan_package(monkeypatch):
    async def fake_scan_package(surface, name):
        return SimpleNamespace(error=None, trust_score=88)

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    score, _ = await watch_router.scan_watch_target("pypi", "pypi", "requests", db=None)
    assert score == 88


@pytest.mark.asyncio
async def test_mcp_dispatches_to_scan_mcp(monkeypatch):
    called = {}

    async def fake_scan_mcp(endpoint):
        called["endpoint"] = endpoint
        return SimpleNamespace(error=None, trust_score=70, tool_manifest_digest="sha256:abc")

    monkeypatch.setattr("src.scanner.scan.scan_mcp", fake_scan_mcp)
    score, digest = await watch_router.scan_watch_target(
        "mcp", "mcp", "https://mcp.example.com/sse", db=None,
    )
    assert called["endpoint"] == "https://mcp.example.com/sse"
    assert score == 70
    # The served tool-definition digest reaches the watch loop, so a changed
    # definition on a live endpoint can fire the drift alert.
    assert digest == "sha256:abc"


@pytest.mark.asyncio
async def test_mcp_without_tools_reports_no_digest(monkeypatch):
    async def fake_scan_mcp(endpoint):
        return SimpleNamespace(error=None, trust_score=70, tool_manifest_digest=None)

    monkeypatch.setattr("src.scanner.scan.scan_mcp", fake_scan_mcp)
    score, digest = await watch_router.scan_watch_target(
        "mcp", "mcp", "https://mcp.example.com/sse", db=None,
    )
    assert score == 70 and digest is None


@pytest.mark.asyncio
async def test_openclaw_dispatches_to_scan_skill(monkeypatch):
    async def fake_scan_skill(owner, repo):
        return SimpleNamespace(error=None, trust_score=82, tool_manifest_digest="abc123")

    monkeypatch.setattr("src.scanner.scan.scan_skill", fake_scan_skill)
    score, digest = await watch_router.scan_watch_target("openclaw", "acme", "my-skill", db=None)
    assert score == 82
    assert digest == "abc123"


@pytest.mark.asyncio
async def test_scan_error_fails_open(monkeypatch):
    """A scanner returning an error yields (None, ...) — the loop retries, never alerts."""
    async def fake_scan_package(surface, name):
        return SimpleNamespace(error="registry 500", trust_score=None)

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    score, _ = await watch_router.scan_watch_target("npm", "npm", "brokenpkg", db=None)
    assert score is None


@pytest.mark.asyncio
async def test_exception_fails_open(monkeypatch):
    """A scanner that raises is swallowed → (None, None), not a crash."""
    async def fake_scan_mcp(endpoint):
        raise RuntimeError("boom")

    monkeypatch.setattr("src.scanner.scan.scan_mcp", fake_scan_mcp)
    score, digest = await watch_router.scan_watch_target("mcp", "mcp", "https://x", db=None)
    assert score is None
    assert digest is None


@pytest.mark.asyncio
async def test_github_dispatches_to_public_scan(monkeypatch):
    """The github surface (and an empty one, the column default) uses public_scan."""
    called = {}

    async def fake_public_scan(owner, repo, force, db):
        called["args"] = (owner, repo)
        return SimpleNamespace(trust_score=55, tool_manifest_digest="ghdigest")

    monkeypatch.setattr("src.api.public_scan_router.public_scan", fake_public_scan)
    score, digest = await watch_router.scan_watch_target("github", "torvalds", "linux", db=None)
    assert called["args"] == ("torvalds", "linux")
    assert score == 55
    assert digest == "ghdigest"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface,name", [("crates", "serde"),
                                          ("huggingface", "openai/whisper-large-v3")])
async def test_crates_and_huggingface_dispatch_to_scan_package(monkeypatch, surface, name):
    # A crates claim's auto-watch (owner "crates") used to fall through to the GitHub
    # scan of crates/<name> and never scored (2026-11-10).
    called = {}

    async def fake_scan_package(s, n):
        called["args"] = (s, n)
        return SimpleNamespace(error=None, trust_score=81)

    async def no_public_scan(**kw):
        raise AssertionError("must not reach the GitHub scan")

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    monkeypatch.setattr("src.api.public_scan_router.public_scan", no_public_scan)
    score, digest = await watch_router.scan_watch_target(surface, surface, name, db=None)
    assert called["args"] == (surface, name)
    assert score == 81 and digest is None


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["gitlab", "rubygems", "x402", "community"])
async def test_unsupported_surface_never_reaches_the_github_scan(monkeypatch, surface):
    async def no_public_scan(**kw):
        raise AssertionError("must not reach the GitHub scan")

    monkeypatch.setattr("src.api.public_scan_router.public_scan", no_public_scan)
    score, digest = await watch_router.scan_watch_target(surface, surface, "x", db=None)
    assert score is None and digest is None


def test_claim_surfaces_are_all_watchable():
    from src.api import account_claims_router as cr
    assert set(cr._SURFACES) <= set(watch_router.WATCH_SURFACES)


# ── re-scan loop: drift decision + baseline ──────────────────────────────────
def test_changed_digest_is_drift_and_becomes_the_baseline():
    from src.jobs.scheduler import _watch_digest_state

    assert _watch_digest_state("sha256:a", "sha256:b") == (True, "sha256:b")
    assert _watch_digest_state("sha256:a", "sha256:a") == (False, "sha256:a")


def test_first_digest_sets_the_baseline_without_alerting():
    from src.jobs.scheduler import _watch_digest_state

    assert _watch_digest_state(None, "sha256:a") == (False, "sha256:a")


def test_empty_scan_keeps_the_baseline_so_a_later_change_still_alerts():
    """A live server that serves no tools for one cycle must not reset the baseline."""
    from src.jobs.scheduler import _watch_digest_state

    drift, baseline = _watch_digest_state("sha256:a", None)
    assert (drift, baseline) == (False, "sha256:a")
    assert _watch_digest_state(baseline, "sha256:b") == (True, "sha256:b")
