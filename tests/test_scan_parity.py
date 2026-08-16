"""Hosted ↔ local parity — the drift guard.

Scans the SAME tree two ways: through ``scan_repo`` (the hosted path, with the
GitHub fetch mocked to serve a fixture) and through ``scan_local`` (the offline
path). The trust score and the finding set must be identical. If anyone changes
one path's detection/selection/scoring and not the other, this goes red.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.scanner import scan as scanmod
from src.scanner.local_scan import _walk_tree, scan_local

FIXTURE = {
    "app.py": (
        "import os\n"
        "def run(cmd):\n"
        "    os.system(cmd)  # unsafe exec\n"
    ),
    "config.py": (
        # a real-looking (but generic, non-provider) hardcoded secret — flagged in
        # BOTH paths. Deliberately not a provider format so it doesn't trip GitHub's
        # own push protection on this test fixture.
        'api_key = "kQ8fJ2mN7pR4tV6wX9zB1cD3eF5gH0jL"\n'
    ),
    "clean.py": "def add(a, b):\n    return a + b\n",
    "requirements.txt": "requests==2.31.0\n",
    "README.md": "# demo\nA demo tool.\n",
}


def _make_fixture(root: Path) -> None:
    for name, body in FIXTURE.items():
        (root / name).write_text(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=root, check=True)


def _finding_key(f) -> tuple:
    return (f.category, f.severity, f.file_path, f.line_number, f.name)


@pytest.mark.asyncio
async def test_hosted_and_local_agree(tmp_path, monkeypatch):
    _make_fixture(tmp_path)

    # The mocked GitHub tree serves exactly the git-tracked file set the local
    # scanner uses, so both paths grade the same files.
    tree = _walk_tree(tmp_path)

    async def fake_tree(owner, repo, token, *a, **k):
        return (tree, False, True, "main")

    async def fake_content(owner, repo, path, token, ref=None, *a, **k):
        p = tmp_path / path
        return p.read_text(encoding="utf-8") if p.exists() else None

    async def fake_pkg(*a, **k):
        return {}

    async def fake_noop(*a, **k):
        return None

    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    # package-coordinate resolution would hit registries; irrelevant to score/findings.
    monkeypatch.setattr(scanmod, "_resolve_repo_package", fake_pkg)
    # Disable the hosted-ONLY network signals so we compare the shared STATIC engine
    # apples-to-apples with the offline scanner (OSV supply-chain, published-artifact
    # diffing, maintainer metadata are documented hosted extras the local scan omits).
    monkeypatch.setattr(scanmod, "_run_supply_chain", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_scan_artifact", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_maintainer_signals", fake_noop)

    hosted = await scanmod.scan_repo("owner/repo", token="x")
    local = scan_local(tmp_path)

    assert hosted.error is None
    assert local.error is None

    # same headline score
    assert hosted.trust_score == local.trust_score, (
        f"score drift: hosted={hosted.trust_score} local={local.trust_score}"
    )

    # same findings (category · severity · file · line · name)
    hk = sorted(_finding_key(f) for f in hosted.findings)
    lk = sorted(_finding_key(f) for f in local.findings)
    assert hk == lk, f"finding drift:\n hosted={hk}\n local={lk}"

    # sanity: the fixture's real secret + unsafe exec were actually caught
    cats = {f.category for f in local.findings}
    assert "secret" in cats
    assert "unsafe_exec" in cats
