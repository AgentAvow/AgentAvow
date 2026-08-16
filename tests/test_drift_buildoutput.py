"""Build-output drift precision: a compiled package shipping dist/*.js built from
src/*.ts must NOT raise a spurious 'ships N source files not in the repo' drift,
but genuinely injected source (outside build dirs) still must."""
from __future__ import annotations

from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile
from src.scanner.artifact_scan import compute_drift


def _af(path: str) -> ArtifactFile:
    return ArtifactFile(path=path, size=10, sha256="x", text="//code", text_sha256="h")


def _fetched(paths):
    return ArtifactFetchResult(
        ecosystem="npm", name="pkg", version="1.0.0", kind="tarball", ok=True,
        files={p: _af(p) for p in paths},
    )


def test_build_output_not_flagged_as_drift():
    # dist/* is compiled from the repo's src/*.ts — expected, not injection
    fetched = _fetched([
        "dist/index.js", "dist/tools/browser.js", "dist/index.d.ts",
        "package.json", "README.md",
    ])
    repo_paths = {"src/index.ts", "src/tools/browser.ts", "package.json", "README.md"}
    drift, findings = compute_drift(fetched, repo_paths, {}, has_install_hook=False)
    drift_findings = [f for f in findings if f.category == "artifact_drift"]
    assert not drift_findings, f"build output wrongly flagged: {[f.name for f in drift_findings]}"


def test_injected_source_outside_build_dir_still_flags():
    fetched = _fetched([
        "dist/index.js",          # expected build output
        "lib/backdoor.py",        # NOT a build dir — genuinely injected source
        "README.md",              # shared file → the diff is comparable
        "package.json",
    ])
    repo_paths = {"src/index.ts", "README.md", "package.json"}
    drift, findings = compute_drift(fetched, repo_paths, {}, has_install_hook=False)
    names = [f.name for f in findings if f.category == "artifact_drift"]
    assert any("ships 1 source" in n for n in names), names
