"""Release-tag drift comparison: a published package must be diffed against its OWN
release tag (via git blob SHAs), not the default branch. This kills the version-skew
false positive where an active repo's main branch has moved past the release."""
from __future__ import annotations

from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile
from src.scanner.artifact_scan import compute_drift


def _af(path: str, blob_sha: str) -> ArtifactFile:
    return ArtifactFile(path=path, size=10, sha256="x", text="code",
                        text_sha256="h", git_blob_sha=blob_sha)


def _fetched(files: dict) -> ArtifactFetchResult:
    return ArtifactFetchResult(ecosystem="pypi", name="mcp", version="2.0.0",
                               kind="sdist", ok=True, files=files)


def test_artifact_matching_release_tag_has_no_drift():
    # every artifact file is byte-identical to the v2.0.0 tag (matching blob SHAs),
    # even though the repo's main branch has moved on — this is the FP we fixed.
    fetched = _fetched({
        "src/mcp/a.py": _af("src/mcp/a.py", "aaa"),
        "src/mcp/b.py": _af("src/mcp/b.py", "bbb"),
        "PKG-INFO": _af("PKG-INFO", "zzz"),  # ignorable metadata
    })
    release = {"src/mcp/a.py": "aaa", "src/mcp/b.py": "bbb"}
    drift, findings = compute_drift(fetched, None, None, has_install_hook=False,
                                    release_blob_shas=release)
    assert [f for f in findings if f.category == "artifact_drift"] == []
    assert drift["added_count"] == 0 and drift["modified_count"] == 0
    assert drift["compared"] is True


def test_injected_file_absent_from_release_flags():
    fetched = _fetched({
        "src/mcp/a.py": _af("src/mcp/a.py", "aaa"),        # in the release
        "src/mcp/backdoor.py": _af("src/mcp/backdoor.py", "evil"),  # NOT in the release
    })
    release = {"src/mcp/a.py": "aaa"}
    _, findings = compute_drift(fetched, None, None, has_install_hook=False,
                               release_blob_shas=release)
    names = [f.name for f in findings if f.category == "artifact_drift"]
    assert any("ships 1 source" in n for n in names), names


def test_tampered_file_differs_from_release_flags():
    fetched = _fetched({"src/mcp/a.py": _af("src/mcp/a.py", "tampered")})
    release = {"src/mcp/a.py": "original"}  # same path, different blob → modified
    _, findings = compute_drift(fetched, None, None, has_install_hook=False,
                               release_blob_shas=release)
    names = [f.name for f in findings if f.category == "artifact_drift"]
    assert any("modifies 1" in n for n in names), names


def test_falls_back_to_branch_view_when_no_release_tag():
    # release_blob_shas=None → old default-branch behavior (path + text-hash based)
    fetched = _fetched({"src/mcp/a.py": _af("src/mcp/a.py", "aaa")})
    drift, findings = compute_drift(fetched, {"src/mcp/a.py"}, {}, has_install_hook=False,
                                    release_blob_shas=None)
    # present in repo_paths, no text-hash mismatch → no drift
    assert [f for f in findings if f.category == "artifact_drift"] == []
