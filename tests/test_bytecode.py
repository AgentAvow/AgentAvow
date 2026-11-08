"""Shipped Python bytecode by target type (src/scanner/bytecode.py, the PyCache trap).

The label-level twins and controls are in tests/adversarial/cases_bytecode.py. These pin
the per-target rules (including the sdist medium, which reads Safe and so cannot sit in
the attack gate), the header check, the wiring into the repo / skill / package paths,
and the coverage gap.
"""
from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from src.scanner import bytecode as bc
from src.scanner import scan as scanmod
from src.scanner.artifact_fetch import _make_file, pypi_result_from_archive
from src.scanner.verdict import cheap_coverage_gap, coverage_gap_notes, decide

PYC = (3531).to_bytes(2, "little") + b"\r\n" + b"\x00" * 12 + b"\xe3" * 40


def test_bytecode_paths():
    for p in ("a.pyc", "x/a.pyo", "x/__pycache__/a.cpython-312.pyc",
              "x/__pycache__/a.cpython-312.opt-2.pyc", "x/__pycache__/odd.bin"):
        assert bc.is_bytecode_path(p), p
    for p in ("a.py", "pyc.py", "__pycache__", "docs/__pycache__.md", "a.pyx"):
        assert not bc.is_bytecode_path(p), p


def test_pyc_header():
    assert bc.looks_like_pyc(PYC)
    assert bc.looks_like_pyc((62211).to_bytes(2, "little") + b"\r\n" + b"\x00" * 4)  # 2.7
    assert not bc.looks_like_pyc(b"\x89PNG\r\n\x1a\n")
    assert not bc.looks_like_pyc(b"#!/usr/bin/env python\n")
    assert not bc.looks_like_pyc(PYC[:4])
    assert _make_file("lib/helper.dat", PYC).pyc_header is True
    assert _make_file("lib/notes.txt", b"hello\r\nworld").pyc_header is False


def test_repo_kinds():
    paths = ["pkg/__init__.py", "pkg/a.py", "pkg/__pycache__/a.cpython-312.pyc",
             "pkg/b.pyc", "pkg/__pycache__/c.cpython-312.pyc", "src/pkg/d.py",
             "pkg/d.pyc", "build/lib/pkg/__pycache__/a.cpython-312.pyc"]
    assert dict(bc.classify_repo(paths)) == {
        "pkg/__pycache__/a.cpython-312.pyc": "shadow",
        "pkg/b.pyc": "sourceless",
        "pkg/__pycache__/c.cpython-312.pyc": "orphan_cache",
        "pkg/d.pyc": "sourceless",            # imported as is: no d.py beside it
        "build/lib/pkg/__pycache__/a.cpython-312.pyc": "elsewhere",
    }


def test_repo_findings_grade_and_gap():
    findings, gaps = bc.repo_bytecode(
        ["pkg/a.py", "pkg/__pycache__/a.cpython-312.pyc",
         "build/lib/pkg/__pycache__/a.cpython-312.pyc"])
    assert gaps == {"bytecode_unread": 2}
    by = {f.file_path: f for f in findings}
    shadow = by["pkg/__pycache__/a.cpython-312.pyc"]
    assert (shadow.category, shadow.severity, shadow.payload) == ("obfuscation", "high", True)
    other = by["build/lib/pkg/__pycache__/a.cpython-312.pyc"]
    assert (other.severity, other.payload) == ("medium", False)
    assert all(f.category != "secret" for f in findings)
    assert bc.repo_bytecode(["pkg/a.py", "README.md"]) == ([], {})


def test_one_finding_per_directory():
    paths = ["m/__init__.py"] + [f"m/__pycache__/x{i}.cpython-312.pyc" for i in range(40)]
    findings, gaps = bc.repo_bytecode(paths)
    assert len(findings) == 1 and gaps == {"bytecode_unread": 40}
    assert "40 files in m/" in findings[0].name
    assert findings[0].snippet.endswith("and 37 more (not read)")


def test_skill_scope_is_the_skill_directory():
    tree = ["skills/a/SKILL.md", "skills/a/run.py", "skills/a/lib/__pycache__/u.cpython-312.pyc",
            "skills/b/__pycache__/v.cpython-312.pyc", "other.pyc"]
    findings, gaps = bc.skill_bytecode(tree, "skills/a")
    assert gaps == {"bytecode_unread": 1}
    assert [(f.severity, f.file_path) for f in findings] == [
        ("high", "skills/a/lib/__pycache__/u.cpython-312.pyc")]
    assert bc.skill_bytecode(tree, "")[1] == {"bytecode_unread": 3}


def _sdist(members: dict[str, bytes]) -> object:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo("demo-1.0/" + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return pypi_result_from_archive("demo", "1.0", "sdist", "https://x/demo-1.0.tar.gz",
                                    buf.getvalue(), installed_paths=None)


def _wheel(members: dict[str, bytes]) -> object:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return pypi_result_from_archive("demo", "1.0", "wheel", "https://x/demo-1.0-py3-none-any.whl",
                                    buf.getvalue(), installed_paths=None)


def _apply(fetched, eco="pypi"):
    r = scanmod.ScanResult(repo=f"{eco}:demo", stars=0, description="", framework="")
    scanmod.apply_artifact_scan(r, eco, fetched)
    return r


def test_sdist_bytecode_is_medium_with_a_gap_and_renamed_pyc_is_caught():
    r = _apply(_sdist({"setup.py": b"from setuptools import setup\nsetup()\n",
                       "demo/__init__.py": b"", "demo/core.py": b"X = 1\n",
                       "demo/__pycache__/core.cpython-312.pyc": PYC,
                       "demo/helper.dat": PYC}))
    hits = [f for f in r.findings if f.category == "obfuscation" and "bytecode" in f.name]
    assert {f.severity for f in hits} == {"medium"}
    assert r.coverage_gaps.get("bytecode_unread") == 2
    assert any("helper.dat" in f.snippet for f in hits)


def test_wheel_bytecode_is_not_graded():
    r = _apply(_wheel({"demo/__init__.py": b"", "demo/core.py": b"X = 1\n",
                       "demo/__pycache__/core.cpython-312.pyc": PYC,
                       "demo-1.0.dist-info/METADATA": b"Name: demo\n"}))
    assert not [f for f in r.findings if "bytecode" in f.name]
    assert "bytecode_unread" not in (r.coverage_gaps or {})


def test_gap_note_is_disclosure_and_blocks_the_mark():
    data = {"trust_score": 92, "findings": {"items": []}, "metadata": {"files_scanned": 40},
            "coverage_gaps": {"bytecode_unread": 2}}
    assert decide(data).decision == "safe"
    assert coverage_gap_notes(data) == ["2 Python bytecode files were not read"]
    assert cheap_coverage_gap(data) is True


@pytest.mark.asyncio
async def test_scan_skill_reads_review_on_bytecode_it_never_fetches(monkeypatch):
    files = {"SKILL.md": "---\nname: demo\ndescription: A demo skill.\n---\nRun run.py.\n",
             "run.py": "print(1)\n", "__pycache__/run.cpython-312.pyc": "x"}

    async def fake_tree(owner, repo, token, meta_out=None):
        return ([{"path": p, "type": "blob", "size": 1} for p in files], False, True, "main")

    fetched: list[str] = []

    async def fake_content(owner, repo, path, token=None, ref=None, *a, **k):
        fetched.append(path)
        return files.get(path)

    async def fake_token():
        return None

    import src.github_auth as gh
    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    monkeypatch.setattr(gh, "get_github_token", fake_token)
    r = await scanmod.scan_skill("o", "r")
    assert r.error is None
    assert "__pycache__/run.cpython-312.pyc" not in fetched
    assert r.coverage_gaps == {"bytecode_unread": 1}
    assert [f.severity for f in r.findings if "bytecode" in f.name] == ["high"]
    from src.api.public_scan_router import _scan_result_to_dict
    assert decide(_scan_result_to_dict(r)).decision == "review"


@pytest.mark.asyncio
async def test_scan_repo_reports_tracked_bytecode(monkeypatch):
    from tests.test_coverage_gaps import _patch_repo

    _patch_repo(monkeypatch, oversized=[{"path": "pkg/big.pyc", "type": "blob",
                                         "size": scanmod._MAX_FILE_SIZE + 1}], fail=set())
    r = await scanmod.scan_repo("owner/repo", token="x")
    assert r.error is None
    assert r.coverage_gaps.get("bytecode_unread") == 1
    assert [f.file_path for f in r.findings if "bytecode" in f.name] == ["pkg/big.pyc"]
