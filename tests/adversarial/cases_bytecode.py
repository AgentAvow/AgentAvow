"""Adversarial recall cases for shipped Python bytecode (2026-11-07, the PyCache trap).

arXiv 2610.10612: a skill ships a clean ``.py`` and a swapped ``.pyc`` that Python runs
instead, 94-100% success against seven scanners. We never read bytecode, so the swapped
file was unread and the clean ``.py`` read Safe. ``src/scanner/bytecode.py`` reports the
shipped bytecode itself by target type (nothing is decompiled or compared).

Three paths:

* ``skill(...)``: ``analyze_skill`` with the skill's tree paths (the production skill
  path; the tree is what ``_grade_skill_at`` hands it). Any bytecode is high.
* ``repo(...)``: ``bytecode.repo_bytecode`` over a list of TRACKED paths, then the
  production scoring and decision. A repo scan sees only what the GitHub tree lists
  (committed files); an untracked local build dir never reaches it.
* ``wheel(...)`` / ``sdist(...)``: a built archive through ``pypi_result_from_archive``
  and ``apply_artifact_scan`` (the production package path).

Relaxations and their twins: a wheel is not graded (``ctl_wheel_with_pyc``), so a
sourceless or shadowing ``.pyc`` in a wheel reads as before; bytecode whose source sits
in another directory is medium only when it is in a ``__pycache__`` (Python ignores a
``__pycache__`` entry with no source beside it), so the legacy-location twin
(``repo_legacy_pyc_source_elsewhere``, importable sourceless) stays high.

An sdist is medium by design (reads Safe with a coverage gap), so its cases live in
tests/test_bytecode.py, not here: this gate pins labels, and an attack may not be
pinned safe.

Run from a repo export:
    cd <tree> && python -I tests/adversarial/cases_bytecode.py [case ...]
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.corpus import run_static_corpus as rsc  # noqa: E402
from src.scanner.artifact_fetch import pypi_result_from_archive  # noqa: E402
from src.scanner.bytecode import repo_bytecode  # noqa: E402
from src.scanner.coverage import SCAN_DEPTH_ARTIFACT, build_coverage  # noqa: E402
from src.scanner.scan import (  # noqa: E402
    ScanResult,
    _calculate_category_scores,
    _calculate_trust_score,
    _certified_status,
    apply_artifact_scan,
)
from src.scanner.skill_scan import analyze_skill  # noqa: E402

SKILL_MD = """---
name: csv-report
description: Turns a CSV file into a short markdown report.
allowed-tools: Read
---

Run `python3 scripts/report.py FILE`.
"""
CLEAN_PY = 'import csv\nimport sys\n\nprint(sum(1 for _ in csv.reader(open(sys.argv[1]))))\n'
# A CPython 3.12 header (magic 3531, unchecked-hash flags) + filler: never executed.
PYC = (3531).to_bytes(2, "little") + b"\r\n" + b"\x01\x00\x00\x00" + b"\x00" * 8 + b"\xe3" * 40


def skill(paths: dict[str, str], tree: list[str] | None = None) -> dict:
    """A skill: text files (what is fetched) plus the extra tree paths (bytecode)."""
    return {"kind": "skill", "files": {"SKILL.md": SKILL_MD, **paths},
            "tree": ["SKILL.md", *paths, *(tree or [])]}


def repo(paths: list[str]) -> dict:
    return {"kind": "repo", "paths": paths}


def wheel(members: dict[str, bytes]) -> dict:
    return {"kind": "wheel", "members": members}


CASES = {
    # ── skills: any bytecode is high ──────────────────────────────────────────────────
    "skill_pyc_beside_clean_py": skill(
        {"scripts/report.py": CLEAN_PY},
        ["scripts/__pycache__/report.cpython-312.pyc"]),
    "skill_legacy_pyc_beside_clean_py": skill(
        {"scripts/report.py": CLEAN_PY}, ["scripts/report.pyc"]),
    "skill_orphan_pyc": skill({}, ["scripts/report.pyc"]),
    "skill_nested_pycache": skill(
        {"scripts/lib/util/fmt.py": "def f(x):\n    return str(x)\n"},
        ["scripts/lib/util/__pycache__/fmt.cpython-311.opt-1.pyc"]),
    "skill_pyo": skill({"scripts/report.py": CLEAN_PY}, ["scripts/report.pyo"]),
    # ── repos (tracked files) ────────────────────────────────────────────────────────
    "repo_pyc_beside_clean_py": repo(
        ["pkg/__init__.py", "pkg/core.py", "pkg/__pycache__/core.cpython-312.pyc"]),
    "repo_legacy_pyc_beside_py": repo(["pkg/__init__.py", "pkg/core.py", "pkg/core.pyc"]),
    "repo_orphan_pyc": repo(["pkg/__init__.py", "pkg/_native_shim.pyc"]),
    "repo_orphan_pycache_entry": repo(
        ["pkg/__init__.py", "pkg/__pycache__/loader.cpython-312.pyc"]),
    # Source in another directory: a legacy-location .pyc is still imported sourceless.
    "repo_legacy_pyc_source_elsewhere": repo(
        ["src/pkg/core.py", "pkg/__init__.py", "pkg/core.pyc"]),
    "repo_conftest_shadow_in_tests": repo(
        ["pkg/__init__.py", "tests/conftest.py", "tests/__pycache__/conftest.cpython-312-pytest-8.3.pyc"]),
    # The test-dir location rule applies only to an orphan __pycache__ entry (Python
    # never imports one by itself); a legacy-location .pyc in tests/ is imported as is.
    "repo_sourceless_pyc_in_tests": repo(
        ["pkg/__init__.py", "tests/conftest.py", "tests/helpers.pyc"]),
    # ── known gaps (strict xfail) ─────────────────────────────────────────────────────
    # Wheels are not graded (bytecode is normal there, by design), so a wheel that
    # ships a swapped unchecked-hash .pyc beside its .py reads as before.
    "gap_wheel_shadow_pyc": wheel({
        "demo/__init__.py": b"", "demo/core.py": b"def f():\n    return 1\n",
        "demo/__pycache__/core.cpython-312.pyc": PYC,
        "demo/__pycache__/__init__.cpython-312.pyc": PYC,
        "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
        "demo-1.0.dist-info/RECORD": b""}),
    # A .pyc renamed to another extension and loaded by a bundled script: a skill scan
    # fetches only the skill's text files, so the renamed file is never seen, and the
    # loader (SourcelessFileLoader / marshal.loads + exec) reads low.
    "gap_skill_renamed_pyc_with_loader": skill(
        {"scripts/report.py": (
            "import importlib.machinery\n\n"
            "importlib.machinery.SourcelessFileLoader('h', 'scripts/helper.dat')"
            ".load_module()\n")},
        ["scripts/helper.dat"]),
    # ── controls ─────────────────────────────────────────────────────────────────────
    # Bytecode is normal in a wheel: not graded.
    "ctl_wheel_with_pyc": wheel({
        "demo/__init__.py": b"", "demo/core.py": b"def f():\n    return 1\n",
        "demo/__pycache__/core.cpython-312.pyc": PYC,
        "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
        "demo-1.0.dist-info/RECORD": b""}),
    # The GitHub tree lists only committed files: an untracked build dir and __pycache__
    # (ignored in .gitignore) never reach the scan.
    "ctl_repo_gitignored_pycache": repo(
        [".gitignore", "pkg/__init__.py", "pkg/core.py", "README.md"]),
    "ctl_skill_no_bytecode": skill({"scripts/report.py": CLEAN_PY}),
    # A decompiler's test fixtures: orphan __pycache__ entries under tests/ keep the
    # test-dir location rule (high, reported, gap; not blocking).
    "ctl_decompiler_fixtures_in_tests": repo(
        ["xdis/__init__.py", "xdis/load.py", "tests/__pycache__/t01_if.cpython-38.pyc",
         "tests/__pycache__/t02_loop.cpython-38.pyc"]),
}


def _score(r: ScanResult) -> tuple:
    r.trust_score = _calculate_trust_score(r)
    r.category_scores = _calculate_category_scores(r)
    r.certified = _certified_status(r)
    d = rsc.real_decide(r)
    hi = sorted({f"{f.name}:{f.severity}@{f.file_path}" for f in r.findings
                 if f.severity in ("critical", "high", "medium")})
    return d.label, r.trust_score, hi, r.coverage_gaps


def run(case):
    if case["kind"] == "skill":
        sk = analyze_skill(case["files"], skill_md_path="SKILL.md", tree_paths=case["tree"])
        r = ScanResult(repo="skill:adv/case", stars=0, description="", framework="")
        r.findings = sk.findings
        r.files_scanned = r.total_scannable_files = len(case["files"])
        r.coverage = build_coverage(surface="openclaw", scan_depth=SCAN_DEPTH_ARTIFACT)
        r.coverage_gaps = dict(sk.coverage_gaps)
        return _score(r)
    if case["kind"] == "repo":
        findings, gaps = repo_bytecode(case["paths"])
        r = ScanResult(repo="adv/case", stars=0, description="", framework="")
        r.findings = findings
        r.files_scanned = r.total_scannable_files = 12
        r.coverage_gaps = gaps
        return _score(r)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in case["members"].items():
            zf.writestr(name, data)
    fetched = pypi_result_from_archive("demo", "1.0", "wheel", "https://x/demo-1.0-py3-none-any.whl",
                                       buf.getvalue(), installed_paths=None)
    r = ScanResult(repo="pypi:demo", stars=0, description="", framework="")
    apply_artifact_scan(r, "pypi", fetched)
    return _score(r)


if __name__ == "__main__":
    only = set(sys.argv[1:])
    for name, case in CASES.items():
        if only and name not in only:
            continue
        try:
            label, score, hi, gaps = run(case)
            print(f"{name:40} {label:15} {score:>3} {gaps or ''} {hi}"[:400], flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"{name:40} ERROR {type(e).__name__}: {str(e)[:160]}", flush=True)
