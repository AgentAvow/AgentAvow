"""GitLab Code Quality output of the local CLI (src/scanner/local_scan.py).

Locks the report shape GitLab parses from ``artifacts:reports:codequality`` (the
gitlab/ component relies on it), the severity mapping, fingerprint stability under
line shifts, subdirectory path prefixing, and the ``--gitlab-code-quality`` flag
writing the file before the gate is applied.
"""
from __future__ import annotations

import io
import json
import subprocess

import pytest

from src.scanner.local_scan import (
    _print_human,
    _scan_path_prefix,
    main,
    result_to_code_quality,
    result_to_dict,
    scan_local,
    verdict_for,
)
from src.scanner.scan import Finding, ScanResult

pytestmark = pytest.mark.filterwarnings("ignore")

_CQ_SEVERITIES = {"info", "minor", "major", "critical", "blocker"}


def _git_init(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)


def _commit_all(path):
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=path, check=True)


def _finding(sev="high", path="app.py", line=3, name="os.system / os.popen (Python)",
             category="unsafe_exec", remediation="Validate input"):
    return Finding(category=category, name=name, severity=sev, file_path=path,
                   line_number=line, snippet="", remediation=remediation)


def _result(findings):
    r = ScanResult(repo="demo", stars=0, description="", framework="")
    r.findings = list(findings)
    return r


# --------------------------------------------------------------------------- #
# Converter
# --------------------------------------------------------------------------- #

def test_code_quality_issue_shape():
    report = result_to_code_quality(_result([_finding()]))
    assert len(report) == 1
    issue = report[0]
    # the fields GitLab requires
    assert issue["description"]
    assert issue["fingerprint"]
    assert issue["severity"] in _CQ_SEVERITIES
    assert issue["location"] == {"path": "app.py", "lines": {"begin": 3}}
    assert issue["check_name"] == "agentavow/unsafe_exec"
    assert issue["type"] == "issue"
    assert "Validate input" in issue["description"]
    json.dumps(report)


def test_severity_mapping_covers_every_scanner_severity():
    sevs = ["critical", "high", "medium", "low", "info"]
    report = result_to_code_quality(_result([_finding(sev=s, line=i + 1)
                                             for i, s in enumerate(sevs)]))
    assert [i["severity"] for i in report] == ["blocker", "critical", "major", "minor", "info"]


def test_unknown_severity_degrades_to_major_not_crash():
    report = result_to_code_quality(_result([_finding(sev="weird")]))
    assert report[0]["severity"] == "major"


def test_fingerprint_stable_under_line_shift_distinct_per_hit():
    """GitLab diffs fingerprints across branches: a finding must keep its id when
    code above it moves, and two hits of the same rule in one file must differ."""
    before = result_to_code_quality(_result([_finding(line=3), _finding(line=9)]))
    after = result_to_code_quality(_result([_finding(line=5), _finding(line=11)]))
    assert [i["fingerprint"] for i in before] == [i["fingerprint"] for i in after]
    assert before[0]["fingerprint"] != before[1]["fingerprint"]
    # and a different file / rule is a different id
    other = result_to_code_quality(_result([_finding(path="b.py")]))
    assert other[0]["fingerprint"] != before[0]["fingerprint"]


def test_line_floor_is_one():
    report = result_to_code_quality(_result([_finding(line=0)]))
    assert report[0]["location"]["lines"]["begin"] == 1


def test_path_prefix_for_subdirectory_scans():
    report = result_to_code_quality(_result([_finding()]), path_prefix="packages/api/")
    assert report[0]["location"]["path"] == "packages/api/app.py"
    # the prefix is part of the identity (same finding in two packages is two issues)
    plain = result_to_code_quality(_result([_finding()]))
    assert report[0]["fingerprint"] != plain[0]["fingerprint"]


def test_scan_path_prefix_from_ci_project_dir(tmp_path, monkeypatch):
    sub = tmp_path / "packages" / "api"
    sub.mkdir(parents=True)
    monkeypatch.delenv("CI_PROJECT_DIR", raising=False)
    assert _scan_path_prefix(sub) == ""
    monkeypatch.setenv("CI_PROJECT_DIR", str(tmp_path))
    assert _scan_path_prefix(sub) == "packages/api"
    assert _scan_path_prefix(tmp_path) == ""
    # a scan outside the checkout gets no prefix rather than a wrong one
    monkeypatch.setenv("CI_PROJECT_DIR", str(tmp_path / "elsewhere"))
    assert _scan_path_prefix(sub) == ""


# --------------------------------------------------------------------------- #
# Verdict wording (the one function the CLI derives it from)
# --------------------------------------------------------------------------- #

def test_verdict_for_tracks_shared_helpers():
    from src.scanner.verdict import is_safe
    from src.trust_tiers import verdict_phrase

    clean = _result([])
    clean.trust_score = 95
    clean.certified = {"eligible": False, "checks": {"no_critical_or_high": True}}
    phrase, value = verdict_for(clean)
    assert phrase == verdict_phrase(95, safe=is_safe(
        {"trust_score": 95, "certified": clean.certified}))
    assert (phrase, value) == ("Safe to connect", "safe")

    # a blocking finding demotes a high score to review
    held = _result([_finding()])
    held.trust_score = 95
    held.certified = {"eligible": False, "checks": {"no_critical_or_high": False}}
    assert verdict_for(held) == ("Review before you connect", "review")

    floor = _result([])
    floor.trust_score = 5
    floor.certified = {"eligible": False, "checks": {"no_critical_or_high": True}}
    assert verdict_for(floor) == ("Do not connect", "do_not_connect")

    d = result_to_dict(held)
    assert d["verdict"] == "review" and d["verdict_phrase"] == "Review before you connect"
    assert "grade" not in json.dumps(d).lower()


# --------------------------------------------------------------------------- #
# CLI flag
# --------------------------------------------------------------------------- #

def _fixture_repo(tmp_path):
    _git_init(tmp_path)
    (tmp_path / "app.py").write_text(
        "import os\ndef run(cmd):\n    os.system(cmd)\n\ndef run2(cmd):\n    os.system(cmd)\n"
    )
    _commit_all(tmp_path)
    return tmp_path


def test_cli_writes_code_quality_report_even_when_gate_fails(tmp_path, capsys):
    repo = _fixture_repo(tmp_path)
    out = tmp_path / "gl-code-quality-report.json"
    rc = main(["scan", str(repo), "--quiet", "--min-score", "100",
               "--gitlab-code-quality", str(out)])
    assert rc == 1  # gate failed ...
    report = json.loads(out.read_text())  # ... but the report is there for the widget
    assert len(report) >= 1
    assert {i["severity"] for i in report} <= _CQ_SEVERITIES
    assert all(i["location"]["path"] == "app.py" for i in report)
    assert "FAIL" in capsys.readouterr().err


def test_human_summary_leads_with_verdict_then_score(tmp_path):
    repo = _fixture_repo(tmp_path)
    buf = io.StringIO()
    _print_human(scan_local(repo), stream=buf)
    text = buf.getvalue()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert lines[0].startswith("AgentAvow")
    assert lines[1].strip().startswith("Verdict     : Review before you connect")
    assert lines[2].strip().startswith("Trust score : ")
    assert "grade" not in text.lower()


def test_cli_report_matches_scan_local(tmp_path):
    repo = _fixture_repo(tmp_path)
    out = tmp_path / "cq.json"
    main(["scan", str(repo), "--quiet", "--gitlab-code-quality", str(out)])
    direct = result_to_code_quality(scan_local(repo))
    assert json.loads(out.read_text()) == direct
