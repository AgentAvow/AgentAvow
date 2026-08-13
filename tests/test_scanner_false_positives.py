"""Tests for scanner false-positive reduction features.

Tests inline suppression (ag-scan:ignore), allowlist, and context-aware scanning.
"""
from __future__ import annotations

from src.scanner.scan import _scan_content


class TestInlineSuppression:
    """Option 1: Lines with ag-scan:ignore are skipped."""

    def test_suppression_skips_finding(self):
        code = 'api_key = "sk-ant-AAAA1234567890BBBB1234567890CCCC1234567890DD"  # ag-scan:ignore\n'
        findings, _, _ = _scan_content(code, "config.py")
        assert len(findings) == 0

    def test_no_suppression_still_flags(self):
        code = 'api_key = "sk-ant-AAAA1234567890BBBB1234567890CCCC1234567890DD"\n'
        findings, _, _ = _scan_content(code, "config.py")
        assert len(findings) > 0

    def test_suppression_in_comment_variants(self):
        code = 'subprocess.run(["ls"])  // ag-scan:ignore\n'
        findings, _, _ = _scan_content(code, "tool.py")
        assert len(findings) == 0


class TestAllowlist:
    """Option 2: Allowlist suppresses specific findings for specific files."""

    def test_allowlist_suppresses_finding(self):
        code = 'subprocess.run(cmd)\n'
        allowlist = {("tool.py", "subprocess.run / Popen (Python)")}
        findings, _, _ = _scan_content(code, "tool.py", allowlist=allowlist)
        assert len(findings) == 0

    def test_allowlist_glob_match(self):
        code = 'subprocess.run(cmd)\n'
        allowlist = {("src/utils/*", "subprocess.run / Popen (Python)")}
        findings, _, _ = _scan_content(code, "src/utils/git.py", allowlist=allowlist)
        assert len(findings) == 0

    def test_allowlist_wrong_file_still_flags(self):
        code = 'subprocess.run(cmd)\n'
        allowlist = {("other.py", "subprocess.run / Popen (Python)")}
        findings, _, _ = _scan_content(code, "tool.py", allowlist=allowlist)
        assert len(findings) > 0

    def test_allowlist_wrong_name_still_flags(self):
        code = 'subprocess.run(cmd)\n'
        allowlist = {("tool.py", "eval() call")}
        findings, _, _ = _scan_content(code, "tool.py", allowlist=allowlist)
        assert len(findings) > 0


class TestContextAwareExec:
    """Option 3: Context-aware scanning for safe exec patterns."""

    def test_subprocess_hardcoded_args_safe(self):
        code = 'subprocess.run(["git", "status"])\n'
        findings, _, _ = _scan_content(code, "deploy.py")
        assert len(findings) == 0

    def test_subprocess_hardcoded_string_safe(self):
        code = "subprocess.run(['pip', 'install', 'requests'])\n"
        findings, _, _ = _scan_content(code, "setup.py")
        assert len(findings) == 0

    def test_subprocess_variable_arg_flagged(self):
        code = 'subprocess.run(user_input)\n'
        findings, _, _ = _scan_content(code, "handler.py")
        assert any(f.category == "unsafe_exec" for f in findings)

    def test_subprocess_shell_false_safe(self):
        code = 'subprocess.run(cmd, shell=False)\n'
        findings, _, _ = _scan_content(code, "runner.py")
        assert len(findings) == 0

    def test_ast_literal_eval_safe(self):
        code = 'result = ast.literal_eval(data)\n'
        findings, _, _ = _scan_content(code, "parser.py")
        assert not any(f.name.startswith("eval() call") for f in findings)

    def test_plain_eval_still_flagged(self):
        code = 'result = eval(user_data)\n'
        findings, _, _ = _scan_content(code, "handler.py")
        assert any(f.name == "eval() call (Python)" for f in findings)


class TestContextAwareFs:
    """Option 3: Context-aware scanning for safe filesystem patterns."""

    def test_open_hardcoded_path_safe(self):
        code = 'data = open("config.json", "r").read()\n'
        findings, _, _ = _scan_content(code, "loader.py")
        assert len(findings) == 0

    def test_with_open_hardcoded_path_safe(self):
        code = 'with open("config.json", "r") as f:\n'
        findings, _, _ = _scan_content(code, "reader.py")
        assert not any(f.category == "fs_access" for f in findings)

    def test_with_open_variable_path_flagged(self):
        code = 'with open(user_path, "w") as f:\n'
        findings, _, _ = _scan_content(code, "handler.py")
        assert any(f.category == "fs_access" for f in findings)

    def test_path_write_text_safe(self):
        code = 'Path("output.txt").write_text(result)\n'
        findings, _, _ = _scan_content(code, "writer.py")
        assert not any(f.category == "fs_access" for f in findings)

    def test_open_variable_write_still_flagged(self):
        """open() with a variable path and write mode is still flagged."""
        code = 'f = open(user_path, "w")\n'
        findings, _, _ = _scan_content(code, "handler.py")
        # This should still be flagged because user_path is a variable
        # The "w" write mode pattern triggers, and it's not a hardcoded path
        # Note: the safe open check matches hardcoded strings, but user_path
        # is a variable so it won't match the safe pattern
        unsafe_fs = [f for f in findings if f.category == "fs_access"]
        assert len(unsafe_fs) > 0


class TestRegexExecNotUnsafeExec:
    """The `.exec()` RegExp method must not be flagged as child_process exec —
    the dominant false positive in regex-heavy JS libs (e.g. lodash)."""

    def test_regexp_exec_method_not_flagged_js(self):
        for code in (
            "var result = reFlags.exec(source);\n",
            "while ((match = pattern.exec(str))) {}\n",
            "return reIsNative.exec(func) != null;\n",
        ):
            findings, _, _ = _scan_content(code, "lodash.js")
            assert not any(f.category == "unsafe_exec" for f in findings), code

    def test_real_child_process_exec_still_flagged_js(self):
        for code in (
            "child_process.exec(userInput);\n",
            "const { exec } = require('child_process'); exec(cmd);\n",
            "cp.spawn(bin, args);\n",
            "execSync('rm -rf /');\n",
        ):
            findings, _, _ = _scan_content(code, "tool.js")
            assert any(f.category == "unsafe_exec" for f in findings), code

    def test_python_exec_method_not_flagged(self):
        code = "value = compiled_re.exec(payload)\n"
        findings, _, _ = _scan_content(code, "tool.py")
        assert not any(f.category == "unsafe_exec" for f in findings)

    def test_python_bare_exec_still_flagged(self):
        code = "exec(untrusted_code)\n"
        findings, _, _ = _scan_content(code, "tool.py")
        assert any(f.category == "unsafe_exec" for f in findings)


# --- README-mined description fallback (score-page "what it does" line) ---

def test_readme_summary_skips_title_and_badges():
    from src.scanner.scan import _readme_summary
    md = (
        "# awesome-tool\n\n"
        "![badge](https://img.shields.io/x)\n[![ci](a)](b)\n\n"
        "Awesome Tool is a fast, typed HTTP client for Python with retries.\n\n"
        "## Install\n"
    )
    assert _readme_summary(md) == (
        "Awesome Tool is a fast, typed HTTP client for Python with retries."
    )


def test_readme_summary_skips_html_and_blockquote_preamble():
    from src.scanner.scan import _readme_summary
    md = (
        "<p align=\"center\"><img src='logo.png'></p>\n\n<h1>Cool Lib</h1>\n\n"
        "> a tagline blockquote\n\n"
        "Cool Lib renders 3D scenes in the browser using WebGPU."
    )
    assert _readme_summary(md) == "Cool Lib renders 3D scenes in the browser using WebGPU."


def test_readme_summary_returns_none_when_only_a_title():
    from src.scanner.scan import _readme_summary
    assert _readme_summary("# my-repo\n") is None
    assert _readme_summary("") is None


def test_readme_summary_long_grabs_two_sentences():
    from src.scanner.scan import _readme_summary
    md = (
        "# Next.js\n\n![b](x)\n\n"
        "Next.js is a React framework for building full-stack web apps. "
        "You use React Components to build UIs, and Next.js for optimizations.\n\n"
        "## Getting Started\n"
    )
    out = _readme_summary(md, long=True)
    assert out.startswith("Next.js is a React framework")
    assert "optimizations" in out  # includes the 2nd sentence


def test_is_distinct_desc_dedupes_near_duplicates():
    from src.scanner.scan import _is_distinct_desc
    # Maintainer copied the README line into About (reworded) -> not distinct.
    assert not _is_distinct_desc(
        "Requests is an elegant and simple HTTP library for Python.",
        "Requests: an elegant and simple HTTP library for Python",
    )
    # A terse tagline + a fuller sentence -> distinct (adds real detail).
    assert _is_distinct_desc(
        "Next.js is a React framework for building full-stack web apps.",
        "The React Framework",
    )
