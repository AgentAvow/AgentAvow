"""Pure-function tests for scripts/dnc_weekly_report.py (no DB, no SSH)."""
from __future__ import annotations

from scripts.dnc_weekly_report import (
    STATUS_HEADING,
    find_previous_report,
    new_status,
    parse_prev_keys,
    parse_remote_output,
    render_report,
    summary_line,
    update_status,
)


def _row(surface="pypi", name="evil", version="1.0", score=10, **kw):
    full = f"{surface}:{name}" if surface in ("npm", "pypi") else name
    return {"surface": surface, "full_name": full, "name": name, "version": version,
            "score": score, "reason": "one critical finding in its code: x",
            "scanned_at": "2026-10-16T22:07:34+00:00",
            "top": {"rule": "curl/wget piped to shell", "severity": "critical",
                    "category": "dynamic_remote_load", "file": "a/b.py", "line": 12}, **kw}


def test_parse_remote_output_ignores_noise():
    out = "Container x Creating\nnoise\n@@DNC_JSON@@[{\"surface\": \"npm\"}]\n"
    assert parse_remote_output(out) == [{"surface": "npm"}]


def test_parse_remote_output_missing_marker():
    try:
        parse_remote_output("nothing")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_report_roundtrips_keys_and_marks_new():
    rows = [_row(), _row("github", "o/r", None, 0)]
    text = render_report(rows, None, "2026-10-16", "2026-10-16 23:00", None)
    keys = parse_prev_keys(text)
    assert keys == {"pypi:pypi:evil": "1.0", "github:o/r": None}
    assert "## Packages (1, 1 new)" in text
    assert text.index("## Packages") < text.index("## Repos")
    assert "`a/b.py:12`" in text
    # Next week: same rows -> nothing new; a new version is flagged.
    assert new_status(_row(), keys) == ""
    assert new_status(_row(version="2.0"), keys) == "new version (was 1.0)"
    assert new_status(_row(name="other"), keys) == "NEW"


def test_report_lists_dropped_targets_and_escapes_pipes():
    prev = {"npm:npm:gone": "1"}
    row = _row(reason="a | b")
    text = render_report([row], prev, "2026-10-23", "t", "2026-10-16.md")
    assert "No longer Do not connect (1)" in text and "`npm:npm:gone`" in text
    assert "a \\| b" in text


def test_parse_prev_keys_absent():
    assert parse_prev_keys("# report without keys") is None


def test_find_previous_report(tmp_path):
    for n in ("2026-10-02.md", "2026-10-09.md", "2026-10-16.md", "notes.md"):
        (tmp_path / n).write_text("x")
    assert find_previous_report(tmp_path, "2026-10-16").name == "2026-10-09.md"
    assert find_previous_report(tmp_path, "2026-10-01") is None
    assert find_previous_report(tmp_path / "missing", "2026-10-16") is None


def test_summary_line():
    line = summary_line([_row(), _row("github", "o/r")], None, "2026-10-16")
    assert line == ("- 2026-10-16: 2 do-not-connect (1 packages), 2 new. "
                    "[dnc-reports/2026-10-16.md](dnc-reports/2026-10-16.md)")


STATUS = "# Title\n\n> quote 1\n> quote 2\n\n**PICK UP** something\n\n## Old\n"


def test_update_status_creates_heading_after_preamble():
    out = update_status(STATUS, "- 2026-10-16: x", "2026-10-16")
    assert out == ("# Title\n\n> quote 1\n> quote 2\n\n" + STATUS_HEADING
                   + "\n\n- 2026-10-16: x\n\n**PICK UP** something\n\n## Old\n")


def test_update_status_prepends_and_replaces_same_date():
    once = update_status(STATUS, "- 2026-10-16: x", "2026-10-16")
    twice = update_status(once, "- 2026-10-23: y", "2026-10-23")
    assert "- 2026-10-23: y\n- 2026-10-16: x\n" in twice
    rerun = update_status(twice, "- 2026-10-23: z", "2026-10-23")
    assert "- 2026-10-23: z\n- 2026-10-16: x\n" in rerun and ": y" not in rerun
    # Nothing else changed.
    assert rerun.replace("- 2026-10-23: z\n", "") == once
