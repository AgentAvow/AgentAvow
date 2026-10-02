"""classify_start: the deterministic WHY for a server that did not start, on the exact
launch errors seen in the 2026-09-30 known-good eval (8 of 20 servers did not start)."""
from __future__ import annotations

import pytest

from src.scanner.behavioral.graders import (
    START_REASONS,
    _clean_detail,
    classify_start,
    grade,
    grade_summary,
)
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.behavioral.transcript import ExerciseTranscript, parse_transcript

SUPABASE = ("server_exited: Please provide a personal access token (PAT) with the "
            "--access-token flag or set the SUPABASE_ACCESS_TOKEN environment variable")
BRAVE = ("server_exited: A Brave API key is required via --brave-api-key, BRAVE_API_KEY, "
         "--brave-api-key-file, or BRAVE_API_KEY_FILE")
MCP_REMOTE = "server_exited: Usage: mcp-remote <https://server-url> [callback-port] [--debug]"
GIT = ("initialize_timeout: WARNING:root:Failed to initialize: Bad git executable.\n"
       "The git executable must be specified in one of the following ways:\n"
       "    - be included in your $PATH\n"
       "    - be set via $GIT_PYTHON_GIT_EXECUTABLE\n"
       "    - explicitly set via git.refresh(<full-path-to-git-executable>)\n\n"
       "All git commands will error until this is rectified.\n\n"
       "This initial message can be silenced or aggravated in the future by setting the\n"
       "$GIT_PYTHON_REFRESH environment variable.")
SQLITE = ("server_exited: Traceback (most recent call last):\n"
          '  File "/work/.local/bin/mcp-server-sqlite", line 8, in <module>\n'
          "    sys.exit(main())\n"
          '  File "/usr/local/lib/python3.12/asyncio/runners.py", line 195, in run\n'
          "    return runner.run(main)\n"
          "TypeError: main() missing 1 required positional argument: 'db_path'")


def _tr(error: str | None, **launch) -> ExerciseTranscript:
    return parse_transcript({"version": 1,
                             "launch": {"command": ["x"], "ok": False, "error": error, **launch},
                             "tools": [], "calls": []})


def _res(transcript=None, **kw) -> BehavioralResult:
    base = dict(ran=True, surface="npm", coordinate="demo", plan="npm-mcp", transcript=transcript)
    base.update(kw)
    return BehavioralResult(**base)


@pytest.mark.parametrize("name,error,reason", [
    ("@supabase/mcp-server-supabase", SUPABASE, "needs_credentials"),
    ("@brave/brave-search-mcp-server", BRAVE, "needs_credentials"),
    ("mcp-remote", MCP_REMOTE, "needs_arguments"),
    ("mcp-server-git", GIT, "missing_binary"),
])
def test_the_real_launch_errors_classify(name, error, reason):
    r = _res(_tr(error))
    got, detail = classify_start(r)
    assert got == reason, name
    assert 0 < len(detail) <= 160 and "\n" not in detail
    assert grade(r) == []  # a non-started server never yields a finding
    s = grade_summary(r)
    assert s["start_reason"] == reason and s["start_reason_detail"] == detail
    assert s["server_failed_to_start"] is True and s["launch_ok"] is False


def test_sqlite_traceback_is_crashed_with_the_exception_line_as_detail():
    # parse_transcript caps launch_error at 300 chars — the exception line survives here
    r = _res(_tr(SQLITE[:300]))
    reason, detail = classify_start(r)
    assert reason == "crashed"
    assert "Traceback" not in detail and "File" not in detail
    assert detail.startswith("server_exited:")
    # a traceback whose exception line was cut off says so instead of quoting a frame
    r = _res(_tr(SQLITE.rsplit("\n", 1)[0]))
    assert classify_start(r) == ("crashed",
                                 "server_exited: Python traceback (exception line truncated)")


def test_markitdown_install_failure_has_no_exercise_and_nonzero_exit():
    r = _res(None, exit_code=1)
    assert classify_start(r) == ("install_failed", "install step exited 1; no exercise ran")
    s = grade_summary(r)
    assert s["exercised"] is False and s["start_reason"] == "install_failed"


def test_exit_137_is_a_resource_limit_with_or_without_the_note():
    assert classify_start(_res(None, exit_code=137))[0] == "resource_limit"
    assert classify_start(_res(_tr("server_exited"), notes=["killed_resource_limit"]))[0] == \
        "resource_limit"
    # the note wins over the transcript's own (incomplete) story
    assert classify_start(_res(_tr(BRAVE), exit_code=137))[0] == "resource_limit"


def test_remaining_vocabulary():
    assert classify_start(_res(parse_transcript({"launch": {"ok": True}}))) == ("started", "")
    assert classify_start(_res(_tr("no_entrypoint_found")))[0] == "no_entrypoint"
    assert classify_start(_res(_tr("initialize_timeout: warming up")))[0] == "timeout"
    assert classify_start(_res(None, exit_code=124, timed_out=True))[0] == "timeout"
    assert classify_start(_res(_tr(
        "spawn_failed: FileNotFoundError: [Errno 2] No such file or directory: 'npx'")))[0] == \
        "missing_binary"
    assert classify_start(_res(_tr("server_exited: boom")))[0] == "crashed"
    assert classify_start(_res(_tr("initialize_error: rpc_error: -32600")))[0] == "crashed"
    assert classify_start(_res(_tr("something odd")))[0] == "unknown"
    assert classify_start(_res(None, exit_code=0)) == ("unknown", "")  # plain exec plan
    assert classify_start(BehavioralResult(ran=False, surface="npm", coordinate="x",
                                           error="ssm_unavailable")) == (
        "unknown", "ssm_unavailable")
    assert classify_start(_res(_tr("x"), notes=["killed_resource_limit"]))[0] == "resource_limit"


def test_environment_variable_alone_is_not_a_credential():
    # GitPython mentions an environment variable; only a credential-looking NAME makes
    # "env var" text a needs_credentials
    assert classify_start(_res(_tr("set the FOO_MODE environment variable")))[0] == "unknown"
    assert classify_start(_res(_tr("set the ACME_API_KEY environment variable")))[0] == \
        "needs_credentials"
    # "PAT" is whole-word and case-sensitive: paths and 'compatible' never match
    assert classify_start(_res(_tr("server_exited: incompatible path /usr/x")))[0] == "crashed"


def test_detail_cleaning():
    d = _clean_detail("server_exited: cannot open /work/node_modules/x/y.js\n   at foo (z.js:1)")
    assert d == "server_exited: cannot open <path>"
    assert _clean_detail("https://github.com/acme/tool failed").startswith("https://github.com")
    assert len(_clean_detail("x" * 1000)) == 160 and _clean_detail("x" * 1000).endswith("…")
    assert _clean_detail("") == "" and _clean_detail(None) == ""


def test_reason_vocabulary_is_closed():
    assert set(START_REASONS) == {
        "started", "needs_credentials", "needs_arguments", "missing_binary", "install_failed",
        "resource_limit", "no_entrypoint", "timeout", "crashed", "unknown",
    }


# @modelcontextprotocol/server-postgres launched bare (its source:
# ``if (args.length === 0) { console.error("Please provide a database URL as a
# command-line argument"); process.exit(1); }``) was classified ``crashed``.
POSTGRES = "server_exited: Please provide a database URL as a command-line argument"


@pytest.mark.parametrize("name,error,reason", [
    ("@modelcontextprotocol/server-postgres", POSTGRES, "needs_arguments"),
    ("server-postgres after a banner", "server_exited: postgres mcp v0.6.2\n" + POSTGRES[15:],
     "needs_arguments"),
    ("mcp-remote", MCP_REMOTE, "needs_arguments"),
    ("usage mid-error", "server_exited: error: bad invocation. usage: tool <dir>",
     "needs_arguments"),
    ("needs a path", "server_exited: Please provide a directory path to serve", "needs_arguments"),
    ("connection string", "server_exited: Provide a connection string for the database",
     "needs_arguments"),
    ("requires an argument", "server_exited: This server requires a --root argument",
     "needs_arguments"),
    ("missing argument", "server_exited: Error: missing required argument 'url'",
     "needs_arguments"),
    ("missing argument bare", "server_exited: missing argument: target", "needs_arguments"),
    ("<url> placeholder", "server_exited: run as: srv <url>", "needs_arguments"),
    ("@brave/brave-search-mcp-server", BRAVE, "needs_credentials"),
    ("@supabase/mcp-server-supabase", SUPABASE, "needs_credentials"),
    ("mcp-server-sqlite (traceback)", SQLITE[:300], "crashed"),
    ("plain crash", "server_exited: TypeError: Cannot read properties of undefined", "crashed"),
])
def test_argument_and_credential_errors_win_over_crashed(name, error, reason):
    assert classify_start(_res(_tr(error)))[0] == reason, name
