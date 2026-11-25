"""Tests for the activity log's redaction and tool-input summaries."""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_activity_redact.py"


def _load():
    spec = importlib.util.spec_from_file_location("agentavow_activity_redact_t", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load()

SECRET_CASES = [
    ("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "aws"),
    ("tok ghp_" + "a1B2c3D4e5" * 4, "ghp_" + "a1B2c3D4e5" * 4, "github"),
    ("tok github_pat_" + "A1b2C3d4E5" * 5, "github_pat_" + "A1b2C3d4E5" * 5, "github"),
    ("ANTHROPIC sk-ant-api03-abcdefghijklmnopqrstuv", "sk-ant-api03-abcdefghijklmnopqrstuv", "api_key"),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890-abcdefghij", "slack"),
    ("g AIza" + "Sy" + "A" * 33, "AIza" + "Sy" + "A" * 33, "google"),
    ("gl glpat-abcdefghij0123456789", "glpat-abcdefghij0123456789", "gitlab"),
    ("n npm_" + "aB3dE5gH7j" * 3 + "aB3dE5", "npm_" + "aB3dE5gH7j" * 3 + "aB3dE5", "npm"),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzzzz\nqqqq\n-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEAzzzz",
        "private_key",
    ),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4", "jwt"),
    ('curl -H "Authorization: Bearer abc.def.ghi" https://x', "abc.def.ghi", "bearer"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "bearer"),
    ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG", "secret"),
    ("db password: hunter2hunter", "hunter2hunter", "secret"),
    ("tool --api-key abc123xyz", "abc123xyz", "secret"),
    ("curl -d '{\"password\":\"hunter2\"}' x", "hunter2", "secret"),
    ('{"api_key": "abc123"}', "abc123", "secret"),
    ("postgres://u:pa@ss@host/db", "ss@", "url_userinfo"),
    ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "entropy"),
    ("x " + "aZ3/Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe", "aZ3/Qw8", "entropy"),
    ("tool --token=abc123xyz", "abc123xyz", "secret"),
    ("mysql -uroot -pS3cret db", "S3cret", "secret"),
    ("git clone https://u:p@github.com/o/r", "u:p@", "url_userinfo"),
    ("curl https://x.io/a?code=12345&state=zz", "code=12345", "query"),
    ("blob " + "Zk9mQ2xR7vB3nT8yWp4sHd6JuE1aXc5MgL0iOb2N", "Zk9mQ2xR7vB3nT8yWp4sHd6JuE1aXc5MgL0iOb2N", "entropy"),
]


@pytest.mark.parametrize("text,secret,kind", SECRET_CASES)
def test_secrets_are_redacted(text, secret, kind):
    out = R.redact(text)
    assert secret not in out
    assert f"[redacted:{kind}]" in out


def test_query_marker_is_exact():
    assert R.redact("https://x.io/a?code=1") == "https://x.io/a?[redacted:query]"


def test_hex_hashes_are_kept():
    text = "git show 9fceb02d0ae598e95dc970b74767f19372d61af8"
    assert R.redact(text) == text


PATH_CASES = [
    "cat /home/alice/projects/agentavow-activity-log/plugins/agentavow-trust/scripts/x.py",
    "ls /home/alice/very-long-directory-name-with-words/and-another-segment-here/file",
    "cp ~/.aws/credentials /tmp/some_long_backup_directory_name/other_part/creds",
    "vi plugins/agentavow-trust/scripts/agentavow_activity_redact.py",
    "cat /home/Alice/My.Docs/Long_Directory_Name_With_Capitals/Another_Segment_Here/f",
    "ls ~/.aws/credentials ~/.ssh/id_ed25519 /usr/local/bin/python3.12",
    "cat ~/Library/Application Support/Google/Chrome/Default/Login Data",
    "cat Documents/Projects/MyApp/src/main.py",
    "cat .git/objects/9f/ceb02d0ae598e95dc970b74767f19372d61af8",
    "cat /usr/share/doc/some-package-name/LICENSE.txt /srv/data/README",
]

LEAK_SECRET = "aZ3/Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"
AWS_TAIL = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
LEAK_CASES = [
    ("/" + LEAK_SECRET, "Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"),
    ("cat /" + LEAK_SECRET, "Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"),
    ("cat ~/" + LEAK_SECRET, "Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"),
    ("cat ./" + LEAK_SECRET, "Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"),
    ("cat /tmp/" + LEAK_SECRET, "Qw8+Lm2Xk9Pv4Rt7Yb1Nc6Hd5Jf0SgUe"),
    ("cat /tmp/" + AWS_TAIL, "bPxRfiCYEXAMPLEKEY"),
    ("cat /mnt/x/Zk9mQ2xR7vB3nT8yWp4sHd6JuE1aXc5MgL0iOb2N", "Zk9mQ2xR7vB3nT8yWp4sHd6JuE1aXc5MgL0iOb2N"),
]


@pytest.mark.parametrize("text,secret", LEAK_CASES)
def test_secret_segment_inside_path_is_redacted(text, secret):
    out = R.redact(text)
    assert secret not in out
    assert "[redacted:entropy]" in out


def test_readable_path_segments_stay_around_a_redacted_one():
    out = R.redact("cat /mnt/x/Zk9mQ2xR7vB3nT8yWp4sHd6JuE1aXc5MgL0iOb2N")
    assert out == "cat /mnt/x/[redacted:entropy]"


@pytest.mark.parametrize("text", PATH_CASES)
def test_paths_survive_entropy_rule(text):
    assert R.redact(text) == text


def test_long_path_in_bash_command_survives():
    cmd = "cat /home/alice/projects/agentavow-activity-log/plugins/agentavow-trust/scripts/x.py"
    assert R.summarize_input("Bash", {"command": cmd}, None) == {"command": cmd}


def test_redact_is_fast_on_large_input():
    import time

    inputs = [
        "a." * 50_000,
        "-" * 100_000,
        "token." * 17_000,
        "--token-" * 12_000,
        "mysql " * 16_000,
        "a://" * 25_000,
        "word " * 20_000,
        "x" * 100_000,
    ]
    for text in inputs:
        t0 = time.perf_counter()
        R.redact(text)
        assert time.perf_counter() - t0 < 0.2, text[:12]


def test_summaries_are_fast_on_large_input():
    import time

    t0 = time.perf_counter()
    R.summarize_input("Bash", {"command": "a." * 500_000}, None)
    assert time.perf_counter() - t0 < 0.2


def test_secret_at_cut_boundary_is_still_caught():
    cmd = "x" * 1990 + " AKIAIOSFODNN7EXAMPLE"
    out = R.summarize_input("Bash", {"command": cmd}, None)["command"]
    assert "AKIAIOSFODNN7" not in out


def test_webfetch_url_and_patch_paths_are_cut():
    url = R.summarize_input("WebFetch", {"url": "https://x.io/" + "p/" * 600}, None)["url"]
    assert len(url) == 500
    patch = "*** Update File: " + "d" * 900 + "\n"
    paths = R.summarize_input("apply_patch", {"input": patch}, None)["paths"]
    assert len(paths[0]) == 500


@pytest.mark.parametrize("tool", [None, 5, ["Bash"]])
def test_non_str_tool_does_not_raise(tool):
    assert R.summarize_input(tool, {"b": 1, "a": 2}, None) == {"arg_names": ["a", "b"]}
    assert R.summarize_input(tool, "oops", None) == {"arg_names": []}


def test_plain_text_is_unchanged():
    text = "ls -la src/ && echo hello world"
    assert R.redact(text) == text


def test_cut_marks_truncation():
    out = R.cut("a" * 3000, 2000)
    assert len(out) == 2000
    assert out.endswith("…[cut]")


def test_cut_leaves_short_text():
    assert R.cut("abc", 10) == "abc"


def test_constants():
    assert (R.CMD_LIMIT, R.TEXT_LIMIT, R.MCP_VALUE_LIMIT) == (2000, 500, 200)


def test_bash_command_is_redacted_and_cut():
    s = R.summarize_input("Bash", {"command": "echo AKIAIOSFODNN7EXAMPLE"}, None)
    assert s == {"command": "echo [redacted:aws]"}
    long = R.summarize_input("exec", {"command": "x " * 3000}, None)
    assert len(long["command"]) == 2000


def test_codex_shell_command_list():
    s = R.summarize_input("shell", {"command": ["bash", "-lc", "ls"]}, None)
    assert s == {"command": "bash -lc ls"}


def test_path_shows_home_as_tilde(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    s = R.summarize_input("Read", {"file_path": str(tmp_path / "a" / "b.py")}, None)
    assert s == {"path": "~/a/b.py"}


def test_large_write_keeps_byte_count_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    content = "x" * (5 * 1024 * 1024)
    s = R.summarize_input("Write", {"file_path": str(tmp_path / "x.txt"), "content": content}, None)
    assert s == {"path": "~/x.txt", "bytes": 5242880}


def test_edit_counts_new_string_bytes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    s = R.summarize_input(
        "Edit", {"file_path": str(tmp_path / "f"), "old_string": "a", "new_string": "héllo"}, None
    )
    assert s == {"path": "~/f", "bytes": 6}
    assert "héllo" not in json.dumps(s)


def test_read_has_no_bytes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert "bytes" not in R.summarize_input("Read", {"file_path": "/etc/hosts"}, None)


def test_notebook_edit_uses_notebook_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    s = R.summarize_input("NotebookEdit", {"notebook_path": "/srv/n.ipynb", "new_source": "ab"}, None)
    assert s == {"path": "/srv/n.ipynb", "bytes": 2}


def test_apply_patch_names_paths_and_size(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    patch = (
        "*** Begin Patch\n*** Update File: src/a.py\n@@\n-old\n+SECRETBODY\n"
        "*** Add File: b.txt\n+hi\n*** End Patch\n"
    )
    s = R.summarize_input("apply_patch", {"input": patch}, None)
    assert s == {"paths": ["src/a.py", "b.txt"], "bytes": len(patch.encode())}


def test_webfetch_url_redacted():
    s = R.summarize_input("WebFetch", {"url": "https://x.io/p?k=v", "prompt": "q"}, None)
    assert s == {"url": "https://x.io/p?[redacted:query]"}


def test_websearch_query_cut():
    s = R.summarize_input("WebSearch", {"query": "q" * 900}, None)
    assert len(s["query"]) == 500


def test_grep_and_glob():
    assert R.summarize_input("Grep", {"pattern": "foo", "path": "src"}, None) == {
        "pattern": "foo",
        "path": "src",
    }
    assert R.summarize_input("Glob", {"pattern": "*.py"}, None) == {"pattern": "*.py", "path": None}


def test_mcp_values_cut_and_redacted():
    s = R.summarize_input(
        "mcp__srv__tool", {"a": "AKIAIOSFODNN7EXAMPLE", "b": "z" * 500, "c": 5}, None
    )
    assert s["args"]["a"] == "[redacted:aws]"
    assert len(s["args"]["b"]) == 200
    assert s["args"]["c"] == "5"


MCP_SECRET_CASES = [
    ("password", "hunter2"),
    ("api_key", "abc123shortkey"),
    ("token", "tok_live_9f8e7d"),
    ("Authorization", "Basic dXNlcjpwYXNz"),
    ("client_secret", "s3cr3tValue!"),
    ("X-Api-Key", "k1"),
    ("PASSWD", "pw"),
    ("refreshToken", "rt-1"),
    ("db_credentials", ["a", "b"]),
    ("auth", {"user": "u", "pw": "p1"}),
]


@pytest.mark.parametrize("name,value", MCP_SECRET_CASES)
def test_mcp_secret_named_args_are_redacted(name, value):
    args = R.summarize_input("mcp__srv__tool", {name: value, "title": "Bug"}, None)["args"]
    assert args == {name: "[redacted:secret]", "title": "Bug"}


def test_mcp_nested_secret_keys_are_redacted():
    value = {"s": {"token": ["leak1", "leak2"], "pin": 7}, "user": "alice",
             "password": "hunter2", "h": [{"Authorization": "Basic dXNlcjpwYXNz", "accept": "json"}],
             "d": {"client_secret": "s3cr3tValue!"}}
    out = R.summarize_input("mcp__srv__tool", {"config": value}, None)["args"]["config"]
    for secret in ("hunter2", "dXNlcjpwYXNz", "s3cr3tValue!", "leak1", "leak2"):
        assert secret not in out
    assert "alice" in out and "json" in out and "'pin': 7" in out
    assert out.count("[redacted:secret]") == 4


def test_mcp_huge_nested_value_is_fast_and_cut():
    import time

    value = {"rows": [{"id": i, "token": "t%d" % i} for i in range(200_000)]}
    t0 = time.perf_counter()
    out = R.summarize_input("mcp__srv__tool", {"q": value}, None)["args"]["q"]
    assert time.perf_counter() - t0 < 0.2
    assert len(out) == 200 and "t1'" not in out


def test_unknown_tool_keeps_names_only():
    s = R.summarize_input("Mystery", {"b": "secret", "a": 1}, None)
    assert s == {"arg_names": ["a", "b"]}


def test_non_dict_input_is_safe():
    assert R.summarize_input("Mystery", "oops", None) == {"arg_names": []}
    assert R.summarize_input("Bash", None, None) == {"command": ""}


def test_summarize_output_dict():
    resp = {"stdout": "hi", "stderr": "", "interrupted": False}
    out = R.summarize_output(resp)
    assert out == {"ok": None, "out_bytes": len(json.dumps(resp).encode())}


def test_summarize_output_str_counts_utf8():
    assert R.summarize_output("héllo") == {"ok": None, "out_bytes": 6}
