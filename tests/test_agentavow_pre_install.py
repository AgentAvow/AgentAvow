"""Install-time check: the server is graded BEFORE `claude mcp add` / a .mcp.json write
runs, and the verdict reaches the person. Warn-only (never denies), fail-open.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_pre_install.py"


def _load():
    spec = importlib.util.spec_from_file_location("pre_install", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook(tmp_path, monkeypatch):
    mod = _load()
    pc = mod._precheck()
    monkeypatch.setattr(pc, "CACHE", tmp_path / "scanned.json")
    monkeypatch.setattr(mod, "_precheck", lambda: pc)
    return mod, pc


def _run(mod, monkeypatch, capsys, payload, scan) -> dict:
    pc = mod._precheck()
    monkeypatch.setattr(pc, "_scan", scan)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    mod.main()
    out = capsys.readouterr().out
    return json.loads(out) if out else {}


def _ok(score, verdict, blocking=0, **extra):
    base = {"score": score, "verdict": verdict, "blocking": blocking, "tier": "standard",
            "grade": "B", "tool_digests": {}, "tool_manifest_digest": None, "sandbox": "",
            "deprecated": False}
    base.update(extra)
    return base


def _bash(cmd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}}


# --- what counts as "adding a server" --------------------------------------------

@pytest.mark.parametrize("cmd,name,cfg", [
    ("claude mcp add deepwiki https://mcp.deepwiki.com/mcp", "deepwiki", {"url": "https://mcp.deepwiki.com/mcp"}),
    ("claude mcp add --transport http deepwiki https://mcp.deepwiki.com/mcp", "deepwiki", {"url": "https://mcp.deepwiki.com/mcp"}),
    ("claude mcp add -s user -t sse ctx https://x.example/sse", "ctx", {"url": "https://x.example/sse"}),
    ("claude mcp add memory -- npx -y @modelcontextprotocol/server-memory", "memory",
     {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}),
    ("claude mcp add -e KEY=1 git -- uvx mcp-server-git", "git", {"command": "uvx", "args": ["mcp-server-git"]}),
    ("cd ~/proj && claude mcp add deepwiki https://mcp.deepwiki.com/mcp && echo ok", "deepwiki",
     {"url": "https://mcp.deepwiki.com/mcp"}),
    ("claude mcp add-json w '{\"url\": \"https://w.example/mcp\"}'", "w", {"url": "https://w.example/mcp"}),
])
def test_claude_mcp_add_forms_are_parsed(hook, cmd, name, cfg):
    mod, _ = hook
    assert mod._server_from_mcp_add(cmd) == (name, cfg)


@pytest.mark.parametrize("cmd", [
    "claude mcp list", "claude mcp remove deepwiki", "npm install chalk", "git add .",
    "echo claude mcp", "claude mcp add", "claude mcp add onlyname",
])
def test_other_commands_are_ignored(hook, cmd):
    mod, _ = hook
    assert mod._server_from_mcp_add(cmd) is None


def test_mcp_json_writes_and_partial_edits_are_parsed(hook):
    mod, _ = hook
    full = json.dumps({"mcpServers": {"a": {"url": "https://a.example/mcp"},
                                      "b": {"command": "npx", "args": ["-y", "b-mcp"]}}})
    assert [n for n, _ in mod._servers_from_mcp_json(full)] == ["a", "b"]
    partial = '"c": {"url": "https://c.example/mcp"}'
    assert mod._servers_from_mcp_json(partial) == [("c", {"url": "https://c.example/mcp"})]
    assert mod._servers_from_mcp_json("not json at all {") == []


def test_targets_come_only_from_scannable_servers(hook):
    mod, pc = hook
    payload = {"tool_name": "Write", "tool_input": {"file_path": "/p/.mcp.json", "content": json.dumps({
        "mcpServers": {"local": {"url": "http://localhost:3000/mcp"},
                       "script": {"command": "node", "args": ["srv.js"]},
                       "pkg": {"command": "npx", "args": ["-y", "some-mcp"]},
                       "remote": {"url": "https://r.example/mcp?token=abc"}}})}}
    ids = sorted(t["id"] for t in mod._targets_for(payload, pc))
    assert ids == ["https://r.example/mcp", "npm:some-mcp"]
    other = {"tool_name": "Write", "tool_input": {"file_path": "/p/package.json", "content": "{}"}}
    assert mod._targets_for(other, pc) == []
    assert mod._targets_for({"tool_name": "Read", "tool_input": {"file_path": "/p/.mcp.json"}}, pc) == []


# --- what the person sees ---------------------------------------------------------

def test_safe_server_gives_a_visible_verdict_and_never_grants_permission(hook, monkeypatch, capsys):
    mod, pc = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add deepwiki https://mcp.deepwiki.com/mcp"),
               lambda t, force=False: _ok(88, "safe"))
    assert "✅ MCP 'deepwiki' (https://mcp.deepwiki.com/mcp): Safe to connect · AgentAvow 88/100" \
        in out["systemMessage"]
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert "permissionDecision" not in hso  # the normal permission flow still runs
    assert "Tell the user this verdict" in hso["additionalContext"]
    assert "https://agentavow.com/check/mcp?endpoint=" in out["systemMessage"]
    # cached for the session-start hook, so it is not reported twice
    cached = json.loads(pc.CACHE.read_text())["deepwiki"]
    assert cached["score"] == 88 and cached["id"] == "https://mcp.deepwiki.com/mcp"


def test_do_not_connect_asks_the_person_with_the_answer_as_the_reason(hook, monkeypatch, capsys):
    mod, _ = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add tm -- npx -y task-master-ai"),
               lambda t, force=False: _ok(36, "needs review", 5, decision="do_not_connect",
                                          decision_reason="one critical finding: eval"))
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert ("⛔ MCP 'tm' (npm:task-master-ai): Do not connect — one critical finding: eval · "
            "AgentAvow 36/100") in hso["permissionDecisionReason"]
    assert "AgentAvow says: Do not connect. Continue anyway?" in hso["permissionDecisionReason"]
    assert "https://agentavow.com/check/pkg/npm/task-master-ai" in out["systemMessage"]


@pytest.mark.parametrize("extra", [
    {"decision": "review", "decision_reason": "one high finding: x"},
    {"tier": "blocked", "decision": "review", "decision_reason": "trust score 4/100 is under 51"},
    {"decision": "review", "decision_reason": "nothing found, but little code to inspect"},
])
def test_review_is_a_note_never_a_prompt(hook, monkeypatch, capsys, extra):
    """Review before you connect — a high finding, a low score, thin coverage — is
    reported and the add goes on. Only Do not connect asks."""
    mod, _ = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add bad https://bad.example/mcp"),
               lambda t, force=False: _ok(40, "needs review", 1, **extra))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "⚠️ MCP 'bad' (https://bad.example/mcp): Review before you connect — " \
        + extra["decision_reason"] in out["systemMessage"]


def test_certified_rides_beside_the_answer(hook, monkeypatch, capsys):
    mod, _ = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add ok https://ok.example/mcp"),
               lambda t, force=False: _ok(98, "safe", decision="safe", certified=True,
                                          decision_reason="nothing found in 40 files"))
    assert "Safe to connect · Certified — nothing found in 40 files · AgentAvow 98/100" \
        in out["systemMessage"]


def test_soft_needs_review_without_findings_notes_and_proceeds(hook, monkeypatch, capsys):
    """DeepWiki-style: 74/100, zero findings, 'thin coverage'. A legitimate server must
    not get the prompt a poisoned one gets — the verdict is shown, the add goes on."""
    mod, _ = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add deepwiki https://mcp.deepwiki.com/mcp"),
               lambda t, force=False: _ok(74, "needs review", 0, tier="standard"))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "Review before you connect · AgentAvow 74/100" in out["systemMessage"]


def test_unscannable_server_notes_it_was_not_scanned_and_proceeds(hook, monkeypatch, capsys):
    mod, pc = hook

    def refuse(t, force=False):
        raise pc._UnscannableError("422")

    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add figma https://mcp.figma.com/mcp"), refuse)
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "not scanned" in out["systemMessage"]
    assert "retry_after" in json.loads(pc.CACHE.read_text())["figma"]


def test_needs_decision_rule_directly(hook):
    mod, _ = hook
    assert mod._needs_decision(None) is False
    assert mod._needs_decision(_ok(74, "needs review", 0, tier="standard")) is False
    assert mod._needs_decision(_ok(60, "needs review", 1, decision="review")) is False
    assert mod._needs_decision(_ok(8, "needs review", 0, tier="blocked")) is False
    assert mod._needs_decision(_ok(40, "needs review", 3, decision="do_not_connect")) is True


def test_transient_failure_and_non_install_commands_are_silent(hook, monkeypatch, capsys):
    mod, _ = hook

    def boom(t, force=False):
        raise TimeoutError("slow")

    assert _run(mod, monkeypatch, capsys, _bash("claude mcp add x https://x.example/mcp"), boom) == {}
    assert _run(mod, monkeypatch, capsys, _bash("npm install chalk"), lambda t, force=False: _ok(1, "x")) == {}
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    mod.main()
    assert capsys.readouterr().out == ""


def test_localhost_and_secret_urls_never_leave_the_machine(hook, monkeypatch, capsys):
    mod, _ = hook
    calls = []
    scan = lambda t, force=False: calls.append(t) or _ok(90, "safe")  # noqa: E731
    assert _run(mod, monkeypatch, capsys, _bash("claude mcp add l http://localhost:8000/mcp"), scan) == {}
    assert _run(mod, monkeypatch, capsys, _bash(
        "claude mcp add s https://h.example/mcp/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"), scan) == {}
    assert calls == []
