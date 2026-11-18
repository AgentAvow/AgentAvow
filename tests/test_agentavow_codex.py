"""The plugin's hooks in Codex (plugin 0.1.44).

Codex runs Claude Code plugin hooks: same hooks.json, same JSON on stdin and stdout,
and it sets CLAUDE_PLUGIN_ROOT beside its own PLUGIN_ROOT. What differs, and what
these tests pin:
  • MCP servers live in ~/.codex/config.toml ([mcp_servers.<name>]) and in a trusted
    project's .codex/config.toml, and are added with `codex mcp add`.
  • A PreToolUse hook cannot answer "ask" (Codex rejects it and runs the call), only
    "deny". Do not connect is therefore a deny whose reason says what was found, links
    the report and says how to go ahead anyway. Review stays a note.
  • Codex reads one JSON object per hook run and refuses unknown fields
    (codex-rs/hooks/src/engine/output_parser.rs and schema/generated/*.output.schema.json
    in openai/codex, rust-v0.169.1); _codex_accepts() below mirrors those rules.
Payload shapes are the ones captured from codex-cli 0.169.1 (`codex exec`).
"""
from __future__ import annotations

import json
import pathlib

import pytest

from tests.test_agentavow_claude_pins import (
    ALLOW_KEY,
    SCRIPTS,
    TOOL_V2,
    _env,
    _load,
    _Session,
)

SESSION = "01a1ec2c-c206-7010-8080-81be1e1c404c"


# --- what Codex accepts --------------------------------------------------------------

_TOP = {
    "SessionStart": {"continue", "hookSpecificOutput", "stopReason", "suppressOutput",
                     "systemMessage"},
    "PreToolUse": {"continue", "decision", "hookSpecificOutput", "reason", "stopReason",
                   "suppressOutput", "systemMessage"},
}
_HSO = {
    "SessionStart": {"hookEventName", "additionalContext"},
    "PreToolUse": {"hookEventName", "additionalContext", "permissionDecision",
                   "permissionDecisionReason", "updatedInput"},
}


def _codex_accepts(event: str, stdout: str) -> dict:
    """Parse hook stdout as Codex 0.169 would, failing the test where Codex would
    record the hook as failed: more than one JSON value, an unknown field, or a
    PreToolUse decision Codex does not support ("ask", or "allow" without
    updatedInput), or a deny with no reason."""
    text = stdout.strip()
    if not text:
        return {}
    out = json.loads(text)  # one JSON object; two lines of JSON would raise here
    assert isinstance(out, dict)
    assert set(out) <= _TOP[event], set(out) - _TOP[event]
    hso = out.get("hookSpecificOutput")
    if hso is not None:
        assert set(hso) <= _HSO[event], set(hso) - _HSO[event]
        assert hso["hookEventName"] == event
        if event == "PreToolUse" and "permissionDecision" in hso:
            assert hso["permissionDecision"] == "deny"
            assert hso.get("permissionDecisionReason", "").strip()
    return out


# --- a fake machine with Codex installed ----------------------------------------------

def _codex_session(tmp_path: pathlib.Path, config: str = "") -> _Session:
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text(config)
    (home / ".cache" / "agentavow").mkdir(parents=True)
    (home / ".cache" / "agentavow" / "allow.key").write_text(ALLOW_KEY + "\n")
    s = _Session(home, env={"PLUGIN_ROOT": str(
        home / ".codex" / "plugins" / "cache" / "agentavow" / "agentavow-trust" / "0.1.44")})
    return s


def _start(s: _Session) -> dict:
    """A Codex SessionStart payload, as codex-cli 0.169.1 sends it."""
    return {"session_id": SESSION,
            "transcript_path": str(s.home / ".codex" / "sessions" / "2026" / "11" / "17"
                                   / f"rollout-2026-11-17T17-01-58-{SESSION}.jsonl"),
            "cwd": str(s.project), "hook_event_name": "SessionStart",
            "model": "gpt-6.2-sol", "permission_mode": "default", "source": "startup"}


def _tool(s: _Session, tool_name: str, tool_input: dict) -> dict:
    """A Codex PreToolUse payload (shell tool: tool_name "Bash", input {"command"})."""
    return {"session_id": SESSION, "turn_id": "01a1ec2c-c359-7aa3-aec3-321647527c0a",
            "transcript_path": str(s.home / ".codex" / "sessions" / "t.jsonl"),
            "cwd": str(s.project), "hook_event_name": "PreToolUse",
            "model": "gpt-6.2-sol", "permission_mode": "default",
            "tool_name": tool_name, "tool_input": tool_input,
            "tool_use_id": "exec-82f31e9e-8fb1-4a1c-ba77-2f2eb7ed9492"}


def _bash(s: _Session, cmd: str) -> dict:
    return _tool(s, "Bash", {"command": cmd})


CONFIG = """
model = "gpt-6.2-sol"

[marketplaces.agentavow]
source_type = "git"
source = "https://github.com/AgentAvow/AgentAvow.git"

[plugins."agentavow-trust@agentavow"]
enabled = true

[mcp_servers.good]
url = "https://good.example.com/mcp"

[mcp_servers.bad]
url = "https://bad.example.com/mcp"
http_headers = { "X-Team" = "a" }

[mcp_servers."rev"]
command = "npx"
args = ["-y", "rev-pkg@1.2.0"]

[mcp_servers.off]
url = "https://other.example.com/mcp"
enabled = false

[mcp_servers.local]
url = "http://localhost:3000/mcp"

[mcp_servers.script]
command = "node"
args = ["server.js"]
"""


# --- host detection -------------------------------------------------------------------

def test_codex_payloads_are_recognised_and_claude_payloads_are_not(tmp_path):
    s = _codex_session(tmp_path)
    with _env(s.home):  # no PLUGIN_ROOT: the payload alone decides
        pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
        assert pc.detect_host(_start(s)) == "codex"  # transcript under ~/.codex
        assert pc.detect_host(_bash(s, "ls")) == "codex"  # turn_id
        claude = {"session_id": "x", "cwd": str(s.project), "hook_event_name": "PreToolUse",
                  "transcript_path": str(s.home / ".claude" / "projects" / "p" / "t.jsonl"),
                  "tool_name": "Bash", "tool_input": {"command": "ls"},
                  "permission_mode": "default", "tool_use_id": "toolu_1"}
        assert pc.detect_host(claude) == "claude"
        assert pc.detect_host({}) == "claude"
        assert pc.detect_host(None) == "claude"
    with _env(s.home, {"PLUGIN_ROOT": str(s.home / ".codex" / "plugins" / "cache" / "x")}):
        assert pc.detect_host({}) == "codex"
    with _env(s.home, {"PLUGIN_ROOT": str(s.home / ".claude" / "plugins" / "x")}):
        assert pc.detect_host({}) == "claude"
    with _env(s.home, {"AGENTAVOW_HOST": "claude"}):
        assert pc.detect_host(_bash(s, "ls")) == "claude"
    with _env(s.home, {"CODEX_HOME": str(tmp_path / "elsewhere")}):
        assert pc.detect_host(_start(s)) == "claude"  # not under the Codex home in use
        assert pc.detect_host(_bash(s, "ls")) == "codex"


# --- config.toml ----------------------------------------------------------------------

def test_codex_config_servers_become_targets(tmp_path):
    s = _codex_session(tmp_path, CONFIG)
    with _env(s.home, s.env):
        pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
        pc._set_session_cwd({"cwd": str(s.project)})
        pc._set_host(_start(s))
        got = {t["name"]: (t["id"], t["scope"]) for t in pc._targets()}
    assert got == {"good": ("https://good.example.com/mcp", "user"),
                   "bad": ("https://bad.example.com/mcp", "user"),
                   "rev": ("npm:rev-pkg", "user")}


def test_the_fallback_reader_reads_server_tables_like_tomllib():
    pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
    full = pc._codex_server_map(pc._toml_load(CONFIG))
    mini = pc._codex_server_map(pc._mini_toml(CONFIG))
    for name in ("good", "rev", "off", "local", "script"):
        assert {k: v for k, v in mini[name].items()} == full[name], name
    assert mini["bad"]["url"] == full["bad"]["url"]
    assert pc._toml_load("this is [not toml") == {}
    assert pc._mini_toml("[mcp_servers.x]\nurl = \"https://x.example/mcp\" # note\n") == {
        "mcp_servers": {"x": {"url": "https://x.example/mcp"}}}


def test_a_broken_config_toml_is_silent(tmp_path):
    s = _codex_session(tmp_path, "[mcp_servers.x\nurl = ")
    assert s.precheck(_start(s)).startswith('{"systemMessage": "AgentAvow: nothing to grade')


def test_project_config_counts_only_when_the_project_is_trusted(tmp_path):
    s = _codex_session(tmp_path, CONFIG)
    (s.project / ".git").mkdir()
    (s.project / ".codex").mkdir()
    (s.project / ".codex" / "config.toml").write_text(
        '[mcp_servers.projsrv]\nurl = "https://proj.example.com/mcp"\n')

    def names() -> set[str]:
        with _env(s.home, s.env):
            pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
            pc._set_session_cwd({"cwd": str(s.project)})
            pc._set_host(_start(s))
            return {t["name"] for t in pc._targets()}

    assert "projsrv" not in names()
    (s.home / ".codex" / "config.toml").write_text(
        CONFIG + f'\n[projects."{s.project.resolve()}"]\ntrust_level = "trusted"\n')
    assert "projsrv" in names()
    (s.home / ".codex" / "config.toml").write_text(
        CONFIG + f'\n[projects."{s.project.resolve()}"]\ntrust_level = "untrusted"\n')
    assert "projsrv" not in names()


def test_servers_from_enabled_codex_plugins_are_graded_but_not_our_own(tmp_path):
    s = _codex_session(tmp_path, CONFIG + '\n[plugins."other@mkt"]\nenabled = true\n'
                       '\n[plugins."gone@mkt"]\nenabled = false\n')
    cache = s.home / ".codex" / "plugins" / "cache"
    for market, name, url in (("mkt", "other", "https://plug.example.com/mcp"),
                              ("mkt", "gone", "https://gone.example.com/mcp"),
                              ("agentavow", "agentavow-trust",
                               "https://agentavow.com/mcp?via=plugin")):
        d = cache / market / name / "1.0.0"
        (d / ".claude-plugin").mkdir(parents=True)
        (d / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": name}))
        (d / ".mcp.json").write_text(json.dumps({"mcpServers": {name + "srv": {"url": url}}}))
    with _env(s.home, s.env):
        pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
        pc._set_session_cwd({"cwd": str(s.project)})
        pc._set_host(_start(s))
        got = {t["name"]: t["scope"] for t in pc._targets()}
    assert got.get("othersrv") == "plugin"
    assert "gonesrv" not in got and "agentavow-trustsrv" not in got


# --- session start --------------------------------------------------------------------

def test_session_start_in_codex_grades_config_toml_servers(tmp_path):
    s = _codex_session(tmp_path, CONFIG)
    out = _codex_accepts("SessionStart", s.precheck(_start(s)))
    assert out["systemMessage"].startswith("AgentAvow pre-check: checked 3 MCP servers")
    assert "'bad' Do not connect" in out["systemMessage"]
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "MCP 'good' (https://good.example.com/mcp): Safe to connect" in ctx
    assert "MCP 'rev' (npm:rev-pkg): Review before you connect" in ctx
    assert "configured for other projects" not in ctx
    # nothing new next time: the once-a-day line for your own (user-scope) servers, then
    # a quiet context; both valid for Codex
    fine = _codex_accepts("SessionStart", s.precheck(_start(s)))
    assert fine["systemMessage"].startswith("AgentAvow: your 3 tools: 1 Safe, 1 Review")
    quiet = _codex_accepts("SessionStart", s.precheck(_start(s)))
    assert "systemMessage" not in quiet
    assert quiet["hookSpecificOutput"]["additionalContext"].startswith(
        "AgentAvow pre-check: nothing new")


def test_codex_intro_names_codex_commands(tmp_path):
    s = _codex_session(tmp_path)
    out = _codex_accepts("SessionStart", s.precheck(_start(s)))
    assert "codex mcp add <name> --url <https url>" in out["systemMessage"]
    assert "claude mcp add" not in out["systemMessage"]


def test_user_agent_says_codex_only_in_codex(tmp_path):
    s = _codex_session(tmp_path)
    with _env(s.home, s.env):
        pc = _load("codex_pc", SCRIPTS / "agentavow_precheck.py")
        pc._set_host(_start(s))
        assert pc._user_agent().endswith("(plugin; codex)")
        assert pc._user_agent().startswith("agentavow-precheck/")
        pc._set_host({})
    with _env(s.home):
        pc._set_host({})
        assert pc._user_agent().endswith("(plugin)")


# --- `codex mcp add` ------------------------------------------------------------------

@pytest.mark.parametrize("cmd,want", [
    ("codex mcp add deepwiki --url https://mcp.deepwiki.com/mcp",
     ("deepwiki", {"url": "https://mcp.deepwiki.com/mcp"})),
    ("codex mcp add --url https://mcp.deepwiki.com/mcp deepwiki",
     ("deepwiki", {"url": "https://mcp.deepwiki.com/mcp"})),
    ("codex mcp add deepwiki --url=https://mcp.deepwiki.com/mcp",
     ("deepwiki", {"url": "https://mcp.deepwiki.com/mcp"})),
    ("codex mcp add gh --url https://api.example.com/mcp --bearer-token-env-var GH_TOKEN",
     ("gh", {"url": "https://api.example.com/mcp"})),
    ("codex mcp add memory -- npx -y @modelcontextprotocol/server-memory",
     ("memory", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]})),
    ("codex mcp add --env API_KEY=x git -- uvx mcp-server-git",
     ("git", {"command": "uvx", "args": ["mcp-server-git"]})),
    ("codex -c x=1 mcp add gadget -- npx -y gadgethumans-mcp@1.0.15",
     None),  # a global flag before `mcp` is not the form people type; not guessed at
    ("cd ~/p && codex mcp add gadget -- npx -y gadgethumans-mcp@1.0.15 && echo done",
     ("gadget", {"command": "npx", "args": ["-y", "gadgethumans-mcp@1.0.15"]})),
    ("codex mcp add w --url https://w.example/mcp 2>&1",
     ("w", {"url": "https://w.example/mcp"})),
])
def test_codex_mcp_add_forms_are_parsed(cmd, want):
    mod = _load("codex_pi", SCRIPTS / "agentavow_pre_install.py")
    assert mod._server_from_codex_mcp_add(cmd) == want


@pytest.mark.parametrize("cmd", [
    "codex mcp list", "codex mcp remove deepwiki", "codex mcp add", "codex mcp add onlyname",
    "echo codex mcp", "claude mcp add x https://x.example/mcp", "codex mcp get x",
])
def test_other_codex_commands_are_ignored(cmd):
    mod = _load("codex_pi", SCRIPTS / "agentavow_pre_install.py")
    assert mod._server_from_codex_mcp_add(cmd) is None


def test_apply_patch_to_config_toml_is_read():
    mod = _load("codex_pi", SCRIPTS / "agentavow_pre_install.py")
    pc = mod._precheck()
    patch = ("*** Begin Patch\n*** Update File: /Users/me/.codex/config.toml\n@@\n"
             " [plugins.\"x@y\"]\n enabled = true\n+\n+[mcp_servers.evil]\n"
             "+url = \"https://evil.example.com/mcp\"\n*** End Patch\n")
    assert mod._servers_from_codex_patch(patch, pc) == [
        ("evil", {"url": "https://evil.example.com/mcp"})]
    add = ("*** Begin Patch\n*** Add File: .codex/config.toml\n+[mcp_servers.mem]\n"
           "+command = \"npx\"\n+args = [\"-y\", \"mem-pkg\"]\n*** End Patch\n")
    assert mod._servers_from_codex_patch(add, pc) == [
        ("mem", {"command": "npx", "args": ["-y", "mem-pkg"]})]
    untouched = ("*** Begin Patch\n*** Update File: /Users/me/.codex/config.toml\n@@\n"
                 " [mcp_servers.old]\n url = \"https://old.example.com/mcp\"\n"
                 "+model = \"x\"\n*** End Patch\n")
    assert mod._servers_from_codex_patch(untouched, pc) == []
    other_file = add.replace(".codex/config.toml", "notes.md")
    assert mod._servers_from_codex_patch(other_file, pc) == []


# --- install-time check in Codex ------------------------------------------------------

def test_codex_mcp_add_of_a_do_not_connect_server_is_denied_with_a_way_forward(tmp_path):
    s = _codex_session(tmp_path)
    raw = s.pre_install(_bash(s, "codex mcp add evil --url https://evil.example.com/mcp"))
    out = _codex_accepts("PreToolUse", raw)
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    reason = hso["permissionDecisionReason"]
    assert "MCP 'evil' (https://evil.example.com/mcp): Do not connect" in reason
    assert "Report: https://agentavow.com/check/mcp?endpoint=" in reason
    assert "outside Codex" in reason and "/hooks" in reason
    assert out["systemMessage"] == reason
    assert '"ask"' not in raw


def test_codex_mcp_add_of_a_package_server_is_checked(tmp_path):
    s = _codex_session(tmp_path)
    s.answers["/package/npm/gadgethumans-mcp"] = s.answers["/package/npm/badpkg"]
    out = _codex_accepts("PreToolUse", s.pre_install(
        _bash(s, "codex mcp add gadget -- npx -y gadgethumans-mcp@1.0.15")))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "npm:gadgethumans-mcp" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_safe_server_is_a_note_never_a_decision(tmp_path):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(
        _bash(s, "codex mcp add fine -- npx -y fine-pkg")))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "Safe to connect" in out["systemMessage"]


def test_codex_review_package_is_a_note_never_a_block(tmp_path):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(_bash(s, "npm install reviewpkg")))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "Review before you connect" in out["systemMessage"]
    assert "The install goes ahead" in out["systemMessage"]


def test_codex_install_of_a_do_not_connect_package_is_denied(tmp_path):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(_bash(s, "npm i badpkg okpkg")))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "install this" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_safe_package_install_is_silent(tmp_path):
    s = _codex_session(tmp_path)
    assert s.pre_install(_bash(s, "pip install requests")) == ""


def test_codex_apply_patch_adding_a_server_is_checked(tmp_path):
    s = _codex_session(tmp_path)
    patch = ("*** Begin Patch\n*** Update File: " + str(s.home / ".codex" / "config.toml")
             + "\n@@\n+[mcp_servers.evil]\n+url = \"https://evil.example.com/mcp\"\n"
             "*** End Patch\n")
    out = _codex_accepts("PreToolUse", s.pre_install(
        _tool(s, "apply_patch", {"command": patch})))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_claude_mcp_add_is_not_a_codex_command(tmp_path):
    s = _codex_session(tmp_path)
    assert s.pre_install(_bash(s, "claude mcp add evil https://evil.example.com/mcp")) == ""


def test_codex_step_naming_agentavow_files_is_denied(tmp_path):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(
        _bash(s, "cat ~/.cache/agentavow/allowed-servers.txt")))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "outside Codex" in out["hookSpecificOutput"]["permissionDecisionReason"]
    patch = ("*** Begin Patch\n*** Add File: " + str(s.home / ".cache" / "agentavow"
                                                     / "allowed-servers.txt")
             + "\n+bad https://bad.example.com/mcp AAAAA-BBBBB\n*** End Patch\n")
    out = _codex_accepts("PreToolUse", s.pre_install(
        _tool(s, "apply_patch", {"command": patch})))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# --- the per-call gate in Codex -------------------------------------------------------

def _graded(tmp_path) -> _Session:
    s = _codex_session(tmp_path, CONFIG + '\n[mcp_servers.newsrv]\n'
                       'url = "https://new.example.com/mcp"\n')
    _codex_accepts("SessionStart", s.precheck(_start(s)))
    return s


def test_codex_gate_denies_a_do_not_connect_server_with_the_allow_line(tmp_path):
    s = _graded(tmp_path)
    out = _codex_accepts("PreToolUse", s.gate_call(_tool(s, "mcp__bad__do", {"x": 1})))
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith("AgentAvow: Do not connect — 1 critical finding(s). MCP 'bad'")
    assert "(not Codex)" in reason and "/hooks" in reason and "Claude" not in reason
    # the confirmation code reaches the person only
    assert "bad https://bad.example.com/mcp " in out["systemMessage"]
    code = out["systemMessage"].split("bad https://bad.example.com/mcp ", 1)[1].split()[0]
    assert code not in reason


def test_codex_gate_turns_a_drift_ask_into_a_deny_that_says_how_to_go_ahead(tmp_path):
    s = _graded(tmp_path)
    assert s.gate_call(_tool(s, "mcp__good__read", {"q": "a"})) == ""
    s.served = [TOOL_V2]
    out = _codex_accepts("PreToolUse", s.gate_call(_tool(s, "mcp__good__read", {"q": "a"})))
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "the definition of 'read' on MCP 'good' changed" in reason
    assert "Codex cannot ask you before this call" in reason
    assert "start a new Codex session" in reason


def test_codex_gate_denies_a_call_naming_agentavow_files(tmp_path):
    s = _graded(tmp_path)
    out = _codex_accepts("PreToolUse", s.gate_call(
        _tool(s, "mcp__fs__read_file", {"path": "~/.cache/agentavow/allow.key"})))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "outside Codex" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_gate_notes_are_one_json_object(tmp_path):
    s = _graded(tmp_path)
    out = _codex_accepts("PreToolUse", s.gate_call(_tool(s, "mcp__newsrv__x", {})))
    assert out == {"systemMessage": "AgentAvow gate: MCP 'newsrv' has no grade on file, so "
                                    "its tools run unchecked. It is checked at your next "
                                    "session start."}
    assert s.gate_call(_tool(s, "mcp__newsrv__x", {})) == ""


def test_codex_gate_is_silent_for_its_own_connector_and_review(tmp_path):
    s = _graded(tmp_path)
    assert s.gate_call(_tool(s, "mcp__agentavow__scan_package", {"name": "x"})) == ""
    assert s.gate_call(_tool(s, "mcp__rev__anything", {})) == ""


def test_codex_output_merges_notes_and_never_asks():
    gate = _load("codex_gate", SCRIPTS / "agentavow_pretool_gate.py")
    printed = json.dumps({"systemMessage": "note one"}) + "\n"
    out = gate.codex_output(("ask", "AgentAvow: the definition changed."), printed)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["systemMessage"].startswith("note one\nAgentAvow: the definition changed.")
    assert gate.codex_output(None, "") is None
    assert gate.codex_output(None, printed) == {"systemMessage": "note one"}
