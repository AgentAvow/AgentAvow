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

def test_install_checks_identify_themselves_apart_from_session_start(hook, monkeypatch, capsys):
    # Usage metrics count install-time checks by their own User-Agent; the scan code is
    # shared with the session-start hook, so the label is the only thing that differs.
    mod, pc = hook
    seen = {}

    def scan(t, force=False):
        seen["ua"] = pc._user_agent()
        return _ok(88, "safe")

    _run(mod, monkeypatch, capsys, _bash("claude mcp add deepwiki https://mcp.deepwiki.com/mcp"), scan)
    assert seen["ua"].startswith("agentavow-preinstall/" + mod.__version__ + " (")


def test_safe_server_gives_a_visible_verdict_and_never_grants_permission(hook, monkeypatch, capsys):
    mod, pc = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add deepwiki https://mcp.deepwiki.com/mcp"),
               lambda t, force=False: _ok(88, "safe"))
    assert "✅ MCP 'deepwiki' (https://mcp.deepwiki.com/mcp): Safe to connect — nothing found · AgentAvow 88/100" \
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
    {"decision": "review", "decision_reason": "the maintainer has deprecated this package"},
])
def test_review_is_a_note_never_a_prompt(hook, monkeypatch, capsys, extra):
    """Review before you connect — a high finding, a low score, deprecation — is
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


def test_thin_coverage_without_findings_reads_safe_and_proceeds(hook, monkeypatch, capsys):
    """DeepWiki-style: 74/100, zero findings, 'thin coverage', from a pre-0.1.20 shape with
    no decision field. Thin coverage reads Safe with its reason (2026-10-08, #19); the add
    goes on."""
    mod, _ = hook
    out = _run(mod, monkeypatch, capsys, _bash("claude mcp add deepwiki https://mcp.deepwiki.com/mcp"),
               lambda t, force=False: _ok(74, "needs review", 0, tier="standard",
                                          reason="thin_coverage"))
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert ("✅ MCP 'deepwiki' (https://mcp.deepwiki.com/mcp): Safe to connect — nothing "
            "found; little code to inspect · AgentAvow 74/100") in out["systemMessage"]


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
    assert _run(mod, monkeypatch, capsys, _bash("echo npm install chalk && ls"),
                lambda t, force=False, stored=False: _ok(1, "x")) == {}
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


# --- package installs (npm / pip / uv …) — quiet by design -----------------------------

def _pkg(decision, reason, score=80, **extra):
    base = {"score": score, "decision": decision, "decision_reason": reason,
            "decision_final": True, "verdict": "safe" if decision == "safe" else "needs review",
            "blocking": 0, "critical": 0, "advisories": 0, "incident": False, "tier": "trusted",
            "grade": "", "tool_digests": {}, "tool_manifest_digest": None, "sandbox": "",
            "deprecated": False, "certified": False, "stale": False, "reason": ""}
    base.update(extra)
    return base


@pytest.mark.parametrize("cmd,want", [
    ("npm install chalk", [("npm", "chalk", "")]),
    ("npm i -D left-pad@1.3.0 @scope/x@^2", [("npm", "left-pad", "1.3.0"), ("npm", "@scope/x", "^2")]),
    ("cd app && pnpm add zod; yarn add react", [("npm", "zod", ""), ("npm", "react", "")]),
    ("bun add hono", [("npm", "hono", "")]),
    ("pip install requests==2.32.3 'pydantic[email]>=2'",
     [("pypi", "requests", "==2.32.3"), ("pypi", "pydantic", ">=2")]),
    ("python3 -m pip install -U httpx", [("pypi", "httpx", "")]),
    ("uv add fastapi && uv pip install rich", [("pypi", "fastapi", ""), ("pypi", "rich", "")]),
    ("pipx install ruff", [("pypi", "ruff", "")]),
    ("poetry add sqlalchemy", [("pypi", "sqlalchemy", "")]),
    ("sudo FOO=1 pip3 install numpy", [("pypi", "numpy", "")]),
    ("npm i a b c d e f g", [("npm", p, "") for p in "abcde"]),            # capped at 5
    ("npm install chalk chalk", [("npm", "chalk", "")]),                   # de-duplicated
])
def test_package_installs_are_recognised(hook, cmd, want):
    mod, pc = hook
    assert mod._package_installs(cmd, pc) == want


@pytest.mark.parametrize("cmd,want", [
    # Redirections are the shell's, never package names (sweep 2026-11-11: '2>&1' was
    # read as a PyPI package named '2').
    ("pip install requests 2>&1", [("pypi", "requests", "")]),
    ("pip install requests 2>&1 | tail -3", [("pypi", "requests", "")]),
    ("pip install requests >/dev/null", [("pypi", "requests", "")]),
    ("pip install requests > /dev/null 2>&1", [("pypi", "requests", "")]),
    ("pip install requests >install.log", [("pypi", "requests", "")]),
    ("pip install requests >>install.log rich", [("pypi", "requests", ""), ("pypi", "rich", "")]),
    ("pip install requests 2>err.txt", [("pypi", "requests", "")]),
    ("pip install requests 2> err.txt", [("pypi", "requests", "")]),
    ("pip install requests &>out.txt", [("pypi", "requests", "")]),
    ("pip install requests &> /dev/null", [("pypi", "requests", "")]),
    ("pip install requests </dev/null", [("pypi", "requests", "")]),
    ("pip install requests 2>&1 | tee pip.log", [("pypi", "requests", "")]),
    ("pip install requests 2>&1 && echo done", [("pypi", "requests", "")]),
    ("pip install requests; echo done", [("pypi", "requests", "")]),
    ("pip install requests & echo done", [("pypi", "requests", "")]),
    ("python3 -m pip install -q httpx 2>/dev/null", [("pypi", "httpx", "")]),
    ("uv pip install rich 2>&1", [("pypi", "rich", "")]),
    ("uv add fastapi >/dev/null 2>&1", [("pypi", "fastapi", "")]),
    ("poetry add sqlalchemy 2>&1 | tail -1", [("pypi", "sqlalchemy", "")]),
    ("pipx install ruff 1>/dev/null", [("pypi", "ruff", "")]),
    ("npm i left-pad 2>&1", [("npm", "left-pad", "")]),
    ("npm install chalk >/dev/null 2>&1", [("npm", "chalk", "")]),
    # Quoted text is not a redirection: a version spec stays a version spec.
    ("pip install 'requests>=2' 2>&1", [("pypi", "requests", ">=2")]),
    ('pip install "pydantic<3" >/dev/null', [("pypi", "pydantic", "<3")]),
])
def test_shell_redirections_are_not_read_as_packages(hook, cmd, want):
    mod, pc = hook
    assert mod._package_installs(cmd, pc) == want


@pytest.mark.parametrize("cmd", [
    "pip install -r requirements.txt 2>&1", "pip install 2>&1", "pip install >/dev/null",
])
def test_redirection_only_commands_install_nothing(hook, cmd):
    mod, pc = hook
    assert mod._package_installs(cmd, pc) == []


@pytest.mark.parametrize("cmd", [
    "npm install", "npm ci", "pnpm install", "uv sync", "pip install -r requirements.txt",
    "pip install -e .", "pip install ./dist/pkg-1.0.whl", "npm i ./local-pkg",
    "npm i git+https://example.com/a/b.git", "npm i owner/repo", "npm i https://x/y.tgz",
    "npm run build", "echo npm install x",
])
def test_lockfile_project_path_and_url_installs_are_left_alone(hook, cmd):
    mod, pc = hook
    assert mod._package_installs(cmd, pc) == []


def _run_pkgs(mod, pc, monkeypatch, capsys, cmd, verdicts, queued=()):
    calls = []

    def scan(t, force=False, stored=False):
        calls.append((t["pkg"], stored))
        if stored and t["pkg"] in queued:
            raise pc._QueuedError("queued")
        v = verdicts.get(t["pkg"])
        if isinstance(v, Exception):
            raise v
        return v

    monkeypatch.setattr(pc, "_scan", scan)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash(cmd))))
    mod.main()
    out = capsys.readouterr().out
    return (json.loads(out) if out else {}), calls


def test_safe_packages_are_silent_but_counted(hook, monkeypatch, capsys):
    mod, pc = hook
    out, calls = _run_pkgs(mod, pc, monkeypatch, capsys, "npm i chalk zod",
                           {"chalk": _pkg("safe", "nothing found"),
                            "zod": _pkg("safe", "nothing found")})
    assert out == {}                                   # nothing shown
    assert calls == [("chalk", True), ("zod", True)]   # stored grades only
    meta = json.loads(pc.CACHE.read_text())[pc.META_KEY]
    assert meta["install_checks"]["count"] == 2 and meta["install_checks"]["flagged"] == 0
    assert mod.STATS_KEY == pc.INSTALL_STATS_KEY


def test_deprecated_reads_as_deprecated_not_a_security_problem(hook, monkeypatch, capsys):
    mod, pc = hook
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "npm install left-pad",
                       {"left-pad": _pkg("review", "the maintainer has deprecated this package",
                                         deprecated=True)})
    msg = out["systemMessage"]
    assert "deprecated by its maintainer — not a security finding" in msg
    assert "Review before you connect" not in msg
    assert "permissionDecision" not in out["hookSpecificOutput"]  # never a prompt


def test_review_is_a_one_line_note_and_the_install_proceeds(hook, monkeypatch, capsys):
    mod, pc = hook
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "npm install shelljs",
                       {"shelljs": _pkg("review", "one high finding: exec with a variable",
                                        score=48, blocking=1)})
    msg = out["systemMessage"]
    assert "⚠️ npm package 'shelljs': Review before you connect" in msg
    assert "The install goes ahead" in msg
    assert "permissionDecision" not in out["hookSpecificOutput"]


def test_do_not_connect_asks_first(hook, monkeypatch, capsys):
    mod, pc = hook
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "pip install evil-pkg",
                       {"evil-pkg": _pkg("do_not_connect",
                                         "a known-malicious package or dependency",
                                         score=5, incident=True)})
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert "⛔ pypi package 'evil-pkg': Do not connect" in hso["permissionDecisionReason"]


def test_never_graded_gets_one_fresh_scan_then_silence(hook, monkeypatch, capsys):
    mod, pc = hook
    out, calls = _run_pkgs(mod, pc, monkeypatch, capsys, "npm i new-a new-b",
                           {"new-a": _pkg("safe", "nothing found"), "new-b": _pkg("safe", "x")},
                           queued=("new-a", "new-b"))
    assert out == {}
    # stored then ONE fresh scan for new-a; new-b gets no fresh scan (FRESH_MAX = 1)
    assert calls == [("new-a", True), ("new-a", False), ("new-b", True)]


def test_unscannable_says_not_checked_and_offline_stays_silent(hook, monkeypatch, capsys):
    mod, pc = hook
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "npm i nope weird boom",
                       {"nope": pc._UnscannableError("404"),
                        "weird": pc._UnscannableError("archive is over the 50 MB limit"),
                        "boom": TimeoutError("slow")})
    msg = out["systemMessage"]
    # The API's answer about the target is said once; a bare status code is not shown.
    assert "❔ npm package 'nope': not checked — AgentAvow couldn't grade it. " in msg
    assert ("❔ npm package 'weird': not checked — AgentAvow couldn't grade it "
            "(archive is over the 50 MB limit)") in msg
    assert "boom" not in msg                                # offline / timeout: silent
    assert "permissionDecision" not in out["hookSpecificOutput"]  # never a prompt
    meta = json.loads(pc.CACHE.read_text()).get(pc.META_KEY, {})
    assert meta.get("install_checks", {}).get("flagged", 0) == 0    # nothing graded or flagged


def test_busy_api_says_not_checked(hook, monkeypatch, capsys):
    import urllib.error
    mod, pc = hook
    busy = urllib.error.HTTPError("https://x", 503, "busy", {}, None)
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "pip install httpx", {"httpx": busy})
    assert "❔ pypi package 'httpx': not checked (AgentAvow is busy right now)" in out[
        "systemMessage"]


@pytest.mark.parametrize("gaps,shown", [
    (["oversized_files"], True),      # a file padded past the read cap
    (["package_skipped"], True),      # payload past the unpack budget
    (["tree_truncated"], False),      # not attacker-cheap for a package: stays silent
    ([], False),
])
def test_safe_with_an_unread_part_says_so_quietly(hook, monkeypatch, capsys, gaps, shown):
    mod, pc = hook
    out, _ = _run_pkgs(mod, pc, monkeypatch, capsys, "npm i big",
                       {"big": _pkg("safe", "nothing found; 1 file over 500 KB was not "
                                    "fully read", gaps=gaps)})
    if not shown:
        assert out == {}
        return
    msg = out["systemMessage"]
    assert "ℹ️ npm package 'big': Safe to connect" in msg
    assert "Part of the package could not be read" in msg and "The install goes ahead" in msg
    assert "permissionDecision" not in out["hookSpecificOutput"]
    meta = json.loads(pc.CACHE.read_text())[pc.META_KEY]
    assert meta["install_checks"]["flagged"] == 0          # a note, not a flag


def test_cached_grade_is_reused_without_a_request(hook, monkeypatch, capsys):
    mod, pc = hook
    _run_pkgs(mod, pc, monkeypatch, capsys, "npm i chalk", {"chalk": _pkg("safe", "nothing found")})
    _, calls = _run_pkgs(mod, pc, monkeypatch, capsys, "npm i chalk", {})
    assert calls == []


def test_install_checks_can_be_switched_off(hook, monkeypatch, capsys):
    mod, pc = hook
    monkeypatch.setenv("AGENTAVOW_INSTALL_CHECKS", "off")
    out, calls = _run_pkgs(mod, pc, monkeypatch, capsys, "npm install shelljs",
                           {"shelljs": _pkg("review", "x", blocking=1)})
    assert out == {} and calls == []


def test_session_start_relays_the_install_count_once(hook, monkeypatch, capsys):
    mod, pc = hook
    _run_pkgs(mod, pc, monkeypatch, capsys, "npm i chalk zod left-pad", {
        "chalk": _pkg("safe", "x"), "zod": _pkg("safe", "x"),
        "left-pad": _pkg("review", "the maintainer has deprecated this package",
                         deprecated=True)})
    cache = pc._load_cache()
    clause = pc._install_clause(cache)
    assert clause == (" Since the last session AgentAvow checked 3 package installs; "
                      "1 needed a look (reported at the time).")
    assert pc._install_clause(cache) == ""        # reset after reading
    cache[pc.META_KEY]["install_checks"] = {"count": 1, "flagged": 0}
    assert pc._install_clause(cache) == (
        " Since the last session AgentAvow checked 1 package install — all Safe to connect.")


# --- only the person may read or change AgentAvow's own files (0.1.37, widened 0.1.38) -
# The second line of defence: an allow line Claude writes lacks the person's code and
# allows nothing anyway (tests/test_agentavow_pretool_gate.py). These are attack twins
# for the spellings a prompt-injected Claude would try first.

def _ask_reason(mod, monkeypatch, capsys, payload):
    out = _run(mod, monkeypatch, capsys, payload, lambda *a, **k: pytest.fail("no scan"))
    h = out["hookSpecificOutput"]
    assert h["permissionDecision"] == "ask"
    return h["permissionDecisionReason"]


@pytest.mark.parametrize("cmd", [
    # plain
    "echo 'srv https://x.example/mcp' >> ~/.cache/agentavow/allowed-servers.txt",
    "printf 'a b\\n' | tee -a $HOME/.cache/agentavow/Allowed-Servers.TXT",
    # obfuscated paths: quotes and backslashes inside words, ${HOME}, a glob, cd + variable
    "echo x >> ~/.cache/agent''avow/allowed-'servers'.txt",
    'echo x >> "${HOME}/.cache/agent"avow/al\\lowed-servers.txt',
    "echo x >> ~/.cache/agent*/allow*",
    "echo x >> ~/.ca*/agentavow/x",
    "cd ~/.cache/agentavow && f=allowed; echo x >> $f-servers.txt",
    "cd ~/.cache && cd agentavow && echo x >> \"$(ls | grep allow)\"",
    "cd agentavow; echo x >> \"$F\"",
    "D=$HOME/.cache; echo x >> $D/agentavow/$N",
    "f=~/.cache/agentavow; printf '%s\\n' x >> $f/$(echo YWxsb3dlZA== | base64 -d)",
    # reading the key behind the codes
    "cat ~/.cache/agentavow/allow.key",
    "xxd \"$HOME/.cache/agentavow/\"*",
    "cat ~/.cache/*/allow*",
    # python -c and friends
    "python3 -c \"import pathlib; (pathlib.Path.home()/'.cache'/'agentavow'/'allowed-servers.txt')"
    ".write_text('srv x')\"",
    "python3 -c \"import os; open(os.path.join(os.path.expanduser('~'), '.cache', 'agentavow', "
    "'a'+'llowed-servers.txt'), 'a').write('x')\"",
    "python3 -c \"import os;d=os.path.expanduser('~/.cache/agentavow');open(d+'/k','w')\"",
    "node -e \"require('fs').appendFileSync(require('os').homedir()+'/.cache/agentavow/x','y')\"",
    "XDG_CACHE_HOME=/x; ls $XDG_CACHE_HOME/agentavow",
    # a parent that could stand for the cache folder still counts (0.1.39)
    "ls ~/.cache/./agentavow",
    "ls ~/.cache/x/../agentavow",
    "C=~/.cache; cat $C/agentavow/scanned.json",
    "cat $(dirname ~/.cache/x)/agentavow/k",
    "ls ~/.cach?/agentavow",
    # cp / mv / tee / ln from another file
    "cp /tmp/list ~/.cache/agentavow/allowed-servers.txt",
    "mv /tmp/l \"$HOME/.cache/agentavow/\"",
    "tee ~/.cache/agentavow/a < /tmp/l",
    "ln -sf /tmp/mine ~/.cache/agentavow/allowed-servers.txt",
    "ln -s ~/.cache/agentavow /tmp/av",
    "rsync /tmp/l ~/.cache/agentavow/",
    # the gate's terminal-only allow-line command, run under a pseudo-terminal
    "script -q /dev/null python3 ~/.claude/plugins/x/scripts/agentavow_pretool_gate.py "
    "--allow-line srv",
    "python3 agentavow_pretool_gate.py --allow_line srv",
])
def test_shell_steps_on_agentavow_files_ask_the_person(hook, monkeypatch, capsys, cmd):
    mod, _ = hook
    reason = _ask_reason(mod, monkeypatch, capsys, _bash(cmd))
    assert "AgentAvow's own files" in reason


@pytest.mark.parametrize("tool,path", [
    ("Write", "/Users/me/.cache/agentavow/allowed-servers.txt"),
    ("Edit", "/home/me/.cache/agentavow/allowed-servers.txt"),
    ("Write", "~/.cache/agentavow/allow.key"),
    ("MultiEdit", "~/.cache/agentavow/scanned.json"),
    ("Write", "~/.cache/agentavow/x.txt"),
])
def test_writes_into_agentavow_folder_ask_the_person(hook, monkeypatch, capsys, tool, path):
    mod, _ = hook
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool,
               "tool_input": {"file_path": path, "content": "srv https://x.example/mcp\n",
                              "old_string": "", "new_string": "x"}}
    _ask_reason(mod, monkeypatch, capsys, payload)


def test_a_write_through_a_symlink_or_relative_path_into_the_folder_asks(
        hook, monkeypatch, capsys, tmp_path):
    mod, _ = hook
    own = tmp_path / "home" / ".cache" / "agentavow"
    own.mkdir(parents=True)
    monkeypatch.setattr(mod, "_own_dir", lambda: own)
    link = tmp_path / "innocent"
    link.symlink_to(own)
    for path, cwd in ((str(link / "list.txt"), "/"), ("innocent/list.txt", str(tmp_path)),
                      ("x", str(own))):
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": cwd,
                   "tool_input": {"file_path": path, "content": "x"}}
        _ask_reason(mod, monkeypatch, capsys, payload)


@pytest.mark.parametrize("payload", [
    _bash("ls ~/.cache"),
    _bash("pytest tests/test_agentavow_pre_install.py --noconftest"),
    _bash("gh pr create --repo AgentAvow/AgentAvow --title 'allow lists'"),
    _bash("du -sh ~/.cache/pip && echo agentavow-trust agentavow_precheck"),
    _bash("sh plugins/agentavow-trust/scripts/run_hook.sh agentavow_precheck.py"),
    _bash("curl -s https://agentavow.com/api/v1/public/scan/repo/a/b"),
    {"hook_event_name": "PreToolUse", "tool_name": "Write",
     "tool_input": {"file_path": "/tmp/notes.txt", "content": "allowed-servers"}},
    {"hook_event_name": "PreToolUse", "tool_name": "Edit",
     "tool_input": {"file_path": "plugins/agentavow-trust/README.md", "old_string": "a",
                    "new_string": "~/.cache/agentavow/allowed-servers.txt"}},
    # A folder named AgentAvow that is not the cache folder (0.1.39): a checkout of this
    # repo, and the plugin's own install folder. These asked on every edit in a checkout.
    _bash("cd /home/me/projects/AgentAvow && git status"),
    _bash("grep -rn verdict /home/me/projects/AgentAvow/src/scanner | head"),
    _bash("sh ~/.claude/plugins/cache/agentavow/agentavow-trust/0.1.38/scripts/run_hook.sh x"),
    _bash("ls /home/me/projects/AgentAvow/tests && du -sh ~/.cache/pip"),
    {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": "/home/me/projects/AgentAvow",
     "tool_input": {"file_path": "/home/me/projects/AgentAvow/src/scanner/scan.py",
                    "old_string": "a", "new_string": "b"}},
    {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": "/home/me/projects/AgentAvow",
     "tool_input": {"file_path": "/home/me/projects/AgentAvow/tests/test_x.py", "content": "x"}},
])
def test_other_steps_are_not_mistaken_for_agentavow_files(hook, monkeypatch, capsys, payload):
    mod, _ = hook
    assert _run(mod, monkeypatch, capsys, payload, lambda *a, **k: None) == {}


# The rule is about where a folder sits, not what it is called: any checkout or worktree
# name, under any plain parent, is not the cache folder. Names and parents are examples
# of the shape, not a list the hook knows.
_CHECKOUT_NAMES = ["AgentAvow", "agentavow", "AGENTAVOW", "AgentAvow-wt-hook",
                   "AgentAvow-review-2", "AgentAvow.bak", "agentavow_old", "AgentAvow2"]
_PLAIN_PARENTS = ["/home/me/projects", "/srv/build/7", "/Users/me/src/github.com/org",
                  "/tmp/ci-workspace", "/mnt/c/Users/me/code"]


@pytest.mark.parametrize("parent", _PLAIN_PARENTS)
@pytest.mark.parametrize("name", _CHECKOUT_NAMES)
def test_any_checkout_folder_name_is_not_the_cache_folder(hook, monkeypatch, capsys,
                                                          parent, name):
    mod, _ = hook
    root = f"{parent}/{name}"
    for payload in (
        _bash(f"cd {root} && git status"),
        _bash(f"grep -rn verdict {root}/src | head"),
        {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": root,
         "tool_input": {"file_path": f"{root}/src/app.py", "old_string": "a",
                        "new_string": "b"}},
    ):
        assert _run(mod, monkeypatch, capsys, payload, lambda *a, **k: None) == {}, payload


@pytest.mark.parametrize("name", _CHECKOUT_NAMES)
def test_relative_cd_into_a_checkout_is_judged_by_the_working_directory(
        hook, monkeypatch, capsys, tmp_path, name):
    mod, _ = hook
    cache = tmp_path / "home" / ".cache"
    (cache / "agentavow").mkdir(parents=True)
    monkeypatch.setattr(mod, "_own_dir", lambda: cache / "agentavow")
    elsewhere = tmp_path / "projects"
    elsewhere.mkdir()
    cmd = _bash(f"cd {name} && git status")
    # From a projects folder: a checkout, whatever it is called.
    assert _run(mod, monkeypatch, capsys, dict(cmd, cwd=str(elsewhere)),
                lambda *a, **k: None) == {}
    if name.lower() == "agentavow":
        # From the cache folder itself, or with no known cwd, or after a second `cd`
        # that could move first: still asks.
        _ask_reason(mod, monkeypatch, capsys, dict(cmd, cwd=str(cache)))
        _ask_reason(mod, monkeypatch, capsys, cmd)
        _ask_reason(mod, monkeypatch, capsys,
                    dict(_bash(f"cd $D; cd {name} && git status"), cwd=str(elsewhere)))


@pytest.mark.parametrize("parent", ["~/.cache", "$HOME/.cache", "${XDG_CACHE_HOME}",
                                    "$C", "~/.cache/.", "~/.cache/x/..", "~/.ca*"])
def test_the_cache_folder_under_any_spelling_still_asks(hook, monkeypatch, capsys, parent):
    mod, _ = hook
    _ask_reason(mod, monkeypatch, capsys, _bash(f"cat {parent}/agentavow/scanned.json"))


# A plain-looking parent can be a symlink to the cache folder: the real path decides,
# and a step that makes a link, or a relative path after a `cd`, is not ruled out.
def _cache_with_alias(mod, monkeypatch, tmp_path):
    cache = tmp_path / "home" / ".cache"
    (cache / "agentavow").mkdir(parents=True)
    monkeypatch.setattr(mod, "_own_dir", lambda: cache / "agentavow")
    work = tmp_path / "work"
    work.mkdir()
    (work / "q").symlink_to(cache)
    return cache, work


def test_a_symlinked_parent_into_the_cache_folder_still_asks(hook, monkeypatch, capsys,
                                                             tmp_path):
    mod, _ = hook
    _, work = _cache_with_alias(mod, monkeypatch, tmp_path)
    _ask_reason(mod, monkeypatch, capsys,
                _bash(f"echo x > {work}/q/agentavow/scanned.json"))
    _ask_reason(mod, monkeypatch, capsys,
                dict(_bash("cat q/agentavow/scanned.json"), cwd=str(work)))


@pytest.mark.parametrize("cmd", [
    "ln -s ~/.cache q && echo x > q/agentavow/scanned.json",
    "python3 -c \"import os;os.symlink(os.path.expanduser('~/.cache'),'q')\"; cat q/agentavow/scanned.json",
    "cd ~ && cat q/agentavow/scanned.json",
    "cat r/agentavow/scanned.json",
    "HOME=/x; cat $HOME/q/agentavow/scanned.json",
])
def test_a_plain_parent_that_could_be_an_alias_still_asks(hook, monkeypatch, capsys, cmd):
    mod, _ = hook
    # No cwd for the relative ones, a link made in the same command, a `cd` first.
    _ask_reason(mod, monkeypatch, capsys, _bash(cmd))


def test_a_checkout_under_home_var_does_not_ask(hook, monkeypatch, capsys):
    mod, _ = hook
    assert _run(mod, monkeypatch, capsys,
                _bash("grep -rn verdict $HOME/projects/AgentAvow/src | head"),
                lambda *a, **k: None) == {}
