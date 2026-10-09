# AgentAvow + Claude Code — scan tools before you trust them

Two opt-in ways to make "check it before you connect it" automatic. Both rely on
the AgentAvow MCP connector being added first:

```bash
claude mcp add --transport http agentavow https://agentavow.com/mcp
```

Both are **your** configuration. AgentAvow's MCP server never forces a scan — that
would be a prompt-injection vector and is explicitly not how this works. You opt in;
you stay in control.

---

## Option 1 — the CLAUDE.md rule (lightest touch)

Copy the one line from `CLAUDE.md-rule.md` into your `~/.claude/CLAUDE.md`. Done.
Now when you ask to install or connect something, the agent scans it first and
reports the verdict before proceeding.

**Test it:** in a fresh session, say *"add the deepwiki MCP server at
https://mcp.deepwiki.com/mcp"*. The agent should scan it with AgentAvow and tell you
the verdict before doing anything else.

---

## Option 2 — the SessionStart hook (automatic, hands-off)

Scans every HTTP MCP server you've configured that hasn't been scanned yet, at the
start of each session, and surfaces the verdict. No need to remember.

**Install:**
```bash
mkdir -p ~/.claude/hooks
cp agentavow_precheck.py agentavow_pretool_gate.py agentavow_pre_install.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/agentavow_precheck.py ~/.claude/hooks/agentavow_pretool_gate.py ~/.claude/hooks/agentavow_pre_install.py
```
Then merge the contents of `settings.hooks.json` into `~/.claude/settings.json`
(under the `hooks` key — keep any hooks you already have). Its `PreToolUse` block is
the per-call gate (below); leave it out for session-start verdicts only.

**Test it:**
1. Direct run (no Claude needed) — after you've added at least one HTTP MCP server:
   ```bash
   echo '{}' | python3 ~/.claude/hooks/agentavow_precheck.py
   ```
   You should see a JSON object with a one-line `systemMessage` summary and an
   `additionalContext` block that lists each new MCP server
   with its answer (Safe to connect / Review before you connect / Do not connect), the
   reason and its AgentAvow score. Run it again — already-scanned servers are
   cached (`~/.cache/agentavow/scanned.json`), so the second run is silent.
2. End to end: add a new MCP server (`claude mcp add --transport http foo <url>`),
   then start a **new** session. The hook scans `foo` and you'll see a line like:
   `⚠️ MCP 'foo' (<url>): Review before you connect — one high finding: … · AgentAvow 66/100`

**Guarantees:** warn-only (never blocks a session), fail-open (a scan error or an
unrecognized config just stays silent), and it only scans each endpoint once. A
server AgentAvow can't read (one that needs sign-in, for example) is reported once
as "not scanned" and left alone for a week. Servers on localhost or a private
network are never sent anywhere, a URL whose path looks like it carries a secret is
withheld, and credentials and query strings are stripped from a URL before it leaves
your machine.

---

## The per-call gate (`agentavow_pretool_gate.py`)

Runs before each MCP tool call and acts on the result the session-start hook stored.
It never calls AgentAvow. **Deny** when the server's answer is "Do not connect" (a
critical finding, a planted credential leaving the sandbox, a known-malicious package)
or its score is in the `blocked` tier (0 to 10 out of 100); the reason leads with the
answer and gives the score and report link. **Ask** when a
remote server now serves a definition for this tool that differs from the one that
was graded, or a tool the grade never saw: the gate re-fetches `tools/list` from the
server itself (at most once per server per 15 minutes) and recomputes the per-tool
digest the signed attestation carries. **Allow**, silently, in every other case:
no grade on file, a stdio server (verdict only), any error or timeout.

Settings, all optional, read from the environment and never sent anywhere:
`AGENTAVOW_GATE_DENY_BELOW` (default: the `blocked` tier; a number such as `51` or a
tier name such as `minimal`; `off` never denies), `AGENTAVOW_GATE_RECHECK_SECONDS`
(default `900`), `AGENTAVOW_GATE=off` (turns the gate off).

Test it without Claude, with a graded server named `example` in your config:
```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"mcp__example__some_tool","session_id":"t","tool_input":{}}' \
  | python3 ~/.claude/hooks/agentavow_pretool_gate.py
```
Silence means allow; a deny or ask is a JSON object with a `permissionDecision`.

**Prefer a plugin?** The same hooks ship in the AgentAvow Trust plugin, with the
connector and a `/scan` command: `/plugin marketplace add AgentAvow/AgentAvow`, then
`/plugin install agentavow-trust@agentavow`. Use one or the other, not both.

**Scope:** covers both remote HTTP(S) MCP servers (scanned as a live endpoint) and
local stdio servers launched from a published package — `npx` / `bunx` (npm) and
`uvx` / `pipx` (PyPI), including scoped names and pinned versions. Servers that run a
hand-written script (`node server.js`, `python server.py`) have no published package
to grade and are skipped.
