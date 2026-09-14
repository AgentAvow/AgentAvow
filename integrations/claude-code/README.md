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
cp agentavow_precheck.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/agentavow_precheck.py
```
Then merge the contents of `settings.hooks.json` into `~/.claude/settings.json`
(under the `hooks` key — keep any hooks you already have).

**Test it:**
1. Direct run (no Claude needed) — after you've added at least one HTTP MCP server:
   ```bash
   echo '{}' | python3 ~/.claude/hooks/agentavow_precheck.py
   ```
   You should see a JSON object whose `additionalContext` lists each new MCP server
   with its AgentAvow score and verdict. Run it again — already-scanned servers are
   cached (`~/.cache/agentavow/scanned.json`), so the second run is silent.
2. End to end: add a new MCP server (`claude mcp add --transport http foo <url>`),
   then start a **new** session. The hook scans `foo` and you'll see a line like:
   `⚠️ MCP 'foo' (<url>): AgentAvow 66/100 — needs review, 1 blocking finding(s).`

**Guarantees:** warn-only (never blocks a session), fail-open (a scan error or an
unrecognized config just stays silent), and it only scans each endpoint once.

**Scope:** covers both remote HTTP(S) MCP servers (scanned as a live endpoint) and
local stdio servers launched from a published package — `npx` / `bunx` (npm) and
`uvx` / `pipx` (PyPI), including scoped names and pinned versions. Servers that run a
hand-written script (`node server.js`, `python server.py`) have no published package
to grade and are skipped.
