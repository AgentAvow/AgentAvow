# Scan tools automatically in Claude Code

Make "check it before you connect it" automatic. Two opt-in ways, both your own
configuration. AgentAvow's MCP server never forces a scan, so nothing here can flag
your setup in a directory review. You opt in; you stay in control.

> **Claude Code, not Claude Desktop.** These use `CLAUDE.md` and hooks, which are
> Claude Code (CLI) features. Claude Desktop has no user `CLAUDE.md` or hooks, so in
> Desktop you invoke AgentAvow on request rather than automatically.

First, add the connector:

```
claude mcp add --transport http agentavow https://agentavow.com/mcp
```

## Option 1 — the CLAUDE.md rule (lightest touch)

Add one line to your `~/.claude/CLAUDE.md` (applies everywhere) or a project's
`CLAUDE.md`:

```
Before installing or connecting a new MCP server, tool, package, or skill, first
scan it with AgentAvow (scan_mcp_server for an MCP URL, scan_package for a package,
scan_repo for a repo) and tell me the verdict before proceeding.
```

Now when you ask to install or connect something, the agent scans it first and
reports the verdict.

**Test it:** in a fresh session, say *"add the deepwiki MCP server at
https://mcp.deepwiki.com/mcp"*. The agent should scan it and report the verdict
before doing anything else.

## Option 2 — the SessionStart hook (automatic, hands-off)

Scans every MCP server you have configured that hasn't been scanned yet, at the
start of each session, and surfaces the verdict. Covers both remote HTTP servers
and local stdio servers launched from a published package (`npx`/`bunx` → npm,
`uvx`/`pipx` → PyPI). It reads your config and calls AgentAvow's public API
directly, so it works at startup before MCP servers connect.

**Install:**

```
mkdir -p ~/.claude/hooks
curl -fsSL https://raw.githubusercontent.com/AgentAvow/AgentAvow/main/integrations/claude-code/agentavow_precheck.py \
  -o ~/.claude/hooks/agentavow_precheck.py
```

Then add this to `~/.claude/settings.json` (merge under `hooks`, keeping anything
you already have):

```
{
  "hooks": {
    "SessionStart": [
      { "matcher": "startup|resume",
        "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/agentavow_precheck.py", "timeout": 30 } ] }
    ]
  }
}
```

**Test it** without even starting Claude, once you have at least one MCP server
configured:

```
echo '{}' | python3 ~/.claude/hooks/agentavow_precheck.py
```

You should see a verdict line per new MCP server. Run it again and it stays silent
(already-scanned servers are cached in `~/.cache/agentavow/scanned.json`). End to
end: add a new server, then start a new session and the verdict appears in context.

## Guarantees

- **Opt-in.** Nothing runs unless you install it.
- **Warn, never block.** A low score adds context; it never stops your session.
- **Fail-open.** A network hiccup or an unrecognized config stays silent and exits
  cleanly. It cannot break session startup.

The hook and the rule live in the repo at
[`integrations/claude-code`](https://github.com/AgentAvow/AgentAvow/tree/main/integrations/claude-code).
