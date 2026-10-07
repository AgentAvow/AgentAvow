# Scan tools automatically in Claude Code

Make "check it before you connect it" automatic. Three opt-in ways, all your own
configuration. AgentAvow's MCP server never forces a scan, so nothing here can flag
your setup in a directory review. You opt in; you stay in control.

> **Where this works.** Plugins, `CLAUDE.md` and hooks are Claude Code features, so
> this covers the Claude Code CLI and the Code tab in the Claude desktop app. In a
> regular Claude chat you ask for a scan rather than getting one automatically.

## The plugin (easiest)

The **AgentAvow Trust** plugin bundles the connector, a `/scan` command, a skill
that scans a server or package before Claude adds it (the same idea as Option 1),
the SessionStart hook described under Option 2, and the per-call gate described
below it. Find it in the Anthropic plugin directory, or install it from the repo:

```
/plugin marketplace add AgentAvow/AgentAvow
/plugin install agentavow-trust@agentavow
```

**Test it:** run `/scan npm chalk`. Then add an MCP server and start a new session;
its answer appears in context.

Every line the plugin shows leads with one of three answers and its reason, then the
score: **Safe to connect**, **Review before you connect**, or **Do not connect**, plus
"· Certified" for a Certified tool. From plugin version 0.1.20:

- **Only Do not connect stops anything.** The per-call gate denies a tool whose server
  reads Do not connect (and, as before, a server in the `blocked` tier). The install
  hook pauses for your confirmation only on Do not connect.
- **Review is a note, never a prompt.** A server or package that reads Review before
  you connect is reported with its reason and proceeds. Nothing prompts on a review
  that only says there was little code to inspect.
- **Dependencies are advice.** The session-start lines for your project's dependencies
  show the same answer and never block: they are already installed.
- **A changed definition still pauses** for your confirmation, whatever the answer.
- **Fail-open.** Any error, timeout or missing grade lets the call through.

If you install the plugin, skip Option 2. It is the same pair of hooks, and running
both scans everything twice.

## Without the plugin

Add the connector:

```
claude mcp add --transport http agentavow https://agentavow.com/mcp
```

## Option 1 — the CLAUDE.md rule (lightest touch)

Add one line to your `~/.claude/CLAUDE.md` (applies everywhere) or a project's
`CLAUDE.md`:

```
Before installing or connecting a new MCP server, tool, package, or skill, first
scan it with AgentAvow (scan_mcp_server for an MCP URL, scan_package for a package,
scan_repo for a repo) and tell me the answer (Safe to connect / Review before you
connect / Do not connect) and its reason before proceeding.
```

Now when you ask to install or connect something, the agent scans it first and
reports the answer.

**Test it:** in a fresh session, say *"add the deepwiki MCP server at
https://mcp.deepwiki.com/mcp"*. The agent should scan it and report the answer
before doing anything else.

## Option 2 — the SessionStart hook (automatic, hands-off)

Scans every MCP server you have configured that hasn't been scanned yet, at the
start of each session, and surfaces its answer. Covers both remote HTTP servers
and local stdio servers launched from a published package (`npx`/`bunx` → npm,
`uvx`/`pipx` → PyPI). It reads your config and calls AgentAvow's public API
directly, so it works at startup before MCP servers connect.

**Install:**

```
mkdir -p ~/.claude/hooks
curl -fsSL https://raw.githubusercontent.com/AgentAvow/AgentAvow/main/integrations/claude-code/agentavow_precheck.py \
  -o ~/.claude/hooks/agentavow_precheck.py
curl -fsSL https://raw.githubusercontent.com/AgentAvow/AgentAvow/main/integrations/claude-code/agentavow_pretool_gate.py \
  -o ~/.claude/hooks/agentavow_pretool_gate.py
```

Then add this to `~/.claude/settings.json` (merge under `hooks`, keeping anything
you already have). The second block is the per-call gate; leave it out if you want
the session-start verdicts only:

```
{
  "hooks": {
    "SessionStart": [
      { "matcher": "startup|resume",
        "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/agentavow_precheck.py", "timeout": 30 } ] }
    ],
    "PreToolUse": [
      { "matcher": "mcp__.*",
        "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/agentavow_pretool_gate.py", "timeout": 8 } ] }
    ]
  }
}
```

**Test it** without even starting Claude, once you have at least one MCP server
configured:

```
echo '{}' | python3 ~/.claude/hooks/agentavow_precheck.py
```

You should see one line per new MCP server, leading with the answer and its reason,
for example:

```
✅ MCP 'files' (npm:@acme/files-mcp): Safe to connect — nothing found in 40 files · AgentAvow 92/100; sandbox: called 9 tools, no network beyond the registry.
```

For a server that runs from an npm or PyPI package, the line ends with the
[behavioral sandbox](./behavioral-sandbox.md) result: how many tools it called and where
it connected (`sandbox: called 9 tools, no network beyond the registry`), what it caught
(`sandbox: CAUGHT a planted credential leaving the sandbox (critical) +1 more`), a run still in progress
(`sandbox: running now, results in about a minute`), or why the server was not exercised
(`sandbox: not started (needs credentials)`). If the
maintainer has deprecated the package, the answer is Review before you connect and the line
says `DEPRECATED by its maintainer (no more security fixes)`. Run it again and it stays silent
(already-scanned servers are cached in `~/.cache/agentavow/scanned.json`). End to
end: add a new server, then start a new session and the answer appears in context.

If you have no remote MCP servers configured yet, the hook instead shows a single line
saying there is nothing to scan and how to scan a tool on demand. It shows that line once
per machine and makes no request for it.

## The per-call gate

The session-start hook grades a server once. The gate acts on that grade every time
Claude is about to call one of the server's tools (tool names look like
`mcp__<server>__<tool>`). It makes no call to AgentAvow.

- **Deny:** the server reads **Do not connect**, or its grade is in the `blocked`
  tier (0 to 10 out of 100). The reason Claude sees leads with the answer and its
  reason, then the score and the report link.
- **Confirm** (`permissionDecision: "ask"`): a remote server now serves a definition for this tool that differs from
  the one AgentAvow graded, or a tool the grade never saw. The gate fetches
  `tools/list` from the server itself (at most once per server per 15 minutes) and
  recomputes the per-tool digest the signed attestation carries, the same derivation
  anyone can run offline. You decide; the server is re-graded at your next session
  start.
- **Allow, silently:** everything else, including Review before you connect. A server with no grade on file, a stdio
  server (nothing served to re-fetch, so only its grade applies), a network error, a
  timeout, a definition the gate cannot canonicalize.

Settings, all optional, read from the environment and never sent anywhere:

- `AGENTAVOW_GATE_DENY_BELOW` (default: deny only Do not connect and the `blocked`
  tier). A number
  such as `51` denies any server graded below it. A tier name (`restricted`,
  `minimal`, `standard`, `trusted`, `verified`) denies anything below that tier's
  floor. `off` never denies; a changed definition still pauses for confirmation.
- `AGENTAVOW_GATE_RECHECK_SECONDS` (default `900`). How often a remote server's
  `tools/list` is re-fetched.
- `AGENTAVOW_GATE=off` turns the gate off. With the manual install, removing the
  `PreToolUse` block does the same; with the plugin, uninstalling it does.

**Test it** without starting Claude. With a graded server named `example` in your
config:

```
echo '{"hook_event_name":"PreToolUse","tool_name":"mcp__example__some_tool","session_id":"t","tool_input":{}}' \
  | python3 ~/.claude/hooks/agentavow_pretool_gate.py
```

Silence means allow. A deny or a confirmation comes back as a JSON object with a
`permissionDecision` and a one-line reason.

## Guarantees

- **Opt-in.** Nothing runs unless you install it.
- **Warn first.** Review before you connect adds context, never a prompt. The only
  thing that can stop a call is the gate, and by default only for a server that reads
  Do not connect or sits in the blocked tier; a changed definition pauses for your
  confirmation.
- **Fail-open.** A network hiccup or an unrecognized config stays silent and exits
  cleanly. It cannot break session startup, and the gate allows the call if anything
  at all goes wrong.
- **Nothing local leaves your machine.** Servers on localhost or a private network
  are skipped. A URL whose path looks like it carries a secret is withheld and
  reported as not scanned. Credentials and query strings are stripped from a URL
  before it is sent to AgentAvow. The gate talks only to the server being called,
  with the `Authorization` header from your config if there is one, as Claude Code
  itself does; that header is never stored or printed.
- **Quiet.** Each server is scanned once. One AgentAvow can't read (it needs
  sign-in, for example) is reported once as "not scanned" and left alone for a week.

The hooks and the rule live in the repo at
[`integrations/claude-code`](https://github.com/AgentAvow/AgentAvow/tree/main/integrations/claude-code).
