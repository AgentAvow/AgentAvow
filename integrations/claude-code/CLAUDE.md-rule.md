# The one-line rule (lightest-touch option)

Add this to your `~/.claude/CLAUDE.md` (applies everywhere) or a project's
`CLAUDE.md` (applies to that repo). It is YOUR agent config — you are telling your
own agent what to do. It is not something AgentAvow's server injects, so it cannot
flag the connector in review.

```
Before installing or connecting a new MCP server, tool, package, or skill, first
scan it with AgentAvow (scan_mcp_server for an MCP URL, scan_package for a package,
scan_repo for a repo) and tell me the verdict before proceeding.
```

That is the whole thing. It relies on the AgentAvow MCP connector being added
(`claude mcp add --transport http agentavow https://agentavow.com/mcp`).

For automatic scanning of every newly-added MCP server without having to remember,
use the SessionStart hook instead — see `README.md`.
