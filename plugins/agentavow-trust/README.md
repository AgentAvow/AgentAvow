# AgentAvow Trust

Check whether a tool is safe before your agent connects to it. AgentAvow scans an MCP
server, a package, or a GitHub repo and returns two scores: a 0–100 trust score, with a
plain safe or needs-review verdict and the findings behind it, and an adoption score
built from real usage (downloads, stars, installs). Every result is signed (Ed25519) and
can be verified offline, so you do not have to take AgentAvow's word for it.

Scanning is free and needs no account.

## What the plugin adds

| Component | What it does | Where it runs |
| --- | --- | --- |
| MCP connector | The AgentAvow tools: `scan_mcp_server`, `scan_package`, `scan_repo`, and identity lookups. All read-only, no sign-in. | Chat, Cowork, Claude Code |
| `/scan` command | `/scan npm chalk`, `/scan owner/repo`, `/scan https://mcp.example.com/mcp` | Chat, Cowork, Claude Code |
| `scan-before-connect` skill | When you ask Claude to add an MCP server or install a package you name, Claude scans it first and tells you the verdict before it goes ahead. | Chat, Cowork, Claude Code |
| SessionStart hook | At the start of a session, grades each MCP server in your config that it has not seen before and adds one line per server to the session. | Claude Code, Cowork |

The hook and the skill warn. They never block: a low score adds context and you decide.

## Try it

```
/scan npm chalk
```

Then add an MCP server and start a new session. The hook reports a line such as:

```
⚠️ MCP 'example' (https://mcp.example.com/mcp): AgentAvow 66/100 — needs review, 1 blocking finding(s).
```

## What the hook reads and what leaves your machine

The hook is one Python script, `scripts/agentavow_precheck.py`. It uses only the
standard library and you can read all of it.

**It reads** three files, looking only for `mcpServers` entries: `~/.claude.json`,
`.mcp.json` in the current folder, and `.claude/settings.json` in the current folder.
From each entry it takes the server URL, or the launcher command and package name.
It does not use headers, environment values, tokens, or any other part of those files.

**It sends** one HTTPS request per new server to `https://agentavow.com/api/v1/public/scan`,
containing either:

- the server URL reduced to scheme, host, and path (any `user:password@` part, query
  string, and fragment are removed first), or
- a package name and its registry (npm or PyPI).

**It does not send:**

- servers on localhost, a private network, or a `.local` / `.internal` name;
- any URL whose path looks like it contains a secret (a UUID or a long token). These
  are reported as "not scanned";
- servers that run a local script (`node server.js`, `python server.py`), which have
  no published package to grade;
- anything else from your machine. No file contents, environment values, or credentials.

**It writes** one file, `~/.cache/agentavow/scanned.json`, so each server is scanned
once. A server AgentAvow cannot read (one that needs sign-in, for example) is reported
once and retried after a week. Delete the file to scan everything again.

The first time the hook finds nothing to scan (no remote MCP servers configured), it
shows one line saying so and how to scan a tool on demand. That line is shown once per
machine, is recorded in the same file, and makes no request.

If the network is down or anything unexpected happens, the hook prints nothing and
exits cleanly. It cannot stop a session from starting.

The MCP connector sends AgentAvow only the target you ask it to scan. Scan results for
public tools are public.

## Privacy and support

- Privacy policy: https://agentavow.com/legal/privacy
- How scoring works: https://agentavow.com/docs/how-grading-works
- Verify a result yourself: https://agentavow.com/docs/verify-attestations
- Questions or problems: support@agentavow.com

## License

MIT. See `LICENSE`.
