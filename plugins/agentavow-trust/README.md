# AgentAvow Trust

**What you'll see.** Install the plugin and start a session. Claude's first reply opens with
one line, for example: "AgentAvow pre-check: graded 8 MCP servers — 5 Safe, 2 Review, 1
Blocked (needs attention: 'task-master' Do not connect — one critical finding: eval of
input). Dependencies: graded 12 of 38 — 11 Safe, 1 Review (needs attention: 'left-pad'
Review before you connect — the maintainer has deprecated this package)." Every line leads
with one of three answers — **Safe to connect**, **Review before you connect** or **Do not
connect** — and the one reason behind it, then the 0–100 score; a Certified tool reads
"Safe to connect · Certified". Ask for the pre-check and you get one such line per server
and per dependency, with its report link. From then on, a server you add with `claude mcp
add` is graded before it is added: "Do not connect" asks you first; "Review before you
connect" (including a clean-but-thin result) just tells you. You decide. Dependencies are read from the session's folder (the `cwd` Claude Code hands the hook). In Claude Desktop's Code tab, which starts in a scratch workspace, move into the project and type `/clear`: the hook runs again for that folder.

Check whether a tool is safe before your agent connects to it. AgentAvow scans an MCP
server, a package, or a GitHub repo and returns one of three answers with its reason,
then two scores underneath: a 0–100 trust score with the findings behind it, and an adoption score
built from real usage (downloads, stars, installs). Every result is signed (Ed25519) and
can be verified offline, so you do not have to take AgentAvow's word for it.

Scanning is free and needs no account.

## What the plugin adds

| Component | What it does | Where it runs |
| --- | --- | --- |
| MCP connector | The AgentAvow tools: `scan_mcp_server`, `scan_package`, `scan_repo`, and identity lookups. All read-only, no sign-in. | Chat, Cowork, Claude Code |
| `/scan` command | `/scan npm chalk`, `/scan owner/repo`, `/scan https://mcp.example.com/mcp` | Chat, Cowork, Claude Code |
| `scan-before-connect` skill | When you ask Claude to add an MCP server or install a package you name, Claude scans it first and tells you the answer before it goes ahead. | Chat, Cowork, Claude Code |
| Install-time hook | When a server is about to be added (`claude mcp add …`, or a write to `.mcp.json`), grades it first. "Do not connect": Claude Code asks you, with the answer as the reason. Anything else (Safe to connect; Review before you connect, including thin coverage; not scannable): a one-line answer and the add proceeds. Never denies. | Claude Code, Cowork |
| SessionStart hook | At the start of a session, grades each MCP server this session can use (user scope, this project) that it has not seen before, and the project's direct dependencies (package.json `dependencies`, requirements.txt, pyproject `[project].dependencies`; up to 15 per start, re-graded only when the declared version changes; `AGENTAVOW_PRECHECK_DEPS=off` turns it off). Servers for other projects are counted and graded when you open them. Claude opens its first reply with a one-line summary (how many Safe / Review / Blocked, the one needing attention), and keeps one line per server and dependency for when you ask. Dependencies are already installed: their answer is advice, never a stop. | Claude Code, Cowork |
| PreToolUse gate | Before each MCP tool call, checks the answer on file for that server. Denies a call to a server whose answer is "Do not connect" (and, as before, one in the blocked tier); asks before a tool whose definition changed since it was graded. "Review before you connect" never prompts. | Claude Code, Cowork |

The session-start hook and the skill warn; a low score adds context and you decide.
The gate is the one part that can stop a call, and by default only for a server whose
answer is "Do not connect" (a critical finding, a planted credential leaving the sandbox,
a known-malicious package) or that is graded in the blocked tier (0 to 10 out of 100). A
changed definition asks; it never denies.

## Per-call gate

`scripts/agentavow_pretool_gate.py` runs before each MCP tool call (tool names look
like `mcp__<server>__<tool>`). It reads the grade the session-start hook stored for
that server and:

- **denies** the call when the server's answer is "Do not connect", or its grade is in
  the `blocked` tier. The reason leads with the answer and gives the score and the
  report link.
- **asks** before a tool on a remote server whose definition no longer matches the one
  AgentAvow graded, or that the grade never saw. The gate fetches `tools/list` from the
  server itself, at most once per server per 15 minutes, and recomputes the per-tool
  digest the signed attestation carries. That is done offline, with no call to
  AgentAvow. A server whose definitions changed is re-graded at your next session
  start.
- **allows** everything else: a server with no grade on file, a stdio server (there is
  no served definition to re-fetch, so only its grade applies), any network error or
  timeout, any definition the gate cannot canonicalize.

It fails open. It stops within 8 seconds, and if anything goes wrong it allows the
call and says nothing.

Settings, all optional, read from the environment and never sent anywhere:

- `AGENTAVOW_GATE_DENY_BELOW` (default: deny on "Do not connect" and the `blocked`
  tier). A number such as `51` also denies any server graded below it. A tier name
  (`restricted`, `minimal`, `standard`, `trusted`, `verified`) also denies anything
  below that tier's floor. `off` never denies, not even on "Do not connect"; a changed
  definition still asks.
- `AGENTAVOW_GATE_RECHECK_SECONDS` (default `900`). How often a remote server's
  `tools/list` is re-fetched to check for a changed definition.
- `AGENTAVOW_GATE=off` turns the gate off. Uninstalling the plugin removes it.

## Try it

```
/scan npm chalk
```

Then add an MCP server and start a new session. The hook reports a line such as:

```
⚠️ MCP 'example' (https://mcp.example.com/mcp): Review before you connect — one high finding: shell command built from user input · AgentAvow 66/100.
```

## The sandbox result in the line

AgentAvow runs every npm and PyPI package it grades in an isolated gVisor sandbox on its own
servers (automatically, on the first scan; results are kept for a day). The hook's line
includes that result in one clause when it exists:

- `sandbox: called 9 tools, network only api.example.com`: the server started, its tools
  were called with synthetic inputs, and these are the hosts it reached (package
  registries left out).
- `sandbox: CAUGHT a read-only tool writing files (high)`: the run observed a behavior
  worth reviewing; a planted credential leaving the sandbox is always listed first.
- `sandbox: not started (needs a database URL)`: the server needs a credential or a
  startup argument the sandbox does not have, so its tools were not called. This is not
  a finding.
- `sandbox: running now, results in about a minute`: the first run is still in progress.
  The answer is provisional until it lands ("…; sandbox still running") and may move to
  "Review before you connect".

The hook makes no extra request for it and nothing from your machine is run in the
sandbox. The `/scan` command and the scan-before-connect skill report the full sandbox
observation (tools called, network, file writes, credentials) as its own section.

## What the hook reads and what leaves your machine

The hooks are two Python scripts, `scripts/agentavow_precheck.py` (session start) and
`scripts/agentavow_pretool_gate.py` (per call). Both use only the standard library and
you can read all of them.

**The session-start hook reads** three files, looking only for `mcpServers` entries:
`~/.claude.json`, `.mcp.json` in the current folder, and `.claude/settings.json` in the
current folder. From each entry it takes the server URL, or the launcher command and
package name. It does not use headers, environment values, tokens, or any other part
of those files.

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
once: per server, the score, tier and grade, the signed per-tool digests, the report
link, and when it was graded. A server AgentAvow cannot read (one that needs sign-in,
for example) is reported once and retried after a week. Delete the file to scan
everything again.

**The gate reads** the same three files, for the URL and any `Authorization` header
of the one server being called, plus its own `AGENTAVOW_GATE*` settings from the
environment. **It sends** one short `initialize` + `tools/list` exchange to that
server, over the URL in your config (`user:password@` and `#fragment` removed), with
the configured `Authorization` header if there is one, as Claude Code itself does when
it connects. A header that still holds a `${...}` placeholder is not expanded and not
sent. Nothing goes to AgentAvow, and the header is never written to the cache or
printed. The gate writes the digests it last saw to the same cache file; the graded
digests are never overwritten by it.

The first time the hook finds nothing to scan (no remote MCP servers configured), it
shows one line saying so and how to scan a tool on demand. That line is shown once per
machine, is recorded in the same file, and makes no request.

If the network is down or anything unexpected happens, either hook prints nothing and
exits cleanly. The session-start hook cannot stop a session from starting, and the
gate cannot stop a call for any reason other than a blocked-tier grade on file.

The MCP connector sends AgentAvow only the target you ask it to scan. Scan results for
public tools are public.

## Privacy and support

- Privacy policy: https://agentavow.com/legal/privacy
- How scoring works: https://agentavow.com/docs/how-grading-works
- Verify a result yourself: https://agentavow.com/docs/verify-attestations
- Questions or problems: support@agentavow.com

## License

MIT. See `LICENSE`.
