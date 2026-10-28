# Changelog

## 0.4.1 (unreleased; prepared 2026-10-11)

- `openai-agents`: `wrap()` now finds the URL of a real `@openai/agents` `MCPServerStreamableHttp` / `MCPServerSSE`, which keeps it on `server.underlying.params.url`. In 0.4.0 such a server was passed through with a "not gated" warning unless you gave it a coordinate. Found by a smoke test against the real SDK (0.20.0).
- `openai-agents`: `McpServerLike` no longer has an index signature, so the SDK's own server classes type-check when passed to `wrap()` / `connectAll()` under `strict`.

## 0.4.0 (published 2026-10-10)

- New `agentavow-trust/claude-agent-sdk`: `createClaudeAgentGate()` checks `mcpServers` before a Claude Agent SDK session (servers that fail are left out; drifted tools go into `disallowedTools`) and adds a `PreToolUse` hook that denies each `mcp__…` call that fails (`'ask'` for Review under `onReview: 'confirm'`), plus a `canUseTool` callback.
- New `agentavow-trust/openai-agents`: `createOpenAIAgentsGate()` wraps an OpenAI Agents SDK MCP server (`connect` refused on a failing answer, drifted tools dropped from `listTools`, `callTool` refused per call) and `connectAll()` connects the servers that pass.
- Both are optional peer dependencies; neither SDK is imported.

## 0.3.2 (unreleased; prepared 2026-10-09)

- CLI `scan` leads with the answer (Safe to connect / Review before you connect / Do not connect) and its reason, adds "· Certified" only from `certified_mark` beside Safe, and no longer prints a letter grade. Report links use `/check/pkg/...` for packages and `jwks_url` comes from the response.
- CLI: the unimplemented `verify` command is gone from the accepted commands; verify offline with the `./verify` export.
- `gate`: `certifiedOf()` reads `certified_mark` (never raw `certified.eligible`), and the mark is off whenever the answer isn't Safe.
- `vercel-ai`: the headline adds Certified only on Safe to connect.

## 0.3.1 (2026-10-08)

- See the README's 0.2.x → 0.3.1 table.
