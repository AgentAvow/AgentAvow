# Changelog

## 0.4.3 (unreleased; prepared 2026-11-11)

- `gate`: the gate now reaches the same answer as the API on dependency advisories. It read the critical/high counts as `max(headline count, items with that severity)`, so the critical dependency advisories in `items` (counted in `critical_all`, never in the shipped `critical`) fired `blockOn: 'critical'`. `vercel/next.js` got Do not connect ("4 critical findings") while the API and MCP answered Safe to connect. The counts are now the shipped headline `critical` / `high` (never `*_all`). A response without headline counts falls back to the blocking items only (no `dependency` category, nothing `shipped: false`).
- `gate`: a shipped critical that the API's rule reads as Review (a hardcoded credential, or the tool's own published advisory) is now `review`, not `do_not_connect`, as on the API.
- `gate`: a `decision` inside the signed payload is the answer on the findings. Policy triggers (blocked tier, sandbox canary, known-malicious dependency, `high` when asked), the floor, staleness and drift still apply on top. An unsigned `decision` still only tightens. New `Grade` fields: `criticalReview`, `decisionSigned`.
- The User-Agent / `clientInfo` version now reads 0.4.3.

## 0.4.2 (unreleased; prepared 2026-11-07)

- `gate`: a served definition the gate cannot bind now fails closed. Before, a definition `canonicalize` refused (a number literal too large for a double, such as `1e400`, parses to `Infinity`) was allowed with the warning "drift not checked". Now it is a `drift` outcome, routed by `onDrift` (default `block`), and the deprecated `evaluate` blocks it the same way.
- `gate`: `toolDigest` now computes the issuer's `.noncanonical` fallback digest for a definition RFC 8785 cannot carry (a lone surrogate or a non-finite number), so a gate binds to such a tool when it is unchanged. When the gate cannot rebuild the issuer's bytes (a number written as `1.0` or `1e2`, an integer beyond 2^53), the digest does not match, and the gate reports drift, never a match. See `docs/standards/tool-manifest-digest-vectors-v1-noncanonical`.
- `gate`: new export `UNBOUND_DIGEST`, the issuer's content-free `.unhashable` digest. A tool signed with it is never treated as a match.
- `toolDigestInput` returns `null` for such definitions (there is no JCS preimage).
- The User-Agent / `clientInfo` version now reads 0.4.2. Before, it still said 0.4.0.

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
