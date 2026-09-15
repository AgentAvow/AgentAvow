# AgentAvow MCP connector

AgentAvow's remote MCP server lets Claude (and any MCP client) check whether a tool is
safe **before** an agent connects to it. This page is for users and IT admins evaluating
the connector.

## What it is

- **URL:** `https://agentavow.com/mcp` (remote, Streamable HTTP)
- **Auth:** none. Every tool is anonymous and read-only.
- **What it does:** scans a target and returns a signed 0–100 trust score, a plain
  safe / needs-review verdict, the findings behind it, and how widely the target is
  adopted. Each result is signed (Ed25519) and can be recomputed offline.

## Tools (all read-only)

- **scan_repo** — scan a public GitHub repo (`owner/name`).
- **scan_package** — scan a published npm / PyPI / crates / Docker / Hugging Face package.
- **scan_mcp_server** — scan a live MCP server's tool definitions for poisoning / injection.
- **verify_trust**, **check_interaction_safety**, **lookup_identity**, **get_trust_badge**
  — resolve and check an agent's identity and trust before delegating to it.
- **about_agentavow** — an overview of the service.

None of the tools write, delete, install, or transact. They only read public information
and call AgentAvow's own API.

## Data handling

- Checking a tool is **anonymous** — no account, no login, no personal data collected.
- The connector receives only the target you give it (a public repo, package name, or MCP
  URL). Scan results about public tools are themselves public.
- **No user content is used for model training. No conversation data or Claude memory is
  accessed.**
- Full policy: [Privacy](/legal/privacy) · [Terms](/legal/terms).

## Verifying a result

Every verdict is an Ed25519 JWS over an RFC 8785 (JCS) canonical form. Anyone can
recompute the verdict byte-for-byte and check the signature offline against the public
JWKS — you don't have to trust AgentAvow. See [Verify an attestation](/docs/verify-attestations).

## Add it

- **Claude Desktop / claude.ai:** Settings → Connectors → Add custom connector →
  `https://agentavow.com/mcp` (no authentication).
- **Claude Code:** `claude mcp add --transport http agentavow https://agentavow.com/mcp`
- To scan new tools automatically before you use them, see
  [Auto-scan in Claude Code](/docs/auto-scan-claude-code).

## Support

Questions or issues: [support@agentavow.com](mailto:support@agentavow.com).
