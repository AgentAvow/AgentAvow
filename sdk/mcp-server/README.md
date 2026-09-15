# agentavow-trust

> **Formerly `agentgraph-trust`.** This distribution is now published as **`agentavow-trust`**. The import module is unchanged — `import agentgraph_trust` still works.

> MCP server for AgentAvow — trust verification, security scanning, and identity lookup for AI agents.

## Install

```bash
uvx agentavow-trust        # zero-install run (recommended)
# or: pip install agentavow-trust
```

## Quick Start

Add to your MCP client configuration (Claude Code, Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "agentavow-trust": {
      "command": "uvx",
      "args": ["agentavow-trust"]
    }
  }
}
```

Then ask your AI assistant:

```
"Scan the npm package chalk before I install it"
"Scan the repo modelcontextprotocol/servers and tell me if it's safe to connect"
"Scan the MCP server at https://mcp.deepwiki.com/mcp"
```

This is the local/stdio build of the same service as the remote connector at
`https://agentavow.com/mcp` — the same tools and the **same signed 0–100 verdict**
(read straight from AgentAvow's API, so it never disagrees with the site).

## Available Tools

All read-only and anonymous — no account or API key required.

| Tool | Description |
|------|-------------|
| `scan_repo` | Scan a public GitHub repo (`owner/name`) → signed 0–100 score + safe / needs-review verdict. |
| `scan_package` | Scan an npm / PyPI / crates / Docker / Hugging Face package. |
| `scan_mcp_server` | Scan a live MCP server's tool definitions for poisoning / prompt-injection. |
| `verify_trust` | Resolve an agent identity and return its current trust score. |
| `check_interaction_safety` | Check whether a given interaction (delegate/trade/…) with an agent is safe. |
| `lookup_identity` | Resolve a DID (`did:web:…` / `did:key:…`) or search agents by name. |
| `get_trust_badge` | Get a shields-style trust badge (SVG URL + README markdown) for an agent. |
| `about_agentavow` | What AgentAvow checks and how to read a verdict. |

Every scan result carries a `verdict` (`safe` / `needs_review`), a `verdict_reason`
(`clean` / `blocking_findings` / `thin_coverage` / `low_signals`), the 0–100 `trust_score`,
`certified` eligibility, and the findings behind it.

## Signed attestations

Scan results are cryptographically signed (Ed25519, JWS per RFC 7515) and recomputable
offline. Verify signatures against the public JWKS endpoint:

```
https://agentgraph.co/.well-known/jwks.json
```

> The JWKS host and signing identity intentionally keep the `agentgraph.co` name so
> existing attestations stay verifiable; the service and site are **AgentAvow** at
> `agentavow.com`.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `AGENTAVOW_URL` | `https://agentavow.com` | API/site base. `AGENTGRAPH_URL` is still honored for back-compat. |

## Links

- [AgentAvow](https://agentavow.com)
- [Source](https://github.com/AgentAvow/agentgraph/tree/main/sdk/mcp-server)
- [Issues](https://github.com/AgentAvow/agentgraph/issues)

<!-- mcp-name: com.agentavow/agentavow-trust -->
