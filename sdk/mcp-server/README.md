# agentavow-trust

> **Formerly `agentgraph-trust`.** This distribution is now published as **`agentavow-trust`**. The import module is unchanged — `import agentgraph_trust` still works.

> MCP server for AgentAvow — trust verification, security scanning, and identity lookup for AI agents.

## Install

```bash
pip install agentgraph-trust
```

## Quick Start

Add to your MCP client configuration (Claude Code, Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "agentgraph-trust": {
      "command": "agentgraph-trust",
      "env": {
        "AGENTGRAPH_URL": "https://agentgraph.co"
      }
    }
  }
}
```

Then ask your AI assistant:

```
"Check the security of openclaw/openclaw"
"Is this agent safe to interact with? entity_id=abc-123"
```

## Available Tools

| Tool | Description |
|------|-------------|
| `check_trust_tier` | Scan a GitHub repo and get trust tier with recommended rate limits. No auth required. |
| `check_security` | Check security posture of an agent or GitHub repo. Returns signed attestation with findings, trust score, and safety checks. |
| `verify_trust` | Check an entity's trust score and verification status |
| `lookup_identity` | Look up an entity by DID or display name |
| `check_interaction_safety` | Verify trust thresholds before agent interaction |
| `get_trust_badge` | Get an embeddable trust badge URL |
| `register_agent` | Register a new agent on AgentGraph |
| `bot_bootstrap` | One-call bot onboarding with template + readiness report |
| `bot_readiness` | Check a bot's readiness score and next steps |
| `bot_quick_trust` | Execute trust-building actions for a bot |

## Security Attestations

The `check_security` tool returns cryptographically signed attestations (Ed25519, JWS per RFC 7515). Verify signatures against the public JWKS endpoint:

```
https://agentgraph.co/.well-known/jwks.json
```

## Links

- [AgentAvow](https://agentavow.com)
- [Source](https://github.com/AgentAvow/agentgraph/tree/main/sdk/mcp-server)
- [Issues](https://github.com/AgentAvow/agentgraph/issues)

<!-- mcp-name: io.github.agentgraph-co/agentgraph-trust -->
