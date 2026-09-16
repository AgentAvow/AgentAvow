---
description: Scan a tool, MCP server, package, or repo with AgentAvow before you trust it
---

Scan `$ARGUMENTS` with AgentAvow and report whether it's safe for an agent to connect to.

Choose the tool by what `$ARGUMENTS` looks like:
- an MCP server URL (e.g. `https://mcp.example.com/mcp`) → `scan_mcp_server`
- a package — "npm chalk", "pypi requests", "crates serde", "docker …", "hf org/model" → `scan_package`
- a GitHub repo "owner/name" (e.g. `modelcontextprotocol/servers`) → `scan_repo`

Report the 0–100 trust score, the plain safe / needs-review verdict, the top findings (with where and how to fix), and the signed, offline-verifiable report link. If `$ARGUMENTS` is empty, ask what to scan.
