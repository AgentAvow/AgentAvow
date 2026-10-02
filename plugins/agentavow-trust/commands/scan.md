---
description: Scan a tool, MCP server, package, or repo with AgentAvow before you trust it
---

Scan `$ARGUMENTS` with AgentAvow and report whether it's safe for an agent to connect to.

Choose the tool by what `$ARGUMENTS` looks like:
- an MCP server URL (e.g. `https://mcp.example.com/mcp`) → `scan_mcp_server`
- a package — "npm chalk", "pypi requests", "crates serde", "docker …", "hf org/model" → `scan_package`
- a GitHub repo "owner/name" (e.g. `modelcontextprotocol/servers`) → `scan_repo`

Report both scores: the 0-100 trust score with its plain safe / needs-review verdict, and the adoption score (downloads, stars, or installs), then the top findings (with where and how to fix), and the signed, offline-verifiable report link. If `$ARGUMENTS` is empty, ask what to scan.

Give the version and publish date from the result's `Version … · published …` line. Do not look them up in the registry.

When the result has an **Observed in the sandbox** block, report it as its own short section: what ran, how many tools were called, where it connected on the network, file writes, whether the planted credentials stayed put, and each thing it caught (name the tool). If the server did not start, say why in the result's words and that it is not a finding. If the result says the sandbox is running now, say so and offer to re-check in about a minute. Never describe the score as "static analysis only" without saying the sandbox is pending or what it observed.
