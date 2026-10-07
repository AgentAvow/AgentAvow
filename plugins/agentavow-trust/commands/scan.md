---
description: Scan a tool, MCP server, package, or repo with AgentAvow before you trust it
---

Scan `$ARGUMENTS` with AgentAvow and report whether it's safe for an agent to connect to.

Choose the tool by what `$ARGUMENTS` looks like:
- an MCP server URL (e.g. `https://mcp.example.com/mcp`) → `scan_mcp_server`
- a package — "npm chalk", "pypi requests", "crates serde", "docker …", "hf org/model" → `scan_package`
- a GitHub repo "owner/name" (e.g. `modelcontextprotocol/servers`) → `scan_repo`

Lead with one of three answers and its reason — Safe to connect, Review before you connect, or Do not connect (the result's `decision` / `decision_reason` when present; otherwise Do not connect on a critical finding, a planted credential leaving the sandbox or a known-malicious package, Safe to connect when the verdict is safe, else Review before you connect) — adding " · Certified" when the tool is certified. Then report both scores: the 0-100 trust score, and the adoption score (downloads, stars, or installs), then the top findings (with where and how to fix), and the signed, offline-verifiable report link. If `$ARGUMENTS` is empty, ask what to scan.

Give the version and publish date from the result's `Version … · published …` line. Do not look them up in the registry.

When the result has an **Observed in the sandbox** block, report it as its own short section: what ran, how many tools were called, where it connected on the network, file writes, whether the planted credentials stayed put, and each thing it caught (name the tool). If the server did not start, say why in the result's words and that it is not a finding. If the result says the sandbox is running now, say so and offer to re-check in about a minute. Never describe the score as "static analysis only" without saying the sandbox is pending or what it observed.


To scan a specific version, put it in the name the way the ecosystem writes it: `name@1.2.3` for npm and crates, `name==1.2.3` for PyPI (for example `scan_package` with registry `pypi`, name `mcp-server-git==2025.7.1`). Do not fetch the registry or the API URL yourself to compare versions; call the tool once per version.
