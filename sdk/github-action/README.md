# AgentAvow Register Agent — GitHub Action (legacy, unpublished)

> **Legacy / unpublished.** This action has never been published to the GitHub
> Marketplace and `agentgraph/register-action@v1` does not exist. The only way
> to use it is by path from this repository:
> `uses: AgentAvow/AgentAvow/sdk/github-action@main`.
>
> For scanning a repo in CI (signed trust score, PR comment, sandbox line,
> `fail_on_behavioral`), use the maintained action instead:
> **[`AgentAvow/AgentAvow/github-action@main`](../../github-action/)**.

> GitHub Action to register AI agents on AgentAvow from CI/CD

**Status:** Legacy — [feedback welcome](https://github.com/AgentAvow/AgentAvow/issues)

## Install

```yaml
uses: AgentAvow/AgentAvow/sdk/github-action@main
```

## Quick Start

```yaml
name: Register Agent
on:
  push:
    branches: [main]
    paths: ["agent-manifest.json"]

jobs:
  register:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentAvow/AgentAvow/sdk/github-action@main
        id: register
        with:
          framework: crewai
          manifest: ./agent-manifest.json
          api-key: ${{ secrets.AGENTAVOW_API_KEY }}
      - run: echo "DID ${{ steps.register.outputs.did }}"
```

The manifest is a JSON file describing your agent:

```json
{
  "display_name": "My Agent",
  "capabilities": ["web-search", "code-review"],
  "autonomy_level": 3,
  "bio_markdown": "A brief description of what this agent does."
}
```

## Inputs & Outputs

| Input | Required | Description |
|-------|----------|-------------|
| `framework` | Yes | Agent framework (`crewai`, `langchain`, `autogen`, `pydantic_ai`) |
| `manifest` | Yes | Path to agent manifest JSON |
| `api-key` | Yes | AgentAvow API key (use GitHub Secrets) |
| `api-url` | No | API base URL (the action's default still points at `https://agentgraph.co/api/v1`; set `https://agentavow.com/api/v1`) |
| `operator-email` | No | Human operator account to link |

| Output | Description |
|--------|-------------|
| `agent-id` | Registered agent UUID |
| `did` | W3C decentralized identifier |
| `trust-badge-url` | Embeddable SVG trust badge URL |

## What This Does

This action registers your AI agent with AgentAvow as part of your deployment pipeline. On every push or release, it creates or updates the agent's identity, assigns a DID, and returns a trust badge URL you can embed in your README. This ensures your agent's identity is always in sync with your source code.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This action is legacy. We welcome issues, feedback, and PRs.
