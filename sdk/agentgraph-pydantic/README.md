# agentavow-pydantic

> **Formerly `agentgraph-pydantic`.** This distribution is now published as **`agentavow-pydantic`**. The import module is unchanged — `import agentgraph_pydantic` still works.

> Trust verification middleware for PydanticAI agents

**Status:** Early Development — [feedback welcome](https://github.com/AgentAvow/AgentAvow/issues)

## Install

```bash
pip install agentavow-pydantic
```

## Quick Start

```python
from agentgraph_pydantic import TrustGuard, check_trust

# Quick one-shot check
result = await check_trust("crewAIInc/crewAI")
if result.allowed:
    print(f"{result.score}/100 ({result.tier}) — safe to execute")

# Reusable guard with a minimum tier
guard = TrustGuard(min_tier="standard")
result = await guard.check("owner/repo")
if not result.allowed:
    raise ValueError(f"Blocked: {result.reason}")
```

## What This Does

`agentgraph-pydantic` lets PydanticAI agents verify the trust score of any GitHub repository before executing tools, calling external code, or loading MCP servers. It queries the AgentAvow Trust Gateway and returns a typed `TrustResult` with the 0-100 score, trust tier, and category breakdowns — no AgentAvow account required for basic checks.

## API

### `check_trust(repo, min_tier="standard") -> TrustResult`

Convenience function for a single trust check.

### `TrustGuard(min_tier, api_url=None, timeout=30.0)`

Reusable guard object. Call `await guard.check(repo)` to verify trust.

### `TrustResult`

| Field | Type | Description |
|-------|------|-------------|
| `repo` | `str` | Repository checked |
| `allowed` | `bool` | Whether the repo meets the minimum tier |
| `score` | `int` | Trust score (0-100) |
| `grade` | `str` | Score band (`A+`/`A`/`B`/`C`/`D`/`F`) derived from the score; kept for compatibility — branch on `score` and `tier` |
| `tier` | `str` | Trust tier (verified/trusted/standard/minimal/restricted/blocked) |
| `reason` | `str` | Human-readable decision reason |
| `category_scores` | `dict[str, int]` | Per-category score breakdown |

## How It Differs from agentgraph-bridge-pydantic

- **agentgraph-pydantic** (this package) — trust verification middleware. Checks whether external tools/repos are safe to use. No account needed.
- **agentgraph-bridge-pydantic** — registration bridge. Registers your PydanticAI agents on the AgentAvow network. Requires an API key.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
