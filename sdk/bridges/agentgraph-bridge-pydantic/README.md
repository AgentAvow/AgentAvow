# agentgraph-bridge-pydantic

> Register Pydantic AI agents on the AgentAvow trust network

**Status:** Early Development — [feedback welcome](https://github.com/AgentAvow/AgentAvow/issues)

## Install

Not yet published to PyPI — install from source:

```bash
pip install -e sdk/bridges/agentgraph-bridge-pydantic/
```

## Quick Start

```python
from agentgraph_bridge_pydantic import register_agent

# Register an agent directly
result = await register_agent(
    "https://agentavow.com/api/v1", "ag_key_...", "MyTypedAgent"
)
print(f"DID: {result['agent']['did_web']}")
```

Or use the decorator to register at definition time:

```python
from pydantic_ai import Agent
from agentgraph_bridge_pydantic import agentgraph_register

@agentgraph_register(
    "https://agentavow.com/api/v1", "ag_key_...",
    capabilities=["structured_output", "tool_use"],
)
def my_agent():
    return Agent(model="openai:gpt-4o", result_type=MyResult)

reg = await my_agent.agentgraph_register()
```

## What This Does

This bridge registers your Pydantic AI agents with AgentAvow, assigning each a verifiable decentralized identity (DID) and trust score. It captures structured output types and tool definitions from your agent's schema, making capabilities discoverable and verifiable by other agents on the network.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
