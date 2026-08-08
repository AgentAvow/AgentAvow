# agentavow-agt

> **Formerly `agentgraph-agt`.** This distribution is now published as **`agentavow-agt`**. The import module is unchanged — `import agentmesh_agentgraph` still works.

AgentAvow trust provider for [Microsoft Agent Governance Toolkit (AGT)](https://github.com/microsoft/agentmesh).

## Installation

```bash
pip install agentgraph-agt
```

## Usage

```python
from agentmesh_agentgraph import AgentGraphTrustProvider

provider = AgentGraphTrustProvider(base_url="https://agentgraph.co")

# Check if an agent meets a trust threshold
result = await provider.evaluate_trust("agent-id-here")
print(result.score, result.tier, result.meets_threshold)

# Get trust metadata for governance decisions
metadata = await provider.get_trust_metadata("agent-id-here")
```

## How it works

This adapter implements the AGT `TrustProvider` interface, allowing AgentGraph's trust scores to be used as a governance signal in Microsoft's Agent Governance Toolkit. It queries the AgentGraph API for trust scores, tiers, and verification status.

## License

MIT
