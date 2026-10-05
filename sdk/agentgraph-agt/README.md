# agentavow-agt

> **Formerly `agentgraph-agt`.** This distribution is now published as **`agentavow-agt`**. The import module is unchanged — `import agentmesh_agentgraph` still works.

AgentAvow trust provider for the [Microsoft Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit).

## Installation

```bash
pip install agentavow-agt
```

## Usage

`AgentGraphTrustProvider` implements the duck-typed external-provider interface
AGT's `TrustEngine` expects. Hand it to the engine and AgentAvow becomes one of
its trust signals:

```python
from agentmesh_agentgraph import AgentGraphTrustProvider

provider = AgentGraphTrustProvider(
    api_url="https://agentavow.com/api/v1",  # this is the built-in default; pass your own host to override
    api_key=None,                            # optional bearer token for authenticated reads
    timeout=10.0,
)

engine = TrustEngine(external_providers=[provider])   # AGT's engine
score = await engine.get_trust_score("agent-id-here")
```

Or call it directly:

```python
# Normalized 0.0-1.0 trust score (0.5 when the agent is unknown or the API is unreachable)
score = await provider.get_trust_score("agent-id-here")

# Sybil-risk estimate from identity verification + external accounts + community signals
sybil = await provider.check_sybil("agent-id-here")
# -> {"risk": "low" | "medium" | "high" | "unknown", "confidence": 0.0-1.0, ...}

# Direct trust connections (depth-1 ego graph)
circle = await provider.get_trust_circle("agent-id-here")   # list[str] of entity ids

# True when the entity exists and its identity is verified (email, operator link, or OAuth)
ok = await provider.verify_identity("agent-id-here")

await provider.close()
```

| Method | Returns | AgentAvow endpoint |
|--------|---------|--------------------|
| `get_trust_score(agent_id)` | `float` 0.0-1.0 | `GET /entities/{id}/trust` |
| `check_sybil(agent_id)` | `dict` (`risk`, `confidence`, `identity_verified`, `external_accounts`, `community_attestations`) | `GET /entities/{id}/trust` |
| `get_trust_circle(agent_id)` | `list[str]` | `GET /graph/ego/{id}?depth=1` |
| `verify_identity(agent_id, credentials=None)` | `bool` | `GET /entities/{id}/trust` |
| `close()` | — | closes the HTTP client |

Every method fails soft (default score, `"unknown"` risk, empty circle, `False`)
and logs a warning rather than raising, so a network error never blocks AGT.

## How it works

This adapter implements the AGT external trust-provider interface, allowing
AgentAvow's trust scores to be used as a governance signal in Microsoft's Agent
Governance Toolkit. It queries the AgentAvow API for trust scores, their
component breakdown, the social graph, and identity-verification status.

## License

MIT
