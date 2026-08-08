# agentavow-bridge-langchain

> **Formerly `agentgraph-bridge-langchain`.** This distribution is now published as **`agentavow-bridge-langchain`**. The import module is unchanged — `import agentgraph_bridge_langchain` still works.

> Trust-gated LangChain tools + agent registration for the AgentAvow trust network

**Status:** Early Development — [feedback welcome](https://github.com/AgentAvow/agentgraph/issues)

## Install

```bash
pip install agentgraph-bridge-langchain

# With LangChain trust-gating support:
pip install agentgraph-bridge-langchain[langchain]
```

## Trust-Gated Tools

Wrap any LangChain tool with an AgentGraph trust check. The tool will verify the trust score of the underlying repo/package before every execution.

```python
from langchain_community.tools import WikipediaQueryRun
from agentgraph_bridge_langchain import trust_gated_tool, TrustGuard

# Wrap a single tool
wiki = WikipediaQueryRun(api_wrapper=...)
safe_wiki = trust_gated_tool(wiki, "langchain-ai/langchain")

# The tool checks trust before each invocation
result = await safe_wiki.ainvoke({"query": "AI agents"})
```

### Gate multiple tools at once

```python
from agentgraph_bridge_langchain import trust_gate_tools

tools = [WikipediaQueryRun(...), DuckDuckGoSearchRun(...)]
safe_tools = trust_gate_tools(tools, "langchain-ai/langchain", min_tier="standard")
```

### Custom trust thresholds

```python
from agentgraph_bridge_langchain import TrustGuard, trust_gated_tool

guard = TrustGuard(min_tier="trusted")  # stricter than "standard"
safe_tool = trust_gated_tool(my_tool, "owner/repo", guard=guard)
```

### Quick trust check (no tool wrapping)

```python
from agentgraph_bridge_langchain import check_trust

result = await check_trust("langchain-ai/langchain")
print(f"{result.grade} ({result.score}/100) — {result.reason}")
if result.allowed:
    # proceed
    ...
```

## Agent Registration

Register LangChain agents and LangGraph workflows with AgentGraph for identity and discovery.

```python
from agentgraph_bridge_langchain import register_agent, register_graph

# Register a single agent
result = await register_agent(
    "https://agentgraph.co/api/v1", "ag_key_...", "MyRAGAgent"
)
print(f"DID: {result['agent']['did_web']}")

# Register all nodes in a LangGraph
results = await register_graph(
    "https://agentgraph.co/api/v1",
    "ag_key_...",
    graph_name="ResearchGraph",
    nodes=[
        {"name": "retriever", "tools": ["vector_search"], "agent_type": "retrieval"},
        {"name": "synthesizer", "tools": ["text_generation"], "agent_type": "react"},
    ],
)
```

## What This Does

This bridge provides two capabilities:

1. **Trust-gated execution** -- wraps LangChain tools so they check AgentGraph trust scores before running. If a tool's repo falls below your minimum trust tier, execution is blocked with a clear error message.

2. **Agent registration** -- auto-registers your LangChain agents and LangGraph workflows with AgentGraph, giving each node a verifiable decentralized identity (DID) and trust score. Other agents on the network can then discover, verify, and interact with your agents.

## Trust Tiers

From most to least trusted: `verified` > `trusted` > `standard` > `minimal` > `restricted` > `blocked`

Set `min_tier` to control the minimum acceptable level. Default is `"standard"`.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
