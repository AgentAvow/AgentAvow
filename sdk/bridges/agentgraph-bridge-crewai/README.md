# agentavow-bridge-crewai

> **Formerly `agentgraph-bridge-crewai`.** This distribution is now published as **`agentavow-bridge-crewai`**. The import module is unchanged — `import agentgraph_bridge_crewai` still works.

> Trust-gated CrewAI tools for the AgentAvow trust network

**Status:** Early Development — [feedback welcome](https://github.com/AgentAvow/agentgraph/issues)

## Install

```bash
pip install agentgraph-bridge-crewai

# With CrewAI trust-gating support:
pip install agentgraph-bridge-crewai[crewai]
```

## Trust-Gated Tools

Wrap any CrewAI tool with an AgentGraph trust check. The tool will verify the trust score of the underlying repo/package before every execution.

```python
from crewai.tools import BaseTool
from agentgraph_bridge_crewai import trust_gated_tool, TrustGuard

class MySearchTool(BaseTool):
    name: str = "search"
    description: str = "Search the web"

    def _run(self, query: str) -> str:
        return f"Results for {query}"

# Wrap a single tool
search = MySearchTool()
safe_search = trust_gated_tool(search, "owner/repo")

# The tool checks trust before each invocation
result = safe_search._run("AI agents")
```

### Gate multiple tools at once

```python
from agentgraph_bridge_crewai import trust_gate_tools

tools = [MySearchTool(), MyAnalysisTool()]
safe_tools = trust_gate_tools(tools, "owner/repo", min_tier="standard")
```

### Custom trust thresholds

```python
from agentgraph_bridge_crewai import TrustGuard, trust_gated_tool

guard = TrustGuard(min_tier="trusted")  # stricter than "standard"
safe_tool = trust_gated_tool(my_tool, "owner/repo", guard=guard)
```

### Quick trust check (no tool wrapping)

```python
from agentgraph_bridge_crewai import check_trust

result = await check_trust("crewai/crewai")
print(f"{result.grade} ({result.score}/100) -- {result.reason}")
if result.allowed:
    # proceed
    ...
```

### Use with CrewAI Agents

```python
from crewai import Agent, Task, Crew
from agentgraph_bridge_crewai import trust_gate_tools

# Gate all tools before assigning to an agent
safe_tools = trust_gate_tools(my_tools, "owner/repo", min_tier="standard")

researcher = Agent(
    role="Researcher",
    goal="Find relevant information",
    backstory="An expert researcher",
    tools=safe_tools,
)

task = Task(
    description="Research AI agent frameworks",
    agent=researcher,
)

crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```

## What This Does

This bridge provides trust-gated execution for CrewAI tools. It wraps CrewAI `BaseTool` instances so they check AgentGraph trust scores before running. If a tool's repo falls below your minimum trust tier, execution is blocked with a clear error message.

## Trust Tiers

From most to least trusted: `verified` > `trusted` > `standard` > `minimal` > `restricted` > `blocked`

Set `min_tier` to control the minimum acceptable level. Default is `"standard"`.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
