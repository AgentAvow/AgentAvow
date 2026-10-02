# agentavow-bridge-autogen

> **Formerly `agentgraph-bridge-autogen`.** This distribution is now published as **`agentavow-bridge-autogen`**. The import module is unchanged — `import agentgraph_bridge_autogen` still works.

> Trust-gated AutoGen tools for the AgentAvow trust network

**Status:** Early Development — [feedback welcome](https://github.com/AgentAvow/AgentAvow/issues)

## Install

```bash
pip install agentavow-bridge-autogen

# With AutoGen support:
pip install agentavow-bridge-autogen[autogen]
```

> **AutoGen version note.** The examples below use the AutoGen **0.2** API
> (`from autogen import register_function, AssistantAgent, UserProxyAgent`).
> The `[autogen]` extra pins `autogen-agentchat>=0.2.0`, which today resolves
> to the 0.4+ line (`import autogen_agentchat`) where `import autogen` and
> `register_function` no longer exist. To run these examples as written,
> install the 0.2 API explicitly: `pip install "autogen-agentchat<0.4"`
> (or the `pyautogen` / `ag2` fork). On 0.4+, the trust gate itself still
> works — `trust_gated_tool` returns a plain callable — so wrap the function
> in `autogen_core.tools.FunctionTool` and pass it to an
> `autogen_agentchat.agents.AssistantAgent(tools=[...])` instead of
> `register_function`.

## Trust-Gated Tools

Wrap any function with an AgentAvow trust check before registering it with AutoGen. The wrapper will verify the trust score of the underlying repo/package before every execution.

```python
from agentgraph_bridge_autogen import trust_gated_tool

def search(query: str) -> str:
    """Search the web for information."""
    return f"Results for {query}"

# Wrap with trust gate
safe_search = trust_gated_tool(search, "owner/repo")

# Register with AutoGen
from autogen import register_function
register_function(
    safe_search,
    caller=assistant,
    executor=user_proxy,
    description="Search the web",
)
```

### Decorator syntax

```python
from agentgraph_bridge_autogen import trust_gated_function

@trust_gated_function("owner/repo", min_tier="trusted")
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))

# Register directly with AutoGen
register_function(
    calculator,
    caller=assistant,
    executor=user_proxy,
    description="Evaluate math expressions",
)
```

### Custom trust thresholds

```python
from agentgraph_bridge_autogen import TrustGuard, trust_gated_tool

guard = TrustGuard(min_tier="trusted")  # stricter than "standard"
safe_tool = trust_gated_tool(my_func, "owner/repo", guard=guard)
```

### Quick trust check (no tool wrapping)

```python
from agentgraph_bridge_autogen import check_trust

result = await check_trust("microsoft/autogen")
print(f"{result.score}/100 {result.tier} -- {result.reason}")
if result.allowed:
    # proceed
    ...
```

### Full AutoGen example

```python
from autogen import AssistantAgent, UserProxyAgent, register_function
from agentgraph_bridge_autogen import trust_gated_tool, TrustGuard

# Create agents
assistant = AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4"},
)
user_proxy = UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
)

# Define and gate tools
def web_search(query: str) -> str:
    """Search the web."""
    return f"Results for {query}"

guard = TrustGuard(min_tier="standard")
safe_search = trust_gated_tool(web_search, "owner/search-lib", guard=guard)

# Register the trust-gated tool
register_function(
    safe_search,
    caller=assistant,
    executor=user_proxy,
    description="Search the web (trust-verified)",
)

# Start conversation -- tools will be trust-checked before execution
user_proxy.initiate_chat(assistant, message="Search for AI agent frameworks")
```

## What This Does

This bridge provides trust-gated execution for AutoGen tool functions. It wraps callable functions so they check AgentAvow trust scores before running. If a tool's repo falls below your minimum trust tier, execution is blocked with a clear error message.

Works with AutoGen's `register_function` pattern -- wrap your functions before registration and trust checks happen transparently on every call.

## Trust Tiers

From most to least trusted: `verified` > `trusted` > `standard` > `minimal` > `restricted` > `blocked`

Set `min_tier` to control the minimum acceptable level. Default is `"standard"`.

## Documentation

Full docs at [agentavow.com/docs](https://agentavow.com/docs)

## Contributing

This package is in early development. We welcome issues, feedback, and PRs.
