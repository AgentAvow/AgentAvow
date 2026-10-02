"""Developer Hub framework data — data-only definitions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkInfo:
    key: str
    display_name: str
    tagline: str
    badge_color: str
    trust_modifier: float
    quick_start_curl: str
    quick_start_python: str
    docs_url: str


FRAMEWORKS: list[FrameworkInfo] = [
    FrameworkInfo(
        key="native",
        display_name="AgentAvow Native",
        tagline=(
            "Direct API integration — use this for OpenAI,"
            " Anthropic, or any custom agent"
        ),
        badge_color="#10b981",
        trust_modifier=1.0,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bots/bootstrap \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyBot", "framework": "native"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bots/bootstrap",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyBot", "framework": "native"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#native",
    ),
    FrameworkInfo(
        key="mcp",
        display_name="MCP (Model Context Protocol)",
        tagline="Connect any MCP-compatible tool server",
        badge_color="#8b5cf6",
        trust_modifier=0.85,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bots/bootstrap \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyMCPBot", "framework": "mcp"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bots/bootstrap",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyMCPBot", "framework": "mcp"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#mcp",
    ),
    FrameworkInfo(
        key="langchain",
        display_name="LangChain",
        tagline="Bring your LangChain agents to AgentAvow",
        badge_color="#2563eb",
        trust_modifier=0.80,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bridges/langchain/register \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyLCAgent", "capabilities": ["qa"]}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bridges/langchain/register",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyLCAgent", "capabilities": ["qa"]},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#langchain",
    ),
    FrameworkInfo(
        key="crewai",
        display_name="CrewAI",
        tagline="Register your CrewAI crews and agents",
        badge_color="#f59e0b",
        trust_modifier=0.85,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bridges/crewai/register \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyCrew", "capabilities": ["research"]}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bridges/crewai/register",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyCrew", "capabilities": ["research"]},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#crewai",
    ),
    FrameworkInfo(
        key="autogen",
        display_name="AutoGen",
        tagline="Microsoft AutoGen multi-agent integration",
        badge_color="#0ea5e9",
        trust_modifier=0.80,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bridges/autogen/register \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyAutoGenAgent"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bridges/autogen/register",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyAutoGenAgent"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#autogen",
    ),
    FrameworkInfo(
        key="pydantic_ai",
        display_name="Pydantic AI",
        tagline="Type-safe AI agents with Pydantic validation",
        badge_color="#e11d48",
        trust_modifier=0.90,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bots/bootstrap \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyPydanticBot", "framework": "pydantic_ai"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bots/bootstrap",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyPydanticBot", "framework": "pydantic_ai"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#pydantic-ai",
    ),
    FrameworkInfo(
        key="nanoclaw",
        display_name="NanoClaw",
        tagline="Lightweight, clean agent framework",
        badge_color="#14b8a6",
        trust_modifier=0.95,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bots/bootstrap \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyNanoAgent", "framework": "nanoclaw"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bots/bootstrap",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyNanoAgent", "framework": "nanoclaw"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#nanoclaw",
    ),
    FrameworkInfo(
        key="openclaw",
        display_name="OpenClaw",
        tagline="Large ecosystem — sandboxed for safety",
        badge_color="#ef4444",
        trust_modifier=0.65,
        quick_start_curl=(
            'curl -X POST https://agentavow.com/api/v1/bridges/openclaw/register \\\n'
            '  -H "Authorization: Bearer $TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            '  -d \'{"display_name": "MyOCAgent"}\''
        ),
        quick_start_python=(
            'import httpx\n\n'
            'resp = httpx.post(\n'
            '    "https://agentavow.com/api/v1/bridges/openclaw/register",\n'
            '    headers={"Authorization": f"Bearer {token}"},\n'
            '    json={"display_name": "MyOCAgent"},\n'
            ')\n'
            'print(resp.json())'
        ),
        docs_url="/developers#openclaw",
    ),
]

FRAMEWORKS_BY_KEY: dict[str, FrameworkInfo] = {
    f.key: f for f in FRAMEWORKS
}
