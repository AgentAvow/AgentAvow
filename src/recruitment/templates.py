"""GitHub issue templates for operator recruitment outreach."""
from __future__ import annotations

# Pre-approved templates — user reviews these once, not individual issues.
# Variables: {repo_name}, {stars}, {framework_type}, {onboarding_url}

TEMPLATES: dict[str, dict[str, str]] = {
    "mcp_server": {
        "title": "Verified trust badge for your MCP server",
        "body": (
            "Hey! We're building [AgentAvow](https://agentavow.com) — "
            "an open trust layer for AI agents: verified identity (W3C DIDs), "
            "trust scores, and auditable interaction trails.\n\n"
            "We've been cataloging MCP servers on GitHub and **{repo_name}** "
            "stood out ({stars} stars). We're offering free verified trust "
            "badges that MCP server authors can embed in their README:\n\n"
            "```markdown\n"
            "[![AgentAvow Verified]"
            "(https://agentavow.com/api/v1/badges/trust/YOUR_ID.svg)]"
            "(https://agentavow.com/check)\n"
            "```\n\n"
            "**What this gets you:**\n"
            "- Verified identity (W3C DID) linked to your MCP server\n"
            "- Trust score that grows as users endorse your server\n"
            "- Public profile page with your server's capabilities\n"
            "- Embeddable badge showing verification status\n\n"
            "Setup takes ~2 minutes: [{onboarding_url}]({onboarding_url})\n\n"
            "We're in early access and actively looking for feedback from MCP "
            "authors. If you have thoughts on what trust/identity infrastructure "
            "MCP servers actually need, we'd love to hear them.\n\n"
            "Not interested? Close this — we won't follow up.\n\n"
            "---\n"
            "*One-time outreach from [AgentAvow](https://agentavow.com). "
            "No further issues will be created on this repo.*"
        ),
    },
    "ai_agent": {
        "title": "Verified trust badge for your AI agent",
        "body": (
            "Hey! We're building [AgentAvow](https://agentavow.com) — "
            "an open trust layer for AI agents: verified identity (W3C DIDs), "
            "trust scores, and auditable interaction trails.\n\n"
            "**{repo_name}** caught our attention as an agent project with "
            "real traction ({stars} stars). We're offering free verified "
            "trust badges for agent developers:\n\n"
            "```markdown\n"
            "[![AgentAvow Verified]"
            "(https://agentavow.com/api/v1/badges/trust/YOUR_ID.svg)]"
            "(https://agentavow.com/check)\n"
            "```\n\n"
            "**What this gets you:**\n"
            "- Verified identity (W3C DID) for your agent\n"
            "- Trust score based on community endorsements\n"
            "- Public profile page with capabilities and history\n"
            "- Embeddable badge for your README\n\n"
            "Setup takes ~2 minutes: [{onboarding_url}]({onboarding_url})\n\n"
            "We're in early access — if you have thoughts on what trust "
            "infrastructure agents actually need, we'd genuinely love to hear "
            "them.\n\n"
            "Not interested? Close this — we won't follow up.\n\n"
            "---\n"
            "*One-time outreach from [AgentAvow](https://agentavow.com). "
            "No further issues will be created on this repo.*"
        ),
    },
}


def render_template(
    template_key: str,
    repo_name: str,
    stars: int,
    onboarding_url: str = "https://agentavow.com/claim",
) -> tuple[str, str]:
    """Render a template, returning (title, body).

    Raises KeyError if template_key is not found.
    """
    tmpl = TEMPLATES[template_key]
    fmt = {
        "repo_name": repo_name,
        "stars": str(stars),
        "framework_type": template_key.replace("_", " "),
        "onboarding_url": onboarding_url,
    }
    return tmpl["title"].format(**fmt), tmpl["body"].format(**fmt)
