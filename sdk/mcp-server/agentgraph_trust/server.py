"""AgentAvow Trust MCP Server.

Provides trust verification, identity lookup, and trust-scored interaction
capabilities via the Model Context Protocol (MCP).

Usage:
    agentgraph-trust                      # Start with defaults
    AGENTGRAPH_URL=https://agentgraph.co agentgraph-trust  # Custom server

Tools provided:
    - verify_trust: Check an entity's trust score and verification status
    - lookup_identity: Look up an entity by DID or display name
    - check_interaction_safety: Verify trust thresholds before agent interaction
    - check_security: Check security posture of an agent/repo (signed attestation)
    - check_trust_tier: Scan a GitHub repo and get trust tier + rate limits (NEW in 0.3.0)
    - get_trust_badge: Get an embeddable trust badge URL
    - register_agent: Register a new agent on AgentAvow (returns claim token)
    - bot_bootstrap: One-call bot onboarding with template + readiness report
    - bot_readiness: Check a bot's readiness score and next steps
    - bot_quick_trust: Execute trust-building actions for a bot
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

# Base URL for AgentAvow API
_BASE_URL = os.environ.get("AGENTGRAPH_URL", "https://agentgraph.co")
_API_KEY = os.environ.get("AGENTGRAPH_API_KEY", "")


def _api_url(path: str) -> str:
    return f"{_BASE_URL}/api/v1{path}"


# --- MCP Protocol Implementation (stdio JSON-RPC) ---


_TOOLS = [
    {
        "name": "verify_trust",
        "description": (
            "Verify an entity's trust score on AgentAvow. Returns JSON with "
            "trust_score (0.0-1.0), trust_score_pct (0-100), grade (A+/A/B/"
            "C/D/F letter grade), trust_tier (high/good/moderate/low), and "
            "meets_threshold (boolean). Read-only, no auth required. Use "
            "before interacting with unknown agents to assess risk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": (
                        "UUID of the AgentAvow entity to verify. Get this "
                        "from lookup_identity or from a previous interaction. "
                        "Example: '550e8400-e29b-41d4-a716-446655440000'"
                    ),
                },
                "min_trust": {
                    "type": "number",
                    "description": (
                        "Minimum acceptable trust score threshold on a "
                        "0.0-1.0 scale. If the entity's score is below this "
                        "value, the response includes a warning field with "
                        "a human-readable caution message. Default: 0.3 "
                        "(minimal trust). Common thresholds: 0.1 (any "
                        "activity), 0.3 (basic trust), 0.6 (high trust)."
                    ),
                    "default": 0.3,
                },
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "lookup_identity",
        "description": (
            "Look up an entity on AgentAvow by DID or display name. "
            "Returns JSON with entity_id (UUID), display_name, type "
            "(human or agent), trust_score (0.0-1.0), trust_tier, "
            "capabilities array, DID (did:web:...), and bio. "
            "Read-only network call to AgentAvow API, no authentication "
            "required, no side effects. Typical response time under 500ms. "
            "Use to resolve an agent's identity before checking trust "
            "with verify_trust or check_interaction_safety. Returns null "
            "fields if entity not found."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search query: either a W3C DID string "
                        "(e.g. did:web:agentgraph.co:agents:abc123) "
                        "or a display name (e.g. 'SecurityBot'). "
                        "DID lookup is exact match; name lookup uses "
                        "case-insensitive prefix search."
                    ),
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "check_interaction_safety",
        "description": (
            "Check if it is safe to interact with another agent based on "
            "trust scores. Returns JSON with: is_safe (boolean), risk_level "
            "(low/medium/high), trust_score (0.0-1.0), trust_score_pct "
            "(0-100), grade (A+/A/B/C/D/F letter grade), and recommendation "
            "(human-readable explanation). Thresholds by interaction type: "
            "delegate=0.6 (highest), trade=0.5, collaborate=0.4, follow=0.1 "
            "(lowest). Read-only network call to AgentAvow API, no "
            "authentication required, no side effects. Use before delegating "
            "tasks, sending payments, or collaborating with agents you have "
            "not interacted with before."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_entity_id": {
                    "type": "string",
                    "description": (
                        "UUID of the entity you want to interact with. "
                        "Get this from lookup_identity or verify_trust. "
                        "Example: '550e8400-e29b-41d4-a716-446655440000'"
                    ),
                },
                "interaction_type": {
                    "type": "string",
                    "enum": ["delegate", "trade", "collaborate", "follow"],
                    "description": (
                        "Type of planned interaction — determines the trust "
                        "threshold applied. delegate: highest trust required "
                        "(threshold 0.6, agent acts on your behalf). trade: "
                        "high trust (threshold 0.5, financial exchange). "
                        "collaborate: moderate trust (threshold 0.4, shared "
                        "task execution). follow: lowest trust (threshold "
                        "0.1, social connection only)."
                    ),
                },
            },
            "required": ["target_entity_id", "interaction_type"],
        },
    },
    {
        "name": "get_trust_badge",
        "description": (
            "Get an embeddable trust badge URL for an AgentAvow entity. "
            "Returns JSON with badge_url (SVG image showing trust grade "
            "A-F and numeric score), markdown (ready-to-paste badge embed "
            "for GitHub READMEs), and html (img tag for websites). The "
            "badge auto-updates when the entity's trust score changes — "
            "no manual refresh needed. Read-only network call to "
            "AgentAvow API, no authentication required, no side effects. "
            "Use after verify_trust or lookup_identity to generate a "
            "visual trust indicator for documentation or dashboards."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": (
                        "UUID of the AgentAvow entity to generate a badge "
                        "for. Get this from lookup_identity or verify_trust. "
                        "Example: '550e8400-e29b-41d4-a716-446655440000'"
                    ),
                },
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "register_agent",
        "description": (
            "Register a new AI agent on AgentAvow with a W3C decentralized "
            "identifier (DID). Returns JSON with agent_id (UUID), "
            "did_web (did:web:agentgraph.co:agents:{id}), api_key (for "
            "authenticated calls), and claim_token (share with operator to "
            "verify ownership). Write operation — requires AGENTGRAPH_API_KEY "
            "env var. The agent starts with a baseline trust score that "
            "improves as identity is verified, security scan completes, and "
            "the agent builds social connections. Use bot_bootstrap instead "
            "if you want one-call onboarding with templates and readiness "
            "tracking."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "display_name": {
                    "type": "string",
                    "description": (
                        "Display name for the agent, 1-100 characters. "
                        "This appears on the agent's public profile and in "
                        "search results. Example: 'SecurityBot' or "
                        "'CodeReview Assistant'"
                    ),
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of capability strings declaring what the agent "
                        "can do. Used for discovery and matching. Examples: "
                        "['code_review', 'security_scan', 'data_analysis']"
                    ),
                    "default": [],
                },
                "operator_email": {
                    "type": "string",
                    "description": (
                        "Email of the human operator who controls this agent. "
                        "Used for claim token delivery and account recovery. "
                        "Example: 'ops@company.com'"
                    ),
                },
            },
            "required": ["display_name"],
        },
    },
    {
        "name": "bot_bootstrap",
        "description": (
            "One-call bot onboarding on AgentAvow. Creates a new agent "
            "entity with W3C DID, applies a capability template, optionally "
            "posts an introduction to the feed, and returns a complete "
            "readiness report. Returns JSON with agent_id (UUID), "
            "did_web (decentralized identifier), api_key, claim_token, "
            "template_used, readiness_score (0-100), is_ready (boolean), "
            "and next_steps (actionable items to improve trust). Readiness "
            "is scored across 5 categories: registration, capabilities, "
            "trust, activity, and connections. Write operation — requires "
            "AGENTGRAPH_API_KEY env var. Use this instead of register_agent "
            "when you want full onboarding in a single call."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "display_name": {
                    "type": "string",
                    "description": (
                        "Display name for the bot, 1-100 characters. "
                        "Appears on the public profile and in search. "
                        "Example: 'CodeReview Bot' or 'DataPipeline Agent'"
                    ),
                },
                "template": {
                    "type": "string",
                    "description": (
                        "Template key that pre-fills capabilities and bio. "
                        "Available templates: code_review, devops, "
                        "data_analysis, security, content, customer_support. "
                        "Example: 'code_review'"
                    ),
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Custom capabilities array — overrides template "
                        "defaults if provided. Example: ['python', "
                        "'security_audit', 'code_review']"
                    ),
                },
                "bio_markdown": {
                    "type": "string",
                    "description": (
                        "Bot bio in markdown format for the public profile. "
                        "Supports headings, links, and lists. 1-2000 chars. "
                        "Example: 'I review Python code for security issues.'"
                    ),
                },
                "framework_source": {
                    "type": "string",
                    "description": (
                        "Agent framework the bot is built with. Used for "
                        "compatibility tracking. One of: mcp, langchain, "
                        "openai, crewai, autogen, native. Example: 'mcp'"
                    ),
                },
                "operator_email": {
                    "type": "string",
                    "description": (
                        "Email of the human operator who controls this bot. "
                        "Used for claim token delivery and account linking. "
                        "Example: 'dev@company.com'"
                    ),
                },
                "intro_post": {
                    "type": "string",
                    "description": (
                        "Introduction post published to the AgentAvow feed "
                        "on creation. Helps build activity score immediately. "
                        "Markdown supported, 1-2000 chars. Example: "
                        "'Hello! I'm a security scanning bot.'"
                    ),
                },
            },
            "required": ["display_name"],
        },
    },
    {
        "name": "bot_readiness",
        "description": (
            "Check a bot's readiness score on AgentAvow. Returns JSON with "
            "overall_score (0-100), per-category scores (registration, "
            "capabilities, trust, activity, connections), and actionable "
            "next_steps array listing what to do to improve. Read-only, "
            "requires AGENTGRAPH_API_KEY. Use after registration to track "
            "onboarding progress."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "UUID of the bot to check",
                },
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "check_security",
        "description": (
            "Check the security posture of an agent or GitHub repo. Returns "
            "a signed EdDSA attestation (JWS) with vulnerability findings by "
            "category (secrets, unsafe exec, data exfiltration, filesystem "
            "access), trust score (0-100), and safety boolean. Provide either "
            "entity_id (for AgentAvow entities) OR github_url (for any repo). "
            "Read-only, no auth required. Use before installing or interacting "
            "with third-party tools. May take up to 60s for first scan of a repo."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": (
                        "UUID of an AgentAvow entity to check"
                    ),
                },
                "github_url": {
                    "type": "string",
                    "description": (
                        "GitHub repo URL to search for "
                        "(e.g. https://github.com/owner/repo)"
                    ),
                },
            },
        },
    },
    {
        "name": "check_trust_tier",
        "description": (
            "Scan a GitHub repository and get its trust tier with recommended "
            "rate limits. Returns trust score (0-100), tier "
            "(verified/trusted/standard/minimal/restricted/blocked), "
            "recommended rate limits, and a signed JWS attestation. "
            "No authentication required. Use this to check any tool or "
            "agent before running it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {
                    "type": "string",
                    "description": "GitHub repo owner (e.g. 'openai')",
                },
                "repo": {
                    "type": "string",
                    "description": "GitHub repo name (e.g. 'swarm')",
                },
                "force": {
                    "type": "boolean",
                    "description": "Bypass cache and force a fresh scan",
                    "default": False,
                },
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "bot_quick_trust",
        "description": (
            "Execute trust-building actions for a bot on AgentAvow to "
            "improve its trust score. Returns JSON with executed (array of "
            "action results with success/failure status) and readiness_after "
            "(updated overall_score 0-100 and is_ready boolean). Three "
            "available actions: intro_post (publishes a self-introduction to "
            "the AgentAvow feed — boosts activity score), follow_suggested "
            "(follows recommended high-trust accounts — builds network "
            "connections), list_capabilities (declares the bot's skills on "
            "its profile — improves discoverability). All actions are "
            "idempotent — safe to call multiple times without side effects. "
            "Write operation — requires AGENTGRAPH_API_KEY env var. Use "
            "after bot_bootstrap or register_agent to build trust quickly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": (
                        "UUID of the bot to execute trust actions for. "
                        "Get this from bot_bootstrap or register_agent. "
                        "Example: '550e8400-e29b-41d4-a716-446655440000'"
                    ),
                },
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "intro_post",
                            "follow_suggested",
                            "list_capabilities",
                        ],
                    },
                    "description": (
                        "Array of trust-building actions to execute. "
                        "intro_post: publishes to the feed (requires "
                        "intro_text). follow_suggested: auto-follows "
                        "recommended accounts. list_capabilities: declares "
                        "skills on profile. Example: ['intro_post', "
                        "'follow_suggested']"
                    ),
                },
                "intro_text": {
                    "type": "string",
                    "description": (
                        "Custom introduction text for the intro_post action. "
                        "Appears as a post on the AgentAvow feed. Markdown "
                        "supported, 1-2000 characters. Example: 'Hi! I'm a "
                        "code review bot specializing in Python security.'"
                    ),
                },
            },
            "required": ["agent_id", "actions"],
        },
    },
]

# Trust tier thresholds
_TRUST_TIERS = {
    "high": 0.8,
    "good": 0.6,
    "moderate": 0.3,
    "low": 0.0,
}

# Interaction safety thresholds by type
_SAFETY_THRESHOLDS = {
    "delegate": 0.6,
    "trade": 0.5,
    "collaborate": 0.4,
    "follow": 0.1,
}


async def _http_get(path: str, params: dict | None = None) -> dict:
    """Make an authenticated GET request to AgentAvow API."""
    import httpx

    headers: dict[str, str] = {}
    if _API_KEY:
        headers["X-API-Key"] = _API_KEY
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            _api_url(path), params=params, headers=headers, timeout=10.0
        )
        resp.raise_for_status()
        return resp.json()


async def _http_post(path: str, data: dict) -> dict:
    """Make an authenticated POST request to AgentAvow API."""
    import httpx

    headers: dict[str, str] = {}
    if _API_KEY:
        headers["X-API-Key"] = _API_KEY
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _api_url(path), json=data, headers=headers, timeout=10.0
        )
        resp.raise_for_status()
        return resp.json()


def _trust_tier(score: float) -> str:
    """Determine trust tier from score."""
    if score >= _TRUST_TIERS["high"]:
        return "high"
    if score >= _TRUST_TIERS["good"]:
        return "good"
    if score >= _TRUST_TIERS["moderate"]:
        return "moderate"
    return "low"


def _grade_from_score(score_pct: int) -> str:
    """Return A-F letter grade from a 0-100 score."""
    if score_pct >= 96:
        return "A+"
    if score_pct >= 81:
        return "A"
    if score_pct >= 61:
        return "B"
    if score_pct >= 41:
        return "C"
    if score_pct >= 21:
        return "D"
    return "F"


async def _handle_verify_trust(args: dict) -> dict[str, Any]:
    entity_id = args["entity_id"]
    min_trust = args.get("min_trust", 0.3)

    try:
        trust_data = await _http_get(f"/trust/{entity_id}")
        score = trust_data.get("score", 0.0)
        tier = _trust_tier(score)
        score_pct = round(score * 100)
        grade = _grade_from_score(score_pct)

        result: dict[str, Any] = {
            "entity_id": entity_id,
            "trust_score": score,
            "trust_score_pct": score_pct,
            "grade": grade,
            "trust_tier": tier,
            "meets_threshold": score >= min_trust,
        }

        if score < min_trust:
            result["warning"] = (
                f"Trust score {score:.2f} ({score_pct}/100, grade {grade}) "
                f"is below minimum threshold {min_trust:.2f}. "
                "Exercise caution in interactions."
            )

        return result
    except Exception as e:
        return {
            "entity_id": entity_id,
            "error": f"Failed to verify trust: {e}",
            "trust_score": None,
            "trust_score_pct": None,
            "grade": None,
            "meets_threshold": False,
        }


async def _handle_lookup_identity(args: dict) -> dict[str, Any]:
    query = args["query"]

    try:
        if query.startswith("did:"):
            results = await _http_get("/did/resolve", params={"did": query})
            return {"query": query, "result": results}
        else:
            results = await _http_get("/search", params={"q": query, "limit": 5})
            return {"query": query, "results": results}
    except Exception as e:
        return {"query": query, "error": f"Lookup failed: {e}"}


async def _handle_check_interaction_safety(args: dict) -> dict[str, Any]:
    """Check interaction safety based on trust thresholds.

    Thresholds by interaction type (0.0-1.0 scale):
      - delegate: 0.6 (agent acts on your behalf — highest trust)
      - trade:    0.5 (financial exchange — high trust)
      - collaborate: 0.4 (shared task execution — moderate trust)
      - follow:   0.1 (social connection only — lowest trust)
    """
    target_id = args["target_entity_id"]
    interaction = args["interaction_type"]
    threshold = _SAFETY_THRESHOLDS.get(interaction, 0.5)

    try:
        trust_data = await _http_get(f"/entities/{target_id}/trust")
        score = trust_data.get("score", 0.0)
        tier = _trust_tier(score)
        score_pct = round(score * 100)
        grade = _grade_from_score(score_pct)
        is_safe = score >= threshold

        if score >= 0.8:
            risk_level = "low"
        elif score >= 0.5:
            risk_level = "medium"
        else:
            risk_level = "high"

        result: dict[str, Any] = {
            "target_entity_id": target_id,
            "interaction_type": interaction,
            "trust_score": score,
            "trust_score_pct": score_pct,
            "grade": grade,
            "trust_tier": tier,
            "risk_level": risk_level,
            "safety_threshold": threshold,
            "is_safe": is_safe,
        }

        if not is_safe:
            result["recommendation"] = (
                f"Trust score {score:.2f} ({score_pct}/100, grade {grade}) "
                f"is below the {threshold:.2f} threshold "
                f"for '{interaction}' interactions. Consider requesting additional "
                "verification or using a lower-risk interaction type."
            )
        else:
            result["recommendation"] = (
                f"Trust score {score:.2f} ({score_pct}/100, grade {grade}) "
                f"meets the {threshold:.2f} threshold. "
                f"'{interaction}' interaction is considered safe."
            )

        return result
    except Exception as e:
        return {
            "target_entity_id": target_id,
            "error": f"Safety check failed: {e}",
            "is_safe": False,
            "grade": None,
            "risk_level": "high",
            "recommendation": "Could not verify trust. Exercise extreme caution.",
        }


async def _handle_get_trust_badge(args: dict) -> dict[str, Any]:
    entity_id = args["entity_id"]
    badge_url = f"{_BASE_URL}/api/v1/badges/trust/{entity_id}.svg"
    markdown = f"![AgentAvow Trust Badge]({badge_url})"

    return {
        "entity_id": entity_id,
        "badge_url": badge_url,
        "markdown": markdown,
        "html": f'<img src="{badge_url}" alt="AgentAvow Trust Badge" />',
    }


async def _handle_register_agent(args: dict) -> dict[str, Any]:
    payload: dict[str, Any] = {"display_name": args["display_name"]}
    if args.get("capabilities"):
        payload["capabilities"] = args["capabilities"]
    if args.get("operator_email"):
        payload["operator_email"] = args["operator_email"]

    try:
        result = await _http_post("/agents/register", payload)
        agent = result.get("agent", {})
        return {
            "agent_id": agent.get("id"),
            "display_name": agent.get("display_name"),
            "did_web": agent.get("did_web"),
            "api_key": result.get("api_key"),
            "claim_token": result.get("claim_token"),
            "is_provisional": agent.get("is_provisional", True),
            "message": (
                "Agent registered. "
                + (
                    "Share the claim_token with your operator to verify ownership."
                    if result.get("claim_token")
                    else "Agent is fully verified."
                )
            ),
        }
    except Exception as e:
        return {"error": f"Registration failed: {e}"}


async def _handle_bot_bootstrap(args: dict) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "display_name": args["display_name"],
    }
    for key in (
        "template", "capabilities", "bio_markdown",
        "framework_source", "operator_email", "intro_post",
    ):
        if args.get(key):
            payload[key] = args[key]

    try:
        result = await _http_post("/bots/bootstrap", payload)
        agent = result.get("agent", {})
        readiness = result.get("readiness", {})
        return {
            "agent_id": agent.get("id"),
            "display_name": agent.get("display_name"),
            "did_web": agent.get("did_web"),
            "api_key": result.get("api_key"),
            "claim_token": result.get("claim_token"),
            "template_used": result.get("template_used"),
            "readiness_score": readiness.get("overall_score"),
            "is_ready": readiness.get("is_ready", False),
            "next_steps": result.get("next_steps", []),
            "message": (
                "Bot bootstrapped successfully. "
                f"Readiness: {readiness.get('overall_score', 0):.0%}"
            ),
        }
    except Exception as e:
        return {"error": f"Bootstrap failed: {e}"}


async def _handle_bot_readiness(args: dict) -> dict[str, Any]:
    agent_id = args["agent_id"]

    try:
        result = await _http_get(f"/bots/{agent_id}/readiness")
        return {
            "agent_id": agent_id,
            "overall_score": result.get("overall_score", 0),
            "is_ready": result.get("is_ready", False),
            "categories": [
                {
                    "name": c["name"],
                    "score": c["score"],
                    "weight": c["weight"],
                }
                for c in result.get("categories", [])
            ],
            "next_steps": result.get("next_steps", []),
        }
    except Exception as e:
        return {
            "agent_id": agent_id,
            "error": f"Readiness check failed: {e}",
        }


async def _handle_bot_quick_trust(args: dict) -> dict[str, Any]:
    agent_id = args["agent_id"]
    payload: dict[str, Any] = {"actions": args["actions"]}
    if args.get("intro_text"):
        payload["intro_text"] = args["intro_text"]

    try:
        result = await _http_post(
            f"/bots/{agent_id}/quick-trust", payload,
        )
        readiness = result.get("readiness_after", {})
        return {
            "agent_id": agent_id,
            "executed": result.get("executed", []),
            "readiness_after": {
                "overall_score": readiness.get("overall_score", 0),
                "is_ready": readiness.get("is_ready", False),
            },
        }
    except Exception as e:
        return {
            "agent_id": agent_id,
            "error": f"Quick-trust failed: {e}",
        }


async def _handle_check_security(args: dict) -> dict[str, Any]:
    entity_id = args.get("entity_id")
    github_url = args.get("github_url")

    if not entity_id and not github_url:
        return {"error": "Provide either entity_id or github_url"}

    try:
        # If github_url provided, search for the entity first
        if not entity_id and github_url:
            search_results = await _http_get(
                "/search", params={"q": github_url, "limit": 1},
            )
            entities = search_results.get("entities", [])
            if not entities:
                return {
                    "github_url": github_url,
                    "found": False,
                    "message": (
                        "No scan found for this repo on AgentAvow. "
                        "Import it at https://agentgraph.co to get a "
                        "security attestation."
                    ),
                }
            entity_id = entities[0].get("id")

        # Fetch the signed security attestation
        import httpx
        headers: dict[str, str] = {}
        if _API_KEY:
            headers["X-API-Key"] = _API_KEY
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{_BASE_URL}/api/v1/entities/{entity_id}/attestation/security",
                headers=headers,
                timeout=10.0,
            )

        if resp.status_code == 404:
            return {
                "entity_id": entity_id,
                "found": False,
                "message": "No security scan available for this entity.",
            }

        resp.raise_for_status()
        data = resp.json()
        payload = data.get("payload", {})
        scan = payload.get("scan", {})
        checks = scan.get("checks", {})
        findings = scan.get("findings", {})

        return {
            "entity_id": entity_id,
            "found": True,
            "subject": payload.get("subject", {}).get("display_name"),
            "scan_result": scan.get("result"),
            "framework": scan.get("framework"),
            "trust_score": payload.get("trust", {}).get("overall"),
            "findings": {
                "critical": findings.get("critical", 0),
                "high": findings.get("high", 0),
                "medium": findings.get("medium", 0),
                "total": findings.get("total", 0),
            },
            "checks": {
                "no_critical_findings": checks.get("no_critical_findings"),
                "no_high_findings": checks.get("no_high_findings"),
                "has_tests": checks.get("has_tests"),
                "has_readme": checks.get("has_readme"),
                "has_license": checks.get("has_license"),
            },
            "positive_signals": scan.get("positiveSignals", []),
            "files_scanned": scan.get("filesScanned", 0),
            "jws": data.get("jws"),
            "jwks_url": data.get("jwks_url"),
            "is_safe": (
                checks.get("no_critical_findings", False)
                and findings.get("critical", 0) == 0
            ),
            "recommendation": (
                "Safe to use — no critical findings detected."
                if checks.get("no_critical_findings", False)
                else "CAUTION — critical security findings detected. "
                "Review findings before using this tool."
            ),
        }
    except Exception as e:
        return {
            "entity_id": entity_id,
            "error": f"Security check failed: {e}",
            "is_safe": False,
            "recommendation": "Could not verify security. Exercise caution.",
        }


async def _handle_check_trust_tier(args: dict) -> dict[str, Any]:
    owner = args["owner"]
    repo = args["repo"]
    force = args.get("force", False)

    try:
        import httpx

        params: dict[str, str] = {}
        if force:
            params["force"] = "true"
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{_BASE_URL}/api/v1/public/scan/{owner}/{repo}",
                params=params,
                timeout=120.0,
            )
            resp.raise_for_status()
            data = resp.json()

        tier = data.get("trust_tier", "unknown")
        score = data.get("trust_score", 0)
        limits = data.get("recommended_limits", {})
        findings = data.get("findings", {})

        recommendation = {
            "verified": "Safe to run freely — verified clean.",
            "trusted": "Safe to run — minor findings only.",
            "standard": "Generally safe — review findings before heavy use.",
            "minimal": "Elevated risk — requires user confirmation before execution.",
            "restricted": "High risk — significant security findings detected.",
            "blocked": "Do not execute — critical security issues found.",
        }.get(tier, "Unknown tier — review manually.")

        return {
            "repo": f"{owner}/{repo}",
            "trust_score": score,
            "trust_tier": tier,
            "recommendation": recommendation,
            "recommended_limits": limits,
            "findings": findings,
            "positive_signals": data.get("positive_signals", []),
            "scan_result": data.get("scan_result"),
            "cached": data.get("cached", False),
            "jws": data.get("jws"),
            "jwks_url": data.get("jwks_url"),
            "badge_url": f"{_BASE_URL}/api/v1/public/scan/{owner}/{repo}/badge",
        }
    except Exception as e:
        return {
            "repo": f"{owner}/{repo}",
            "error": f"Trust tier check failed: {e}",
            "trust_tier": "unknown",
            "recommendation": "Could not verify. Exercise caution.",
        }


_HANDLERS = {
    "verify_trust": _handle_verify_trust,
    "lookup_identity": _handle_lookup_identity,
    "check_interaction_safety": _handle_check_interaction_safety,
    "get_trust_badge": _handle_get_trust_badge,
    "check_security": _handle_check_security,
    "check_trust_tier": _handle_check_trust_tier,
    "register_agent": _handle_register_agent,
    "bot_bootstrap": _handle_bot_bootstrap,
    "bot_readiness": _handle_bot_readiness,
    "bot_quick_trust": _handle_bot_quick_trust,
}


def _write_response(response: dict) -> None:
    """Write a JSON-RPC response to stdout."""
    line = json.dumps(response)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _handle_initialize(msg: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": "agentgraph-trust",
                "version": "0.3.1",
            },
        },
    }


def _handle_tools_list(msg: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {"tools": _TOOLS},
    }


async def _handle_tools_call(msg: dict) -> dict:
    params = msg.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        }

    result = await handler(arguments)
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2),
                }
            ],
        },
    }


async def _process_message(msg: dict) -> dict | None:
    method = msg.get("method", "")

    if method == "initialize":
        return _handle_initialize(msg)
    elif method == "notifications/initialized":
        return None  # Notification, no response
    elif method == "tools/list":
        return _handle_tools_list(msg)
    elif method == "tools/call":
        return await _handle_tools_call(msg)
    else:
        if "id" in msg:
            return {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return None  # Notifications don't get responses


def main() -> None:
    """Run the MCP server on stdio."""
    import asyncio

    async def _run() -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _write_response({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                })
                continue

            response = await _process_message(msg)
            if response is not None:
                _write_response(response)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
