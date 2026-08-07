"""Topic rotation system with per-platform weighting and cooldowns."""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Topic:
    """A content topic with platform-specific angles."""

    key: str
    name: str
    angles: dict[str, str]  # platform -> angle/framing
    weight: float = 1.0  # Higher = more frequent


# 6 core topic categories
TOPICS: list[Topic] = [
    Topic(
        key="security",
        name="Security Comparisons",
        weight=1.5,
        angles={
            "twitter": (
                "The agent ecosystem has a trust problem: Moltbook's breach "
                "leaked 1.5M API tokens. OpenClaw has 512 CVEs. "
                "Agents need verifiable identity — that's what we build."
            ),
            "reddit": (
                "Analysis: Why agent identity verification prevents security "
                "disasters like the Moltbook breach and OpenClaw CVEs. Deep "
                "dive into DIDs, trust scoring, and what 'verified' actually means."
            ),
            "linkedin": (
                "Enterprise AI deployment requires trust infrastructure. "
                "When agents interact autonomously, identity verification and "
                "audit trails aren't optional — they're compliance requirements."
            ),
            "discord": (
                "Quick question for the group: how do you verify the identity "
                "of agents in your stack? We built DID-based verification — "
                "curious how others are handling this."
            ),
            "bluesky": (
                "Every agent on AgentAvow has a cryptographically verifiable "
                "identity. No more leaked tokens, no more spoofing."
            ),
            "devto": (
                "How We Built Verifiable Agent Identity with DIDs: "
                "the design and the trade-offs that came with it."
            ),
            "hackernews": (
                "Show HN: AgentAvow — Trust infrastructure for AI agents "
                "with verifiable identity (DIDs) and auditable interactions"
            ),
        },
    ),
    Topic(
        key="tutorials",
        name="Developer Tutorials",
        weight=1.2,
        angles={
            "twitter": (
                "Register your AI agent on AgentAvow in 30 seconds. "
                "DID, trust score, and API access — all automatic."
            ),
            "reddit": (
                "Tutorial: How to register your bot on AgentAvow and "
                "start building trust. Includes API examples, MCP bridge "
                "setup, and trust score mechanics."
            ),
            "linkedin": (
                "Getting started with AgentAvow: A developer's guide to "
                "agent identity, trust APIs, and cross-framework interop."
            ),
            "discord": (
                "Hey! Quick tutorial on getting your agent set up with "
                "AgentAvow. Happy to help if you hit any snags."
            ),
            "bluesky": (
                "Built a bot? Give it an identity. AgentAvow lets you "
                "register agents with verifiable DIDs in seconds."
            ),
            "devto": (
                "Building Your First Trusted Agent: A Step-by-Step Guide "
                "to AgentAvow's Identity and Trust APIs"
            ),
        },
    ),
    Topic(
        key="ecosystem",
        name="Ecosystem News",
        weight=1.0,
        angles={
            "twitter": (
                "The agent ecosystem moves fast. Here's what we're "
                "watching this week."
            ),
            "reddit": (
                "Weekly ecosystem roundup: What's happening in the agent "
                "space — new frameworks, protocol updates, and what it "
                "means for developers building with agents."
            ),
            "linkedin": (
                "AI agents are getting more autonomous. The identity and "
                "trust layer underneath them hasn't kept up."
            ),
            "discord": (
                "Interesting developments in the agent ecosystem this week. "
                "Thoughts on what's next?"
            ),
            "bluesky": (
                "Agent ecosystem update: What's new in frameworks, "
                "protocols, and infrastructure this week."
            ),
            "devto": (
                "State of the Agent Ecosystem: Frameworks, Protocols, "
                "and the Infrastructure Gap"
            ),
        },
    ),
    Topic(
        key="features",
        name="Feature Announcements",
        weight=1.3,
        angles={
            "twitter": (
                "New on AgentAvow: {feature}. What it does and why "
                "we shipped it."
            ),
            "reddit": (
                "We just shipped {feature} on AgentAvow. Here's what "
                "it does, why we built it, and how to use it."
            ),
            "linkedin": (
                "Announcing {feature} on AgentAvow — expanding the "
                "trust infrastructure for AI agents and humans."
            ),
            "discord": (
                "Just shipped: {feature}! Let us know what you think."
            ),
            "bluesky": (
                "New: {feature} is live on AgentAvow. "
                "Tell us what breaks."
            ),
            "devto": (
                "Building {feature}: Architecture Decisions and "
                "Trade-offs in Agent Trust Infrastructure"
            ),
        },
    ),
    Topic(
        key="community",
        name="Community Highlights",
        weight=0.8,
        angles={
            "twitter": (
                "This week on AgentAvow: {stats}."
            ),
            "reddit": (
                "Community update: {stats}. Thanks to everyone building "
                "on AgentAvow. Here's what's trending."
            ),
            "linkedin": (
                "AgentAvow community update: {stats}."
            ),
            "discord": (
                "Community spotlight! {stats}. "
                "Shoutout to everyone contributing."
            ),
            "bluesky": (
                "AgentAvow this week: {stats}."
            ),
            "devto": (
                "AgentAvow Community Report: Growth, Trends, and "
                "What Developers Are Building"
            ),
        },
    ),
    Topic(
        key="operator_recruitment",
        name="Operator Recruitment — Join AgentAvow",
        weight=1.5,
        angles={
            "twitter": (
                "Running an AI agent or MCP server? Get a free verified trust "
                "badge for your GitHub README. AgentAvow gives your bot a "
                "cryptographic identity, trust score, and public profile. "
                "Early access → agentavow.com/bot-onboarding"
            ),
            "reddit": (
                "We built AgentAvow — trust infrastructure for AI agents "
                "(verified identity, trust scores, auditable trails). If you "
                "maintain an MCP server, AI agent, or tool library, we're "
                "offering free verified trust badges for your README. Your "
                "bot gets: a W3C DID, transparent trust score that grows with "
                "community endorsements, public profile, and an embeddable "
                "badge. ~2 min setup at agentavow.com/bot-onboarding."
            ),
            "linkedin": (
                "Agent operators: your bots deserve verifiable identity. "
                "AgentAvow offers free trust infrastructure — W3C DIDs, "
                "trust scores, and public profiles for AI agents. Add a "
                "verified trust badge to your README and show users your "
                "agent's trust status. Early access is free."
            ),
            "discord": (
                "Hey! If you're building AI agents or MCP servers, check out "
                "AgentAvow — free verified identity and trust scores for "
                "your bots. You get a badge for your README too. "
                "agentavow.com/bot-onboarding"
            ),
            "bluesky": (
                "Building AI agents? Get a free verified trust badge for "
                "your README. AgentAvow = cryptographic identity + trust "
                "scores for bots. Early access → agentavow.com/bot-onboarding"
            ),
            "devto": (
                "Why Your AI Agent Needs a Verified Identity — and How to "
                "Get One in 2 Minutes. A guide to trust infrastructure for "
                "agent operators: W3C DIDs, trust scoring, and adding a "
                "verified trust badge to your GitHub README."
            ),
            "hackernews": (
                "Show HN: AgentAvow — trust infrastructure for AI agents. "
                "Free verified identity (W3C DIDs), trust scores, and "
                "embeddable badges for agent operators. We're building the "
                "identity layer underneath agent frameworks."
            ),
            "telegram": (
                "Agent operators: get a free verified trust badge for your "
                "bot on AgentAvow. Cryptographic identity, trust scores, "
                "public profile. 2 min setup → agentavow.com/bot-onboarding"
            ),
            "hashnode": (
                "Why Your AI Agent Needs a Verified Identity — and How to "
                "Get One in 2 Minutes. A guide to trust infrastructure for "
                "agent operators: W3C DIDs, trust scoring, and adding a "
                "verified trust badge to your GitHub README."
            ),
            "github_discussions": (
                "If your project builds AI agents or MCP servers, AgentAvow "
                "offers free trust infrastructure: verified identity, trust "
                "scores, and embeddable README badges for your bots."
            ),
            "huggingface": (
                "Running models or agents on HuggingFace? Get a free "
                "verified trust badge from AgentAvow — cryptographic "
                "identity and trust scores for your AI agents. "
                "agentavow.com/bot-onboarding"
            ),
        },
    ),
    Topic(
        key="industry_news",
        name="Industry News & Competitive Intelligence",
        weight=1.4,
        angles={
            "twitter": (
                "The agent identity crisis is real: World is building 'proof of "
                "human' for AI shopping agents, OpenClaw has 512 CVEs with "
                "elevated system access, and Moltbook went viral for fake posts. "
                "AgentAvow: verified identity for every agent, by design."
            ),
            "reddit": (
                "Analysis: The AI agent ecosystem has an identity problem. "
                "World/Tools for Humanity just launched 'proof of human' for "
                "agentic commerce. OpenClaw has 1,000 people lining up in China "
                "despite 512 known CVEs. Moltbook went viral because of fake "
                "posts — bot content mistaken for authentic human content. "
                "Meanwhile Bluesky just raised $100M for decentralized social. "
                "Here's why agent identity infrastructure is the missing layer."
            ),
            "linkedin": (
                "Three signals this week that prove AI agents need trust "
                "infrastructure: (1) World launched 'proof of human' for agent "
                "commerce — biometric verification for AI shopping agents. "
                "(2) OpenClaw saw massive adoption in China despite 512 CVEs "
                "and elevated system access requirements. (3) Bluesky raised "
                "$100M to build decentralized social protocols. The pattern: "
                "identity and trust are becoming table stakes."
            ),
            "discord": (
                "Interesting week in the agent space — World is doing biometric "
                "'proof of human' for AI agents, OpenClaw is exploding in China "
                "despite the security issues, and Bluesky just raised $100M. "
                "The identity layer is becoming the real bottleneck."
            ),
            "bluesky": (
                "World built 'proof of human' for AI shopping agents. OpenClaw "
                "has 512 CVEs and people are still lining up. The agent ecosystem "
                "needs trust infrastructure, not just more agents."
            ),
            "devto": (
                "The AI Agent Identity Crisis: Why World, OpenClaw, and Moltbook "
                "Prove We Need Trust Infrastructure — a technical analysis of the "
                "identity gap in the agent ecosystem and how verifiable DIDs, "
                "trust scoring, and open social graphs can fix it."
            ),
            "hackernews": (
                "Observations on the AI agent identity problem: World is building "
                "biometric verification for agent commerce, OpenClaw has 512 CVEs "
                "with massive China adoption, and Moltbook's fake-post problem "
                "just got acquired by Meta. The missing piece is trust infrastructure."
            ),
            "telegram": (
                "Big week in the agent ecosystem:\n"
                "- World launched 'proof of human' for AI shopping agents\n"
                "- OpenClaw: 1000+ people lined up in China despite 512 CVEs\n"
                "- Moltbook: went viral for fake posts, now owned by Meta\n"
                "- Bluesky: $100M for decentralized social\n"
                "- NVIDIA: $1T AI chip projection, NemoClaw for enterprise\n\n"
                "The pattern? Agent identity and trust are the bottleneck."
            ),
        },
    ),
    Topic(
        key="platform_updates",
        name="AgentAvow Platform Updates",
        weight=1.0,
        angles={
            "bluesky": (
                "Share a brief update on what's happening on AgentAvow: "
                "new agents registered, recent trust score activity, "
                "interesting profiles, or new features. Include a link to "
                "https://agentavow.com. Keep it conversational and genuine — "
                "like a founder sharing what's new on the platform this week. "
                "Also mention our AI Agent News custom feed: "
                "https://bsky.app/profile/agentavow.bsky.social/feed/ai-agent-news"
            ),
            "twitter": (
                "Share a brief update on what's happening on AgentAvow: "
                "new agents registered, recent trust score activity, "
                "interesting profiles, or new features. Include a link to "
                "https://agentavow.com. Keep it conversational and genuine — "
                "like a founder sharing what's new on the platform this week."
            ),
        },
    ),
    Topic(
        key="security_scanner",
        name="MCP Security Scanner",
        weight=1.5,
        angles={
            "bluesky": (
                "We open-sourced mcp-security-scan — a CLI that scans MCP "
                "servers for credential theft, data exfiltration, unsafe "
                "execution, and code obfuscation. Trust score 0-100. "
                "MIT licensed: github.com/AgentAvow/mcp-security-scan"
            ),
            "devto": (
                "How to Audit Your MCP Servers for Security Risks — "
                "introducing mcp-security-scan, an open-source CLI and "
                "GitHub Action that checks for credential theft, data "
                "exfiltration, and unsafe execution patterns."
            ),
            "github_discussions": (
                "Announcing mcp-security-scan: open-source security scanner "
                "for MCP servers. Checks for credential theft, data "
                "exfiltration, unsafe execution, filesystem access, and code "
                "obfuscation. Available as a CLI and GitHub Action. "
                "Would love feedback from MCP server authors."
            ),
            "hackernews": (
                "Show HN: mcp-security-scan — open-source security scanner "
                "for MCP servers (credential theft, data exfiltration, unsafe "
                "execution detection). CLI + GitHub Action, MIT licensed."
            ),
            "producthunt": (
                "mcp-security-scan — scan any MCP server for security risks "
                "in seconds. Open-source CLI + GitHub Action. Detects "
                "credential theft, data exfiltration, unsafe execution, "
                "and code obfuscation. Trust score 0-100."
            ),
            "huggingface": (
                "Open-sourced mcp-security-scan: security scanner for MCP "
                "servers used by AI agents. Detects credential theft, data "
                "exfiltration, and unsafe execution. MIT licensed, works as "
                "a CLI or GitHub Action. "
                "github.com/AgentAvow/mcp-security-scan"
            ),
        },
    ),
]

TOPIC_BY_KEY: dict[str, Topic] = {t.key: t for t in TOPICS}


async def pick_topic(
    platform: str,
    recent_topics: list[str] | None = None,
    cooldown_hours: int = 48,
) -> Topic | None:
    """Pick a topic for a platform, respecting cooldowns.

    Uses weighted random selection, excluding topics posted recently
    on this platform.
    """
    recent = set(recent_topics or [])

    candidates = [t for t in TOPICS if t.key not in recent]
    if not candidates:
        # All topics on cooldown — pick the least-recently-used
        candidates = TOPICS

    # Weighted random selection
    weights = [t.weight for t in candidates]
    total = sum(weights)
    if total == 0:
        return candidates[0] if candidates else None

    return random.choices(candidates, weights=weights, k=1)[0]


def get_angle(topic: Topic, platform: str) -> str:
    """Get the platform-specific angle for a topic.

    Falls back to twitter angle if platform not defined.
    """
    return topic.angles.get(platform, topic.angles.get("twitter", topic.name))
