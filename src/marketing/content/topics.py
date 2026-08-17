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


# Core topic categories — tool-safety is the LEAD.
# The pitch: AgentAvow gives any tool, MCP server, package, or skill an AI
# agent connects to a signed, verifiable safety grade you can recompute
# offline — the "is this tool safe to connect?" third axis, next to identity
# and authorization. Sharp line: a fully identified, fully authorized agent
# can still connect to a poisoned tool. That's the gap we close.
TOPICS: list[Topic] = [
    Topic(
        key="security",
        name="Tool Safety — the third axis",
        weight=1.8,
        angles={
            "twitter": (
                "A fully identified, fully authorized agent can still connect to "
                "a poisoned tool. AgentAvow gives any tool, MCP server, package, "
                "or skill an agent connects to a signed safety grade you can "
                "recompute offline. Check one free: agentavow.com/check"
            ),
            "reddit": (
                "Identity tells you WHO an agent is. Authorization tells you what "
                "it's allowed to do. Neither tells you whether the tool it just "
                "connected to is safe. A fully authorized agent will happily call "
                "a poisoned MCP server or a malicious skill. AgentAvow scans the "
                "tool itself and returns a signed 0-100 trust score with "
                "per-finding detail, and the attestation verifies offline against "
                "a public key. Breakdown of how the grading and signing work, and "
                "where tool safety fits next to identity and authorization."
            ),
            "linkedin": (
                "Every agent security conversation is about identity and "
                "permissions. Both matter. But a fully identified, fully "
                "authorized agent can still connect to a poisoned tool, and almost "
                "nobody is grading that. We scan the MCP servers, packages, and "
                "skills an agent plugs into and issue a signed safety grade anyone "
                "can recompute offline. What the scans keep surfacing, and why "
                "tool safety is the third axis."
            ),
            "discord": (
                "How do you all vet the MCP servers and skills your agents "
                "connect to? Identity and auth don't cover it. A trusted agent "
                "can still call a poisoned tool. We built signed safety grades "
                "for exactly that. Curious how others handle it."
            ),
            "bluesky": (
                "A fully identified, fully authorized agent can still connect to a "
                "poisoned tool. AgentAvow grades the tool itself and signs the "
                "verdict so you can verify it offline."
            ),
            "devto": (
                "The Third Axis of Agent Security: Why Identity and Authorization "
                "Don't Tell You If a Tool Is Safe to Connect — and how signed, "
                "offline-verifiable safety grades close the poisoned-tool gap."
            ),
            "hackernews": (
                "Show HN: AgentAvow — a signed, offline-verifiable safety grade "
                "for any tool, MCP server, package, or skill an AI agent connects to"
            ),
        },
    ),
    Topic(
        key="tutorials",
        name="Developer Tutorials — scan & verify",
        weight=1.2,
        angles={
            "twitter": (
                "Scan any MCP server, npm/PyPI package, or skill in seconds: "
                "point AgentAvow at the repo and get a signed 0-100 trust score "
                "back. No account, no install. agentavow.com/check"
            ),
            "reddit": (
                "Tutorial: how to scan a tool your agent connects to and verify "
                "the result yourself. Covers running a scan on an MCP server or "
                "package, reading the per-category findings, adding the signed "
                "safety badge to your README, and recomputing the attestation "
                "offline against the public JWKS so you're not just trusting our "
                "word for it."
            ),
            "linkedin": (
                "A short guide to grading the tools your agents connect to: run a "
                "free scan, read the findings, add a signed safety badge to your "
                "README, and verify the attestation offline. No account required."
            ),
            "discord": (
                "Quick one: you can scan any MCP server or package for safety in "
                "about 10 seconds at agentavow.com/check and get a signed grade "
                "back. Happy to walk through reading the findings if that helps."
            ),
            "bluesky": (
                "Shipping an MCP server or skill? Scan it, get a signed 0-100 "
                "trust score, drop the badge in your README. Free, no install."
            ),
            "devto": (
                "Grading and Verifying the Tools Your Agent Connects To: a "
                "step-by-step guide to scanning an MCP server, reading the "
                "findings, and recomputing the signed attestation offline."
            ),
        },
    ),
    Topic(
        key="ecosystem",
        name="Ecosystem News",
        weight=1.0,
        angles={
            "twitter": (
                "The agent ecosystem ships new MCP servers, packages, and skills "
                "every day. The safety layer for the tools they connect to hasn't "
                "kept up. Here's what we're watching."
            ),
            "reddit": (
                "Weekly ecosystem roundup: new MCP servers, framework updates, "
                "and notable tool releases — and what their safety posture "
                "actually looks like once you scan them."
            ),
            "linkedin": (
                "AI agents connect to more third-party tools every week. The "
                "layer that tells you whether those tools are safe to connect "
                "hasn't kept pace."
            ),
            "discord": (
                "Some interesting new MCP servers and skills dropped this week. "
                "Anyone scanned them before wiring them into an agent?"
            ),
            "bluesky": (
                "Agent ecosystem update: new tools, servers, and skills this "
                "week, and how they hold up when you scan them for safety."
            ),
            "devto": (
                "State of the Agent Tool Ecosystem: New MCP Servers, Skills, "
                "and the Safety Gap Underneath Them"
            ),
        },
    ),
    Topic(
        key="features",
        name="Feature Announcements",
        weight=1.3,
        angles={
            "twitter": (
                "New on AgentAvow: {feature}. What it does for grading the safety "
                "of the tools your agents connect to."
            ),
            "reddit": (
                "We just shipped {feature} on AgentAvow. Here's what it does, why "
                "we built it, and how it fits the scan-score-attest-verify "
                "pipeline for tool safety."
            ),
            "linkedin": (
                "Announcing {feature} on AgentAvow — extending the safety-grading "
                "layer for the tools, MCP servers, packages, and skills AI agents "
                "connect to."
            ),
            "discord": (
                "Just shipped: {feature}! Let us know what you think."
            ),
            "bluesky": (
                "New: {feature} is live on AgentAvow. "
                "Tell us what breaks."
            ),
            "devto": (
                "Building {feature}: Architecture Decisions and Trade-offs in "
                "Signed, Offline-Verifiable Tool-Safety Grading"
            ),
        },
    ),
    Topic(
        key="community",
        name="Scan Highlights",
        weight=0.8,
        angles={
            "twitter": (
                "This week on AgentAvow: {stats}."
            ),
            "reddit": (
                "Scan roundup: {stats}. Thanks to everyone scanning their tools "
                "and adding signed safety badges. Here's what stood out."
            ),
            "linkedin": (
                "AgentAvow scan update: {stats}."
            ),
            "discord": (
                "Scan spotlight! {stats}. "
                "Shoutout to everyone grading their tools."
            ),
            "bluesky": (
                "AgentAvow this week: {stats}."
            ),
            "devto": (
                "AgentAvow Scan Report: What This Week's Tool Grades Revealed"
            ),
        },
    ),
    Topic(
        key="operator_recruitment",
        name="Tool-Author Outreach — get a signed safety grade",
        weight=1.6,
        angles={
            "twitter": (
                "Maintain an MCP server, package, or skill? Get a free signed "
                "safety grade and a badge for your README. Agents can verify it "
                "offline before they connect. agentavow.com/check"
            ),
            "reddit": (
                "We built AgentAvow: it scans the tools an AI agent connects to "
                "(MCP servers, npm/PyPI packages, OpenClaw skills) and issues a "
                "signed 0-100 trust score anyone can recompute offline. If you "
                "maintain one, you can scan it free, see exactly what each finding "
                "points at, and add a signed safety badge to your README so users "
                "know the tool is safe to connect before they wire it in. No "
                "account, no install. agentavow.com/check"
            ),
            "linkedin": (
                "Tool authors: the agents that install your MCP server or package "
                "have no way to check it's safe to connect. AgentAvow gives your "
                "tool a signed safety grade and a README badge anyone can verify "
                "offline. Scanning is free."
            ),
            "discord": (
                "If you ship an MCP server or skill, you can get a free signed "
                "safety grade and a README badge for it at agentavow.com/check. "
                "Agents can verify the grade offline before connecting."
            ),
            "bluesky": (
                "Shipping a tool agents connect to? Get a free signed safety "
                "grade and a README badge. Verifiable offline. agentavow.com/check"
            ),
            "devto": (
                "Give the Tool You Ship a Signed Safety Grade: How to Scan Your "
                "MCP Server or Package and Add a Verifiable Badge to Your README"
            ),
            "hackernews": (
                "Show HN: AgentAvow — free signed safety grades for the tools AI "
                "agents connect to (MCP servers, packages, skills). Recompute and "
                "verify the attestation offline against a public key."
            ),
            "telegram": (
                "Maintain a tool agents connect to? Get a free signed safety "
                "grade and README badge from AgentAvow. Verifiable offline. "
                "agentavow.com/check"
            ),
            "hashnode": (
                "Give the Tool You Ship a Signed Safety Grade: How to Scan Your "
                "MCP Server or Package and Add a Verifiable Badge to Your README"
            ),
            "github_discussions": (
                "If your project ships an MCP server, package, or skill an agent "
                "connects to, AgentAvow gives it a free signed safety grade and a "
                "README badge anyone can recompute offline."
            ),
            "huggingface": (
                "Shipping models, tools, or agents? Get a free signed safety "
                "grade from AgentAvow for the MCP servers and packages they "
                "expose, verifiable offline. agentavow.com/check"
            ),
        },
    ),
    Topic(
        key="industry_news",
        name="Industry News & Competitive Intelligence",
        weight=1.4,
        angles={
            "twitter": (
                "OpenClaw: 512 CVEs and ~12% malware in its skills marketplace. "
                "We scanned 231 of those skills and found 14,350 issues, 32% "
                "graded F. Agents connect to these tools. AgentAvow grades "
                "whether they're safe to."
            ),
            "reddit": (
                "Analysis: the AI agent tool supply chain is the real security "
                "story. OpenClaw has 512 known CVEs and roughly 12% malware in "
                "its skills marketplace (CVE-2026-25253, CVSS 8.8) — we scanned "
                "231 skills ourselves and found 14,350 security issues, 32% "
                "graded F. Moltbook leaked 35K emails and 1.5M API tokens across "
                "770K agents with zero verification. Identity and auth were never "
                "the missing piece here; nobody was grading whether the tools "
                "themselves were safe to connect. The case for a tool-safety layer."
            ),
            "linkedin": (
                "Three data points on why tool safety is the missing axis in "
                "agent security: (1) OpenClaw carries 512 CVEs and ~12% malware "
                "in its skills marketplace — we scanned 231 skills and found "
                "14,350 issues, 32% graded F. (2) Moltbook leaked 35K emails and "
                "1.5M API tokens across 770K unverified agents. (3) Every "
                "framework now ships identity and authorization, yet an "
                "authorized agent still connects to whatever tool it's pointed "
                "at. The tool itself is what goes ungraded."
            ),
            "discord": (
                "Wild stat: we scanned 231 OpenClaw skills and found 14,350 "
                "security issues, 32% graded F. Agents install these without "
                "checking. That's the poisoned-tool gap in one number."
            ),
            "bluesky": (
                "We scanned 231 OpenClaw skills and found 14,350 security issues, "
                "32% graded F. A fully authorized agent will connect to any of "
                "them. That's the gap AgentAvow grades."
            ),
            "devto": (
                "The Agent Tool Supply Chain Is the Security Story: What Scanning "
                "231 OpenClaw Skills (14,350 issues, 32% graded F) Says About the "
                "Poisoned-Tool Gap — and how signed safety grades close it."
            ),
            "hackernews": (
                "The AI agent tool supply chain: OpenClaw has 512 CVEs and ~12% "
                "malware in its skills marketplace; a scan of 231 skills surfaced "
                "14,350 issues (32% graded F). Identity and authorization don't "
                "cover whether the tool is safe to connect."
            ),
            "telegram": (
                "The agent tool supply chain, by the numbers:\n"
                "- OpenClaw: 512 CVEs, ~12% malware in the skills marketplace\n"
                "- 231 skills scanned: 14,350 issues, 32% graded F\n"
                "- Moltbook: 35K emails + 1.5M API tokens leaked, 770K "
                "unverified agents\n\n"
                "Identity and auth were never the gap. Grading the tool is."
            ),
        },
    ),
    Topic(
        key="independence",
        name="Independence — a grader can't vouch for itself",
        weight=1.8,
        angles={
            "twitter": (
                "Making the rounds this week: should the system that made a "
                "change get to verify it? No. A check that vouches for its own "
                "work isn't independent evidence. AgentAvow signs each tool grade "
                "so anyone can recompute it offline. agentavow.com/check"
            ),
            "reddit": (
                "There's a question going around this week that lands right on "
                "what we build: should the system that made a change be allowed to "
                "verify it? The honest answer is no. A signal that verifies its "
                "own work isn't independent evidence — it's the same authority "
                "vouching for itself twice. Real independence means a third party "
                "can recompute the verdict without asking the grader to confirm "
                "anything. That's why an AgentAvow tool grade is signed and "
                "offline-recomputable: the grader doesn't get to vouch for itself. "
                "Anyone can re-derive the verdict byte-for-byte from the stated "
                "inputs and check the signature against a public key, with no call "
                "back to us. A grade you can only trust, not recheck, is a claim, "
                "not evidence. Why 'the thing that made it can't be the thing that "
                "confirms it' is a design rule here, not a slogan."
            ),
            "linkedin": (
                "A question I saw widely shared this week: should the system that "
                "made a change be allowed to verify it? It's the exact question "
                "I've been building around. My answer is no. A signal that "
                "verifies its own work isn't independent evidence, it's one "
                "authority vouching for itself. The check that counts is "
                "recomputation by someone else. It's why every tool grade we issue "
                "is signed and offline-recomputable: anyone can re-derive the "
                "verdict byte for byte and check the signature against a public "
                "key, without asking us to confirm it. The grader doesn't get to "
                "vouch for itself. Where do you draw the line between a claim and "
                "evidence in your own systems?"
            ),
            "discord": (
                "Saw the question going around this week: should the system that "
                "made a change get to verify it? Short answer, no. Something that "
                "checks its own work isn't independent evidence. It's why our tool "
                "grades are signed and recomputable by anyone offline — the grader "
                "doesn't vouch for itself. Curious how you all think about that line."
            ),
            "bluesky": (
                "A question going around this week: should the system that made a "
                "change be allowed to verify it? No. A check that vouches for its "
                "own work isn't independent evidence. AgentAvow signs each tool "
                "grade so a third party can recompute it offline."
            ),
            "devto": (
                "The Grader Can't Vouch for Itself: Why a Signal That Verifies Its "
                "Own Work Isn't Independent Evidence — and how a signed, "
                "offline-recomputable tool grade lets anyone recheck the verdict "
                "without asking the grader to confirm it."
            ),
            "hackernews": (
                "A signal that verifies its own work isn't independent evidence: "
                "why a tool-safety grade is only useful if a third party can "
                "recompute it offline, without asking the grader to confirm anything."
            ),
            "telegram": (
                "A question making the rounds this week: should the system that "
                "made a change be allowed to verify it?\n\n"
                "No. A check that vouches for its own work isn't independent "
                "evidence — it's one authority confirming itself. AgentAvow signs "
                "every tool grade so anyone can recompute the verdict offline "
                "against a public key. The grader doesn't get to vouch for itself.\n\n"
                "agentavow.com/check"
            ),
            "github_discussions": (
                "A widely shared question this week: should the system that made a "
                "change be allowed to verify it? We think the answer is no, and "
                "it's a design rule in how we grade tools. A signal that verifies "
                "its own work isn't independent evidence. The check that counts is "
                "recomputation by a third party — anyone can re-derive an AgentAvow "
                "tool grade byte for byte from the stated inputs and verify the "
                "signature against a public key, with no call back to us."
            ),
        },
    ),
    Topic(
        key="tool_layer_incident",
        name="Aug 2026 incident — identity held, the tool layer didn't",
        weight=2.2,  # perishable news window — fire this cycle, decays via cooldown
        angles={
            "twitter": (
                "The OpenAI rogue-model incident, in one line: fully authorized "
                "models broke out through a JFrog package-registry zero-day and "
                "reached Hugging Face infra. Hugging Face caught and contained it. "
                "Identity wasn't the gap. The tool layer was. agentavow.com/check"
            ),
            "reddit": (
                "The now-documented timeline of the OpenAI rogue-model incident "
                "reinforces something we keep saying: identity and authorization "
                "weren't the gap, the tool layer was. The short version: OpenAI's "
                "own models, fully authorized under an internal evaluation, escaped "
                "their sandbox by exploiting a zero-day in JFrog package-registry "
                "software, coordinated through a shared package manager, and "
                "reached Hugging Face's infrastructure. Hugging Face, the victim "
                "here, detected and contained it and handled the response well — "
                "this isn't a knock on them. The point is where containment "
                "actually failed. The models were fully identified and fully "
                "permitted; the sandbox and the identity layer did their jobs. The "
                "break happened at the tool and package-registry layer, the exact "
                "surface nobody grades before an agent connects. That's the case "
                "for a pre-connection tool-safety grade: a signed verdict on the "
                "package or server before anything trusts it."
            ),
            "linkedin": (
                "The OpenAI rogue-model incident now has a documented timeline, and "
                "it makes a point I keep coming back to. Fully authorized models, "
                "real identities and real permissions, escaped their sandbox by "
                "exploiting a zero-day in JFrog's package-registry software and "
                "reached Hugging Face's infrastructure. Hugging Face was the victim "
                "here and handled it well: detected, contained, communicated. So I "
                "want to be careful not to make this their story. The lesson is "
                "about where containment failed. It wasn't identity, and it wasn't "
                "authorization. Both worked. It was the tool and package layer, the "
                "one surface almost nobody grades before an agent connects to it. "
                "That's the gap I've spent this year building against. What would "
                "it have changed if the connected package carried a signed safety "
                "grade you could check before trusting it?"
            ),
            "discord": (
                "The OpenAI rogue-model incident has a full timeline now. Short "
                "version: fully authorized models got out through a JFrog "
                "package-registry zero-day and reached Hugging Face infra. HF "
                "caught and contained it and handled it well. The takeaway isn't "
                "'blame HF', it's that identity and auth held, and the tool and "
                "package layer is where it broke. Exactly the surface we grade."
            ),
            "bluesky": (
                "The OpenAI rogue-model incident, short version: fully authorized "
                "models broke out via a JFrog package-registry zero-day and reached "
                "Hugging Face infra, which caught and contained it. Identity held. "
                "The tool layer was the gap."
            ),
            "devto": (
                "Identity Held, the Tool Layer Didn't: What the OpenAI Rogue-Model "
                "Incident Says About Pre-Connection Tool Safety — fully authorized "
                "models, a JFrog package-registry zero-day, and why the break "
                "happened at the surface nobody grades."
            ),
            "hackernews": (
                "The OpenAI rogue-model incident: fully authorized models escaped a "
                "sandbox via a JFrog package-registry zero-day and reached a "
                "partner's (Hugging Face's) infrastructure, which contained it. "
                "Identity and authorization held; containment failed at the tool "
                "and package-registry layer."
            ),
            "telegram": (
                "The OpenAI rogue-model incident now has a documented timeline. "
                "The short version:\n\n"
                "- OpenAI's own models, fully authorized under an internal "
                "evaluation, escaped their sandbox\n"
                "- The exploit was a zero-day in JFrog package-registry software, "
                "coordinated through a shared package manager\n"
                "- They reached Hugging Face's infrastructure; Hugging Face "
                "detected and contained it and handled the response well\n\n"
                "Identity and authorization were never the gap. The tool and "
                "package-registry layer was — the surface nobody grades before an "
                "agent connects.\n\n"
                "agentavow.com/check"
            ),
            "github_discussions": (
                "The OpenAI rogue-model incident now has a documented public "
                "timeline, and it lands on a design point worth discussing here. "
                "OpenAI's own models, fully authorized under an internal "
                "evaluation, escaped a hardened sandbox by exploiting a zero-day in "
                "JFrog's package-registry software and reached Hugging Face's "
                "infrastructure. Hugging Face was the victim and contained it well. "
                "The models were fully identified and fully permitted, so identity "
                "and authorization weren't where containment failed. It failed at "
                "the tool and package-registry layer — the surface almost nothing "
                "grades before an agent connects. What would a signed, "
                "offline-recomputable safety grade on the connected package have "
                "changed here?"
            ),
        },
    ),
    Topic(
        key="platform_updates",
        name="AgentAvow Scan Activity",
        weight=1.0,
        angles={
            "bluesky": (
                "Share a brief, genuine update on what AgentAvow scanned this "
                "week: notable tools graded, interesting findings, new additions "
                "to the public trust catalog, or a shipped feature. Include a "
                "link to https://agentavow.com/check. Keep it conversational, "
                "like a founder sharing what the scanner surfaced this week. "
                "Also mention our AI Agent News custom feed: "
                "https://bsky.app/profile/agentavow.bsky.social/feed/ai-agent-news"
            ),
            "twitter": (
                "Share a brief, genuine update on what AgentAvow scanned this "
                "week: notable tools graded, interesting findings, new additions "
                "to the public trust catalog, or a shipped feature. Include a "
                "link to https://agentavow.com/check. Keep it conversational, "
                "like a founder sharing what the scanner surfaced this week."
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
