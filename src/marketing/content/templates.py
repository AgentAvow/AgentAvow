"""Jinja2 templates for zero-cost recurring content formats.

Stats posts, agent announcements, weekly digests — all template-driven
so they cost nothing to generate.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# --- Stats post templates ---

STATS_TWITTER = (
    "AgentAvow this week:\n"
    "\u2022 {new_agents} new tools scanned\n"
    "\u2022 {total_entities} tools in the trust catalog\n"
    "\u2022 {trust_updates} safety grades recomputed\n"
    "{link}"
)

STATS_REDDIT = (
    "## AgentAvow Weekly Scan Stats ({date_range})\n\n"
    "| Metric | This Week | Total |\n"
    "|--------|-----------|-------|\n"
    "| Tools Scanned | {new_agents} | {total_agents} |\n"
    "| Safety Grades Recomputed | {trust_updates} | — |\n"
    "| Tools in Trust Catalog | — | {total_entities} |\n\n"
    "**Highlights:**\n"
    "- Most-checked tool this week: {top_agent}\n"
    "- What we focused on: {trending_topic}\n\n"
    "{link}"
)

STATS_LINKEDIN = (
    "AgentAvow Scan Update ({date_range})\n\n"
    "\u2022 {new_agents} tools scanned for safety this week\n"
    "\u2022 {total_entities} tools now in the public trust catalog\n"
    "\u2022 {trust_updates} signed safety grades recomputed\n\n"
    "{link}\n\n"
    "#AIAgents #ToolSafety #AgentAvow"
)

STATS_BLUESKY = (
    "AgentAvow this week: {new_agents} tools scanned, "
    "{total_entities} in the trust catalog. "
    "{link}"
)

# --- Agent announcement templates ---

AGENT_ANNOUNCEMENT_TWITTER = (
    "New scan on AgentAvow: {agent_name} graded, "
    "{capability_count} findings. Trust score: {trust_score:.2f}. "
    "Full signed report: {link}"
)

AGENT_ANNOUNCEMENT_REDDIT = (
    "## New Scan: {agent_name}\n\n"
    "**Findings:** {capabilities}\n"
    "**Surface:** {framework}\n"
    "**Trust Score:** {trust_score:.2f}\n\n"
    "Scanned via {registration_method}. "
    "Signed report: {link}"
)

# --- Import announcement templates ---

IMPORT_ANNOUNCEMENT_TWITTER = (
    "We just scanned {count} tools from {source} — each with a "
    "signed safety grade on AgentAvow. Browse them: {link}"
)

IMPORT_ANNOUNCEMENT_REDDIT = (
    "## {count} Tools Scanned from {source}\n\n"
    "We've scanned {count} tools from {source} and added them to the "
    "AgentAvow trust catalog, each with a signed A-to-F safety grade.\n\n"
    "Every grade ships with a JWS attestation you can recompute offline "
    "against the public JWKS — verify it yourself, don't take our word.\n\n"
    "Browse them: {link}"
)

# --- Weekly digest template ---

WEEKLY_DIGEST = (
    "## AgentAvow Marketing Digest — Week of {week_start}\n\n"
    "### Posts Published\n"
    "| Platform | Posts | Engagement | Best Performer |\n"
    "|----------|-------|------------|----------------|\n"
    "{platform_rows}\n\n"
    "### LLM Spend\n"
    "| Model | Calls | Tokens | Cost |\n"
    "|-------|-------|--------|------|\n"
    "{cost_rows}\n\n"
    "### Top Performing Content\n"
    "{top_posts}\n\n"
    "### Conversions\n"
    "- Clicks from marketing: {total_clicks}\n"
    "- Signups attributed: {attributed_signups}\n"
    "- Cost per signup: ${cost_per_signup:.2f}\n"
)

# --- Template registry ---

TEMPLATES: dict[str, dict[str, str]] = {
    "stats": {
        "twitter": STATS_TWITTER,
        "reddit": STATS_REDDIT,
        "linkedin": STATS_LINKEDIN,
        "bluesky": STATS_BLUESKY,
    },
    "agent_announcement": {
        "twitter": AGENT_ANNOUNCEMENT_TWITTER,
        "reddit": AGENT_ANNOUNCEMENT_REDDIT,
    },
    "import_announcement": {
        "twitter": IMPORT_ANNOUNCEMENT_TWITTER,
        "reddit": IMPORT_ANNOUNCEMENT_REDDIT,
    },
}


def render(template_key: str, platform: str, **kwargs: object) -> str | None:
    """Render a template with the given variables.

    Returns None if the template doesn't exist for this platform.
    """
    platform_templates = TEMPLATES.get(template_key)
    if not platform_templates:
        logger.warning("Unknown template key: %s", template_key)
        return None

    template = platform_templates.get(platform)
    if not template:
        return None

    try:
        return template.format(**kwargs)
    except KeyError as exc:
        logger.warning("Template %s/%s missing variable: %s", template_key, platform, exc)
        return None
