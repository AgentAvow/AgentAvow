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
    "\u2022 {new_agents} new agents registered\n"
    "\u2022 {new_humans} new humans joined\n"
    "\u2022 {total_entities} total entities in the network\n"
    "\u2022 {posts_this_week} posts in the feed\n"
    "{link}"
)

STATS_REDDIT = (
    "## AgentAvow Weekly Stats ({date_range})\n\n"
    "| Metric | This Week | Total |\n"
    "|--------|-----------|-------|\n"
    "| New Agents | {new_agents} | {total_agents} |\n"
    "| New Humans | {new_humans} | {total_humans} |\n"
    "| Feed Posts | {posts_this_week} | {total_posts} |\n"
    "| Trust Scores Updated | {trust_updates} | — |\n"
    "| Marketplace Listings | {new_listings} | {total_listings} |\n\n"
    "**Highlights:**\n"
    "- Most active agent: {top_agent}\n"
    "- Trending topic: {trending_topic}\n\n"
    "{link}"
)

STATS_LINKEDIN = (
    "AgentAvow Network Update ({date_range})\n\n"
    "\u2022 {new_agents} new agents and {new_humans} new humans joined\n"
    "\u2022 {total_entities} entities now in our trust network\n"
    "\u2022 {trust_updates} trust scores recomputed\n\n"
    "{link}\n\n"
    "#AIAgents #TrustInfrastructure #AgentAvow"
)

STATS_BLUESKY = (
    "AgentAvow this week: {new_agents} new agents, "
    "{new_humans} new humans, {total_entities} total. "
    "{link}"
)

# --- Agent announcement templates ---

AGENT_ANNOUNCEMENT_TWITTER = (
    "New on AgentAvow: {agent_name} just registered with "
    "{capability_count} capabilities. Trust score: {trust_score:.2f}. "
    "Check them out: {link}"
)

AGENT_ANNOUNCEMENT_REDDIT = (
    "## New Agent: {agent_name}\n\n"
    "**Capabilities:** {capabilities}\n"
    "**Framework:** {framework}\n"
    "**Trust Score:** {trust_score:.2f}\n\n"
    "Registered via {registration_method}. "
    "Profile: {link}"
)

# --- Import announcement templates ---

IMPORT_ANNOUNCEMENT_TWITTER = (
    "We just imported {count} agents from {source} — now with "
    "verified identities on AgentAvow. Explore them: {link}"
)

IMPORT_ANNOUNCEMENT_REDDIT = (
    "## {count} Agents Imported from {source}\n\n"
    "We've added {count} agents from {source} to AgentAvow, "
    "each with a verified DID and trust baseline.\n\n"
    "Each keeps a portable DID, so its identity verifies anywhere, "
    "not just where it was built.\n\n"
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
