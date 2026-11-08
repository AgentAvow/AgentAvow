"""The published review rules Connector Preflight checks against, with their sources.

Every automated gate in ``gates.py`` / ``plugin_check.py`` cites one or more entries of
``SOURCES``. ``RULES_CHECKED`` is the date someone last re-read every source and brought
the gates in line; the Preflight page shows it, and says so when it is old, so the
check never goes stale silently. Re-read the sources and bump the date together.

``basis`` on a gate says where a rule comes from:

* ``documented`` — written in the store's own docs (cited).
* ``observed``   — what the Claude plugin directory does but does not document yet
  (cited to the public report of it). Shown as observed, never as a documented rule.
* ``agentavow``  — AgentAvow's own safety signal. Not a store rule; it never decides
  "Directory-Ready".
"""
from __future__ import annotations

RULES_CHECKED = "2026-11-07"
# The page flags the rules as possibly out of date past this many days.
STALE_AFTER_DAYS = 60

SOURCES: dict[str, dict[str, str]] = {
    "claude_connector_checklist": {
        "title": "Claude: connector pre-submission checklist",
        "url": "https://claude.com/docs/connectors/building/review-criteria",
    },
    "claude_connector_submit": {
        "title": "Claude: submit a connector",
        "url": "https://claude.com/docs/connectors/building/submission",
    },
    "claude_connector_auth": {
        "title": "Claude: authentication for connectors",
        "url": "https://claude.com/docs/connectors/building/authentication",
    },
    "claude_connector_limits": {
        "title": "Claude: build an MCP server (size and timeout limits)",
        "url": "https://claude.com/docs/connectors/building/index",
    },
    "claude_verification": {
        "title": "Claude: connector verification",
        "url": "https://claude.com/docs/connectors/verification",
    },
    "claude_plugin_checklist": {
        "title": "Claude: plugin pre-submission checklist",
        "url": "https://claude.com/docs/plugins/pre-submission-checklist",
    },
    "claude_publish": {
        "title": "Claude: publish to the directory",
        "url": "https://claude.com/docs/directory/publish",
    },
    "claude_directory_policy": {
        "title": "Anthropic Software Directory Policy",
        "url": "https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy",
    },
    "claude_verified_only_report": {
        "title": "Observed, not yet documented: Verified-only refusals "
                 "(anthropics/claude-plugins-official#7024)",
        "url": "https://github.com/anthropics/claude-plugins-official/issues/7024",
    },
    "openai_guidelines": {
        "title": "OpenAI: plugin guidelines",
        "url": "https://developers.openai.com/plugins/plugin-guidelines",
    },
    "openai_app_review": {
        "title": "OpenAI: remote MCP server review requirements",
        "url": "https://developers.openai.com/plugins/deploy/app-review",
    },
    "openai_submission_errors": {
        "title": "OpenAI: plugin submission errors",
        "url": "https://developers.openai.com/plugins/deploy/submission-errors",
    },
    "openai_ui_csp": {
        "title": "OpenAI: build a ChatGPT UI (content security policy)",
        "url": "https://developers.openai.com/plugins/build/chatgpt-ui#content-security-policy-csp",
    },
}


def cite(*ids: str) -> list[dict[str, str]]:
    """The ``{title, url}`` entries for ``ids`` (unknown ids are a programming error)."""
    return [SOURCES[i] for i in ids]


def _item(item_id: str, label: str, store: str, kind: str, *source_ids: str) -> dict:
    return {"id": item_id, "label": label, "store": store, "applies_to": kind,
            "sources": cite(*source_ids)}


# Rules a URL, repo or manifest can't show. The page lists them under the automated
# gates so a submitter still walks every published requirement.
MANUAL_CHECKLIST: list[dict] = [
    # Claude: MCP connector
    _item("claude_test_account", "Test credentials for a fully populated account, entered in "
          "the portal", "anthropic", "connector", "claude_connector_checklist"),
    _item("claude_listing_materials", "Documentation URL, privacy policy URL, support contact "
          "and icon ready for the listing", "anthropic", "connector", "claude_connector_submit"),
    _item("claude_tested_in_claude", "Every tool exercised in MCP Inspector and as a custom "
          "connector in Claude", "anthropic", "connector", "claude_connector_checklist"),
    _item("claude_functional_quality", "Every tool succeeds with valid input and returns "
          "actionable errors, not a bare \"Internal Server Error\"", "anthropic", "connector",
          "claude_connector_checklist"),
    _item("claude_result_limits", "Tool results stay under about 150,000 characters and calls "
          "finish within 240 seconds", "anthropic", "connector", "claude_connector_limits"),
    _item("claude_data_scope", "No conversation data beyond what a tool needs, and no reading "
          "of Claude's memory, chat history or user files", "anthropic", "connector",
          "claude_connector_checklist"),
    _item("claude_api_ownership", "The server calls your own APIs (or ones you legitimately "
          "proxy), and its domain matches your service", "anthropic", "connector",
          "claude_connector_checklist"),
    _item("claude_unsupported_uses", "No money or crypto transfers and no AI image, video or "
          "audio generation", "anthropic", "connector", "claude_connector_checklist"),
    _item("claude_public_docs", "Public documentation (a blog post or help article is enough) "
          "by your publish date", "anthropic", "connector", "claude_connector_checklist"),
    # Claude: plugin bundle
    _item("claude_plugin_validate", "Run Validate in the developer portal and clear every "
          "finding marked Blocking", "anthropic", "plugin", "claude_plugin_checklist"),
    _item("claude_plugin_readme_discloses", "The README describes everything the plugin runs, "
          "sends or fetches (the security scan reads it)", "anthropic", "plugin",
          "claude_plugin_checklist"),
    _item("claude_plugin_name_unique", "The plugin name is yours and not taken, look-alike or a "
          "brand you don't own", "anthropic", "plugin", "claude_plugin_checklist"),
    _item("claude_plugin_also_connector", "If you run the remote MCP server the plugin points "
          "at, submit the server as an MCP connector too", "anthropic", "plugin",
          "claude_publish"),
    # OpenAI: ChatGPT apps / plugins with MCP
    _item("openai_identity", "Individual or business identity verified for the name you "
          "publish under", "openai", "connector", "openai_app_review"),
    _item("openai_domain_challenge", "Domain verification token served at "
          "/.well-known/openai-apps-challenge", "openai", "connector",
          "openai_submission_errors"),
    _item("openai_test_cases", "Exactly five positive and three negative test cases, a demo "
          "recording, and release notes", "openai", "connector", "openai_submission_errors"),
    _item("openai_listing_urls", "Website, support, privacy policy and terms URLs over HTTPS",
          "openai", "connector", "openai_submission_errors"),
    _item("openai_privacy_policy", "A published privacy policy covering the user data your tools "
          "return, and no restricted data (card data, PHI, government IDs, credentials)",
          "openai", "connector", "openai_guidelines", "openai_app_review"),
    _item("openai_response_minimization", "Tool results carry no session, trace or request IDs, "
          "logs or other internal identifiers", "openai", "connector", "openai_guidelines"),
    _item("openai_commerce", "No ads, no digital-goods sales or upsells, and no prohibited goods",
          "openai", "connector", "openai_guidelines"),
    _item("openai_demo_account", "If the server uses OAuth: a demo login with sample data and no "
          "MFA", "openai", "connector", "openai_app_review"),
]


def rules_payload() -> dict:
    """What ``GET /public/preflight/rules`` returns."""
    return {
        "rules_checked": RULES_CHECKED,
        "stale_after_days": STALE_AFTER_DAYS,
        "sources": list(SOURCES.values()),
        "manual_checklist": MANUAL_CHECKLIST,
    }
