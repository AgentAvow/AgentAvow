"""Canonical Hacker News "Show HN" playbook.

Single source of truth for the HN submission contract. A Show HN gets flagged
fast if you paste promo copy as the post body, so the correct shape is:
  title (<=80 chars) + URL in the url field + EMPTY body + a substantive first
  comment posted immediately.

The admin draft-review (web/.../MarketingTab.tsx -> HNContract) renders exactly
these four fields. Keep the prose here in sync with docs/internal/hn-launch-package.md.
"""
from __future__ import annotations

HN_TITLE_MAX = 80


def build_hn_playbook(
    check_url: str = "https://agentavow.com/check",
) -> dict:
    """Return the structured HN playbook dict stored under
    ``utm_params.platform_playbook.hackernews`` on an HN draft.

    The four live fields (title / url / body / first_comment) are what you post;
    the rest is reference for working the thread.
    """
    title = (
        "Show HN: Is this MCP server safe? Paste a GitHub repo, get a security grade"
    )
    # Hard invariant: HN truncates/penalizes long titles. Never emit >80.
    if len(title) > HN_TITLE_MAX:  # pragma: no cover - guarded at authoring time
        title = title[:HN_TITLE_MAX]

    first_comment = (
        "Built this because there's no easy way to tell if an MCP server or agent "
        "tool is safe before you wire it into your stack — and a lot of them "
        "execute code, hold API keys, or run with broad permissions.\n\n"
        "Paste any GitHub repo (no login) and you get a grade plus the actual "
        "findings: hardcoded secrets, unsafe exec, missing auth, dependency risks. "
        "We've scanned ~985 MCP/agent repos so far; high-severity findings show up "
        "even in popular, well-maintained projects.\n\n"
        "Each scan also emits an Ed25519-signed trust envelope you can re-verify "
        "yourself against our published JWKS — two SDKs do it client-side "
        "(pip install agentavow-sdk / npm i agentavow-trust). Happy to go into "
        "methodology and false-positive handling."
    )

    return {
        # --- the four fields you actually post ---
        "title": title,
        "url": check_url,
        "body": "",  # leave empty — Show HN with a URL needs no body copy
        "first_comment": first_comment,
        # --- reference for working the thread ---
        "title_alternatives": [
            "Show HN: Free security scanner for MCP servers and AI agent tools",
        ],
        "pre_scanned": (
            "Warm/recognizable if asked: github/github-mcp-server 100 · "
            "microsoft/playwright-mcp 100 · cloudflare/mcp-server-cloudflare 88 · "
            "upstash/context7 18 (94 high) · modelcontextprotocol/python-sdk "
            "(1 critical). Let commenters surface the spicy ones; don't lead with them."
        ),
        "talking_points": [
            "Methodology: static + dependency analysis (secrets, unsafe exec/eval, "
            "shell=True, auth gaps, OWASP patterns, dep CVEs). Not runtime/behavioral.",
            "False positives are real — we'd rather over-surface than miss; every "
            "finding shows the file + pattern so you can judge.",
            "Score is a triage signal, not a verdict. 100 != audited-safe; F != malware.",
            "Don't have to trust our score — the envelope is Ed25519-signed and "
            "re-verifiable; SDKs verify client-side byte-for-byte.",
            "Business model: free scanning; premium/enterprise later. Not monetizing "
            "the checker.",
        ],
        "checklist": [
            "Warm the HN account FIRST (last attempt died at 1-karma/throttled).",
            "Post a weekday 9-11am ET.",
            "Post the first comment within minutes.",
            "Monitor + reply for 6+ hours — fast, substantive, non-defensive.",
            "Plug exact corpus numbers from data/corpus/ before posting.",
        ],
    }
