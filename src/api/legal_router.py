"""Server-rendered legal pages.

The interactive legal pages live in the SPA (web/src/rebrand/pages/Legal.tsx), but a
JS-only render is invisible to non-browser fetchers — crawlers, link unfurlers, and
app-store/Directory compliance reviewers get an empty shell. This router serves the
SAME text as fully-rendered, self-contained HTML so the policy/terms are always
readable without executing JavaScript.

Nginx routes a direct hit on /legal/privacy and /legal/terms here; in-app soft
navigation still renders the React page. Keep the clauses below in sync with the
PRIVACY and TERMS arrays in Legal.tsx (faithful copies of the same short text).
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/legal", tags=["legal"])

_PRIVACY_CLAUSES: list[tuple[str, str]] = [
    ('1. Overview',
     'Effective November 10, 2026. AgentAvow checks whether a software tool is '
     'safe for an AI agent to connect to: a GitHub repository, a published '
     'package, a live MCP server, an agent skill, or an A2A agent card. This policy explains what we receive when '
     'you use agentavow.com, our public API, or our connector for AI '
     'assistants, what we do with it, and how long we keep it. Checking a tool '
     'does not require an account.'),
    ('2. Using the connector in an AI assistant (MCP)',
     '<p>When an AI assistant calls one of our tools on your behalf, we '
     "receive:</p><ul><li><strong>The tool's inputs:</strong> the repository, "
     'package name and optional version, MCP server URL, or agent identifier '
     'you asked about, and whether to re-scan.</li><li><strong>Standard request '
     'data:</strong> the IP address and User-Agent of the '
     'request.</li></ul><p>Our tools accept only those inputs. We do not ask '
     'for your conversation, chat history, memories, files, name, email '
     'address, or account with the assistant, and we do not store anything '
     'beyond the inputs listed above. Your assistant decides what to put in '
     'those inputs; they are short identifiers such as a package name or URL. '
     'Some assistants attach optional hints to a request (for example a coarse '
     'location or an anonymous identifier); we do not read or store them. The '
     'connector has no sign-in.</p><p>We use the inputs only to run the check '
     'you asked for: we fetch public information about that tool from its '
     'source (GitHub, the package registry, or the MCP server itself), analyze '
     'it, and return the result. All eight tools are read-only: they never '
     'change anything in your accounts or in the tool being checked.</p>'),
    ('3. What our results contain',
     'Results describe the tool that was checked: an answer (Safe to connect, '
     'Review before you connect, or Do not connect) with its reason, a trust '
     'score, an adoption score, findings, and a signed attestation. They '
     'contain no personal data about you. Results for public tools are public: '
     'they may be cached, shown on agentavow.com, and listed in our public '
     'catalog. Do not submit anything you consider confidential.'),
    ('4. Accounts and alerts (optional)',
     'If you create an account: your email address, display name, and, if you '
     'sign in with Google, the basic profile Google shares, or, if you sign in '
     'with GitHub, your GitHub user ID, username, name, avatar and verified '
     'email address (read-only access; the GitHub sign-in token is not '
     'stored). If you watch a '
     'tool: the tools you watch and any webhook URL you configure (its signing '
     'secret is stored encrypted). If you scan a private repository with a '
     'GitHub token, the token is used for that scan only and is not stored.'),
    ('5. Logs, metrics and analytics',
     '<ul><li><strong>Server logs</strong> (IP address, User-Agent, the '
     'requested path including the tool checked, time, status) are kept to '
     'operate and secure the service. They are rotated automatically and '
     'typically kept for less than 30 days.</li><li><strong>Usage '
     'metrics</strong> are daily counts (for example, calls per tool and per '
     'assistant product). To count distinct callers we store a one-way hash of '
     'the IP address and User-Agent combined with a salt that changes every '
     'day, not the IP address itself. Metrics are kept for up to 90 '
     'days.</li><li><strong>Cloudflare Web Analytics</strong> measures page '
     'loads and does not use cookies. It receives the address of the pages you '
     'view, without the query string. It never receives the address of a check '
     'result page (any page under /check/, whose address names the tool you '
     'checked or, for a private scan, your repository): it does not run on '
     'those pages, and once you open one from another page it sends nothing '
     'more until you reload.</li><li><strong>Our own site analytics</strong> do '
     'not use cookies either, and are stored in our own database. The first '
     'time you open agentavow.com, our code stores a random identifier called '
     "<code>ag_session_id</code> in your browser's local storage. It holds no "
     "name or email address. It stays until you clear your browser's data for "
     'our site, and your next visit then creates a new one. If you create an '
     'account, we link the identifier to that '
     'account.</li><li><strong>What those analytics record:</strong> pages you '
     'view, submitting a check box (not what you typed), results shown, clicks '
     'on our add and install links, copies of an install command or a badge, '
     'and steps in creating an account. Each record holds the event, the '
     'identifier, the page path, the time, and the IP address of the request. '
     'On a check page the path names the tool you checked. The query string is '
     'left out, so an MCP server URL given there is not recorded, and a '
     'one-time private scan is recorded as /check/private with no repository '
     'name.</li><li><strong>Campaign links:</strong> if you arrive through a '
     'link with campaign tags (utm_source, utm_medium, utm_campaign, '
     'utm_content, utm_term), your browser keeps them in session storage as '
     '<code>ag_utm</code> until the tab closes and sends them with each event. '
     'It also keeps a marker, <code>ag_landed</code>, so a landing counts once '
     'per tab. We store the first tags we see for an identifier, with the page '
     'it landed on, so a later visit from the same browser counts toward the '
     'same campaign.</li><li><strong>How long:</strong> these analytics records '
     'have no automatic deletion date. You can ask us to delete them (section '
     '8).</li><li><strong>Meta Pixel, on /claude-code only:</strong> '
     '/claude-code is the page our ads on Facebook and Instagram lead to. That '
     'page, and no other page on agentavow.com, loads the Meta Pixel, a script '
     'from Meta Platforms (connect.facebook.net), so we can measure how many '
     'people our ads bring there and how many copy the install command. It '
     'never runs on a check page. When it runs, your browser sends Meta a '
     'page-view event and, the first time you copy the install command, one '
     'copy event. With them Meta receives the page address (including any '
     'campaign tags in it), the page you came from, your IP address and browser '
     'details, and any cookies your browser already holds for facebook.com. The '
     'pixel may also set its own cookie on agentavow.com, <code>_fbp</code>, '
     'which Meta uses to recognize the same browser later. We do not send Meta '
     'your name, email address or any other contact details (no Advanced '
     'Matching), we turn off its automatic collection of button clicks and page '
     'details, and we send Meta nothing from our servers. Meta uses this data '
     'under its own <a href="https://www.facebook.com/privacy/policy/">privacy '
     'policy</a>, including to measure and improve ads, and may use it to '
     'choose ads it shows you. <strong>To opt out:</strong> turn on Global '
     'Privacy Control or Do Not Track in your browser and the pixel is not '
     'loaded at all; or block connect.facebook.net with your browser or a '
     'content blocker; or turn off activity from ad partners in your Meta <a '
     'href="https://www.facebook.com/adpreferences/">ad preferences</a>. '
     'Clearing your cookies for agentavow.com removes '
     '<code>_fbp</code>.</li><li><strong>Error reports</strong> are sent to our '
     'error-tracking provider (Sentry) to fix bugs.</li></ul>'),
    ('6. How we use data',
     'To run the checks and features you request, send the alerts you subscribe '
     'to, secure the service against abuse, and understand aggregate usage, '
     'including which pages and campaigns bring people to the site. We do not '
     'sell personal data or use it to train AI models. We do not use it for '
     'advertising, except that the Meta Pixel on /claude-code (section 5) tells '
     'Meta about visits to that page so we can measure our ads.'),
    ('7. Sharing',
     'We share data only with service providers that run parts of the service '
     'for us (Amazon Web Services for hosting, Resend for email '
     'delivery, Sentry for error tracking, Cloudflare for website analytics, '
     'Meta Platforms for measuring our ads on /claude-code only (section 5), '
     'and Google or GitHub only if you choose to sign in with them), and when the law requires '
     "it. When we check a tool, we contact that tool's public source (GitHub, a "
     'package registry, or the MCP server you named).'),
    ('8. Retention and your rights',
     'Account data is kept while your account is active and deleted on request. '
     'Logs, metrics and analytics records are kept as described in section 5. '
     'You may ask for access to, correction of, or deletion of your personal '
     'data at <a href="mailto:privacy@agentavow.com">privacy@agentavow.com</a>.'),
    ('9. Children',
     'AgentAvow is a developer tool and is not directed at children under 16. '
     'We do not knowingly collect their personal data.'),
    ('10. Changes',
     'We will post changes here with a new effective date.'),
    ('11. Contact',
     'Privacy questions: <a '
     'href="mailto:privacy@agentavow.com">privacy@agentavow.com</a>.'),
]

_TERMS_CLAUSES: list[tuple[str, str]] = [
    ("1. Acceptance of Terms",
     'Effective October 9, 2026. By accessing or using AgentAvow (the "Service"), you '
     "agree to be bound by these Terms of Service. If you do not agree, do not use the Service."),
    ("2. The Service",
     "AgentAvow scans tools, MCP servers, and packages and produces a signed, verifiable "
     "safety score. Checking is free and requires no account. An account is needed only "
     "for watch/alerts, API keys, and claiming repositories you own."),
    ("3. Eligibility",
     "You must be at least 13 years of age (16 in the European Economic Area) to create "
     "an account. By registering, you represent that you meet this requirement."),
    ("4. Accounts",
     "<ul><li>Provide accurate information when creating an account.</li><li>You are "
     "responsible for keeping your credentials and API keys secure.</li><li>Do not create "
     "accounts for spamming, impersonation, or abuse.</li><li>We may suspend or terminate "
     "accounts that violate these Terms.</li></ul>"),
    ("5. Scan Results — provided \"as is\"",
     "Scan scores and attestations are computed algorithmically and provided for "
     "informational purposes only. They inform a decision — they are not a warranty. "
     "AgentAvow does not guarantee their accuracy or completeness and is not liable for "
     "decisions made in reliance on them. Scores reflect a scan at a point in time; a tool "
     "can change after it is scanned. Verify anything you depend on, and consider watching "
     "it for changes."),
    ("6. Acceptable Use",
     "<ul><li>Do not attempt to manipulate or game scores.</li><li>Do not scrape the "
     "Service or evade rate limits.</li><li>Do not use the Service to distribute malware, "
     "phishing, or spam.</li><li>Do not attempt to circumvent security or moderation "
     "systems.</li></ul>"),
    ("7. Disclaimer of Warranties",
     'The Service is provided "as is" and "as available" without warranties of any kind, '
     "express or implied, including merchantability, fitness for a particular purpose, and "
     "non-infringement. AgentAvow does not warrant that the Service will be uninterrupted, "
     "error-free, or secure."),
    ("8. Limitation of Liability",
     "To the maximum extent permitted by law, AgentAvow shall not be liable for any "
     "indirect, incidental, special, consequential, or punitive damages, or loss of "
     "profits, data, or goodwill, arising from your use of or inability to use the Service. "
     "AgentAvow's aggregate liability shall not exceed one hundred U.S. dollars (US $100) or "
     "the amount you paid AgentAvow in the prior twelve months, whichever is greater."),
    ("9. Dispute Resolution",
     "Before any formal proceeding, contact us at "
     '<a href="mailto:legal@agentavow.com">legal@agentavow.com</a> and attempt to resolve '
     "the dispute informally for at least 30 days."),
    ("10. Changes",
     "We may update these Terms. Material changes will be posted here with an updated date. "
     "Continued use after changes constitutes acceptance."),
    ("11. Contact",
     'Questions about these Terms: <a href="mailto:legal@agentavow.com">legal@agentavow.com</a>.'),
]


def _render(title: str, description: str, slug: str, clauses: list[tuple[str, str]]) -> str:
    sections = "\n".join(
        f'<section><h2>{h}</h2><div class="body">{body}</div></section>'
        for h, body in clauses
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · AgentAvow</title>
<meta name="description" content="{description}">
<link rel="canonical" href="https://agentavow.com/legal/{slug}">
<style>
  :root {{ color-scheme: light dark; --bg:#0b0f17; --fg:#e6edf3; --muted:#9aa7b6; --accent:#5eead4; --line:#1e2733; }}
  @media (prefers-color-scheme: light) {{ :root {{ --bg:#ffffff; --fg:#0b0f17; --muted:#5b6673; --accent:#0d9488; --line:#e5e9ef; }} }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:760px; margin:0 auto; padding:56px 24px 80px; }}
  a {{ color:var(--accent); }}
  h1 {{ font-size:32px; font-weight:800; letter-spacing:-0.02em; margin:0 0 6px; }}
  .sub {{ color:var(--muted); font-size:14px; margin:0 0 32px; }}
  section {{ padding:18px 0; border-top:1px solid var(--line); }}
  section:first-of-type {{ border-top:none; }}
  h2 {{ font-size:17px; font-weight:600; margin:0 0 6px; }}
  .body {{ color:var(--muted); }}
  ul {{ margin:6px 0 0; padding-left:20px; }}
  li {{ margin:2px 0; }}
  .home {{ display:inline-block; margin-top:36px; color:var(--muted); font-size:14px; }}
</style>
</head>
<body>
  <main class="wrap">
    <h1>{title}</h1>
    <p class="sub">AgentAvow · agentavow.com</p>
    {sections}
    <a class="home" href="https://agentavow.com/">← Back to AgentAvow</a>
  </main>
</body>
</html>"""


@router.get("/privacy", include_in_schema=False)
async def privacy_policy() -> HTMLResponse:
    """Fully-rendered privacy policy — readable without JavaScript."""
    return HTMLResponse(_render(
        "Privacy Policy",
        "AgentAvow Privacy Policy — what we collect and how we use it. Checking a tool "
        "needs no account.",
        "privacy", _PRIVACY_CLAUSES,
    ))


@router.get("/terms", include_in_schema=False)
async def terms_of_service() -> HTMLResponse:
    """Fully-rendered terms of service — readable without JavaScript."""
    return HTMLResponse(_render(
        "Terms of Service",
        "AgentAvow Terms of Service — using the signed safety-scanning service.",
        "terms", _TERMS_CLAUSES,
    ))
