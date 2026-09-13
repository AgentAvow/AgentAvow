"""Server-rendered legal pages.

The interactive legal pages live in the SPA (web/src/rebrand/pages/Legal.tsx),
but a JS-only render is invisible to non-browser fetchers — crawlers, link
unfurlers, and app-store/Directory compliance reviewers get an empty shell.
This router serves the SAME privacy-policy text as fully-rendered, self-contained
HTML so the policy is always readable without executing JavaScript.

Nginx routes a direct hit on /legal/privacy here; in-app soft navigation still
renders the React page. Keep the clauses below in sync with the PRIVACY array in
Legal.tsx (both are faithful copies of the same short, rarely-changing policy).
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/legal", tags=["legal"])

# (heading, body-html) — a faithful copy of PRIVACY in web/src/rebrand/pages/Legal.tsx.
_PRIVACY_CLAUSES: list[tuple[str, str]] = [
    ("1. Overview",
     "This Policy describes what AgentAvow collects and how we use it. Checking a "
     "tool is anonymous — no account or tracking is required to get a result."),
    ("2. What We Collect",
     "<ul><li><strong>Account data</strong> (if you register): email, display name.</li>"
     "<li><strong>Watch/alert data:</strong> the tools you watch and any webhook URL "
     "you configure.</li><li><strong>Usage data:</strong> aggregate, privacy-preserving "
     "analytics about how the Service is used.</li></ul>"),
    ("3. How We Use It",
     "<ul><li>To provide scans, alerts, and the features you request.</li>"
     "<li>To send the change-alerts you subscribe to.</li>"
     "<li>To secure and improve the Service.</li></ul>"),
    ("4. Public Information",
     "Scan results about public tools and repositories are public. Do not submit "
     "anything you consider confidential when scanning."),
    ("5. Sharing",
     "We do not sell your data. We share it only with service providers who help us "
     "run the Service, or when required by law."),
    ("6. Retention & Your Rights",
     "We keep account data while your account is active. You may request access to or "
     'deletion of your personal data at <a href="mailto:privacy@agentavow.com">'
     "privacy@agentavow.com</a>."),
    ("7. Contact",
     'Privacy questions: <a href="mailto:privacy@agentavow.com">privacy@agentavow.com</a>.'),
]


def _render_privacy() -> str:
    sections = "\n".join(
        f'<section><h2>{h}</h2><div class="body">{body}</div></section>'
        for h, body in _PRIVACY_CLAUSES
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Privacy Policy · AgentAvow</title>
<meta name="description" content="AgentAvow Privacy Policy — what we collect and how we use it. Checking a tool is anonymous.">
<link rel="canonical" href="https://agentavow.com/legal/privacy">
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
    <h1>Privacy Policy</h1>
    <p class="sub">AgentAvow · agentavow.com</p>
    {sections}
    <a class="home" href="https://agentavow.com/">← Back to AgentAvow</a>
  </main>
</body>
</html>"""


@router.get("/privacy", include_in_schema=False)
async def privacy_policy() -> HTMLResponse:
    """Fully-rendered privacy policy — readable without JavaScript."""
    return HTMLResponse(_render_privacy())
