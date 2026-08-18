from __future__ import annotations

import html as html_mod
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from src.config import settings

logger = logging.getLogger(__name__)

# Load templates once at import time
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _grade_and_color(score: int | None) -> tuple[str, str]:
    """Letter grade + hex color for a 0-100 score (mirrors the app's grade bands)."""
    s = score if score is not None else 0
    if s >= 97:
        return "A+", "#22c55e"
    if s >= 90:
        return "A", "#22c55e"
    if s >= 80:
        return "B", "#3b82f6"
    if s >= 70:
        return "C", "#eab308"
    if s >= 50:
        return "D", "#f97316"
    return "F", "#ef4444"


def render_watch_notification(
    kind: str, owner: str, repo: str,
    old_score: int | None, new_score: int | None,
) -> tuple[str, str]:
    """Build (subject, html) for a watch email. ``kind`` is drop | improve | drift."""
    full = f"{owner}/{repo}"
    base = settings.base_url.rstrip("/")
    grade, badge_color = _grade_and_color(new_score)
    delta = (new_score - old_score) if (new_score is not None and old_score is not None) else 0

    # Email-native trust mark: a horizontal 10-segment power bar (SVG is stripped by
    # Gmail, so the mark is drawn with table cells — renders everywhere). Filled count
    # = round(score/10), filled cells in the tier colour, the rest neutral slate.
    lv = round((new_score or 0) / 10)
    _seg = []
    for i in range(10):
        fill = badge_color if i < lv else "#243458"
        _seg.append(
            f'<td style="width:14px;height:9px;background-color:{fill};'
            f'border-radius:1px;font-size:0;line-height:0;">&nbsp;</td>'
        )
        if i < 9:
            _seg.append('<td style="width:3px;font-size:0;line-height:0;">&nbsp;</td>')
    trust_bar = (
        '<table cellpadding="0" cellspacing="0" role="presentation"><tr>'
        + "".join(_seg) + "</tr></table>"
    )

    if kind == "improve":
        accent, tag = "#22c55e", "Good news"
        headline = f"{repo} improved 🎉"
        score_line = f"{old_score} → {new_score} · up {abs(delta)} pts"
        message = (
            f"A tool you're watching got safer. <b style=\"color:#f1f5f9;\">{full}</b> "
            f"rose from {old_score} to {new_score}/100 on its latest re-scan — worth a look "
            f"at what changed."
        )
        cta_label, subject = "See what improved", f"AgentAvow · {repo} improved 🎉"
    elif kind == "drift":
        accent, tag = "#f59e0b", "Definition changed"
        headline = f"{repo}'s signed definition changed"
        score_line = "tool definition changed"
        message = (
            f"The signed tool definition for <b style=\"color:#f1f5f9;\">{full}</b> changed "
            f"since your last check — the kind of silent update a rug-pull hides behind. "
            f"Review what moved before your agents keep using it."
        )
        cta_label, subject = "Review the change", f"AgentAvow alert · {repo} definition changed"
    else:  # drop
        accent, tag = "#ef4444", "Score dropped"
        headline = f"{repo} got riskier"
        score_line = f"{old_score} → {new_score} · down {abs(delta)} pts"
        message = (
            f"A tool you're watching dropped in score. <b style=\"color:#f1f5f9;\">{full}</b> "
            f"fell from {old_score} to {new_score}/100 — review it before your agents keep "
            f"connecting to it."
        )
        cta_label, subject = "See the report", f"AgentAvow alert · {repo} score dropped"

    html = _load_template(
        "watch_notification.html",
        _raw={
            "accent": accent, "badge_color": badge_color, "grade": grade,
            "trust_bar": trust_bar,
            "tag": tag, "headline": headline, "repo": full,
            "new_score": str(new_score if new_score is not None else "—"),
            "score_line": score_line, "message": message,
            "cta_label": cta_label,
            "cta_url": f"{base}/check/{owner}/{repo}",
            "watches_url": f"{base}/account",
        },
    )
    return subject, html


def _load_template(
    name: str,
    *,
    _raw: dict[str, str] | None = None,
    **kwargs: str,
) -> str:
    """Load an HTML template and substitute placeholders.

    Regular kwargs are HTML-escaped for safety.
    Keys passed via ``_raw`` are inserted verbatim (pre-rendered HTML).
    """
    path = _TEMPLATE_DIR / name
    if not path.exists():
        logger.warning("Email template %s not found, using plain text fallback", name)
        return kwargs.get("fallback", "")
    content = path.read_text()
    # Insert raw HTML first (no escaping)
    for key, value in (_raw or {}).items():
        content = content.replace(f"{{{{{key}}}}}", str(value))
    # Then escaped values
    for key, value in kwargs.items():
        content = content.replace(f"{{{{{key}}}}}", html_mod.escape(str(value)))
    return content


async def _send_via_resend(to: str, subject: str, html_body: str) -> bool:
    """Send email via Resend API."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": settings.from_email,
                    "to": [to],
                    "subject": subject,
                    "html": html_body,
                },
            )
            if resp.status_code in (200, 201):
                logger.info("Email sent via Resend to %s: %s", to, subject)
                return True
            logger.error("Resend API error %s: %s", resp.status_code, resp.text)
            return False
    except Exception:
        logger.exception("Failed to send email via Resend to %s", to)
        return False


async def _send_via_smtp(to: str, subject: str, html_body: str) -> bool:
    """Send email via SMTP."""
    import aiosmtplib

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = settings.from_email
        msg["To"] = to
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )
        logger.info("Email sent via SMTP to %s: %s", to, subject)
        return True
    except Exception:
        logger.exception("Failed to send email via SMTP to %s", to)
        return False


async def send_email(to: str, subject: str, html_body: str) -> bool:
    """Send an email with rate limiting, retry, and overflow queuing.

    Delegates to :func:`src.email_queue.send_email_rated` which enforces a
    per-minute rate limit (configurable via ``EMAIL_RATE_LIMIT_PER_MINUTE``),
    retries on transient failures, and queues overflow when the limit is hit.

    Returns True on success (or queued), False on failure after retries.
    """
    from src.email_queue import send_email_rated

    return await send_email_rated(to, subject, html_body)


async def send_verification_email(to: str, token: str) -> bool:
    """Send email verification link."""
    verify_url = f"{settings.base_url}/verify-email?token={token}"
    html = _load_template(
        "verify_email.html",
        verify_url=verify_url,
        fallback=f"Verify your email: {verify_url}",
    )
    return await send_email(to, "Verify your AgentAvow email", html)


async def send_password_reset_email(to: str, token: str) -> bool:
    """Send password reset link."""
    reset_url = f"{settings.base_url}/reset-password?token={token}"
    html = _load_template(
        "reset_password.html",
        reset_url=reset_url,
        fallback=f"Reset your password: {reset_url}",
    )
    return await send_email(to, "Reset your AgentAvow password", html)


async def send_welcome_email(to: str, display_name: str) -> bool:
    """Send welcome email after verification."""
    html = _load_template(
        "welcome.html",
        display_name=display_name,
        app_url=settings.base_url,
        fallback=f"Welcome to AgentAvow, {display_name}!",
    )
    return await send_email(to, "Welcome to AgentAvow!", html)


async def send_moderation_flag_email(
    to: str,
    entity_name: str,
    content_preview: str,
    reason: str,
    appeal_url: str,
) -> bool:
    """Notify an entity that their content was flagged for moderation."""
    html = _load_template(
        "moderation_flag_notify.html",
        entity_name=entity_name,
        content_preview=content_preview,
        reason=reason,
        appeal_url=appeal_url,
        fallback=(
            f"Hi {entity_name}, your content was flagged for: {reason}. "
            f"Appeal at: {appeal_url}"
        ),
    )
    return await send_email(
        to, "AgentAvow: Your content has been flagged", html,
    )


async def send_moderation_resolved_email(
    to: str,
    entity_name: str,
    content_preview: str,
    decision: str,
    reason: str,
) -> bool:
    """Notify an entity of a moderation decision on their content."""
    html = _load_template(
        "moderation_resolved.html",
        entity_name=entity_name,
        content_preview=content_preview,
        decision=decision,
        reason=reason,
        fallback=(
            f"Hi {entity_name}, moderation decision: {decision}. "
            f"Reason: {reason}"
        ),
    )
    return await send_email(
        to, "AgentAvow: Moderation decision on your content", html,
    )


async def send_moderation_appeal_received_email(
    to: str,
    entity_name: str,
    content_preview: str,
) -> bool:
    """Confirm that a moderation appeal was received."""
    html = _load_template(
        "moderation_appeal_received.html",
        entity_name=entity_name,
        content_preview=content_preview,
        fallback=(
            f"Hi {entity_name}, your appeal has been received and is "
            f"under review."
        ),
    )
    return await send_email(
        to, "AgentAvow: Appeal received", html,
    )


async def send_social_notification_email(
    to: str,
    entity_name: str,
    title: str,
    body: str,
    action_url: str,
    action_label: str = "View on AgentAvow",
) -> bool:
    """Send email notification for social events (reply, follow, mention, vote)."""
    html = _load_template(
        "social_notification.html",
        entity_name=entity_name,
        title=title,
        body=body,
        action_url=action_url,
        action_label=action_label,
        fallback=f"{title}: {body}",
    )
    return await send_email(to, title, html)


async def send_moderation_appeal_decision_email(
    to: str,
    entity_name: str,
    decision: str,
    reason: str,
) -> bool:
    """Notify an entity of the outcome of their moderation appeal."""
    html = _load_template(
        "moderation_appeal_decision.html",
        entity_name=entity_name,
        decision=decision,
        reason=reason,
        fallback=(
            f"Hi {entity_name}, your appeal decision: {decision}. "
            f"Details: {reason}"
        ),
    )
    return await send_email(
        to, "AgentAvow: Appeal decision", html,
    )
