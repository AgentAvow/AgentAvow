"""Scanner health checks + admin alerting for the security re-scan job.

The daily security re-scan (Job 19 in ``src/jobs/scheduler.py``) depends on a
working GitHub token. When the token silently expires — a 401 on every repo —
the re-scan fails *quietly*: the loop's ``except Exception`` just logs and moves
on, catalog grades go stale, and nobody is told. This module closes that gap:

* :func:`check_github_token_health` — a cheap probe against
  ``GET /rate_limit`` (this endpoint does NOT consume rate-limit budget). A 401
  means a dead/expired token; a low ``remaining`` means we're near the hourly
  budget.
* :func:`alert_scan_health` — a throttled admin e-mail that reuses the
  ``src.email.send_email`` path plus a Redis TTL key so a persistent failure
  nudges once every few hours instead of spamming every scheduler tick. This is
  the same throttle pattern as ``reddit_reminder._send_dry_feed_alert``.
* :func:`check_and_alert_token` / :func:`alert_rescan_exception` — convenience
  wrappers the scheduler calls directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# GitHub's REST rate_limit endpoint is free — it does NOT consume core budget —
# so it is safe to call on every scheduler tick and between scans.
_RATE_LIMIT_URL = "https://api.github.com/rate_limit"
_TIMEOUT = 10

# Warn below this many core-API requests remaining. A single re-scan can burn up
# to ~200 requests (~1 API call per file, capped at scan._MAX_FILES_PER_REPO=200
# plus repo + tree calls), so dropping under a few hundred means the next scan
# may not finish before the hourly reset.
LOW_REMAINING_THRESHOLD = 500

# Throttle: at most one alert of each ``kind`` per this window (6h).
_ALERT_THROTTLE_SECONDS = 6 * 60 * 60


@dataclass
class TokenHealth:
    """Result of a GitHub token probe."""

    ok: bool                 # token usable AND comfortably within budget
    status: int              # HTTP status from /rate_limit (0 on transport error)
    remaining: int | None    # core requests remaining this hour, if known
    dead: bool               # True when the token is invalid/expired (401)
    reason: str              # human-readable summary


async def check_github_token_health() -> TokenHealth:
    """Probe the app's ``settings.github_token`` against ``GET /rate_limit``.

    * 401 → the token is dead/invalid/expired (``dead=True``).
    * 200 with a low ``remaining`` → near the hourly budget (``ok=False``).
    * 200 with healthy ``remaining`` → all good (``ok=True``).

    Never raises: a transport/DNS/timeout error comes back as
    ``ok=False, dead=False`` so the caller can log the blip without misfiring a
    "rotate your token" alert.
    """
    from src.config import settings

    token = settings.github_token
    if not token:
        return TokenHealth(
            ok=False, status=0, remaining=None, dead=True,
            reason="No GITHUB_TOKEN configured",
        )

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"token {token}",
    }
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_RATE_LIMIT_URL, headers=headers)
    except Exception as exc:  # transport/DNS/timeout — not a verdict on the token
        logger.warning("GitHub token health probe failed to connect: %s", exc)
        return TokenHealth(
            ok=False, status=0, remaining=None, dead=False,
            reason=f"rate_limit probe connection error: {exc}",
        )

    if resp.status_code == 401:
        return TokenHealth(
            ok=False, status=401, remaining=None, dead=True,
            reason="GitHub returned 401 Unauthorized — token expired or revoked",
        )
    if resp.status_code != 200:
        # 403 can be a hard block or a secondary rate limit; treat as unhealthy
        # but only "dead" when GitHub explicitly rejects the credentials (401).
        return TokenHealth(
            ok=False, status=resp.status_code, remaining=None, dead=False,
            reason=f"GitHub /rate_limit returned {resp.status_code}",
        )

    try:
        core = resp.json().get("resources", {}).get("core", {})
        remaining = int(core.get("remaining", 0))
    except Exception:
        remaining = None

    if remaining is not None and remaining < LOW_REMAINING_THRESHOLD:
        return TokenHealth(
            ok=False, status=200, remaining=remaining, dead=False,
            reason=f"GitHub rate limit low — only {remaining} core requests remaining",
        )

    return TokenHealth(
        ok=True, status=200, remaining=remaining, dead=False,
        reason=f"token healthy ({remaining} core requests remaining)",
    )


async def alert_scan_health(kind: str, subject: str, detail_html: str) -> None:
    """E-mail the admin about a scanner-health problem, throttled per ``kind``.

    Reuses ``src.email.send_email`` and a Redis TTL key (once every 6h) so a
    persistent failure nudges without spamming every scheduler tick — the same
    throttle pattern as ``reddit_reminder._send_dry_feed_alert``. Distinct
    ``kind`` values throttle independently (a dead token and a job exception can
    each alert once/6h).
    """
    throttle_key = f"ag:scanhealth:alert:{kind}"
    try:
        from src.redis_client import get_redis

        r = get_redis()
        if await r.get(throttle_key):
            return
        await r.set(throttle_key, "1", ex=_ALERT_THROTTLE_SECONDS)
    except Exception:
        # Redis down — better to send (and possibly repeat) than swallow the alert.
        logger.debug(
            "Redis unavailable for scan-health alert throttle", exc_info=True,
        )

    try:
        from src.config import settings
        from src.email import send_email

        await send_email(settings.admin_email, subject, detail_html)
        logger.info(
            "Sent scanner-health alert (%s) to %s", kind, settings.admin_email,
        )
    except Exception:
        logger.warning(
            "Failed to send scanner-health alert (%s)", kind, exc_info=True,
        )


async def check_and_alert_token() -> TokenHealth:
    """Probe the GitHub token and fire a throttled admin alert if it's dead/low.

    Returns the :class:`TokenHealth` so the caller can decide whether to skip
    the re-scan — a dead token means every repo fetch will 401, so there is no
    point running the loop.
    """
    health = await check_github_token_health()
    if health.dead:
        await alert_scan_health(
            "github_token_dead",
            "AgentAvow: GitHub scanner token is DEAD (re-scans failing)",
            (
                "<p>The security re-scan job could not authenticate to GitHub.</p>"
                f"<p><b>What happened:</b> {health.reason}.</p>"
                "<p>Every repo scan will 401 until this is fixed, so catalog "
                "grades will go stale.</p>"
                "<p><b>Fix:</b> rotate <code>GITHUB_TOKEN</code> in "
                "<code>.env.secrets</code> and restart the backend.</p>"
            ),
        )
    elif not health.ok and health.remaining is not None:
        await alert_scan_health(
            "github_token_low",
            "AgentAvow: GitHub scanner token near its rate limit",
            (
                f"<p>The GitHub token has only <b>{health.remaining}</b> core API "
                "requests remaining this hour.</p>"
                "<p>Re-scans may not complete before the hourly reset. If this "
                "recurs, widen the token budget (GitHub App) or lower "
                "<code>SECURITY_RESCAN_LIMIT</code> / "
                "<code>PUBLIC_CACHE_REFRESH_LIMIT</code>.</p>"
            ),
        )
    return health


async def alert_rescan_exception(exc: BaseException) -> None:
    """Fire a throttled admin alert when the re-scan job raised an exception."""
    await alert_scan_health(
        "rescan_exception",
        "AgentAvow: security re-scan job FAILED (exception)",
        (
            "<p>The daily security re-scan raised an exception and did not "
            "complete this cycle.</p>"
            f"<p><b>Error:</b> <code>{type(exc).__name__}: {exc}</code></p>"
            "<p>If this is a 401 storm, rotate <code>GITHUB_TOKEN</code> in "
            "<code>.env.secrets</code>. Otherwise check the backend logs for the "
            "full traceback.</p>"
        ),
    )
