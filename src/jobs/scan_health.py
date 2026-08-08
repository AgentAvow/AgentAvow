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

# Redis flag the PUBLIC scan path reads cheaply to decide whether to degrade
# (serve stale cache + defer fresh GitHub-hitting scans). Set by the real-time
# response inspector below and by the periodic budget probe; auto-expires so the
# scan path recovers on its own once the hourly budget resets.
GITHUB_BUDGET_LOW_FLAG = "ag:scanhealth:github_budget_low"

# Default in-request back-off when GitHub gives us no Retry-After/reset to honor.
_DEFAULT_BACKOFF_SECONDS = 2.0


def _int_or_none(value: object) -> int | None:
    """Parse a header value to int, tolerating None / junk."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


@dataclass
class TokenHealth:
    """Result of a GitHub token probe."""

    ok: bool                 # token usable AND comfortably within budget
    status: int              # HTTP status from /rate_limit (0 on transport error)
    remaining: int | None    # core requests remaining this hour, if known
    dead: bool               # True when the token is invalid/expired (401)
    reason: str              # human-readable summary
    mechanism: str = "unknown"  # "github_app" | "pat" — which credential is active


async def check_github_token_health() -> TokenHealth:
    """Probe the *active* GitHub credential against ``GET /rate_limit``.

    Validates whichever mechanism ``get_github_token()`` resolves to — the
    GitHub App installation token when App creds are configured, else the legacy
    PAT — so the health check follows the same switchover as the scanner itself.

    * 401 → the credential is dead/invalid/expired (``dead=True``).
    * 200 with a low ``remaining`` → near the hourly budget (``ok=False``).
    * 200 with healthy ``remaining`` → all good (``ok=True``).

    Never raises: a transport/DNS/timeout error comes back as
    ``ok=False, dead=False`` so the caller can log the blip without misfiring a
    "rotate your token" alert.
    """
    from src.github_auth import _app_configured, get_github_token

    mechanism = "github_app" if _app_configured() else "pat"
    token = await get_github_token()
    if not token:
        return TokenHealth(
            ok=False, status=0, remaining=None, dead=True,
            reason="No GitHub credentials configured (neither App nor PAT)",
            mechanism=mechanism,
        )

    # Bearer works for both installation tokens and classic/fine-grained PATs.
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
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
            mechanism=mechanism,
        )

    if resp.status_code == 401:
        return TokenHealth(
            ok=False, status=401, remaining=None, dead=True,
            reason=f"GitHub returned 401 Unauthorized — {mechanism} credential expired or revoked",
            mechanism=mechanism,
        )
    if resp.status_code != 200:
        # 403 can be a hard block or a secondary rate limit; treat as unhealthy
        # but only "dead" when GitHub explicitly rejects the credentials (401).
        return TokenHealth(
            ok=False, status=resp.status_code, remaining=None, dead=False,
            reason=f"GitHub /rate_limit returned {resp.status_code}",
            mechanism=mechanism,
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
            mechanism=mechanism,
        )

    return TokenHealth(
        ok=True, status=200, remaining=remaining, dead=False,
        reason=f"{mechanism} credential healthy ({remaining} core requests remaining)",
        mechanism=mechanism,
    )


async def alert_scan_health(
    kind: str, subject: str, detail_html: str, throttle_seconds: int | None = None,
) -> None:
    """E-mail the admin about a scanner-health problem, throttled per ``kind``.

    Reuses ``src.email.send_email`` and a Redis TTL key (default once every 6h)
    so a persistent failure nudges without spamming every scheduler tick — the
    same throttle pattern as ``reddit_reminder._send_dry_feed_alert``. Distinct
    ``kind`` values throttle independently (a dead token and a job exception can
    each alert once/6h). ``throttle_seconds`` overrides the window per ``kind``
    — the real-time rate-limit alerts pass a shorter (~90 min) window so they
    surface faster than the daily probe's 6h cadence.
    """
    if throttle_seconds is None:
        throttle_seconds = _ALERT_THROTTLE_SECONDS
    throttle_key = f"ag:scanhealth:alert:{kind}"
    try:
        from src.redis_client import get_redis

        r = get_redis()
        if await r.get(throttle_key):
            return
        await r.set(throttle_key, "1", ex=throttle_seconds)
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
        if health.mechanism == "github_app":
            fix_html = (
                "<p><b>Fix:</b> the GitHub App private key was rejected — verify "
                "<code>GITHUB_APP_ID</code>, <code>GITHUB_APP_PRIVATE_KEY</code>, and "
                "<code>GITHUB_APP_INSTALLATION_ID</code> in <code>.env.secrets</code> "
                "(a rotated/removed key or an uninstalled App will 401), then restart "
                "the backend. Removing the App creds falls back to "
                "<code>GITHUB_TOKEN</code> automatically.</p>"
            )
        else:
            fix_html = (
                "<p><b>Fix:</b> rotate <code>GITHUB_TOKEN</code> in "
                "<code>.env.secrets</code> and restart the backend — or configure the "
                "GitHub App creds (<code>GITHUB_APP_ID</code> / "
                "<code>GITHUB_APP_PRIVATE_KEY</code> / "
                "<code>GITHUB_APP_INSTALLATION_ID</code>) so the token never expires.</p>"
            )
        await alert_scan_health(
            "github_token_dead",
            "AgentAvow: GitHub scanner credential is DEAD (re-scans failing)",
            (
                "<p>The security re-scan job could not authenticate to GitHub.</p>"
                f"<p><b>Active mechanism:</b> {health.mechanism}.</p>"
                f"<p><b>What happened:</b> {health.reason}.</p>"
                "<p>Every repo scan will 401 until this is fixed, so catalog "
                "grades will go stale.</p>"
                + fix_html
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


# ---------------------------------------------------------------------------
# Real-time GitHub rate-limit protection (live public-scan path)
# ---------------------------------------------------------------------------
# The functions above run only from the daily re-scan job. Under live user
# traffic the public scan API can drain / 429 the GitHub budget mid-day, so the
# scan path routes its metered GitHub responses through ``note_github_response``
# and a cheap periodic probe (``check_github_budget``) keeps the degradation
# flag fresh between daily ticks.


def _reset_str(reset_epoch: int | None) -> str:
    """Human-readable UTC reset time (+ minutes away) for an X-RateLimit-Reset."""
    if reset_epoch is None:
        return "unknown"
    import time
    from datetime import datetime, timezone

    try:
        when = datetime.fromtimestamp(reset_epoch, tz=timezone.utc)
        mins = max(0, int((reset_epoch - time.time()) / 60))
        return f"{when.isoformat()} (~{mins} min from now)"
    except (ValueError, OverflowError, OSError):
        return str(reset_epoch)


async def set_budget_low_flag(ttl: int | None = None) -> None:
    """Set the Redis ``github_budget_low`` flag the scan path reads to degrade."""
    if ttl is None:
        try:
            from src.config import settings

            ttl = settings.github_budget_low_flag_ttl_seconds
        except Exception:
            ttl = 20 * 60
    try:
        from src.redis_client import get_redis

        await get_redis().set(GITHUB_BUDGET_LOW_FLAG, "1", ex=ttl)
    except Exception:
        logger.debug("Could not set github_budget_low flag", exc_info=True)


async def clear_budget_low_flag() -> None:
    """Clear the degradation flag once the budget has recovered."""
    try:
        from src.redis_client import get_redis

        await get_redis().delete(GITHUB_BUDGET_LOW_FLAG)
    except Exception:
        logger.debug("Could not clear github_budget_low flag", exc_info=True)


async def is_github_budget_low() -> bool:
    """Cheap read of the degradation flag (used on the hot scan path).

    Fails OPEN (returns False) if Redis is unavailable — a missing flag must
    never wedge scanning; the per-scan real-time inspector is the backstop.
    """
    try:
        from src.redis_client import get_redis

        return bool(await get_redis().get(GITHUB_BUDGET_LOW_FLAG))
    except Exception:
        return False


async def alert_github_rate_limited(
    *, remaining: int | None, reset_epoch: int | None,
    retry_after: int | None, context: str,
) -> None:
    """Throttled admin alert: a live scan call was rate-limited (403/429)."""
    from src.config import settings

    ra = f"{retry_after}s" if retry_after is not None else "not provided"
    rem = remaining if remaining is not None else "unknown"
    await alert_scan_health(
        "github_ratelimited",
        "AgentAvow: GitHub RATE-LIMITED on the live scan path",
        (
            "<p>A GitHub API call in the public scan path was <b>rate-limited</b> "
            "(HTTP 403/429 — primary or secondary limit).</p>"
            f"<p><b>Where:</b> {context}.</p>"
            f"<p><b>Remaining core budget:</b> {rem}.</p>"
            f"<p><b>Resets at:</b> {_reset_str(reset_epoch)}.</p>"
            f"<p><b>Retry-After:</b> {ra}.</p>"
            "<p>The scan path is now serving stale cache and deferring fresh "
            "scans (graceful degradation) until the budget recovers. If this "
            "recurs, widen the budget (GitHub App) or lower "
            "<code>RATE_LIMIT_GLOBAL_FRESH_SCANS_PER_MINUTE</code> / "
            "<code>RATE_LIMIT_FRESH_SCANS_PER_MINUTE</code>.</p>"
        ),
        throttle_seconds=settings.github_ratelimit_alert_throttle_seconds,
    )


async def alert_github_budget_low(
    *, remaining: int | None, reset_epoch: int | None, context: str,
) -> None:
    """Throttled admin alert: live scan traffic drove the budget below the
    warning threshold (but not yet rate-limited)."""
    from src.config import settings

    await alert_scan_health(
        "github_budget_low_live",
        "AgentAvow: GitHub budget running LOW (live scan traffic)",
        (
            f"<p>Live scan traffic has driven GitHub's remaining core budget to "
            f"<b>{remaining}</b> requests — below the "
            f"{settings.github_ratelimit_alert_threshold} warning threshold.</p>"
            f"<p><b>Where:</b> {context}.</p>"
            f"<p><b>Resets at:</b> {_reset_str(reset_epoch)}.</p>"
            f"<p>Below <b>{settings.github_budget_floor}</b> the scan path starts "
            "serving stale cache and deferring fresh scans. You're being warned "
            "now, before it's a problem.</p>"
        ),
        throttle_seconds=settings.github_ratelimit_alert_throttle_seconds,
    )


async def note_github_response(
    status_code: int, headers: object, *, context: str = "",
) -> float | None:
    """Inspect a GitHub API response from the scan path for rate-limit signals.

    Fires throttled admin alerts and maintains the ``github_budget_low``
    degradation flag in real time — the "you'll know before it's a problem"
    signal that the daily probe can't provide.

    * 403/429 with rate-limit markers (Retry-After, or remaining==0) → treat as
      rate-limited: alert, set the flag, and return a suggested back-off (honors
      Retry-After, else time-to-reset).
    * ``X-RateLimit-Remaining`` below the degradation floor → set the flag.
    * ``X-RateLimit-Remaining`` below the alert threshold → alert.

    Returns a suggested back-off in seconds when rate-limited, else ``None``.
    Never raises — best-effort protection must not break a scan.
    """
    try:
        from src.config import settings

        alert_threshold = settings.github_ratelimit_alert_threshold
        floor = settings.github_budget_floor
    except Exception:
        alert_threshold, floor = LOW_REMAINING_THRESHOLD, 200

    def _h(name: str) -> object:
        try:
            return headers.get(name)  # type: ignore[union-attr]
        except Exception:
            return None

    remaining = _int_or_none(_h("x-ratelimit-remaining"))
    reset = _int_or_none(_h("x-ratelimit-reset"))
    retry_after = _int_or_none(_h("retry-after"))

    # A 403 is only a rate limit when GitHub says so (Retry-After present, or
    # the core budget is exhausted). A plain 403 (private repo, bad token) is
    # NOT a rate limit and must not trip degradation.
    is_rate_limited = status_code == 429 or (
        status_code == 403 and (retry_after is not None or remaining == 0)
    )

    if is_rate_limited:
        try:
            await set_budget_low_flag()
            await alert_github_rate_limited(
                remaining=remaining, reset_epoch=reset,
                retry_after=retry_after, context=context or "scan path",
            )
        except Exception:
            logger.debug("rate-limited alert/flag failed", exc_info=True)
        # Suggested back-off: honor Retry-After, else seconds-to-reset.
        if retry_after is not None:
            return float(max(0, retry_after))
        if reset is not None:
            import time

            return float(max(0.0, reset - time.time()))
        return _DEFAULT_BACKOFF_SECONDS

    if remaining is not None:
        try:
            if remaining < floor:
                await set_budget_low_flag()
            if remaining < alert_threshold:
                await alert_github_budget_low(
                    remaining=remaining, reset_epoch=reset,
                    context=context or "scan path",
                )
        except Exception:
            logger.debug("low-budget alert/flag failed", exc_info=True)

    return None


async def check_github_budget() -> TokenHealth:
    """Periodic (15-30 min) free probe that maintains the degradation flag.

    Reuses :func:`check_github_token_health` (a free ``GET /rate_limit`` call),
    then sets the ``github_budget_low`` flag when core-remaining is below the
    floor and clears it once recovered. Runs between the daily re-scan ticks so
    the scan path's cheap flag read stays accurate.
    """
    from src.config import settings

    health = await check_github_token_health()
    if health.remaining is not None:
        if health.remaining < settings.github_budget_floor:
            await set_budget_low_flag()
        else:
            await clear_budget_low_flag()
    return health
