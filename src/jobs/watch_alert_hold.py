"""Hold back score-change watch alerts during a planned catalog re-score.

When the scoring formula changes, every stored grade is re-scored and re-signed in one
pass (tracked follow-up #5). Without a hold, the next watch re-scan would compare each
watched tool's new score with the baseline stored under the old formula and send a
"score dropped" / "score improved" alert for every tool the formula moved, though the
tool itself did not change.

While the hold is set:

* the watch re-scan loop (``scheduler._run_watch_rescan``) and the GitHub App private
  repo re-scan (``app_scan._maybe_notify``) send no score-drop or score-improved alert
  (no notification, email or webhook), and still store the new score as the baseline,
  so the change is absorbed silently and does not fire after the hold clears;
* a signed tool-definition change (``tool_manifest_digest`` drift) and a sandbox
  behavior change still alert as usual. A re-score does not change either, so an alert
  on them during the hold is a real change.

The hold is one Redis key with a TTL, so a hold that is never cleared expires on its
own. Reading it fails open: if Redis cannot be read, alerts go out as normal (a spurious
alert is better than a missed one). Set it with ``scripts/ops/watch_alert_hold.py``.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

HOLD_KEY = "agentavow:watch:score_alert_hold"
MAX_HOLD_SECONDS = 72 * 60 * 60  # a forgotten hold can never outlive three days
DEFAULT_HOLD_SECONDS = 30 * 60 * 60  # one full daily watch pass plus margin


async def set_hold(seconds: int = DEFAULT_HOLD_SECONDS, reason: str = "") -> int:
    """Set (or extend) the hold for ``seconds`` (clamped to 1..MAX_HOLD_SECONDS).
    Returns the TTL actually set."""
    from src.redis_client import get_redis

    ttl = max(1, min(int(seconds), MAX_HOLD_SECONDS))
    value = json.dumps({"reason": str(reason)[:200],
                        "set_at": datetime.now(timezone.utc).isoformat()})
    await get_redis().set(HOLD_KEY, value, ex=ttl)
    logger.warning("watch score-alert hold SET for %ds: %s", ttl, reason)
    return ttl


async def clear_hold() -> bool:
    """Clear the hold. True if one was set."""
    from src.redis_client import get_redis

    removed = bool(await get_redis().delete(HOLD_KEY))
    logger.warning("watch score-alert hold CLEARED (was set: %s)", removed)
    return removed


async def hold_status() -> dict | None:
    """``{"reason", "set_at", "ttl"}`` while the hold is set, else None. Raises if
    Redis cannot be read (for the admin script; the alert path uses
    :func:`score_alerts_held`)."""
    from src.redis_client import get_redis

    r = get_redis()
    raw = await r.get(HOLD_KEY)
    if raw is None:
        return None
    try:
        info = json.loads(raw)
        info = info if isinstance(info, dict) else {}
    except (TypeError, ValueError):
        info = {}
    info["ttl"] = await r.ttl(HOLD_KEY)
    return info


async def score_alerts_held() -> bool:
    """True while a planned re-score holds back score-change alerts. Fails open."""
    try:
        from src.redis_client import get_redis

        return bool(await get_redis().exists(HOLD_KEY))
    except Exception:  # noqa: BLE001 — never let the hold check stop an alert
        logger.debug("watch score-alert hold check failed; alerting as normal",
                     exc_info=True)
        return False
