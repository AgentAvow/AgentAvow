"""Sandbox watchdog: page the admin when the behavioral tier stops working quietly.

The sandbox fails OPEN by design — a scan never waits on it — so when it breaks nothing
user-facing errors. Two incidents on 2026-10-08 showed what that costs: a leaked slot
counter left every scan "analysis running", and a full scratch disk on the sandbox box
truncated captures so vulnerable tools graded clean. This turns the quiet failure modes
into an admin notification + the admin's HMAC-signed alert webhook (the same path as
the weekly eval's regression alert), at most once a day per condition.

Conditions (each a pure check over Redis state; ``evaluate`` returns the ones that hold):
  ``eval_stale``       the weekly eval has not produced a report for 8 days
  ``backfill_stale``   the backfill has not run for 24 h while eligible rows remain
  ``disk_low``         the sandbox box refused a run for low disk (sandbox_disk_low)
  ``slots``            the slot watchdog (``slots.check_health``) logged a warning

Runs from the backfill loop's queue tick (every 10 min). Never raises.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

EVAL_STALE_DAYS = 8
BACKFILL_STALE_HOURS = 24
DEDUPE_TTL = 24 * 3600
DEDUPE_PREFIX = "ag:ops:sandbox_watchdog:alerted:"
WEBHOOK_TYPE = "agentavow.ops.sandbox_watchdog"
METRICS_PREFIX = "ag:metrics:behavioral"


def _s(v: object) -> str:
    return v.decode() if isinstance(v, bytes) else ("" if v is None else str(v))


def _parse(ts: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


async def evaluate(now: datetime | None = None, slot_warnings: list[str] | None = None,
                   ) -> list[tuple[str, str, str]]:
    """``[(condition, title, body)]`` for every condition that holds right now."""
    import json

    from src.config import settings
    from src.redis_client import get_redis

    now = now or datetime.now(timezone.utc)
    r = get_redis()
    out: list[tuple[str, str, str]] = []

    # 1. weekly eval stopped producing reports
    if getattr(settings, "behavioral_eval_enabled", True):
        raw = _s(await r.get("ag:eval:behavioral:latest"))
        ran_at = None
        if raw:
            try:
                ran_at = _parse(str(json.loads(raw).get("ran_at") or ""))
            except ValueError:
                ran_at = None
        if ran_at and now - ran_at > timedelta(days=EVAL_STALE_DAYS):
            days = (now - ran_at).days
            out.append(("eval_stale", "Sandbox eval has not run",
                        f"The weekly behavioral eval last produced a report {days} days ago "
                        f"({ran_at.isoformat(timespec='minutes')}). The loop may have died; "
                        "check the backend log for 'Behavioral eval loop' and the admin "
                        "dashboard's Eval tile."))

    # 2. backfill stopped advancing while there is work left
    if getattr(settings, "behavioral_backfill_enabled", True):
        prog = {_s(k): _s(v) for k, v in (await r.hgetall(
            "ag:backfill:behavioral:progress") or {}).items()}
        last = _parse(prog.get("last_run_at", ""))
        try:
            eligible = int(float(prog.get("total_eligible") or 0))
            done = int(float(prog.get("done") or 0))
        except ValueError:
            eligible, done = 0, 0
        if last and eligible > done and now - last > timedelta(hours=BACKFILL_STALE_HOURS):
            hours = int((now - last).total_seconds() // 3600)
            out.append(("backfill_stale", "Sandbox backfill has stalled",
                        f"The behavioral backfill last ran {hours} h ago with {eligible - done} "
                        "eligible rows still waiting. Check the backend log for 'Behavioral "
                        "backfill' and whether the sandbox tier is enabled."))

    # 3. the sandbox box refused runs for low disk (today or yesterday)
    disk = 0
    for d in (now, now - timedelta(days=1)):
        disk += int(float(_s(await r.get(
            f"{METRICS_PREFIX}:runner_error:sandbox_disk_low:{d.strftime('%Y-%m-%d')}")) or 0))
    if disk:
        out.append(("disk_low", "Sandbox box is low on disk",
                    f"{disk} sandbox run(s) in the last day were refused because the "
                    "sandbox box has under 1 GB free in /var/tmp/agentavow-beh. Runs are not "
                    "happening. Check `df -h /var/tmp /tmp` on the box via SSM and clear "
                    "leftover beh_* files."))

    # 4. the slot watchdog fired
    if slot_warnings:
        out.append(("slots", "Sandbox slots look stuck", " ".join(slot_warnings)))
    return out


async def run_watchdog(slot_warnings: list[str] | None = None,
                       now: datetime | None = None) -> list[str]:
    """Evaluate and alert (deduped per condition for 24 h). Returns the conditions alerted
    this call. Never raises."""
    alerted: list[str] = []
    try:
        from src.jobs.behavioral_eval import notify_admins
        from src.redis_client import get_redis

        r = get_redis()
        for cond, title, body in await evaluate(now, slot_warnings):
            if not await r.set(f"{DEDUPE_PREFIX}{cond}", "1", nx=True, ex=DEDUPE_TTL):
                continue  # already alerted for this condition in the last day
            logger.warning("sandbox watchdog: %s — %s", title, body)
            await notify_admins(title, body, reference_id=f"sandbox-watchdog:{cond}",
                                payload={"type": WEBHOOK_TYPE, "event": cond,
                                         "title": title, "body": body})
            alerted.append(cond)
    except Exception:
        logger.debug("sandbox watchdog failed", exc_info=True)
    return alerted
