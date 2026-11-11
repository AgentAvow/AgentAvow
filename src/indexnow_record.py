"""The last IndexNow pings, kept in Redis for the admin dashboard.

``scripts/indexnow_ping.py`` runs on the machine that deploys, which can't reach prod
Redis. ``scripts/deploy-prod.sh`` pipes the ping's JSON result into the backend
container instead::

    python -m src.indexnow_record < result.json

Only a small, checked set of fields is kept: when, how many URLs, the HTTP status and
the outcome. The newest :data:`KEEP` runs are kept, with no expiry.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

RUNS_KEY = "ag:metrics:indexnow:runs"
KEEP = 20
OUTCOMES = ("sent", "not_confirmed", "nothing_changed", "http_error", "skipped")


def clean_run(raw: object) -> dict | None:
    """The fields worth keeping from one ping result, or None if it isn't one."""
    if not isinstance(raw, dict) or raw.get("outcome") not in OUTCOMES:
        return None
    submitted = raw.get("submitted")
    status = raw.get("status")
    at = raw.get("at")
    try:
        when = datetime.fromisoformat(str(at)) if at else datetime.now(timezone.utc)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return {
        "at": when.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "outcome": raw["outcome"],
        "submitted": submitted if isinstance(submitted, int) and submitted >= 0 else 0,
        "status": status if isinstance(status, int) and 100 <= status <= 599 else None,
    }


async def record_run(raw: object) -> bool:
    """Store one ping result at the head of the list. Best-effort: False on bad input or
    a Redis failure."""
    run = clean_run(raw)
    if run is None:
        return False
    try:
        from src.redis_client import get_redis

        r = get_redis()
        await r.lpush(RUNS_KEY, json.dumps(run))
        await r.ltrim(RUNS_KEY, 0, KEEP - 1)
        return True
    except Exception:
        return False


async def recent_runs(limit: int = 5) -> list[dict]:
    """The newest runs first. Fail-open: [] when Redis is unavailable."""
    try:
        from src.redis_client import get_redis

        raw = await get_redis().lrange(RUNS_KEY, 0, max(0, limit - 1))
    except Exception:
        return []
    runs = []
    for item in raw or []:
        try:
            run = clean_run(json.loads(item))
        except (TypeError, ValueError):
            continue
        if run:
            runs.append(run)
    return runs


def main() -> int:
    import asyncio

    try:
        raw = json.loads(sys.stdin.read() or "null")
    except ValueError:
        raw = None
    ok = asyncio.run(record_run(raw))
    print("indexnow: result recorded" if ok else "indexnow: result not recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
