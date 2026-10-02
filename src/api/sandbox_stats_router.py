"""Public behavioral-sandbox statistics.

``GET /public/sandbox-stats`` returns aggregate counts only: lifetime totals of
sandbox runs, exercised MCP servers, tools called, behavioral findings and canary
credential leaks, plus the last 30 days of runs / exercised / findings and the
30-day findings broken down by rule. No package, repo or server names are read or
returned. The counters are written by the public scan path; a missing key reads as
0. The response is cached for 5 minutes.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from src.api.metrics_dashboard_router import (
    BEHAVIORAL_RULES,
    BEHAVIORAL_TOTALS,
    read_behavioral_counters,
    window_day_strs,
)
from src.api.rate_limit import rate_limit_reads

router = APIRouter(prefix="/public", tags=["public"])

_CACHE_KEY = "public:sandbox-stats:v1"
_CACHE_TTL = 300
_WINDOW = 30


async def _compute() -> dict:
    day_strs = window_day_strs(_WINDOW)
    daily_names = ["runs", "exercised", "with_findings"] + [f"rule:{r}" for r in BEHAVIORAL_RULES]
    daily, totals = await read_behavioral_counters(day_strs, daily_names, BEHAVIORAL_TOTALS)

    def tot(name: str) -> int:
        return int(sum(daily.get(name, [])))

    by_rule = {r: tot(f"rule:{r}") for r in BEHAVIORAL_RULES}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {t: int(totals.get(t, 0)) for t in BEHAVIORAL_TOTALS},
        "last_30_days": {
            "runs": tot("runs"),
            "exercised": tot("exercised"),
            "runs_with_findings": tot("with_findings"),
            "findings": sum(by_rule.values()),
            "findings_by_rule": by_rule,
        },
    }


@router.get("/sandbox-stats", dependencies=[Depends(rate_limit_reads)])
async def sandbox_stats() -> dict:
    """Aggregate behavioral-sandbox counts (no names). Cached 5 minutes.

    - ``totals``: lifetime ``runs``, ``exercised`` (MCP servers that started and had
      their tools called), ``tools_called``, ``findings``, ``canary_leaks``.
    - ``last_30_days``: ``runs``, ``exercised``, ``runs_with_findings``, ``findings``
      (sum of ``findings_by_rule``) and ``findings_by_rule``.
    """
    from src import cache

    cached = await cache.get(_CACHE_KEY)
    if cached is not None:
        return cached
    result = await _compute()
    await cache.set(_CACHE_KEY, result, ttl=_CACHE_TTL)
    return result
