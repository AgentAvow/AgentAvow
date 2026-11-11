"""Daily metrics the admin dashboard keeps as a series: the catalog answer mix and
Certified count (x402 excluded), and weekly npm / PyPI downloads of agentavow-trust.

Runs from the 6-hour scheduler loop. Each run rewrites today's Redis hash, so the
day's last run wins and a missed run leaves a gap rather than a wrong number. The
hashes carry no TTL: they are the durable copy the dashboard reads, like the
nightly traffic snapshot (``ag:metrics:traffic:<day>``).

  ag:metrics:catalog_daily:<day>  safe, review, do_not_connect, unscored, certified, total
  ag:metrics:downloads:<day>      npm_week, pypi_week, pypi_month (missing = fetch failed)

The registry fetches use two fixed public URLs (no user input), a short timeout, and
never raise.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CATALOG_PREFIX = "ag:metrics:catalog_daily:"
DOWNLOADS_PREFIX = "ag:metrics:downloads:"
PACKAGE = "agentavow-trust"
NPM_URL = f"https://api.npmjs.org/downloads/point/last-week/{PACKAGE}"
PYPI_URL = f"https://pypistats.org/api/packages/{PACKAGE}/recent"
DECISIONS = ("safe", "review", "do_not_connect")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def catalog_mix(rows) -> dict[str, int]:
    """Answer mix and Certified count over catalog rows, x402 left out (as on the
    site: ~33k listing-only Safe rows would swamp the mix)."""
    out = {d: 0 for d in DECISIONS} | {"unscored": 0, "certified": 0, "total": 0}
    for r in rows:
        if getattr(r, "surface", None) == "x402":
            continue
        out["total"] += 1
        d = getattr(r, "decision", None)
        if getattr(r, "trust_score", None) is None or d not in DECISIONS:
            out["unscored"] += 1
        else:
            out[d] += 1
        if getattr(r, "certified_mark", None) is True:
            out["certified"] += 1
    return out


async def current_catalog_mix(db) -> dict[str, int]:
    """The mix right now: the static launch corpus plus community scans."""
    from src.api.scan_catalog_router import _community_rows, _get_catalog

    rows = list(_get_catalog()["rows"]) + list(await _community_rows(db))
    return catalog_mix(rows)


async def fetch_registry_downloads() -> dict[str, int]:
    """Weekly npm downloads and recent PyPI downloads of agentavow-trust. A source
    that fails is left out of the result (never a zero that was not measured)."""
    import httpx

    out: dict[str, int] = {}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False,
                                 headers={"User-Agent": "agentavow-metrics/1"}) as client:
        try:
            r = await client.get(NPM_URL)
            if r.status_code == 200:
                n = r.json().get("downloads")
                if isinstance(n, int):
                    out["npm_week"] = n
        except Exception:
            logger.debug("npm downloads fetch failed", exc_info=True)
        try:
            r = await client.get(PYPI_URL)
            if r.status_code == 200:
                data = r.json().get("data") or {}
                for src_key, dst in (("last_week", "pypi_week"), ("last_month", "pypi_month")):
                    if isinstance(data.get(src_key), int):
                        out[dst] = data[src_key]
        except Exception:
            logger.debug("pypi downloads fetch failed", exc_info=True)
    return out


async def _write_hash(prefix: str, values: dict) -> None:
    from src.redis_client import get_redis

    r = get_redis()
    key = f"{prefix}{_today()}"
    await r.delete(key)
    if values:
        await r.hset(key, mapping={k: str(v) for k, v in values.items()})


async def run_metrics_daily(db) -> dict:
    """Write today's catalog mix and download counts. Never raises."""
    summary: dict = {}
    try:
        mix = await current_catalog_mix(db)
        await _write_hash(CATALOG_PREFIX, mix)
        summary["catalog"] = mix
    except Exception:
        logger.exception("daily catalog mix failed")
    try:
        downloads = await fetch_registry_downloads()
        if downloads:
            await _write_hash(DOWNLOADS_PREFIX, downloads)
        summary["downloads"] = downloads
    except Exception:
        logger.exception("daily registry downloads failed")
    return summary


async def read_daily(prefix: str, day_strs: list[str]) -> dict[str, dict[str, int]]:
    """``{day: {field: int}}`` for the days that have a hash. {} on Redis failure."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        out: dict[str, dict[str, int]] = {}
        for d in day_strs:
            raw = await r.hgetall(f"{prefix}{d}")
            if not raw:
                continue
            row: dict[str, int] = {}
            for k, v in raw.items():
                key = k.decode() if isinstance(k, bytes) else str(k)
                try:
                    row[key] = int(float(v.decode() if isinstance(v, bytes) else v))
                except (TypeError, ValueError):
                    continue
            out[d] = row
        return out
    except Exception:
        return {}
