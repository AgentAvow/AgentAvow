"""Per-tool check counts for the Trust Index card "Most checked this week".

One Redis sorted set per UTC day (``ag:checks:tool:<YYYY-MM-DD>``): member = the tool's
result-page key (the catalog's page identity, ``scan_catalog_router._path_key``), score =
how many checks that page got that day. Each key expires 14 days after its day. Nothing
about the caller is stored: no IP, no User-Agent, no account.

What counts as a check: a public scan request that returned a result (repo, package,
skill or MCP server; the result page fetches the same endpoint, so a page view is one
check). Left out:

* automated traffic and our own clients (``src.traffic_class.classify_user_agent``:
  only ``human`` and ``agent`` count; the MCP bridge's own call counts as an agent when
  it names a real surface);
* the owner's machines (``settings.metrics_owner_ips``);
* internal calls with no request (catalog re-scans, watches, claims, gateway);
* "still checking" (202) answers, so a forced re-scan and the polls that wait for it
  count once, when the result lands.

Best effort throughout: counting never fails or slows a scan by more than one Redis
round trip.
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

KEY_PREFIX = "ag:checks:tool:"
KEEP_DAYS = 14
WINDOW_DAYS = 7


def day_key(day: date) -> str:
    return f"{KEY_PREFIX}{day.isoformat()}"


def _expire_at(day: date) -> int:
    """Unix time KEEP_DAYS after the end of ``day`` (UTC)."""
    end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return int((end + timedelta(days=KEEP_DAYS)).timestamp())


def _owner_ips() -> set[str]:
    try:
        from src.config import settings

        raw = getattr(settings, "metrics_owner_ips", "") or ""
        return {x.strip() for x in raw.split(",") if x.strip()}
    except Exception:
        return set()


def counts_for(request: Any) -> bool:
    """True when this request is a check by a person or an agent, from a machine that is
    not the owner's."""
    try:
        from starlette.requests import Request

        if not isinstance(request, Request):
            return False
        from src.api.rate_limit import _get_client_ip, _internal_call
        from src.traffic_class import classify_user_agent

        internal = _internal_call(request)
        if internal is not None:
            # The MCP bridge: its own User-Agent is a library; the surface it forwards
            # says who the call is for ("other" = crawlers and unknown clients).
            cls = "agent" if internal[1] not in ("", "other") else "automated"
        else:
            cls = classify_user_agent(request.headers.get("user-agent"))
        if cls not in ("human", "agent"):
            return False
        ip = _get_client_ip(request)
        return not (ip and ip in _owner_ips())
    except Exception:
        return False


async def record_check(page_key: str, today: date | None = None) -> None:
    """Add one check for ``page_key`` to today's set. Never raises."""
    if not page_key:
        return
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = today or datetime.now(timezone.utc).date()
        key = day_key(day)
        await r.zincrby(key, 1, page_key)
        await r.expireat(key, _expire_at(day))
    except Exception:
        logger.debug("tool check not recorded", exc_info=False)


async def week_counts(today: date | None = None, days: int = WINDOW_DAYS) -> dict[str, int]:
    """{page_key: checks} over the last ``days`` UTC days, today included."""
    out: dict[str, int] = {}
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = today or datetime.now(timezone.utc).date()
        for i in range(days):
            rows = await r.zrange(day_key(day - timedelta(days=i)), 0, -1, withscores=True)
            for member, score in rows or []:
                k = member.decode() if isinstance(member, bytes) else str(member)
                out[k] = out.get(k, 0) + int(score)
    except Exception:
        logger.debug("tool check counts unavailable", exc_info=False)
    return out


def counted(key_of: Callable[[dict[str, Any]], str | None]):
    """Decorate a public scan route so a returned result counts as one check of the page
    ``key_of(kwargs)`` names. Internal callers call the same function with no request
    (or a stand-in) and are never counted. ``functools.wraps`` keeps the signature, so
    FastAPI injects the same parameters."""
    def deco(fn: Callable[..., Awaitable[Any]]):
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            resp = await fn(*args, **kwargs)
            try:
                status = getattr(resp, "status_code", 200)
                if status == 200 and counts_for(kwargs.get("request")):
                    key = key_of(kwargs)
                    if key:
                        await record_check(key)
            except Exception:
                logger.debug("tool check skipped", exc_info=False)
            return resp
        return wrapper
    return deco


# --- page keys, as the catalog keys its rows (scan_catalog_router.page_path_for) ------
_PKG_ALIASES = {"python": "pypi", "crate": "crates", "cargo": "crates", "rust": "crates",
                "hf": "huggingface", "hugging_face": "huggingface",
                "hugging-face": "huggingface", "container": "docker", "oci": "docker",
                "image": "docker", "dockerhub": "docker"}


def _key(surface: str, name: str | None, full_name: str | None,
         endpoint: str | None = None) -> str | None:
    from src.api.scan_catalog_router import _path_key, page_path_for
    return _path_key(page_path_for(surface, name, full_name, endpoint))


def repo_key(kw: dict[str, Any]) -> str | None:
    owner, repo = str(kw.get("owner") or ""), str(kw.get("repo") or "")
    return _key("github", f"{owner}/{repo}", f"{owner}/{repo}") if owner and repo else None


def skill_key(kw: dict[str, Any]) -> str | None:
    owner, repo = str(kw.get("owner") or ""), str(kw.get("repo") or "")
    return _key("openclaw", f"{owner}/{repo}", f"{owner}/{repo}") if owner and repo else None


def package_key(kw: dict[str, Any]) -> str | None:
    surface = str(kw.get("surface") or "").strip().lower()
    surface = _PKG_ALIASES.get(surface, surface)
    name = str(kw.get("name") or "").strip().strip("/")
    return _key(surface, name, None) if surface and name else None


def mcp_key(kw: dict[str, Any]) -> str | None:
    endpoint = kw.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        return None
    try:
        from src.ssrf import mcp_endpoint_identity
        url = mcp_endpoint_identity(endpoint.strip())
    except Exception:
        return None
    return _key("mcp", url, None, url)
