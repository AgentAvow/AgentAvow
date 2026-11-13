"""Polite HTTP for the registries: per-registry pacing, backoff on 429/5xx, call counts.

Every registry call in this package goes through :class:`Fetcher`. Pacing is a minimum
gap between two calls to the same registry, sized under each one's posted or observed
limit (npm documents 5,000 requests an hour; GitHub search allows 30 a minute). A 429 or
5xx is retried after ``Retry-After`` when the server sends one, else after an
exponential backoff, at most ``max_attempts`` times. GitHub's core budget is read from
the ``x-ratelimit-remaining`` header of every GitHub reply, so a caller can stop before
it eats into the budget live user scans need.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

# policy -> minimum seconds between two calls. Hourly ceiling = 3600 / gap.
POLICIES: dict[str, float] = {
    "mcp_registry": 0.75,   # registry.modelcontextprotocol.io: community-run, no posted limit
    "npm": 1.0,             # registry.npmjs.org: 5,000/h posted; this is 3,600/h at most
    "pypi": 1.0,            # pypi.org: no hard limit; be courteous
    "github": 1.5,          # api.github.com core: 5,000/h shared with live scans; <=2,400/h
    "github_search": 2.5,   # api.github.com/search: 30/min
    "clawhub": 1.0,         # clawhub.ai: no posted limit
    "smithery": 1.0,        # registry.smithery.ai: no posted limit
    "ecosystems": 1.0,      # packages.ecosyste.ms: free API, be courteous
}

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
USER_AGENT = "AgentAvowBot/1.0 (+https://agentavow.com/docs/how-it-works; catalog refresh)"


class Fetcher:
    """Paced GET with retry. ``client`` is an ``httpx.AsyncClient`` (or a test double
    with an async ``get(url, params=, headers=)``); ``sleep`` and ``clock`` are
    injectable so tests run instantly."""

    def __init__(
        self,
        client: Any,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        policies: dict[str, float] | None = None,
        max_attempts: int = 5,
        base_backoff: float = 2.0,
        max_backoff: float = 300.0,
    ) -> None:
        self.client = client
        self._sleep = sleep
        self._clock = clock
        self.policies = dict(POLICIES if policies is None else policies)
        self.max_attempts = max(1, max_attempts)
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._last: dict[str, float] = {}
        self.calls: dict[str, int] = {}
        self.retries: dict[str, int] = {}
        self.slept: float = 0.0
        self.github_remaining: int | None = None

    async def _pace(self, policy: str) -> None:
        gap = self.policies.get(policy, 1.0)
        last = self._last.get(policy)
        if last is not None:
            wait = last + gap - self._clock()
            if wait > 0:
                self.slept += wait
                await self._sleep(wait)
        self._last[policy] = self._clock()

    def backoff_for(self, resp: Any, attempt: int) -> float:
        """Seconds to wait before retry ``attempt`` (1-based): ``Retry-After`` when the
        server sent a number of seconds, else base * 2^(attempt-1); capped."""
        ra = None
        try:
            ra = (resp.headers or {}).get("retry-after") if resp is not None else None
        except Exception:
            ra = None
        if ra is not None:
            try:
                return min(self.max_backoff, max(0.0, float(ra)))
            except (TypeError, ValueError):
                pass
        return min(self.max_backoff, self.base_backoff * (2 ** (attempt - 1)))

    def _note_github(self, resp: Any) -> None:
        try:
            v = (resp.headers or {}).get("x-ratelimit-remaining")
            if v is not None:
                self.github_remaining = int(v)
        except (TypeError, ValueError, AttributeError):
            pass

    async def get(
        self, url: str, *, policy: str, params: dict | None = None,
        headers: dict | None = None,
    ) -> Any | None:
        """The response (any status) after pacing and retries, or None when every
        attempt failed in transport. Retries 429 / 5xx only."""
        hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
        resp = None
        for attempt in range(1, self.max_attempts + 1):
            await self._pace(policy)
            self.calls[policy] = self.calls.get(policy, 0) + 1
            try:
                resp = await self.client.get(url, params=params, headers=hdrs)
            except Exception as e:  # transport error: back off and retry
                logger.debug("catalog_growth GET %s failed: %s", url, e)
                resp = None
            if resp is not None and policy.startswith("github"):
                self._note_github(resp)
            status = getattr(resp, "status_code", None)
            # GitHub signals an exhausted budget as 403 + remaining 0: do not retry it
            # (the reset can be an hour away); the caller stops its GitHub work.
            if resp is not None and status not in RETRY_STATUSES:
                return resp
            if attempt == self.max_attempts:
                break
            self.retries[policy] = self.retries.get(policy, 0) + 1
            wait = self.backoff_for(resp, attempt)
            self.slept += wait
            await self._sleep(wait)
        return resp

    async def get_json(self, url: str, *, policy: str, params: dict | None = None,
                       headers: dict | None = None) -> Any | None:
        """Parsed JSON of a 200 reply, else None."""
        resp = await self.get(url, policy=policy, params=params, headers=headers)
        if resp is None or getattr(resp, "status_code", None) != 200:
            return None
        try:
            return resp.json()
        except Exception:
            return None
