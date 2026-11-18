"""One HTTP client for the registry fetchers: deadlines, one retry layer, a breaker (#406).

The GitHub, npm, PyPI, crates.io, Docker Hub and Hugging Face fetchers all go through
``fetch_client``. It gives each fetch:

* **A deadline.** Every fetch gets a total time budget covering all of its calls and
  retries. Each attempt's timeout is capped by the time left, and so is any ambient
  deadline a caller set with ``deadline_scope`` (for example, the time left on the
  inbound request). Running out raises ``DeadlineExceeded``, an
  ``httpx.TimeoutException``, so the fetchers' existing error handling and messages
  are unchanged.
* **One retry layer.** Only ``GET`` (and ``HEAD``) are ever retried, only on transient
  failures: a connect error or connect timeout, 429, 502, 503 and 504. Waits use full
  jitter, honour ``Retry-After`` up to a cap, and never run past the deadline. When the
  retries are spent, the last response is returned (or the last error raised), so a
  fetcher reports exactly what it reported before. httpx's own transport retries are
  set to 0.
* **A per-host circuit breaker.** After ``BREAKER_THRESHOLD`` consecutive failed calls
  to a host, calls to it fail at once with ``CircuitOpenError`` (an
  ``httpx.TransportError``) for ``BREAKER_COOLOFF_S``. Then one trial call is let
  through: success closes the breaker, failure opens it again. The breaker table is
  bounded (LRU), so it can't grow without limit.
* **The SSRF guard on every attempt.** The client uses ``src.ssrf``'s pinned transport,
  which resolves and validates the host for each request it sends, retries included.
  Redirects stay off (the fetchers never followed them), so there is no unchecked hop.

The live MCP-server scanning path (JSON-RPC POSTs) does not use this module and must
never be retried.
"""
from __future__ import annotations

import asyncio
import contextvars
import email.utils
import logging
import random
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

import httpx

logger = logging.getLogger(__name__)

# Retry policy
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 0.25
BACKOFF_CAP_S = 2.0
RETRY_AFTER_CAP_S = 5.0
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
_RETRYABLE_EXCEPTIONS = (httpx.ConnectError, httpx.ConnectTimeout)
_SAFE_METHODS = frozenset({"GET", "HEAD"})

# Default per-attempt connect timeout
CONNECT_TIMEOUT_S = 5.0

# Breaker policy
BREAKER_THRESHOLD = 5
BREAKER_COOLOFF_S = 30.0
BREAKER_MAX_HOSTS = 256

# Indirection so tests can drive a fake clock and skip real sleeps.
_monotonic = time.monotonic
_sleep = asyncio.sleep
_random = random.random


class DeadlineExceeded(httpx.TimeoutException):
    """The fetch ran out of its time budget."""


class CircuitOpenError(httpx.TransportError):
    """The host's breaker is open; no request was sent."""


# ---------------------------------------------------------------------------
# Deadlines
# ---------------------------------------------------------------------------

_ambient_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "source_import_deadline", default=None
)


class Deadline:
    """An absolute point on the monotonic clock."""

    def __init__(self, at: float) -> None:
        self.at = at

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        """``seconds`` from now, or sooner if an ambient deadline ends first."""
        at = _monotonic() + seconds
        ambient = _ambient_deadline.get()
        if ambient is not None:
            at = min(at, ambient)
        return cls(at)

    def remaining(self) -> float:
        return self.at - _monotonic()


@contextmanager
def deadline_scope(seconds: float) -> Iterator[None]:
    """Cap every fetch started inside this block at ``seconds`` from now."""
    at = _monotonic() + seconds
    outer = _ambient_deadline.get()
    token = _ambient_deadline.set(at if outer is None else min(at, outer))
    try:
        yield
    finally:
        _ambient_deadline.reset(token)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Consecutive-failure breaker for one host. Not thread-safe; one event loop."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self, host: str, *, threshold: int = BREAKER_THRESHOLD,
        cooloff: float = BREAKER_COOLOFF_S,
    ) -> None:
        self.host = host
        self.threshold = threshold
        self.cooloff = cooloff
        self.state = self.CLOSED
        self.failures = 0
        self.opened_at = 0.0
        self._probe_in_flight = False

    def before_call(self) -> None:
        """Raise ``CircuitOpenError`` if a call must not go out now."""
        if self.state == self.CLOSED:
            return
        if self.state == self.OPEN:
            if _monotonic() - self.opened_at < self.cooloff:
                raise self._open_error()
            self.state = self.HALF_OPEN
            self._probe_in_flight = False
        # Half-open: one trial call at a time.
        if self._probe_in_flight:
            raise self._open_error()
        self._probe_in_flight = True

    def record_success(self) -> None:
        if self.state != self.CLOSED:
            logger.info("circuit closed for %s", self.host)
        self.state = self.CLOSED
        self.failures = 0
        self._probe_in_flight = False

    def record_failure(self) -> None:
        self._probe_in_flight = False
        if self.state == self.HALF_OPEN:
            self._open()
            return
        self.failures += 1
        if self.state == self.CLOSED and self.failures >= self.threshold:
            self._open()

    def release(self) -> None:
        """The call ended without saying anything about the host's health."""
        self._probe_in_flight = False

    def _open(self) -> None:
        self.state = self.OPEN
        self.opened_at = _monotonic()
        logger.warning(
            "circuit opened for %s after %d consecutive failures; cooling off %.0fs",
            self.host, self.failures, self.cooloff,
        )

    def _open_error(self) -> CircuitOpenError:
        return CircuitOpenError(
            f"{self.host} is failing; not calling it for up to {self.cooloff:.0f}s"
        )


class _BreakerRegistry:
    """A bounded host → breaker table (least recently used host is evicted)."""

    def __init__(self, max_hosts: int = BREAKER_MAX_HOSTS) -> None:
        self.max_hosts = max_hosts
        self._breakers: OrderedDict[str, CircuitBreaker] = OrderedDict()

    def get(self, host: str) -> CircuitBreaker:
        host = host.lower()
        breaker = self._breakers.get(host)
        if breaker is None:
            breaker = CircuitBreaker(host)
            self._breakers[host] = breaker
            while len(self._breakers) > self.max_hosts:
                self._breakers.popitem(last=False)
        else:
            self._breakers.move_to_end(host)
        return breaker

    def clear(self) -> None:
        self._breakers.clear()

    def __len__(self) -> int:
        return len(self._breakers)


breakers = _BreakerRegistry()


# ---------------------------------------------------------------------------
# Retry helpers
# ---------------------------------------------------------------------------

def _backoff(attempt: int) -> float:
    """Full jitter: uniform in [0, min(cap, base * 2**attempt))."""
    return _random() * min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** attempt))


def _retry_after(resp: httpx.Response) -> float | None:
    """Seconds from a ``Retry-After`` header (delta or HTTP date), if present."""
    value = (resp.headers.get("retry-after") or "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------

class FetchClient:
    """A thin wrapper around ``httpx.AsyncClient``; use it through ``fetch_client``."""

    def __init__(
        self, client: httpx.AsyncClient, deadline: Deadline, *,
        attempt_timeout: float, connect_timeout: float,
    ) -> None:
        self._client = client
        self.deadline = deadline
        self.attempt_timeout = attempt_timeout
        self.connect_timeout = connect_timeout

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.request("GET", url, headers=headers)

    async def request(
        self, method: str, url: str, *, headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        method = method.upper()
        max_attempts = MAX_ATTEMPTS if method in _SAFE_METHODS else 1
        breaker = breakers.get(httpx.URL(url).host)
        breaker.before_call()
        try:
            return await self._with_retries(method, url, headers, breaker, max_attempts)
        finally:
            # Frees a half-open trial slot however the call ended (cancellation
            # included). A no-op once an outcome was recorded.
            breaker.release()

    async def _with_retries(
        self, method: str, url: str, headers: dict[str, str] | None,
        breaker: CircuitBreaker, max_attempts: int,
    ) -> httpx.Response:
        attempt = 0
        while True:
            attempt += 1
            if self.deadline.remaining() <= 0:
                # Out of time before anything was sent: not the host's fault.
                raise DeadlineExceeded(
                    f"deadline exceeded before calling {httpx.URL(url).host}"
                )
            try:
                resp = await self._attempt(method, url, headers)
            except _RETRYABLE_EXCEPTIONS:
                if attempt < max_attempts and await self._wait(_backoff(attempt)):
                    continue
                breaker.record_failure()
                raise
            except httpx.TransportError:
                # Timeouts, read errors and the like: not retried, but a failure.
                breaker.record_failure()
                raise
            # Anything else (an SSRF refusal is a ValueError, or cancellation) says
            # nothing about the host's health and is left to the caller.

            if resp.status_code in RETRYABLE_STATUSES:
                if attempt < max_attempts:
                    delay = self._delay_for(resp, attempt)
                    if delay is not None and await self._wait(delay):
                        continue
                breaker.record_failure()
                return resp
            if resp.status_code >= 500:
                breaker.record_failure()
            else:
                breaker.record_success()
            return resp

    async def _attempt(
        self, method: str, url: str, headers: dict[str, str] | None,
    ) -> httpx.Response:
        remaining = self.deadline.remaining()
        timeout = httpx.Timeout(
            min(self.attempt_timeout, remaining),
            connect=min(self.connect_timeout, remaining),
        )
        try:
            async with asyncio.timeout(remaining):
                if method == "GET":
                    return await self._client.get(url, headers=headers, timeout=timeout)
                return await self._client.request(
                    method, url, headers=headers, timeout=timeout,
                )
        except TimeoutError as exc:
            raise DeadlineExceeded(
                f"deadline exceeded calling {httpx.URL(url).host}"
            ) from exc

    def _delay_for(self, resp: httpx.Response, attempt: int) -> float | None:
        """How long to wait before retrying ``resp``, or None to stop now."""
        retry_after = _retry_after(resp)
        if retry_after is None:
            return _backoff(attempt)
        if retry_after > RETRY_AFTER_CAP_S:
            return None
        return retry_after

    async def _wait(self, delay: float) -> bool:
        """Sleep ``delay`` if it leaves time for another attempt; False means stop."""
        if delay >= self.deadline.remaining():
            return False
        await _sleep(delay)
        return True


@asynccontextmanager
async def fetch_client(
    *, total: float, attempt_timeout: float = 10.0,
    connect_timeout: float = CONNECT_TIMEOUT_S,
) -> AsyncIterator[FetchClient]:
    """A client for one fetch, with a ``total`` deadline across all of its calls."""
    from src.ssrf import build_ssrf_safe_transport

    deadline = Deadline.after(total)
    async with httpx.AsyncClient(
        transport=build_ssrf_safe_transport(retries=0),
        timeout=httpx.Timeout(attempt_timeout, connect=connect_timeout),
        follow_redirects=False,
    ) as client:
        yield FetchClient(
            client, deadline,
            attempt_timeout=attempt_timeout, connect_timeout=connect_timeout,
        )
