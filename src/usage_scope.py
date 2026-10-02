"""What counts as usage: the per-request scope every usage counter consults.

Half of raw production traffic is redirects — vulnerability scanners probing
``/.env``, bots still hitting the retired domains, http→https and www→apex hops,
and an uptime monitor polling the old domain once a minute. None of that is a
person or an agent using the product, so none of it may land in a usage counter.

Rules (changed ``RULES_CHANGED_ON``; the dashboard shows the date so the trend
break reads as a rule change, not a drop):

* a response with status 301 / 302 / 308 is a redirect, not usage;
* a request whose ``Host`` is one of ``LEGACY_HOSTS`` is not usage, whatever its
  status (nginx still proxies ``/api``, ``/.well-known`` and friends for the old
  domain so README badges and signed receipts keep resolving);
* both are counted once, under ``REDIRECTED_METRIC``, so the junk volume stays
  visible as its own line.

How it works: ``usage_scope_middleware`` opens a ``UsageScope`` for the request
before the handler runs. A counter bump inside the request calls ``admit`` — if
the host is legacy the bump is dropped; otherwise it is queued, because the
status is not known until the handler returns. When the response is ready the
middleware ``settle``s the scope: a redirect drops the queue, anything else
flushes it. Bumps that happen after settling (background work) are written
through immediately, unless the request was excluded. Outside any request
(jobs, tests) ``admit`` always says yes, so nothing else changes.
"""
from __future__ import annotations

import contextvars
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Hosts that are not the product any more. Requests arriving under them are the
# redirect tail of the rebrand (and the bots that never updated), not usage.
LEGACY_HOSTS: frozenset[str] = frozenset({
    "agentgraph.co", "www.agentgraph.co",
    "agentgraph.me", "www.agentgraph.me",
    "agentgraph.io", "www.agentgraph.io",
    "www.agentavow.com",
})

REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 308})

# The one counter a redirect or legacy-host request may bump.
REDIRECTED_METRIC = "requests_redirected"

# The day these counting rules took effect (ISO date). Surfaced by the dashboard.
RULES_CHANGED_ON = "2026-10-02"


@dataclass
class UsageScope:
    """Per-request bookkeeping. ``excluded`` means nothing counts; ``settled``
    means the response status is known and ``pending`` has been dealt with."""

    excluded: bool = False
    settled: bool = False
    pending: list[str] = field(default_factory=list)


_SCOPE: contextvars.ContextVar[UsageScope | None] = contextvars.ContextVar(
    "agentavow_usage_scope", default=None
)


def is_legacy_host(host: str | None) -> bool:
    """True when the ``Host`` header (with or without a port) is a retired domain."""
    h = (host or "").strip().lower()
    if h.startswith("["):  # IPv6 literal: never a legacy host
        return False
    return h.split(":", 1)[0].rstrip(".") in LEGACY_HOSTS


def current_scope() -> UsageScope | None:
    return _SCOPE.get()


def usage_excluded() -> bool:
    """True inside a request that must not count as usage (legacy host, or a
    redirect once settled). False outside any request."""
    scope = _SCOPE.get()
    return bool(scope is not None and scope.excluded)


def admit(name: str) -> bool:
    """Decide what a counter bump should do right now.

    Returns True when the bump should be written immediately: outside a request,
    for ``REDIRECTED_METRIC`` itself, or after the scope has settled as usage.
    Returns False when the bump was dropped (excluded request) or queued on the
    scope until the response status is known.
    """
    scope = _SCOPE.get()
    if scope is None or name == REDIRECTED_METRIC:
        return True
    if scope.excluded:
        return False
    if scope.settled:
        return True
    scope.pending.append(name)
    return False


def settle(scope: UsageScope, status_code: int) -> list[str]:
    """Mark the response status known. A redirect excludes the request and drops
    its queued bumps; otherwise the queued names are returned for flushing."""
    scope.settled = True
    if status_code in REDIRECT_STATUSES:
        scope.excluded = True
    names, scope.pending = scope.pending, []
    return [] if scope.excluded else names


async def usage_scope_middleware(request, call_next):
    """Starlette HTTP middleware: open the scope, run the request, settle, flush.

    Instrumentation never changes a response: every counter write is wrapped so
    a Redis outage (or a bug here) is swallowed and the response goes out as is.
    """
    scope = UsageScope(excluded=is_legacy_host(request.headers.get("host")))
    token = _SCOPE.set(scope)
    try:
        response = await call_next(request)
    finally:
        _SCOPE.reset(token)
    try:
        await _finish(scope, response.status_code, request)
    except Exception:  # pragma: no cover - instrumentation must never raise
        logger.debug("usage scope finish failed", exc_info=True)
    return response


async def _finish(scope: UsageScope, status_code: int, request) -> None:
    from src.api.metrics_dashboard_router import bump_metric

    names = settle(scope, status_code)
    if scope.excluded:
        await bump_metric(REDIRECTED_METRIC)
        return
    for name in names:
        await bump_metric(name)
