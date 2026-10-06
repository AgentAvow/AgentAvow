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
  domain so README badges and signed receipts keep resolving) — except the
  trust-badge endpoints (``BADGE_PATH_PREFIXES``): a README badge embedded
  before the rebrand still renders from the old domain, and that is adoption;
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

from src.traffic_class import classify_user_agent

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

# Paths that still count as usage on a legacy host: README badges embedded before
# the rebrand point at agentgraph.co and nginx keeps proxying them, so a
# github-camo fetch there is a real badge render, not redirect junk.
BADGE_PATH_PREFIXES: tuple[str, ...] = ("/api/v1/badges/",)

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


def is_badge_path(path: str | None) -> bool:
    """True for the trust-badge endpoints (SVG, embed, README snippet)."""
    return (path or "").startswith(BADGE_PATH_PREFIXES)


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
    legacy = is_legacy_host(request.headers.get("host"))
    scope = UsageScope(excluded=legacy and not is_badge_path(request.url.path))
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
    from src.api.metrics_dashboard_router import (
        HOOK_PATH_PREFIX,
        bump_metric,
        bump_metric_by_client,
        is_hook_request,
        record_hook_checkin,
        record_human_visitor,
    )

    names = settle(scope, status_code)
    if scope.excluded:
        await bump_metric(REDIRECTED_METRIC)
        return
    for name in names:
        await bump_metric(name)
    # Distinct people per day: only a request that counts as usage AND comes from
    # a browser User-Agent joins the salted HLL (never a bot, never a redirect).
    user_agent = request.headers.get("user-agent", "")
    if classify_user_agent(user_agent) == "human":
        from src.api.rate_limit import _get_client_ip

        await record_human_visitor(_get_client_ip(request), user_agent)
    # Every answered public scan request, split by who sent it (person / agent /
    # script). Counted here, after the handler, so a cached scan (the common case)
    # counts the same as a fresh one; the handlers themselves no longer count.
    path = request.url.path
    if path.startswith(HOOK_PATH_PREFIX) and status_code < 400:
        await bump_metric_by_client("scan_request", user_agent)
    # The Claude Code plugin's session-start hook: same place, same reason.
    if is_hook_request(path, user_agent):
        from src.api.rate_limit import _get_client_ip

        await record_hook_checkin(_get_client_ip(request), user_agent)
