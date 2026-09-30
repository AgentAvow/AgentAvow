"""Sentry ``before_send`` filter: drop events that are expected behavior, not errors.

Kept free of app imports so it can be unit-tested without booting FastAPI.
"""
from __future__ import annotations

from urllib.parse import urlsplit

# A client that opens the GET SSE stream on /mcp and then goes away (uptime monitors,
# a closed laptop) surfaces through Starlette's BaseHTTPMiddleware as one of these.
# Tool calls ride separate POSTs and are unaffected.
_MCP_DISCONNECT_TYPES = frozenset({"EndOfStream", "ClientDisconnect"})
_MCP_DISCONNECT_MESSAGES = ("No response returned", "Received exception from stream")


def _exception_chain(exc: BaseException | None):
    """Yield *exc* and everything it wraps (causes, contexts, exception groups)."""
    seen: set[int] = set()
    stack = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        stack.extend(getattr(e, "exceptions", None) or ())
        stack.append(e.__cause__)
        stack.append(e.__context__)


def _is_scan_timeout(exc: BaseException | None) -> bool:
    """The designed large-scan cap: HTTPException(503, 'Scan is taking longer…') tells
    the caller to retry and the result caches. Genuine 5xx still report."""
    return (
        getattr(exc, "status_code", None) == 503
        and "taking longer" in str(getattr(exc, "detail", "")).lower()
    )


def _is_mcp_client_disconnect(event: dict, exc: BaseException | None) -> bool:
    path = urlsplit((event.get("request") or {}).get("url") or "").path
    logger_name = event.get("logger") or ""
    if not (path == "/mcp" or path.startswith("/mcp/") or logger_name.startswith("mcp.")):
        return False
    for e in _exception_chain(exc):
        if type(e).__name__ in _MCP_DISCONNECT_TYPES:
            return True
        if isinstance(e, RuntimeError) and _MCP_DISCONNECT_MESSAGES[0] in str(e):
            return True
    message = str((event.get("logentry") or {}).get("message") or event.get("message") or "")
    return any(m in message for m in _MCP_DISCONNECT_MESSAGES)


def before_send(event: dict, hint: dict | None) -> dict | None:
    exc_info = hint.get("exc_info") if hint else None
    exc = exc_info[1] if exc_info else None
    if _is_scan_timeout(exc) or _is_mcp_client_disconnect(event, exc):
        return None
    return event
