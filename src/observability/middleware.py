"""Request correlation middleware: request id, W3C trace context and the access log.

A plain ASGI middleware (not ``BaseHTTPMiddleware``) installed outermost, so the ids
it binds are visible to every middleware, route and task under it.

* ``X-Request-ID``: a caller's value is kept when it is 1-128 characters of
  ``A-Z a-z 0-9 . _ : -``; anything else is replaced. Otherwise a 32-character id is
  generated. The response always carries it.
* ``traceparent``: a valid caller header continues that trace with a new server span;
  otherwise a new trace starts. The response carries this server's ``traceparent``.
* One access line per request (method, path, status, duration), skipping the health
  probes passed in ``skip_log_paths``.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Iterable

from src.observability.context import bind, unbind
from src.observability.tracing import start_server_span

logger = logging.getLogger("src.main")

REQUEST_ID_HEADER = "x-request-id"
_REQUEST_ID_OK = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def new_request_id() -> str:
    return uuid.uuid4().hex


def accept_request_id(value: str | None) -> str:
    """The caller's request id when it is safe to echo and log, else a fresh one."""
    if value and _REQUEST_ID_OK.fullmatch(value):
        return value
    return new_request_id()


def _header(scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            try:
                return value.decode("latin-1")
            except Exception:  # noqa: BLE001
                return None
    return None


class ObservabilityMiddleware:
    def __init__(self, app, skip_log_paths: Iterable[str] = ()) -> None:
        self.app = app
        self.skip_log_paths = frozenset(skip_log_paths)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = accept_request_id(_header(scope, b"x-request-id"))
        trace = start_server_span(_header(scope, b"traceparent"))
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["trace_id"] = trace.trace_id
        state["span_id"] = trace.span_id

        status_holder = {"status": 500}
        start = time.monotonic()

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = [
                    (k, v) for k, v in message.get("headers", [])
                    if k.lower() not in (b"x-request-id", b"traceparent")
                ]
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                headers.append((b"traceparent", trace.traceparent.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        tokens = bind(request_id, trace.trace_id, trace.span_id)
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            if path not in self.skip_log_paths:
                duration_ms = round((time.monotonic() - start) * 1000, 1)
                method = scope.get("method", "-")
                client = scope.get("client")
                logger.info(
                    "%s %s %s %.1fms",
                    method, path, status_holder["status"], duration_ms,
                    extra={
                        "method": method,
                        "path": path,
                        "status_code": status_holder["status"],
                        "duration_ms": duration_ms,
                        "client_ip": client[0] if client else "-",
                        "entity_id": state.get("entity_id", "-"),
                    },
                )
            unbind(tokens)
