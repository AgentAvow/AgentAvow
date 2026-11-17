"""Per-request correlation ids, held in contextvars.

Set once by the request middleware (src/observability/middleware.py) and read by the
log formatter, so every line logged while a request is being served carries the same
``request_id`` and ``trace_id`` without passing them around. Tasks started during a
request copy the context, so their lines carry them too.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

request_id_var: ContextVar[str | None] = ContextVar("agentavow_request_id", default=None)
trace_id_var: ContextVar[str | None] = ContextVar("agentavow_trace_id", default=None)
span_id_var: ContextVar[str | None] = ContextVar("agentavow_span_id", default=None)


@dataclass(frozen=True)
class _Tokens:
    request_id: Token
    trace_id: Token
    span_id: Token


def bind(request_id: str, trace_id: str, span_id: str) -> _Tokens:
    """Set the ids for the current context; pass the result to ``unbind``."""
    return _Tokens(
        request_id_var.set(request_id),
        trace_id_var.set(trace_id),
        span_id_var.set(span_id),
    )


def unbind(tokens: _Tokens) -> None:
    request_id_var.reset(tokens.request_id)
    trace_id_var.reset(tokens.trace_id)
    span_id_var.reset(tokens.span_id)


def current_request_id() -> str | None:
    return request_id_var.get()


def current_trace_id() -> str | None:
    return trace_id_var.get()


def current_span_id() -> str | None:
    return span_id_var.get()
