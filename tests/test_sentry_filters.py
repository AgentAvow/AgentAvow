"""Tests for the Sentry before_send filter (src/sentry_filters.py)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from src.sentry_filters import before_send


class EndOfStream(Exception):  # noqa: N818 — mirrors anyio.EndOfStream by name
    pass


class ClientDisconnect(Exception):  # noqa: N818 — mirrors starlette's by name
    pass


def _event(url: str | None = None, **extra) -> dict:
    ev: dict = dict(extra)
    if url:
        ev["request"] = {"url": url}
    return ev


def _hint(exc: BaseException | None) -> dict:
    return {"exc_info": (type(exc), exc, None)} if exc else {}


@pytest.mark.parametrize("exc", [
    RuntimeError("No response returned."),
    EndOfStream(),
    ClientDisconnect(),
])
@pytest.mark.parametrize("url", ["https://agentavow.com/mcp", "https://agentavow.com/mcp/"])
def test_mcp_client_disconnects_are_dropped(exc, url):
    assert before_send(_event(url), _hint(exc)) is None


def test_wrapped_disconnect_is_dropped():
    try:
        try:
            raise EndOfStream()
        except EndOfStream as inner:
            raise RuntimeError("No response returned.") from inner
    except RuntimeError as outer:
        assert before_send(_event("https://agentavow.com/mcp/"), _hint(outer)) is None


def test_disconnect_inside_exception_group_is_dropped():
    class TaskGroupError(Exception):  # shaped like ExceptionGroup (py311+)
        exceptions = (ClientDisconnect(),)

    group = TaskGroupError("unhandled errors in a TaskGroup")
    assert before_send(_event("https://agentavow.com/mcp"), _hint(group)) is None


def test_mcp_sdk_stream_log_is_dropped():
    ev = _event(logger="mcp.server.streamable_http",
                logentry={"message": "Received exception from stream: "})
    assert before_send(ev, {}) is None


@pytest.mark.parametrize("exc", [
    ValueError("boom"),
    RuntimeError("something else broke"),
    KeyError("tool"),
])
def test_real_mcp_errors_still_report(exc):
    ev = _event("https://agentavow.com/mcp")
    assert before_send(ev, _hint(exc)) is ev


@pytest.mark.parametrize("url", [
    "https://agentavow.com/api/v1/public/scan/mcp",
    "https://agentavow.com/mcpx",
    "https://agentavow.com/api/v1/feed",
])
def test_same_exception_elsewhere_still_reports(url):
    ev = _event(url)
    assert before_send(ev, _hint(RuntimeError("No response returned."))) is ev


def test_disconnect_logged_by_uvicorn_without_a_request_url_is_dropped():
    """BACKEND-28: uvicorn's 'Exception in ASGI application' log event carries no
    request context, so the /mcp path gate never sees it. The RuntimeError only exists
    when the client went away; with no URL it is dropped on the exception alone."""
    ev = _event(logger="uvicorn.error", logentry={"message": "Exception in ASGI application"})
    assert before_send(ev, _hint(RuntimeError("No response returned."))) is None


def test_other_runtime_errors_without_a_url_still_report():
    ev = _event(logger="uvicorn.error")
    assert before_send(ev, _hint(RuntimeError("boom"))) is ev


def test_designed_scan_timeout_is_dropped():
    exc = HTTPException(status_code=503, detail="Scan is taking longer than usual.")
    assert before_send(_event("https://agentavow.com/api/v1/public/scan/x/y"), _hint(exc)) is None


def test_other_503_still_reports():
    ev = _event("https://agentavow.com/api/v1/public/scan/x/y")
    exc = HTTPException(status_code=503, detail="Database unavailable")
    assert before_send(ev, _hint(exc)) is ev


def test_event_without_hint_passes_through():
    ev = _event("https://agentavow.com/")
    assert before_send(ev, None) is ev
