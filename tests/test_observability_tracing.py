"""Request ids, W3C traceparent and per-line correlation (#405)."""
from __future__ import annotations

import io
import json
import logging
import re

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from src.observability.context import current_request_id, current_trace_id
from src.observability.logs import JSONFormatter, TextFormatter, resolve_format
from src.observability.middleware import ObservabilityMiddleware, accept_request_id
from src.observability.tracing import parse_traceparent, start_server_span

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT = "00f067aa0ba902b7"
VALID = f"00-{TRACE}-{PARENT}-01"
_TP = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-0[01]")

# --- traceparent parsing ---------------------------------------------------------------


def test_parse_valid():
    assert parse_traceparent(VALID) == (TRACE, PARENT, "01")


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "garbage",
        f"00-{TRACE.upper()}-{PARENT}-01",          # uppercase hex
        f"00-{'0' * 32}-{PARENT}-01",               # all-zero trace id
        f"00-{TRACE}-{'0' * 16}-01",                # all-zero parent id
        f"ff-{TRACE}-{PARENT}-01",                  # forbidden version
        f"00-{TRACE}-{PARENT}-01-extra",            # v00 has exactly four fields
        f"00-{TRACE[:-1]}-{PARENT}-01",             # short trace id
        f"00-{TRACE}-{PARENT}-1",                   # short flags
        f"0x-{TRACE}-{PARENT}-01",                  # non-hex version
        "00-" + "a" * 600,                          # far too long
    ],
)
def test_parse_invalid(header):
    assert parse_traceparent(header) is None


def test_future_version_may_append_fields():
    assert parse_traceparent(f"01-{TRACE}-{PARENT}-01-whatever") == (TRACE, PARENT, "01")


def test_server_span_continues_valid_trace():
    ctx = start_server_span(VALID)
    assert ctx.trace_id == TRACE
    assert ctx.parent_id == PARENT
    assert ctx.span_id != PARENT and re.fullmatch(r"[0-9a-f]{16}", ctx.span_id)
    assert ctx.traceparent == f"00-{TRACE}-{ctx.span_id}-01"


def test_server_span_keeps_only_sampled_flag():
    assert start_server_span(f"00-{TRACE}-{PARENT}-00").flags == "00"
    assert start_server_span(f"00-{TRACE}-{PARENT}-03").flags == "01"


def test_server_span_starts_new_trace_without_header():
    a, b = start_server_span(None), start_server_span("nonsense")
    assert a.parent_id is None and b.parent_id is None
    assert a.trace_id != b.trace_id
    assert _TP.fullmatch(a.traceparent)


# --- request id ------------------------------------------------------------------------


def test_generated_request_id_is_long():
    rid = accept_request_id(None)
    assert re.fullmatch(r"[0-9a-f]{32}", rid)


@pytest.mark.parametrize("good", ["abc", "req-123_x.y:z", "a" * 128, "0123456789abcdef"])
def test_caller_request_id_kept_when_safe(good):
    assert accept_request_id(good) == good


@pytest.mark.parametrize(
    "bad", ["", "a" * 129, "has space", "new\nline", "quote\"", "<script>", "ü-unicode"],
)
def test_caller_request_id_replaced_when_unsafe(bad):
    rid = accept_request_id(bad)
    assert rid != bad
    assert re.fullmatch(r"[0-9a-f]{32}", rid)


# --- middleware, end to end on a small app ---------------------------------------------


@pytest.fixture
def captured():
    """JSON lines written by the root logger while the test runs."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        yield lambda: [json.loads(line) for line in buf.getvalue().splitlines() if line]
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


class _InnerHTTPMiddleware(BaseHTTPMiddleware):
    """A BaseHTTPMiddleware under ours, like the ones in src/main.py."""

    async def dispatch(self, request, call_next):
        logging.getLogger("test.inner").info("inner middleware saw request")
        return await call_next(request)


async def _route(request):
    logging.getLogger("test.route").info("handling request")
    return JSONResponse({
        "rid": current_request_id(),
        "tid": current_trace_id(),
        "state_rid": request.state.request_id,
    })


async def _boom(request):
    raise RuntimeError("kaboom")


def _app() -> Starlette:
    app = Starlette(routes=[Route("/x", _route), Route("/health", _route), Route("/boom", _boom)])
    app.add_middleware(_InnerHTTPMiddleware)
    app.add_middleware(ObservabilityMiddleware, skip_log_paths={"/health"})
    return app


async def _get(path: str, headers: dict | None = None):
    transport = ASGITransport(app=_app(), raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        return await c.get(path, headers=headers or {})


async def test_response_carries_generated_ids(captured):
    r = await _get("/x")
    rid = r.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", rid)
    m = _TP.fullmatch(r.headers["traceparent"])
    assert m
    body = r.json()
    assert body == {"rid": rid, "tid": m.group(1), "state_rid": rid}


async def test_caller_request_id_and_trace_are_reused(captured):
    r = await _get("/x", {"X-Request-ID": "caller-req-42", "traceparent": VALID})
    assert r.headers["x-request-id"] == "caller-req-42"
    m = _TP.fullmatch(r.headers["traceparent"])
    assert m.group(1) == TRACE
    assert m.group(2) != PARENT  # our own span


async def test_bad_caller_request_id_is_replaced(captured):
    r = await _get("/x", {"X-Request-ID": "x" * 300})
    assert r.headers["x-request-id"] != "x" * 300
    assert re.fullmatch(r"[0-9a-f]{32}", r.headers["x-request-id"])


async def test_every_line_in_a_request_carries_ids(captured):
    r = await _get("/x", {"traceparent": VALID})
    rid = r.headers["x-request-id"]
    # The test client's own "HTTP Request" line is logged outside the request.
    lines = [e for e in captured() if e["logger"] != "httpx"]
    msgs = {e["message"] for e in lines}
    assert "inner middleware saw request" in msgs
    assert "handling request" in msgs
    assert any(e.get("path") == "/x" and e.get("status_code") == 200 for e in lines)
    for e in lines:
        assert e["request_id"] == rid, e
        assert e["trace_id"] == TRACE, e


async def test_probe_paths_are_not_access_logged(captured):
    await _get("/health")
    assert not any(e.get("path") == "/health" for e in captured())


async def test_unhandled_error_is_access_logged_as_500(captured):
    r = await _get("/boom")
    assert r.status_code == 500
    access = [e for e in captured() if e.get("path") == "/boom"]
    assert access and access[0]["status_code"] == 500


async def test_ids_do_not_leak_past_the_request(captured):
    await _get("/x")
    assert current_request_id() is None
    assert current_trace_id() is None


# --- the real app ----------------------------------------------------------------------


@pytest.fixture
async def client():
    from src.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_main_app_echoes_request_id_and_traceparent(client):
    r = await client.get("/livez", headers={"X-Request-ID": "probe-1", "traceparent": VALID})
    assert r.headers["x-request-id"] == "probe-1"
    assert _TP.fullmatch(r.headers["traceparent"]).group(1) == TRACE


async def test_main_app_error_body_request_id_matches_header(client):
    r = await client.get("/api/v1/definitely-not-a-route-405")
    assert r.status_code == 404
    assert r.json()["request_id"] == r.headers["x-request-id"]


def test_main_app_observability_is_outermost():
    from src.main import app

    assert app.user_middleware[0].cls is ObservabilityMiddleware


# --- format selection ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "debug", "expected"),
    [("", True, "text"), ("", False, "json"), ("json", True, "json"), ("text", False, "text")],
)
def test_resolve_format(fmt, debug, expected):
    assert resolve_format(fmt, debug) == expected


def test_json_line_is_one_object_with_ids():
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(JSONFormatter())
    lg = logging.getLogger("test.oneline")
    lg.handlers, lg.propagate = [h], False
    lg.info("multi\nline message", extra={"request_id": "r1", "trace_id": TRACE})
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["message"] == "multi\nline message"
    assert entry["request_id"] == "r1" and entry["trace_id"] == TRACE
    assert {"timestamp", "level", "logger"} <= entry.keys()


def test_text_format_names_request_id():
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(TextFormatter())
    lg = logging.getLogger("test.text")
    lg.handlers, lg.propagate = [h], False
    lg.info("hello", extra={"request_id": "r2"})
    assert "hello" in buf.getvalue() and "[request_id=r2]" in buf.getvalue()


def test_log_format_setting_is_validated():
    from src.config import ConfigError, load_settings

    assert load_settings(log_format="JSON").log_format == "json"
    with pytest.raises(ConfigError, match="LOG_FORMAT"):
        load_settings(log_format="xml")
