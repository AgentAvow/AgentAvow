"""Every API error is RFC 9457 problem+json with the old fields kept (#409).

Shape tests run on a small app with the real handlers and the real observability
middleware; the integration tests at the bottom go through src.main's app.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import urllib.error
import uuid

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from src.errors import ApiError
from src.errors.handlers import (
    PROBLEM_MEDIA_TYPE,
    field_errors,
    install_problem_handlers,
    is_legacy_path,
)
from src.observability.middleware import ObservabilityMiddleware

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE}-00f067aa0ba902b7-01"
PROBLEM_KEYS = {"type", "title", "status", "code", "detail", "instance", "request_id", "trace_id"}


class Item(BaseModel):
    name: str
    count: int


def _build_app() -> FastAPI:
    app = FastAPI()

    def add(prefix: str) -> None:
        @app.get(prefix + "/status/{code}")
        async def status(code: int):
            raise HTTPException(status_code=code, detail=f"failed with {code}")

        @app.get(prefix + "/dict")
        async def dict_detail():
            raise HTTPException(status_code=400, detail={"reason": "bad", "hint": [1, 2]})

        @app.get(prefix + "/rate")
        async def rate():
            raise HTTPException(status_code=429, detail="Rate limit exceeded",
                                headers={"X-RateLimit-Limit": "60"})

        @app.get(prefix + "/coded")
        async def coded():
            raise ApiError(422, "nope", code="validation_failed")

        @app.get(prefix + "/crash")
        async def crash():
            raise RuntimeError("db password hunter2 at /srv/app/secret.py line 9")

        @app.post(prefix + "/items")
        async def items(item: Item):
            return item

    add("/api/v1")
    add("/mcp")
    add("/.well-known")

    @app.get("/api/v1/public/scan/{owner}/{repo}/badge")
    async def badge(owner: str, repo: str):
        raise HTTPException(status_code=404, detail="Entity not found")

    @app.get("/api/v1/badges/trust/{eid}.svg")
    async def badge_svg(eid: str):
        raise HTTPException(status_code=404, detail="Entity not found")

    install_problem_handlers(app)
    app.add_middleware(ObservabilityMiddleware)
    return app


APP = _build_app()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=APP, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _assert_problem(resp: httpx.Response, status: int, code: str) -> dict:
    assert resp.status_code == status
    assert resp.headers["content-type"] == PROBLEM_MEDIA_TYPE
    body = resp.json()
    assert PROBLEM_KEYS <= set(body)
    assert body["status"] == status
    assert body["code"] == code
    assert body["type"] == f"https://agentavow.com/problems/{code}"
    assert body["title"]
    assert body["request_id"] == resp.headers["x-request-id"]
    return body


# --- shape, per status ---------------------------------------------------------------


@pytest.mark.parametrize("status,code", [
    (400, "bad_request"), (401, "unauthorized"), (403, "forbidden"), (404, "not_found"),
    (405, "method_not_allowed"), (409, "conflict"), (410, "gone"),
    (413, "payload_too_large"), (422, "unprocessable_content"), (429, "rate_limited"),
    (500, "internal_error"), (502, "bad_gateway"), (503, "service_unavailable"),
    (504, "gateway_timeout"), (418, "client_error"), (507, "server_error"),
])
async def test_http_exception_shape_per_status(client, status, code):
    resp = await client.get(f"/api/v1/status/{status}?token=ghp_secret")
    body = _assert_problem(resp, status, code)
    assert body["detail"] == f"failed with {status}"
    assert body["instance"] == f"/api/v1/status/{status}"  # no query string


async def test_trace_id_is_the_request_trace(client):
    resp = await client.get("/api/v1/status/404", headers={"traceparent": TRACEPARENT})
    assert _assert_problem(resp, 404, "not_found")["trace_id"] == TRACE
    resp = await client.get("/api/v1/status/404")
    assert len(_assert_problem(resp, 404, "not_found")["trace_id"]) == 32


async def test_caller_request_id_is_echoed(client):
    resp = await client.get("/api/v1/status/404", headers={"X-Request-ID": "my-req-1"})
    assert _assert_problem(resp, 404, "not_found")["request_id"] == "my-req-1"


async def test_unknown_route_and_wrong_method(client):
    _assert_problem(await client.get("/api/v1/no-such-route"), 404, "not_found")
    body = _assert_problem(await client.delete("/api/v1/items"), 405, "method_not_allowed")
    assert body["detail"] == "Method Not Allowed"


async def test_rate_limit_429_keeps_its_headers(client):
    resp = await client.get("/api/v1/rate")
    body = _assert_problem(resp, 429, "rate_limited")
    assert body["detail"] == "Rate limit exceeded"
    assert resp.headers["x-ratelimit-limit"] == "60"


async def test_api_error_code_is_used(client):
    _assert_problem(await client.get("/api/v1/coded"), 422, "validation_failed")


async def test_validation_error_lists_each_field(client):
    resp = await client.post("/api/v1/items", json={"count": "many"})
    body = _assert_problem(resp, 422, "validation_failed")
    # detail stays the pydantic list (ADR 0005); errors has one entry per field.
    assert isinstance(body["detail"], list) and len(body["detail"]) == 2
    assert {d["loc"][-1] for d in body["detail"]} == {"name", "count"}
    by_field = {e["field"]: e for e in body["errors"]}
    assert set(by_field) == {"name", "count"}
    assert by_field["name"] == {"location": "body", "field": "name",
                                "message": "Field required", "type": "missing"}
    assert by_field["count"]["type"] == "int_parsing"


async def test_unhandled_exception_is_generic(client):
    resp = await client.get("/api/v1/crash")
    body = _assert_problem(resp, 500, "internal_error")
    assert body["detail"] == "Internal server error"
    assert body["title"] == "Internal server error"
    text = resp.text
    for leak in ("hunter2", "secret.py", "RuntimeError", "Traceback", "line 9"):
        assert leak not in text


# --- the old fields keep their exact values ------------------------------------------


@pytest.mark.parametrize("path,method,kwargs", [
    ("/status/404", "get", {}),
    ("/status/503", "get", {}),
    ("/dict", "get", {}),
    ("/rate", "get", {}),
    ("/crash", "get", {}),
    ("/items", "post", {"json": {"count": "many"}}),
])
async def test_detail_and_request_id_match_the_legacy_answer(client, path, method, kwargs):
    """The same error on a legacy path (old handler behaviour) and on an API path:
    `detail` is identical and `request_id` is the response's X-Request-ID."""
    old = await getattr(client, method)("/mcp" + path, headers={"X-Request-ID": "old-1"},
                                        **kwargs)
    new = await getattr(client, method)("/api/v1" + path, headers={"X-Request-ID": "new-1"},
                                        **kwargs)
    assert old.status_code == new.status_code
    assert old.json()["detail"] == new.json()["detail"]
    assert old.json()["request_id"] == "old-1"
    assert new.json()["request_id"] == "new-1" == new.headers["x-request-id"]


async def test_dict_detail_is_passed_through(client):
    body = _assert_problem(await client.get("/api/v1/dict"), 400, "bad_request")
    assert body["detail"] == {"reason": "bad", "hint": [1, 2]}


# --- excluded paths keep the old answer exactly --------------------------------------


@pytest.mark.parametrize("prefix", ["/mcp", "/.well-known"])
@pytest.mark.parametrize("path,method,kwargs,status", [
    ("/status/404", "get", {}, 404),
    ("/rate", "get", {}, 429),
    ("/crash", "get", {}, 500),
    ("/items", "post", {"json": {}}, 422),
])
async def test_excluded_paths_keep_legacy_json(client, prefix, path, method, kwargs, status):
    resp = await getattr(client, method)(prefix + path, **kwargs)
    assert resp.status_code == status
    assert resp.headers["content-type"] == "application/json"
    assert set(resp.json()) == {"detail", "request_id"}


@pytest.mark.parametrize("path", [
    "/api/v1/public/scan/acme/tool/badge",
    # A fixed id: pytest -n workers must all collect the same test ids.
    "/api/v1/badges/trust/00000000-0000-4000-8000-000000000418.svg",
])
async def test_badge_errors_keep_legacy_json(client, path):
    resp = await client.get(path)
    assert resp.status_code == 404
    assert resp.headers["content-type"] == "application/json"
    assert resp.json() == {"detail": "Entity not found",
                           "request_id": resp.headers["x-request-id"]}


@pytest.mark.parametrize("path,legacy", [
    ("/mcp", True), ("/mcp/", True), ("/mcp/x", True), ("/mcpx", False),
    ("/.well-known/jwks.json", True), ("/api/v1/badges/embed/x", True),
    ("/api/v1/badges/readme/x", True), ("/api/v1/public/scan/o/r/badge", True),
    ("/api/v1/public/scan/mcp/badge", True), ("/api/v1/public/scan/o/r/card.svg", True),
    ("/api/v1/public/scan/o/r/og-image", True), ("/api/v1/public/scan/og.png", True),
    ("/api/v1/mcp/tools", False), ("/api/v1/public/scan/o/r", False),
    ("/api/v1/entities/x/badges", False), ("/api/v1/public/scan/o/r/verdict.json", False),
])
def test_is_legacy_path(path, legacy):
    assert is_legacy_path(path) is legacy


def test_field_errors_handles_root_and_nested_locations():
    assert field_errors([
        {"loc": ("body",), "msg": "Invalid JSON", "type": "json_invalid"},
        {"loc": ("body", "items", 0, "name"), "msg": "m", "type": "t"},
        {"loc": ("query", "limit"), "msg": "m", "type": "t"},
        {"loc": ("weird",), "msg": "m", "type": "t"},
    ]) == [
        {"location": "body", "field": None, "message": "Invalid JSON", "type": "json_invalid"},
        {"location": "body", "field": "items.0.name", "message": "m", "type": "t"},
        {"location": "query", "field": "limit", "message": "m", "type": "t"},
        {"location": None, "field": "weird", "message": "m", "type": "t"},
    ]


# --- clients that read `detail` ------------------------------------------------------

_PROBLEM_404 = {
    "type": "https://agentavow.com/problems/not_found", "title": "Not found", "status": 404,
    "code": "not_found", "detail": "Entity not found", "instance": "/api/v1/x",
    "request_id": "r1", "trace_id": TRACE,
}


def _problem_response(status: int, body: dict) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode(),
                          headers={"content-type": PROBLEM_MEDIA_TYPE},
                          request=httpx.Request("GET", "https://agentavow.test/api/v1/x"))


def test_python_sdk_reads_problem_json(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "sdk" / "python"))
    client_mod = pytest.importorskip("agentgraph.client")
    exc_mod = pytest.importorskip("agentgraph.exceptions")
    c = client_mod.AgentGraphClient("https://agentavow.test")
    with pytest.raises(exc_mod.NotFoundError) as err:
        c._parse_response(_problem_response(404, _PROBLEM_404))
    assert err.value.message == "Entity not found"
    body = {**_PROBLEM_404, "status": 409, "code": "conflict", "detail": "Already exists"}
    with pytest.raises(exc_mod.AgentGraphError) as err:
        c._parse_response(_problem_response(409, body))
    assert err.value.message == "Already exists" and err.value.status_code == 409


@pytest.mark.parametrize("script", [
    ROOT / "plugins" / "agentavow-trust" / "scripts" / "agentavow_precheck.py",
    ROOT / "integrations" / "claude-code" / "agentavow_precheck.py",
])
def test_plugin_hook_reads_problem_json(script, monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(f"precheck_409_{script.parent.name}", script)
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    monkeypatch.setattr(hook, "CACHE", tmp_path / "scanned.json")

    def refuse(*_a, **_k):
        raise urllib.error.HTTPError(
            "https://agentavow.test", 404, "Not Found",
            {"Content-Type": PROBLEM_MEDIA_TYPE}, io.BytesIO(json.dumps(_PROBLEM_404).encode()),
        )

    monkeypatch.setattr(hook.urllib.request, "urlopen", refuse)
    with pytest.raises(hook._UnscannableError, match="Entity not found"):
        hook._fetch("/public/scan/acme/tool", {})


# --- through src.main's app ----------------------------------------------------------


@pytest_asyncio.fixture
async def main_client(db):
    from src.database import get_db
    from src.main import app

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


async def test_main_app_unknown_route_is_problem_json(main_client):
    resp = await main_client.get("/api/v1/definitely-not-a-route")
    body = _assert_problem(resp, 404, "not_found")
    assert body["detail"] == "Not Found"


async def test_main_app_validation_error_is_problem_json(main_client):
    resp = await main_client.post("/api/v1/auth/register", json={"email": "x"})
    body = _assert_problem(resp, 422, "validation_failed")
    assert isinstance(body["detail"], list)
    assert {"password", "display_name"} <= {e["field"] for e in body["errors"]}


async def test_main_app_badge_404_is_unchanged(main_client):
    resp = await main_client.get(f"/api/v1/badges/trust/{uuid.uuid4()}.svg")
    assert resp.status_code == 404
    assert resp.headers["content-type"] == "application/json"
    assert resp.json() == {"detail": "Entity not found",
                           "request_id": resp.headers["x-request-id"]}


async def test_main_app_badge_success_is_still_svg(main_client):
    resp = await main_client.get("/api/v1/public/scan/npm/x/badge?metric=adoption")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/svg+xml")


async def test_main_app_badge_validation_error_is_unchanged(main_client):
    resp = await main_client.get("/api/v1/public/scan/o/r/badge?style=bogus")
    assert resp.status_code == 422
    assert resp.headers["content-type"] == "application/json"
    assert set(resp.json()) == {"detail", "request_id"}


async def test_main_app_well_known_error_is_unchanged(main_client):
    for resp in (await main_client.get("/.well-known/no-such-document.json"),
                 await main_client.post("/.well-known/jwks.json")):
        assert resp.status_code in (404, 405)
        assert resp.headers["content-type"] == "application/json"
        assert set(resp.json()) == {"detail", "request_id"}


async def test_main_app_mcp_error_stays_json_rpc(main_client):
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    from src.bridges import mcp_streamable as m

    sm = StreamableHTTPSessionManager(app=m.server, json_response=m.session_manager.json_response,
                                      stateless=m.session_manager.stateless)
    saved = m.session_manager
    async with sm.run():
        m.session_manager = sm
        try:
            resp = await main_client.post(
                "/mcp/", content=b"{not json",
                headers={"content-type": "application/json",
                         "accept": "application/json, text/event-stream",
                         "mcp-protocol-version": "2025-11-25"},
            )
        finally:
            m.session_manager = saved
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["jsonrpc"] == "2.0" and body["error"]["code"] == -32700
    assert "type" not in body and "code" not in body
