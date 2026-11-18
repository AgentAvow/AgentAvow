"""Optional Idempotency-Key on POST and PATCH, stored in Redis (#407, ADR 0007).

The first part runs a small app with the real middleware, the real problem handlers
and the real observability middleware against the test Redis (REDIS_URL). The second
part goes through src.main's app: watches, two accounts with one key, exclusions and
the OpenAPI document.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from httpx import ASGITransport, AsyncClient

from src import idempotency
from src.errors.handlers import PROBLEM_MEDIA_TYPE, install_problem_handlers
from src.idempotency import (
    HEADER,
    IN_FLIGHT_TTL_SECONDS,
    INVALID_CREDENTIAL,
    MAX_STORED_BODY_BYTES,
    RECORD_TTL_SECONDS,
    SECRET_FIELD_RE,
    IdempotencyMiddleware,
    caller_subject,
    carries_secret,
    is_covered,
    storage_key,
    valid_key,
)
from src.observability.middleware import ObservabilityMiddleware

REPLAYED = "idempotent-replayed"


def _redis():
    from src.redis_client import get_redis

    return get_redis()


def _down_redis():
    # Nothing listens on port 1: every call fails to connect.
    return aioredis.Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.2)


class Counter:
    def __init__(self) -> None:
        self.calls = 0
        self.gate: asyncio.Event | None = None
        self.entered = asyncio.Event()


def _build_app(counter: Counter, redis_factory=_redis) -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/things", status_code=201)
    async def create(request: Request, response: Response):
        counter.calls += 1
        counter.entered.set()
        if counter.gate is not None:
            await counter.gate.wait()
        body = await request.json()
        response.headers["Location"] = f"/api/v1/things/{counter.calls}"
        response.headers["Set-Cookie"] = "session=abc"
        return {"n": counter.calls, "echo": body}

    @app.patch("/api/v1/things/{tid}")
    async def update(tid: str, request: Request):
        counter.calls += 1
        return {"n": counter.calls, "tid": tid, "echo": await request.json()}

    @app.post("/api/v1/flaky")
    async def flaky():
        counter.calls += 1
        if counter.calls == 1:
            raise HTTPException(status_code=503, detail="try again")
        return {"n": counter.calls}

    @app.post("/api/v1/crash")
    async def crash():
        counter.calls += 1
        raise RuntimeError("boom")

    @app.post("/api/v1/missing")
    async def missing():
        counter.calls += 1
        raise HTTPException(status_code=404, detail="no such thing")

    @app.post("/api/v1/big")
    async def big():
        counter.calls += 1
        return Response(b"x" * (MAX_STORED_BODY_BYTES + 1), media_type="text/plain")

    @app.post("/api/v1/stream")
    async def stream():
        counter.calls += 1

        async def gen():
            yield b"data: 1\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/v1/public/scan/beacon/{event}")
    async def beacon(event: str):
        counter.calls += 1
        return {"n": counter.calls}

    @app.post("/api/v1/leaky")
    async def leaky():
        counter.calls += 1
        return {"n": counter.calls, "nested": {"signing_secret": "whsec_x"}}

    @app.post("/api/v1/auth/login")
    async def login():
        counter.calls += 1
        return {"n": counter.calls}

    @app.put("/api/v1/things/{tid}")
    async def put(tid: str):
        counter.calls += 1
        return {"n": counter.calls}

    install_problem_handlers(app)
    app.add_middleware(IdempotencyMiddleware, redis_factory=redis_factory)
    app.add_middleware(ObservabilityMiddleware)
    return app


@pytest_asyncio.fixture
async def counter():
    return Counter()


@pytest_asyncio.fixture
async def client(counter):
    transport = ASGITransport(app=_build_app(counter), raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def down_client(counter):
    app = _build_app(counter, redis_factory=_down_redis)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _key() -> str:
    return f"test-{uuid.uuid4()}"


def _assert_problem(resp, status: int, code: str) -> dict:
    assert resp.status_code == status, resp.text
    assert resp.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)
    body = resp.json()
    assert body["code"] == code and body["status"] == status
    assert body["request_id"] == resp.headers["x-request-id"]
    return body


# --- replay ----------------------------------------------------------------------


async def test_repeat_with_same_key_and_body_replays_first_answer(client, counter):
    key = _key()
    first = await client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key})
    second = await client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key})
    assert counter.calls == 1
    assert first.status_code == second.status_code == 201
    assert second.json() == first.json() == {"n": 1, "echo": {"a": 1}}
    assert REPLAYED not in first.headers
    assert second.headers[REPLAYED] == "true"
    # Headers that describe the result are repeated; the cookie and ids are not.
    assert second.headers["location"] == first.headers["location"]
    assert second.headers["content-type"] == first.headers["content-type"]
    assert "set-cookie" in first.headers and "set-cookie" not in second.headers
    assert second.headers["x-request-id"] != first.headers["x-request-id"]


async def test_patch_is_covered(client, counter):
    key = _key()
    a = await client.patch("/api/v1/things/7", json={"b": 2}, headers={HEADER: key})
    b = await client.patch("/api/v1/things/7", json={"b": 2}, headers={HEADER: key})
    assert counter.calls == 1 and a.json() == b.json() and b.headers[REPLAYED] == "true"


async def test_same_key_on_another_path_is_another_record(client, counter):
    key = _key()
    await client.patch("/api/v1/things/1", json={}, headers={HEADER: key})
    r = await client.patch("/api/v1/things/2", json={}, headers={HEADER: key})
    assert counter.calls == 2 and REPLAYED not in r.headers


async def test_stored_4xx_is_replayed(client, counter):
    key = _key()
    a = await client.post("/api/v1/missing", headers={HEADER: key})
    b = await client.post("/api/v1/missing", headers={HEADER: key})
    assert a.status_code == b.status_code == 404
    assert b.headers[REPLAYED] == "true" and counter.calls == 1
    assert b.json()["detail"] == "no such thing"


# --- misuse ----------------------------------------------------------------------


async def test_same_key_with_different_body_is_422(client, counter):
    key = _key()
    await client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key})
    r = await client.post("/api/v1/things", json={"a": 2}, headers={HEADER: key})
    _assert_problem(r, 422, "idempotency_key_reused")
    assert counter.calls == 1


async def test_same_key_with_different_query_is_422(client, counter):
    key = _key()
    await client.post("/api/v1/things?x=1", json={}, headers={HEADER: key})
    r = await client.post("/api/v1/things?x=2", json={}, headers={HEADER: key})
    _assert_problem(r, 422, "idempotency_key_reused")


async def test_repeat_while_first_is_running_is_409_with_retry_after(client, counter):
    key = _key()
    counter.gate = asyncio.Event()
    first = asyncio.create_task(
        client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key}),
    )
    await asyncio.wait_for(counter.entered.wait(), 5)
    r = await client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key})
    body = _assert_problem(r, 409, "idempotency_key_in_use")
    assert r.headers["retry-after"] == idempotency.IN_USE_RETRY_AFTER
    assert body["instance"] == "/api/v1/things"
    # A different body while it runs is still misuse, not "wait".
    r2 = await client.post("/api/v1/things", json={"a": 9}, headers={HEADER: key})
    _assert_problem(r2, 422, "idempotency_key_reused")
    counter.gate.set()
    done = await first
    assert done.status_code == 201
    again = await client.post("/api/v1/things", json={"a": 1}, headers={HEADER: key})
    assert again.headers[REPLAYED] == "true" and counter.calls == 1


@pytest.mark.parametrize("bad", ["", "   ", "x" * 256, "café", "tab\there"])
async def test_invalid_key_is_400(client, counter, bad):
    r = await client.post(
        "/api/v1/things", json={}, headers=[(HEADER, bad.encode("utf-8"))],
    )
    _assert_problem(r, 400, "idempotency_key_invalid")
    assert counter.calls == 0


async def test_two_key_headers_are_400(client, counter):
    r = await client.post("/api/v1/things", json={}, headers=[(HEADER, "a"), (HEADER, "b")])
    _assert_problem(r, 400, "idempotency_key_invalid")
    assert counter.calls == 0


def test_valid_key_bounds():
    assert valid_key("a") and valid_key("x" * 255) and valid_key("a b~!")
    assert not valid_key("") and not valid_key("x" * 256) and not valid_key("\x7f")


# --- what is not stored ----------------------------------------------------------


async def test_unkeyed_write_runs_every_time(client, counter):
    a = await client.post("/api/v1/things", json={"a": 1})
    b = await client.post("/api/v1/things", json={"a": 1})
    assert counter.calls == 2
    assert a.json()["n"] == 1 and b.json()["n"] == 2
    assert REPLAYED not in b.headers


async def test_5xx_answer_is_not_stored_so_retry_runs(client, counter):
    key = _key()
    a = await client.post("/api/v1/flaky", headers={HEADER: key})
    b = await client.post("/api/v1/flaky", headers={HEADER: key})
    assert a.status_code == 503 and b.status_code == 200 and counter.calls == 2
    c = await client.post("/api/v1/flaky", headers={HEADER: key})
    assert c.headers[REPLAYED] == "true" and counter.calls == 2


async def test_unhandled_exception_frees_the_key(client, counter):
    key = _key()
    a = await client.post("/api/v1/crash", headers={HEADER: key})
    b = await client.post("/api/v1/crash", headers={HEADER: key})
    assert a.status_code == b.status_code == 500 and counter.calls == 2


async def test_oversized_and_streamed_answers_pass_through_and_are_not_stored(
    client, counter,
):
    key = _key()
    a = await client.post("/api/v1/big", headers={HEADER: key})
    assert len(a.content) == MAX_STORED_BODY_BYTES + 1
    await client.post("/api/v1/big", headers={HEADER: key})
    assert counter.calls == 2
    key2 = _key()
    s = await client.post("/api/v1/stream", headers={HEADER: key2})
    assert s.text == "data: 1\n\n"
    await client.post("/api/v1/stream", headers={HEADER: key2})
    assert counter.calls == 4


# --- exclusions ------------------------------------------------------------------


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/v1/public/scan/beacon/install"),
    ("POST", "/api/v1/auth/login"),
    ("PUT", "/api/v1/things/1"),
])
async def test_excluded_routes_ignore_the_header(client, counter, method, path):
    key = _key()
    a = await client.request(method, path, headers={HEADER: key})
    b = await client.request(method, path, headers={HEADER: key})
    assert a.status_code == b.status_code == 200
    assert counter.calls == 2 and REPLAYED not in b.headers
    # Not even validated there.
    c = await client.request(method, path, headers={HEADER: "x" * 300})
    assert c.status_code == 200


@pytest.mark.parametrize("path", [
    "/mcp", "/mcp/", "/api/v1/public/scan", "/api/v1/public/scan/submit",
    "/api/v1/public/scan/beacon/install", "/api/v1/public/plugin/active",
    "/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/sso/saml/callback",
    "/api/v1/marketplace/stripe/webhook", "/api/v1/gateway/webhook/rescan",
    "/api/v1/mcp/tools/call", "/health",
])
def test_excluded_paths(path):
    assert not is_covered("POST", path)


@pytest.mark.parametrize("path", [
    "/api/v1/watches", "/api/v1/account/claims", "/api/v1/account/claims/1/verify",
    "/api/v1/account/alert-webhook/test", "/api/v1/webhooks/w1",
    "/api/v1/account/github-app/claim-repo", "/api/v1/public/send-setup",
])
def test_covered_paths(path):
    assert is_covered("POST", path) and is_covered("PATCH", path)
    assert not is_covered("GET", path) and not is_covered("PUT", path)
    assert not is_covered("DELETE", path)


# --- Redis down ------------------------------------------------------------------


async def test_redis_down_with_key_is_503_and_write_does_not_run(down_client, counter):
    r = await down_client.post("/api/v1/things", json={"a": 1}, headers={HEADER: _key()})
    _assert_problem(r, 503, "idempotency_unavailable")
    assert r.headers["retry-after"] == idempotency.UNAVAILABLE_RETRY_AFTER
    assert counter.calls == 0


async def test_redis_down_without_key_works_as_today(down_client, counter):
    r = await down_client.post("/api/v1/things", json={"a": 1})
    assert r.status_code == 201 and r.json()["n"] == 1 and counter.calls == 1
    r = await down_client.post("/api/v1/public/scan/beacon/x", headers={HEADER: _key()})
    assert r.status_code == 200 and counter.calls == 2


# --- TTL -------------------------------------------------------------------------


async def test_record_ttl_and_in_flight_ttl(client, counter):
    key = _key()
    rkey = storage_key("anon", "POST", "/api/v1/things", key)
    redis = _redis()
    counter.gate = asyncio.Event()
    task = asyncio.create_task(client.post("/api/v1/things", json={}, headers={HEADER: key}))
    await asyncio.wait_for(counter.entered.wait(), 5)
    ttl = await redis.ttl(rkey)
    assert 0 < ttl <= IN_FLIGHT_TTL_SECONDS
    counter.gate.set()
    await task
    ttl = await redis.ttl(rkey)
    assert IN_FLIGHT_TTL_SECONDS < ttl <= RECORD_TTL_SECONDS
    # Once the record expires, the key runs the write again.
    await redis.delete(rkey)
    r = await client.post("/api/v1/things", json={}, headers={HEADER: key})
    assert REPLAYED not in r.headers and counter.calls == 2


async def test_raw_key_and_credentials_are_not_in_redis_key_names(client):
    key = _key()
    await client.post("/api/v1/things", json={}, headers={HEADER: key, "X-API-Key": "sekrit"})
    rkey = storage_key(caller_subject({b"x-api-key": b"sekrit"}), "POST",
                       "/api/v1/things", key)
    assert await _redis().exists(rkey)
    assert key not in rkey and "sekrit" not in rkey


# --- caller scope ----------------------------------------------------------------


async def test_callers_with_the_same_key_do_not_share_answers(client, counter):
    key = _key()
    a = await client.post("/api/v1/things", json={}, headers={HEADER: key, "X-API-Key": "k1"})
    b = await client.post("/api/v1/things", json={}, headers={HEADER: key, "X-API-Key": "k2"})
    c = await client.post("/api/v1/things", json={}, headers={HEADER: key})
    assert counter.calls == 3
    assert {a.json()["n"], b.json()["n"], c.json()["n"]} == {1, 2, 3}
    assert REPLAYED not in b.headers and REPLAYED not in c.headers


def test_caller_subject():
    from src.api.auth_service import create_access_token

    sub = uuid.uuid4()
    tok = create_access_token(sub, "human")
    assert caller_subject({b"authorization": f"Bearer {tok}".encode()}) == f"sub:{sub}"
    assert caller_subject({}) == "anon"
    assert caller_subject({b"authorization": b"Bearer not-a-jwt"}) == INVALID_CREDENTIAL
    assert caller_subject({b"authorization": b"Basic abc"}) == INVALID_CREDENTIAL
    # The API key decides, as in get_current_entity.
    both = {b"x-api-key": b"k", b"authorization": f"Bearer {tok}".encode()}
    assert caller_subject(both).startswith("apikey:")


# --- through src.main's app ------------------------------------------------------


@pytest_asyncio.fixture
async def main_client(db, monkeypatch):
    from src.api import watch_router
    from src.database import get_db
    from src.main import app

    scans: list[tuple] = []

    async def fake_scan(surface, owner, repo, db_):
        scans.append((surface, owner, repo))
        return watch_router.WatchScan(None, None)

    monkeypatch.setattr(watch_router, "scan_watch_target_detail", fake_scan)

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        c.scans = scans
        yield c
    app.dependency_overrides.clear()


async def _token(c: AsyncClient) -> str:
    email = f"idem-{uuid.uuid4().hex[:10]}@example.com"
    user = {"email": email, "password": "Str0ngP@ss", "display_name": "Idem"}
    r = await c.post("/api/v1/auth/register", json=user)
    assert r.status_code in (200, 201), r.text
    r = await c.post("/api/v1/auth/login", json={"email": email, "password": user["password"]})
    return r.json()["access_token"]


async def test_watch_create_replays_and_scans_once(main_client):
    tok = await _token(main_client)
    h = {"Authorization": f"Bearer {tok}", HEADER: _key()}
    body = {"surface": "github", "owner": "acme", "repo": f"tool-{uuid.uuid4().hex[:6]}"}
    a = await main_client.post("/api/v1/watches", json=body, headers=h)
    b = await main_client.post("/api/v1/watches", json=body, headers=h)
    assert a.status_code == b.status_code == 201, a.text
    assert b.json() == a.json() and b.headers[REPLAYED] == "true"
    assert len(main_client.scans) == 1
    # Outer middleware still wraps the replay.
    assert b.headers["x-request-id"] and b.headers["x-content-type-options"] == "nosniff"


async def test_two_users_with_the_same_key_get_their_own_watch(main_client):
    key = _key()
    body = {"surface": "github", "owner": "acme", "repo": f"tool-{uuid.uuid4().hex[:6]}"}
    t1, t2 = await _token(main_client), await _token(main_client)
    a = await main_client.post("/api/v1/watches", json=body,
                               headers={"Authorization": f"Bearer {t1}", HEADER: key})
    b = await main_client.post("/api/v1/watches", json=body,
                               headers={"Authorization": f"Bearer {t2}", HEADER: key})
    assert a.status_code == b.status_code == 201
    assert REPLAYED not in b.headers
    assert a.json()["id"] != b.json()["id"]
    assert len(main_client.scans) == 2


async def test_main_app_invalid_key_is_problem_json(main_client):
    tok = await _token(main_client)
    r = await main_client.post(
        "/api/v1/watches", json={"owner": "a", "repo": "b"},
        headers={"Authorization": f"Bearer {tok}", HEADER: "x" * 256},
    )
    _assert_problem(r, 400, "idempotency_key_invalid")
    assert main_client.scans == []


async def test_main_app_login_ignores_the_key(main_client):
    r = await main_client.post("/api/v1/auth/login",
                               json={"email": "nobody@example.com", "password": "x"},
                               headers={HEADER: "x" * 300})
    assert r.status_code != 400 or r.json().get("code") != "idempotency_key_invalid"
    assert REPLAYED not in r.headers


def test_openapi_documents_the_optional_header():
    from src.main import app

    paths = app.openapi()["paths"]

    def params(path, method):
        return [p for p in paths[path][method].get("parameters", [])
                if p["name"] == HEADER and p["in"] == "header"]

    for path, method in [("/api/v1/watches", "post"), ("/api/v1/account/claims", "post"),
                         ("/api/v1/account/github-app/claim-repo", "post"),
                         ("/api/v1/webhooks/{webhook_id}", "patch")]:
        (p,) = params(path, method)
        assert p["required"] is False
        assert p["schema"]["maxLength"] == 255
    for path, method in [("/api/v1/auth/login", "post"), ("/api/v1/auth/register", "post"),
                         ("/api/v1/public/scan/beacon/{event}", "post"),
                         ("/api/v1/public/scan/submit", "post"),
                         ("/api/v1/marketplace/stripe/webhook", "post"),
                         ("/api/v1/watches", "get")]:
        assert params(path, method) == []
    assert "/mcp" not in paths
    # Routes that mint secrets do not document it either.
    assert params("/api/v1/account/api-keys", "post") == []


# --- secrets are never stored ----------------------------------------------------


@pytest.mark.parametrize("path", [
    "/api/v1/account/api-keys", "/api/v1/account/alert-webhook/rotate-secret",
    "/api/v1/webhooks", "/api/v1/agents", "/api/v1/agents/register",
    "/api/v1/agents/abc/rotate-key", "/api/v1/agents/abc/recover-key",
    "/api/v1/a2a/agent-card/import", "/api/v1/bots/bootstrap", "/api/v1/bots/import-source",
    "/api/v1/attestation-providers/register", "/api/v1/organizations/o1/api-keys",
    "/api/v1/migration/moltbook", "/api/v1/sandbox/token",
    "/api/v1/marketplace/l1/purchase", "/api/v1/marketplace/purchases/t1/confirm",
    "/api/v1/marketplace/purchases/t1/cancel", "/api/v1/marketplace/purchases/t1/refund",
    "/api/v1/marketplace/capabilities/l1/adopt",
])
def test_routes_that_mint_secrets_are_excluded(path):
    assert not is_covered("POST", path) and not is_covered("PATCH", path)


def test_secret_route_patterns_match_whole_paths_only():
    assert is_covered("PATCH", "/api/v1/webhooks/w1")
    assert is_covered("POST", "/api/v1/agents/claim")
    assert is_covered("PATCH", "/api/v1/agents/a1/api-keys/k1")


def test_carries_secret():
    assert carries_secret({"api_key": "ag_live_x"}) and not carries_secret({"key": "step1"})
    assert carries_secret({"a": [{"client_secret": "pi_x"}]})
    assert carries_secret({"claim_token": "t"}) and carries_secret({"API_KEY": "k"})
    assert not carries_secret({"key_id": "k", "page_key": "p", "max_tokens_per_call": 5, "token": None})
    assert not carries_secret({"has_secret": True, "secret": ""})


async def test_answer_with_a_secret_is_not_stored(client, counter):
    key = _key()
    a = await client.post("/api/v1/leaky", headers={HEADER: key})
    b = await client.post("/api/v1/leaky", headers={HEADER: key})
    assert a.status_code == b.status_code == 200
    assert REPLAYED not in b.headers and counter.calls == 2
    rkey = storage_key("anon", "POST", "/api/v1/leaky", key)
    assert not await _redis().exists(rkey)


def _api_routes(routes, prefix=""):
    """(path, APIRoute) for every route, also with FastAPI's lazily included routers."""
    from fastapi.routing import APIRoute

    for r in routes:
        if isinstance(r, APIRoute):
            yield prefix + r.path, r
        elif hasattr(r, "original_router"):
            yield from _api_routes(r.original_router.routes,
                                   prefix + r.include_context.prefix)


def _schema_secret_fields(schema, components, seen=frozenset(), at=""):
    out: list[str] = []
    if not isinstance(schema, dict):
        return out
    ref = schema.get("$ref")
    if ref:
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            return out
        return _schema_secret_fields(components.get(name, {}), components, seen | {name}, at)
    for name, sub in (schema.get("properties") or {}).items():
        if SECRET_FIELD_RE.match(name) and sub.get("type") in (None, "string"):
            out.append(f"{at}.{name}")
        out += _schema_secret_fields(sub, components, seen, f"{at}.{name}")
    for k in ("items", "additionalProperties"):
        out += _schema_secret_fields(schema.get(k), components, seen, at + "[]")
    for k in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(k) or []:
            out += _schema_secret_fields(sub, components, seen, at)
    return out


def test_no_covered_route_documents_a_secret_in_its_answer():
    """Walk every covered operation's response schemas: a secret-named field means
    the route belongs in SECRET_ROUTES (src/idempotency.py)."""
    from src.main import app

    doc = app.openapi()
    components = doc.get("components", {}).get("schemas", {})
    leaks = {}
    for path, ops in doc["paths"].items():
        for method, op in ops.items():
            if not isinstance(op, dict) or not is_covered(method, path):
                continue
            fields: list[str] = []
            for resp in (op.get("responses") or {}).values():
                for media in (resp.get("content") or {}).values():
                    fields += _schema_secret_fields(media.get("schema"), components)
            if fields:
                leaks[f"{method.upper()} {path}"] = sorted(set(fields))
    assert not leaks, f"covered routes answer secret-named fields: {leaks}"


def test_no_covered_route_returns_a_secret_named_literal():
    """Untyped (dict) answers are not in the schema: read each covered endpoint's
    source for a secret-named dict key instead."""
    import inspect
    import re

    from src.main import app

    literal = re.compile(r"""["'](\w+)["']\s*:""")
    leaks = {}
    for path, route in _api_routes(app.routes):
        for method in route.methods:
            if not is_covered(method, path):
                continue
            try:
                src = inspect.getsource(route.endpoint)
            except (OSError, TypeError):
                continue
            names = {n for n in literal.findall(src) if SECRET_FIELD_RE.match(n)}
            if names:
                leaks[f"{method} {path}"] = sorted(names)
    assert not leaks, f"covered routes build secret-named answers: {leaks}"


def test_covered_route_walk_sees_the_routes():
    from src.main import app

    covered = {(m, p) for p, r in _api_routes(app.routes) for m in r.methods
               if is_covered(m, p)}
    assert ("POST", "/api/v1/watches") in covered
    assert ("POST", "/api/v1/account/claims") in covered
    assert len(covered) > 100


# --- credentials are checked before a replay -------------------------------------


async def test_logged_out_token_cannot_replay(main_client):
    tok = await _token(main_client)
    h = {"Authorization": f"Bearer {tok}", HEADER: _key()}
    body = {"surface": "github", "owner": "acme", "repo": f"tool-{uuid.uuid4().hex[:6]}"}
    a = await main_client.post("/api/v1/watches", json=body, headers=h)
    assert a.status_code == 201
    out = await main_client.post("/api/v1/auth/logout",
                                 headers={"Authorization": f"Bearer {tok}"})
    assert out.status_code == 200, out.text
    b = await main_client.post("/api/v1/watches", json=body, headers=h)
    problem = _assert_problem(b, 401, "unauthorized")
    assert problem["detail"] == "Token has been revoked"
    assert REPLAYED not in b.headers
    assert len(main_client.scans) == 1
    # A different body is refused the same way, before a 422 could say anything.
    c = await main_client.post("/api/v1/watches", json={**body, "repo": "x"}, headers=h)
    _assert_problem(c, 401, "unauthorized")


async def test_revoked_api_key_cannot_replay(main_client):
    tok = await _token(main_client)
    auth = {"Authorization": f"Bearer {tok}"}
    created = await main_client.post("/api/v1/account/api-keys", json={"label": "idem"},
                                     headers=auth)
    assert created.status_code == 201, created.text
    raw, key_id = created.json()["key"], created.json()["id"]
    h = {"X-API-Key": raw, HEADER: _key()}
    body = {"surface": "github", "owner": "acme", "repo": f"tool-{uuid.uuid4().hex[:6]}"}
    a = await main_client.post("/api/v1/watches", json=body, headers=h)
    assert a.status_code == 201, a.text
    b = await main_client.post("/api/v1/watches", json=body, headers=h)
    assert b.headers[REPLAYED] == "true"
    revoked = await main_client.delete(f"/api/v1/account/api-keys/{key_id}", headers=auth)
    assert revoked.status_code == 204, revoked.text
    c = await main_client.post("/api/v1/watches", json=body, headers=h)
    _assert_problem(c, 401, "unauthorized")
    assert REPLAYED not in c.headers
    assert len(main_client.scans) == 1


async def test_api_key_create_ignores_the_header(main_client):
    tok = await _token(main_client)
    h = {"Authorization": f"Bearer {tok}", HEADER: _key()}
    a = await main_client.post("/api/v1/account/api-keys", json={"label": "a"}, headers=h)
    b = await main_client.post("/api/v1/account/api-keys", json={"label": "a"}, headers=h)
    assert a.status_code == b.status_code == 201
    assert a.json()["key"] != b.json()["key"] and REPLAYED not in b.headers


async def test_invalid_token_with_a_key_runs_as_unkeyed(main_client):
    h = {"Authorization": "Bearer not-a-jwt", HEADER: _key()}
    r = await main_client.post("/api/v1/watches", json={"owner": "a", "repo": "b"}, headers=h)
    assert r.status_code == 401 and REPLAYED not in r.headers
