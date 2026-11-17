"""Optional ``Idempotency-Key`` on POST and PATCH, with the outcome shared in Redis (#407).

A client that retries a write after a timeout can send the same ``Idempotency-Key``
both times. The first request runs; its response (status, the headers that describe
the body, the body) is stored in Redis for ``RECORD_TTL_SECONDS``. A repeat with the
same key and the same request is answered from the store, with
``Idempotent-Replayed: true``, and the write does not run again.

The header is optional everywhere. A request without it runs exactly as before, and a
Redis outage never touches it. See docs/adr/0007-idempotency-key.md.

- Scope: the key is stored per (key, method, path, caller). The caller is the API key
  (hashed), the JWT subject, the hash of any other credential, or ``anon``, so two
  accounts that pick the same key never see each other's responses.
- Same key, different request (body, query or content type): 422
  ``idempotency_key_reused``.
- Same key while the first request still runs: 409 ``idempotency_key_in_use`` with
  ``Retry-After``.
- Key not 1-255 printable ASCII characters, or sent twice: 400
  ``idempotency_key_invalid``.
- Redis unreachable and the request sent a key: 503 ``idempotency_unavailable`` with
  ``Retry-After``. The write does not run unguarded.
- Not stored, so a retry runs again: 5xx, 401, 408, 425 and 429 answers, an unhandled
  exception, a streamed (``text/event-stream``) answer and a body over
  ``MAX_STORED_BODY_BYTES``.

Only ``/api/v1`` routes are covered, minus ``EXCLUDED_PREFIXES`` (the hosted ``/mcp``
connector is outside ``/api/v1`` and never covered).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

from starlette.requests import Request

from src.errors import catalog
from src.errors.handlers import ProblemResponse, problem_body

logger = logging.getLogger(__name__)

HEADER = "Idempotency-Key"
REPLAYED_HEADER = "Idempotent-Replayed"
METHODS = frozenset({"POST", "PATCH"})
COVERED_PREFIX = "/api/v1/"

# Routes that ignore the header: it is neither checked nor stored, and the request
# runs as it always has. Add a reason with every entry (and in ADR 0007).
EXCLUDED_PREFIXES: tuple[str, ...] = (
    # Public scans, /submit and /beacon/{event}: anonymous callers (MCP server,
    # GitHub Action, GitLab component, plugin hooks, ChatGPT app); a scan is already
    # close to idempotent through its 1-hour cache.
    "/api/v1/public/scan",
    # The plugin hooks' anonymous activity ping.
    "/api/v1/public/plugin/",
    # Login, register, refresh and the rest: anonymous, and their answers carry
    # tokens and cookies that must not sit in a shared store.
    "/api/v1/auth/",
    # The SAML callback is posted by the identity provider, not by our clients.
    "/api/v1/sso/",
    # Webhooks we receive: the sender has its own retry and delivery ids.
    "/api/v1/marketplace/stripe/webhook",
    "/api/v1/gateway/webhook/rescan",
    # The MCP bridge speaks JSON-RPC, which has its own retry semantics (like /mcp).
    "/api/v1/mcp/",
)

RECORD_TTL_SECONDS = 24 * 60 * 60
# How long a request may hold its key before a repeat may run it again. Covers a
# watch's baseline scan; a crashed worker frees the key after this.
IN_FLIGHT_TTL_SECONDS = 5 * 60
MAX_STORED_BODY_BYTES = 256 * 1024
MAX_KEY_LENGTH = 255
REDIS_TIMEOUT_SECONDS = 2.0
IN_USE_RETRY_AFTER = "1"
UNAVAILABLE_RETRY_AFTER = "5"

# Answers that are not stored: the retry runs the write again.
_NOT_STORED_STATUSES = frozenset({401, 408, 425, 429})
# Response headers a replay repeats. Everything else (cookies, rate-limit counters,
# request and trace ids) belongs to the request that produced it.
_REPLAYED_HEADERS = frozenset({
    b"content-type", b"content-language", b"content-disposition", b"location",
    b"etag", b"last-modified", b"link", b"cache-control",
})

_KEY_PREFIX = "idem:v1:"
_IN_FLIGHT = "inflight:"
_DONE = "done:"

# Replace the in-flight marker only when it is still ours.
_FINISH_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
end
return nil
"""
_RELEASE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""


class StoreUnavailableError(Exception):
    """Redis did not answer: a keyed request fails closed."""


def is_covered(method: str, path: str) -> bool:
    """True when a POST or PATCH to ``path`` honours ``Idempotency-Key``."""
    if method.upper() not in METHODS or not path.startswith(COVERED_PREFIX):
        return False
    return not path.startswith(EXCLUDED_PREFIXES)


def valid_key(value: str) -> bool:
    """1-255 characters, each printable ASCII (space to tilde)."""
    return 0 < len(value) <= MAX_KEY_LENGTH and all(" " <= ch <= "~" for ch in value)


def _sha256(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def caller_subject(headers: dict[bytes, bytes]) -> str:
    """Who the key belongs to. Never the raw credential: only a hash or the JWT sub."""
    api_key = headers.get(b"x-api-key")
    if api_key is not None:
        # get_current_entity tries the API key first, so it decides the caller.
        return "apikey:" + _sha256(api_key)
    auth = headers.get(b"authorization", b"")
    if auth:
        if auth[:7].lower() == b"bearer ":
            from src.api.auth_service import decode_token

            payload = decode_token(auth[7:].decode("latin-1").strip())
            if payload and payload.get("kind") == "access" and payload.get("sub"):
                return "sub:" + str(payload["sub"])
        # An expired or unknown credential: its own scope, so its 401 is never shared.
        return "cred:" + _sha256(auth)
    return "anon"


def storage_key(subject: str, method: str, path: str, key: str) -> str:
    return _KEY_PREFIX + _sha256(
        subject.encode(), method.encode(), path.encode(), key.encode("ascii"),
    )


def request_fingerprint(scope: dict, body: bytes) -> str:
    """The request a key was first used with: method, path, query, content type, body."""
    headers = dict(scope.get("headers") or [])
    return _sha256(
        scope["method"].encode(),
        scope["path"].encode(),
        scope.get("query_string") or b"",
        headers.get(b"content-type", b""),
        body,
    )


def _default_redis():
    from src.redis_client import get_redis

    return get_redis()


class IdempotencyMiddleware:
    """Pure ASGI middleware. Added innermost in src/main.py, so CORS, security
    headers and the request id still wrap a replayed answer."""

    def __init__(self, app, redis_factory: Callable[[], Any] | None = None) -> None:
        self.app = app
        self.redis_factory = redis_factory or _default_redis

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not is_covered(scope["method"], scope["path"]):
            await self.app(scope, receive, send)
            return
        values = [v for k, v in scope.get("headers") or [] if k == b"idempotency-key"]
        if not values:
            await self.app(scope, receive, send)
            return

        if len(values) > 1:
            await self._problem(scope, receive, send, 400, "idempotency_key_invalid",
                                "Send one Idempotency-Key header, not several.")
            return
        try:
            key = values[0].decode("ascii").strip()
        except UnicodeDecodeError:
            key = ""
        if not valid_key(key):
            await self._problem(
                scope, receive, send, 400, "idempotency_key_invalid",
                f"Idempotency-Key must be 1 to {MAX_KEY_LENGTH} printable ASCII characters.",
            )
            return

        body, disconnected = await _read_body(receive)
        if disconnected:
            return  # The client left before sending its request; nothing to run.
        replay_receive = _replaying_receive(body, receive)

        method = scope["method"]
        rkey = storage_key(caller_subject(dict(scope.get("headers") or [])),
                           method, scope["path"], key)
        fingerprint = request_fingerprint(scope, body)
        marker = f"{_IN_FLIGHT}{secrets.token_hex(8)}:{fingerprint}"

        try:
            acquired, existing = await self._acquire(rkey, marker)
        except StoreUnavailableError:
            await self._problem(
                scope, replay_receive, send, 503, "idempotency_unavailable",
                "The Idempotency-Key store is unavailable, so this write was not run. "
                "Retry later, or send the request without the key.",
                {"Retry-After": UNAVAILABLE_RETRY_AFTER},
            )
            return

        if not acquired:
            await self._answer_existing(scope, replay_receive, send, existing, fingerprint)
            return

        await self._run_and_store(scope, replay_receive, send, rkey, marker, fingerprint)

    # -- Redis ------------------------------------------------------------------------

    async def _redis_call(self, fn: Callable[[Any], Any]) -> Any:
        try:
            return await asyncio.wait_for(fn(self.redis_factory()), REDIS_TIMEOUT_SECONDS)
        except Exception as exc:  # redis errors, OSError, timeouts
            raise StoreUnavailableError(str(exc)) from exc

    async def _acquire(self, rkey: str, marker: str) -> tuple[bool, str | None]:
        """Take the key for this request, or return what is stored under it."""
        for _ in range(3):
            ok = await self._redis_call(
                lambda r: r.set(rkey, marker, nx=True, ex=IN_FLIGHT_TTL_SECONDS),
            )
            if ok:
                return True, None
            existing = await self._redis_call(lambda r: r.get(rkey))
            if existing is not None:
                return False, existing if isinstance(existing, str) else existing.decode()
            # It expired between SET and GET: try to take it again.
        raise StoreUnavailableError("could not take or read the key")

    async def _finish(self, rkey: str, marker: str, record: dict) -> None:
        value = _DONE + json.dumps(record, separators=(",", ":"))
        try:
            await self._redis_call(
                lambda r: r.eval(_FINISH_LUA, 1, rkey, marker, value, RECORD_TTL_SECONDS),
            )
        except StoreUnavailableError:
            # The write ran; only the replay is lost. The in-flight marker expires.
            logger.warning("idempotency: could not store the response", exc_info=True)

    async def _release(self, rkey: str, marker: str) -> None:
        try:
            await self._redis_call(lambda r: r.eval(_RELEASE_LUA, 1, rkey, marker))
        except StoreUnavailableError:
            logger.warning("idempotency: could not release the key", exc_info=True)

    # -- answers ----------------------------------------------------------------------

    async def _answer_existing(self, scope, receive, send, existing: str,
                               fingerprint: str) -> None:
        if existing.startswith(_DONE):
            try:
                record = json.loads(existing[len(_DONE):])
            except ValueError:
                record = {}
            if record.get("fp") != fingerprint:
                await self._reused(scope, receive, send)
                return
            await _send_replay(send, record)
            return
        # In flight: "inflight:<token>:<fingerprint>"
        stored_fp = existing.rsplit(":", 1)[-1]
        if stored_fp != fingerprint:
            await self._reused(scope, receive, send)
            return
        await self._problem(
            scope, receive, send, 409, "idempotency_key_in_use",
            "A request with this Idempotency-Key is still running. Retry shortly to get "
            "its answer.",
            {"Retry-After": IN_USE_RETRY_AFTER},
        )

    async def _reused(self, scope, receive, send) -> None:
        await self._problem(
            scope, receive, send, 422, "idempotency_key_reused",
            "This Idempotency-Key was already used with a different request. Use a new "
            "key for a new request.",
        )

    async def _problem(self, scope, receive, send, status: int, code: str, detail: str,
                       headers: dict[str, str] | None = None) -> None:
        request = Request(scope, receive)
        response = ProblemResponse(
            status_code=status,
            content=problem_body(request, status, catalog.get(code), detail),
            headers=headers,
        )
        await response(scope, receive, send)

    async def _run_and_store(self, scope, receive, send, rkey: str, marker: str,
                             fingerprint: str) -> None:
        state: dict[str, Any] = {"mode": None, "start": None, "chunks": [], "size": 0,
                                 "stored": False}

        async def flush_buffer() -> None:
            await send(state["start"])
            for chunk in state["chunks"]:
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            state["chunks"] = []

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                status = message["status"]
                ctype = dict(message.get("headers") or []).get(b"content-type", b"")
                if (status >= 500 or status < 200 or status in _NOT_STORED_STATUSES
                        or ctype.startswith(b"text/event-stream")):
                    state["mode"] = "pass"
                    await send(message)
                else:
                    state["mode"] = "buffer"
                    state["start"] = message
                return
            if message["type"] != "http.response.body" or state["mode"] != "buffer":
                await send(message)
                return

            chunk = message.get("body", b"")
            more = message.get("more_body", False)
            state["size"] += len(chunk)
            if state["size"] > MAX_STORED_BODY_BYTES:
                state["mode"] = "pass"
                await flush_buffer()
                await send(message)
                return
            state["chunks"].append(chunk)
            if more:
                return
            start = state["start"]
            body = b"".join(state["chunks"])
            await self._finish(rkey, marker, {
                "fp": fingerprint,
                "status": start["status"],
                "headers": [
                    [k.decode("latin-1"), v.decode("latin-1")]
                    for k, v in start.get("headers") or []
                    if k.lower() in _REPLAYED_HEADERS
                ],
                "body": base64.b64encode(body).decode("ascii"),
                "stored_at": int(time.time()),
            })
            state["stored"] = True
            await send(start)
            await send({"type": "http.response.body", "body": body, "more_body": False})

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if not state["stored"]:
                await self._release(rkey, marker)


async def _read_body(receive) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b"", True
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return b"".join(chunks), False


def _replaying_receive(body: bytes, receive):
    sent = False

    async def replay():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


async def _send_replay(send, record: dict) -> None:
    body = base64.b64decode(record.get("body", ""))
    headers = [
        (k.encode("latin-1"), v.encode("latin-1")) for k, v in record.get("headers", [])
    ]
    headers.append((b"content-length", str(len(body)).encode()))
    headers.append((REPLAYED_HEADER.lower().encode(), b"true"))
    await send({"type": "http.response.start", "status": int(record["status"]),
                "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


# -- OpenAPI ------------------------------------------------------------------------

OPENAPI_PARAMETER: dict[str, Any] = {
    "name": HEADER,
    "in": "header",
    "required": False,
    "description": (
        "Optional. Send a unique value (1-255 printable ASCII characters) to make a "
        "retry safe: a repeat with the same key and request gets the first answer "
        f"again, with `{REPLAYED_HEADER}: true`, for 24 hours. The same key with a "
        "different request answers 422, and a repeat while the first still runs "
        "answers 409 with Retry-After. See docs/adr/0007-idempotency-key.md."
    ),
    "schema": {"type": "string", "minLength": 1, "maxLength": MAX_KEY_LENGTH},
}


def add_openapi_parameter(schema: dict) -> dict:
    """Document the optional header on every covered POST and PATCH operation."""
    for path, ops in (schema.get("paths") or {}).items():
        for method, op in ops.items():
            if not isinstance(op, dict) or not is_covered(method, path):
                continue
            params = op.setdefault("parameters", [])
            if not any(p.get("name") == HEADER and p.get("in") == "header" for p in params):
                params.append(dict(OPENAPI_PARAMETER))
    return schema


def install_openapi(app) -> None:
    """Wrap ``app.openapi`` so the generated document carries the header."""
    original = app.openapi

    def openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        return add_openapi_parameter(original())

    app.openapi = openapi
