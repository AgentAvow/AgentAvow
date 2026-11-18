"""Exception handlers that answer every API error as RFC 9457 problem+json (#409).

The body keeps the two fields clients already read, with exactly their old values:

- ``detail``: the ``HTTPException`` detail (a string, or whatever the route passed),
  the pydantic error list for a 422 validation error, ``"Internal server error"``
  for an unhandled exception.
- ``request_id``: the request's ``X-Request-ID`` (src/observability).

and adds ``type``, ``title``, ``status``, ``code``, ``instance`` and ``trace_id``.
A 422 validation error also carries ``errors``, one entry per invalid field. See
docs/adr/0005-errors-are-problem-json.md for why 422 ``detail`` stays a list.

Some paths keep the old ``application/json`` ``{"detail", "request_id"}`` answer
unchanged (``is_legacy_path``): the hosted ``/mcp`` endpoint (JSON-RPC clients), badge
and other image routes embedded in READMEs, and ``/.well-known/*``.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.errors import catalog
from src.errors.catalog import ErrorCode

logger = logging.getLogger(__name__)

PROBLEM_MEDIA_TYPE = "application/problem+json"

# Paths that keep the pre-#409 error answer exactly:
# - /mcp: the hosted MCP endpoint; its clients speak JSON-RPC, not HTTP problems.
# - /.well-known/*: fixed discovery documents (JWKS, did:web) read by verifiers.
# - badge and image routes: embedded in READMEs and social cards.
_LEGACY_EXACT = frozenset({"/mcp"})
_LEGACY_PREFIXES = ("/mcp/", "/.well-known/", "/api/v1/badges/")
_LEGACY_SUFFIXES = ("/badge", ".svg", "/og-image", ".png")


def is_legacy_path(path: str) -> bool:
    """True when ``path`` keeps the old ``{"detail", "request_id"}`` JSON answer."""
    if path in _LEGACY_EXACT or path.startswith(_LEGACY_PREFIXES):
        return True
    return path.rstrip("/").endswith(_LEGACY_SUFFIXES)


class ProblemResponse(JSONResponse):
    media_type = PROBLEM_MEDIA_TYPE


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def _trace_id(request: Request) -> str | None:
    trace_id = getattr(request.state, "trace_id", None)
    if trace_id is None:
        from src.observability.context import current_trace_id

        trace_id = current_trace_id()
    return trace_id


def problem_body(
    request: Request, status: int, entry: ErrorCode, detail: Any,
) -> dict[str, Any]:
    """The problem document. ``detail`` and ``request_id`` are the legacy fields."""
    return {
        "type": entry.type,
        "title": entry.title,
        "status": status,
        "code": entry.code,
        "detail": detail,
        # The path only: a query string can carry tokens or emails.
        "instance": request.url.path,
        "request_id": _request_id(request),
        "trace_id": _trace_id(request),
    }


def _entry_for(exc: Exception, status: int) -> ErrorCode:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in catalog.CATALOG:
        return catalog.CATALOG[code]
    return catalog.default_for_status(status)


def _sanitize_value(v: object) -> object:
    """Recursively make a value JSON-serializable."""
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, dict):
        return {k: _sanitize_value(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_sanitize_value(item) for item in v]
    return str(v)


def sanitize_validation_errors(errors: list[dict]) -> list[dict]:
    """Make validation error dicts JSON-serializable.

    Pydantic/FastAPI may put non-serializable objects (e.g. ValueError) in the
    ``ctx`` field. Convert them recursively. This is the pre-#409 ``detail`` list.
    """
    sanitized = []
    for err in errors:
        clean = dict(err)
        if "ctx" in clean:
            clean["ctx"] = _sanitize_value(clean["ctx"])
        sanitized.append(clean)
    return sanitized


_LOCATIONS = ("body", "query", "path", "header", "cookie")


def field_errors(errors: list[dict]) -> list[dict[str, Any]]:
    """One entry per invalid field: where it is, which field, what is wrong."""
    out: list[dict[str, Any]] = []
    for err in errors:
        loc = [str(part) for part in (err.get("loc") or ())]
        location = loc[0] if loc and loc[0] in _LOCATIONS else None
        rest = loc[1:] if location else loc
        out.append({
            "location": location,
            "field": ".".join(rest) if rest else None,
            "message": str(err.get("msg", "")),
            "type": str(err.get("type", "")),
        })
    return out


async def validation_exception_handler(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    detail = sanitize_validation_errors(exc.errors())
    if is_legacy_path(request.url.path):
        return JSONResponse(
            status_code=422,
            content={"detail": detail, "request_id": _request_id(request)},
        )
    body = problem_body(request, 422, catalog.get("validation_failed"), detail)
    body["errors"] = field_errors(detail)
    return ProblemResponse(status_code=422, content=body)


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException,
) -> JSONResponse:
    status = exc.status_code
    if status < 400 or is_legacy_path(request.url.path):
        return JSONResponse(
            status_code=status,
            content={"detail": exc.detail, "request_id": _request_id(request)},
        )
    return ProblemResponse(
        status_code=status,
        content=problem_body(request, status, _entry_for(exc, status), exc.detail),
        headers=dict(exc.headers) if exc.headers else None,
    )


async def unhandled_exception_handler(
    request: Request, exc: Exception,
) -> JSONResponse:
    request_id = _request_id(request)
    logger.error(
        "Unhandled exception [request_id=%s]: %s",
        request_id,
        exc,
        exc_info=True,
        extra={"request_id": request_id, "trace_id": _trace_id(request)},
    )
    # Generic on purpose: no message, type, stack or other internal detail.
    if is_legacy_path(request.url.path):
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )
    return ProblemResponse(
        status_code=500,
        content=problem_body(
            request, 500, catalog.get("internal_error"), "Internal server error",
        ),
        # This answer comes from outside the observability middleware, which would
        # otherwise add the header.
        headers={"X-Request-ID": request_id},
    )


def install_problem_handlers(app: FastAPI) -> None:
    """Register the handlers. Called once from src/main.py."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
