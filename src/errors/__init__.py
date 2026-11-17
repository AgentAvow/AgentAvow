"""API errors: one RFC 9457 problem+json shape and one code catalog (#409).

- ``src.errors.catalog``: the stable codes and the default code per HTTP status.
- ``src.errors.handlers``: the exception handlers, registered by src/main.py.
- ``ApiError``: an ``HTTPException`` that names its catalog code.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from src.errors.catalog import CATALOG, DEFAULT_CODE_BY_STATUS, ErrorCode, default_for_status


class ApiError(HTTPException):
    """An HTTP error with a specific catalog code: ``raise ApiError(404, "...", code=...)``.

    The code must be in the catalog and belong to the same status, so a typo or a
    mismatched code fails where it is raised, in tests, instead of on a client.
    """

    def __init__(
        self,
        status_code: int,
        detail: Any = None,
        *,
        code: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if code is not None:
            entry = CATALOG.get(code)
            if entry is None:
                raise ValueError(f"unknown error code {code!r}")
            if entry.status != status_code:
                raise ValueError(
                    f"error code {code!r} is for status {entry.status}, not {status_code}"
                )
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code or default_for_status(status_code).code


__all__ = ["CATALOG", "DEFAULT_CODE_BY_STATUS", "ApiError", "ErrorCode", "default_for_status"]
