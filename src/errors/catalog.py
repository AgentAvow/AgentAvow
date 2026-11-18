"""The error code catalog: one stable ``code`` per kind of failure (#409).

Every error the API answers carries a ``code`` from this table. Clients branch on
``code`` (or ``status``), never on the human-readable ``title`` or ``detail``.

Codes are a public contract. Never rename or remove one:
``tests/test_errors_catalog.py`` pins the whole table, so a rename or removal fails
CI. Add a new code instead and leave the old one in place.

Part 1 of #409 gives each HTTP status a default code (``DEFAULT_CODE_BY_STATUS``).
Routers move onto specific codes (``ApiError(code=...)``) in a later change.
"""
from __future__ import annotations

from dataclasses import dataclass

# The ``type`` member of a problem is this base plus the code. It is an identifier
# (RFC 9457 section 3.1.1 allows a URI that does not resolve); a docs page per code
# can be served there later without changing any response.
PROBLEM_TYPE_BASE = "https://agentavow.com/problems/"


@dataclass(frozen=True)
class ErrorCode:
    code: str
    status: int
    title: str

    @property
    def type(self) -> str:
        return PROBLEM_TYPE_BASE + self.code


def _codes(*entries: tuple[str, int, str]) -> dict[str, ErrorCode]:
    table: dict[str, ErrorCode] = {}
    for code, status, title in entries:
        if code in table:
            raise ValueError(f"duplicate error code {code!r}")
        table[code] = ErrorCode(code, status, title)
    return table


CATALOG: dict[str, ErrorCode] = _codes(
    # Generic, one per status: the default when a route does not name a code.
    ("bad_request", 400, "Bad request"),
    ("unauthorized", 401, "Authentication required"),
    ("payment_required", 402, "Payment required"),
    ("forbidden", 403, "Forbidden"),
    ("not_found", 404, "Not found"),
    ("method_not_allowed", 405, "Method not allowed"),
    ("not_acceptable", 406, "Not acceptable"),
    ("request_timeout", 408, "Request timeout"),
    ("conflict", 409, "Conflict"),
    ("gone", 410, "Gone"),
    ("length_required", 411, "Length required"),
    ("precondition_failed", 412, "Precondition failed"),
    ("payload_too_large", 413, "Payload too large"),
    ("uri_too_long", 414, "URI too long"),
    ("unsupported_media_type", 415, "Unsupported media type"),
    ("unprocessable_content", 422, "Unprocessable content"),
    ("locked", 423, "Locked"),
    ("precondition_required", 428, "Precondition required"),
    ("rate_limited", 429, "Too many requests"),
    ("unavailable_for_legal_reasons", 451, "Unavailable for legal reasons"),
    ("internal_error", 500, "Internal server error"),
    ("not_implemented", 501, "Not implemented"),
    ("bad_gateway", 502, "Bad gateway"),
    ("service_unavailable", 503, "Service unavailable"),
    ("gateway_timeout", 504, "Gateway timeout"),
    # Fallbacks for a status with no entry above (e.g. 418, 499).
    ("client_error", 400, "Client error"),
    ("server_error", 500, "Server error"),
    # Specific codes.
    ("validation_failed", 422, "Request validation failed"),
    # Idempotency-Key (src/idempotency.py, #407).
    ("idempotency_key_invalid", 400, "Invalid Idempotency-Key"),
    ("idempotency_key_in_use", 409, "Idempotency-Key in use"),
    ("idempotency_key_reused", 422, "Idempotency-Key reused with a different request"),
    ("idempotency_unavailable", 503, "Idempotency store unavailable"),
)

# The code an error gets when its route did not name one: the first entry listed for
# its status. The generic codes come first, so a specific code added below never
# becomes a default.
DEFAULT_CODE_BY_STATUS: dict[int, str] = {}
for _entry in CATALOG.values():
    DEFAULT_CODE_BY_STATUS.setdefault(_entry.status, _entry.code)
del _entry


def get(code: str) -> ErrorCode:
    """The catalog entry for ``code``; KeyError when it is not in the catalog."""
    return CATALOG[code]


def default_for_status(status: int) -> ErrorCode:
    """The default entry for an HTTP status: its own code, else the class fallback."""
    code = DEFAULT_CODE_BY_STATUS.get(status)
    if code is None:
        code = "server_error" if status >= 500 else "client_error"
    return CATALOG[code]
