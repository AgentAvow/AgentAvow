"""The error code catalog is a public contract (#409): renaming or removing a code
fails here. To add a code, add it to src/errors/catalog.py and to FROZEN below."""
from __future__ import annotations

import pytest

from src.errors import ApiError
from src.errors.catalog import (
    CATALOG,
    DEFAULT_CODE_BY_STATUS,
    PROBLEM_TYPE_BASE,
    default_for_status,
)

# code -> status. Never edit or delete an entry; only append.
FROZEN: dict[str, int] = {
    "bad_request": 400,
    "unauthorized": 401,
    "payment_required": 402,
    "forbidden": 403,
    "not_found": 404,
    "method_not_allowed": 405,
    "not_acceptable": 406,
    "request_timeout": 408,
    "conflict": 409,
    "gone": 410,
    "length_required": 411,
    "precondition_failed": 412,
    "payload_too_large": 413,
    "uri_too_long": 414,
    "unsupported_media_type": 415,
    "unprocessable_content": 422,
    "locked": 423,
    "precondition_required": 428,
    "rate_limited": 429,
    "unavailable_for_legal_reasons": 451,
    "internal_error": 500,
    "not_implemented": 501,
    "bad_gateway": 502,
    "service_unavailable": 503,
    "gateway_timeout": 504,
    "client_error": 400,
    "server_error": 500,
    "validation_failed": 422,
}


def test_no_code_was_renamed_or_removed():
    missing = sorted(set(FROZEN) - set(CATALOG))
    assert not missing, f"error codes removed or renamed: {missing}"


def test_no_code_changed_status():
    changed = {c: (s, CATALOG[c].status) for c, s in FROZEN.items() if CATALOG[c].status != s}
    assert not changed


def test_every_new_code_is_frozen_too():
    assert sorted(set(CATALOG) - set(FROZEN)) == [], "add new codes to FROZEN"


def test_codes_are_snake_case_and_types_are_stable():
    for code, entry in CATALOG.items():
        assert entry.code == code
        assert code.replace("_", "").isalpha() and code == code.lower()
        assert entry.type == PROBLEM_TYPE_BASE + code
        assert entry.title and entry.title.strip() == entry.title


def test_each_default_belongs_to_its_status():
    for status, code in DEFAULT_CODE_BY_STATUS.items():
        assert CATALOG[code].status == status


@pytest.mark.parametrize("status,code", [
    (400, "bad_request"), (401, "unauthorized"), (404, "not_found"), (422, "unprocessable_content"),
    (429, "rate_limited"), (500, "internal_error"), (503, "service_unavailable"),
    (418, "client_error"), (499, "client_error"), (507, "server_error"),
])
def test_default_for_status(status, code):
    assert default_for_status(status).code == code


def test_api_error_checks_its_code():
    assert ApiError(404, "gone").code == "not_found"
    assert ApiError(422, "bad", code="validation_failed").code == "validation_failed"
    with pytest.raises(ValueError, match="unknown error code"):
        ApiError(404, code="no_such_code")
    with pytest.raises(ValueError, match="is for status 404"):
        ApiError(400, code="not_found")
