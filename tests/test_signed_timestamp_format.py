"""Signed scan timestamps are RFC 3339 at millisecond precision with Z, so a consumer whose
clock type holds milliseconds (JavaScript Date, jose) reads the instant the issuer wrote.
Microseconds were truncated by such consumers and misjudged freshness at the boundary
(reported by an outside reader on probityai/agent-evidence-atlas#49)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from src.signing import rfc3339_ms

MS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def test_format_is_milliseconds_and_z():
    dt = datetime(2026, 10, 2, 21, 28, 34, 85197, tzinfo=timezone.utc)
    assert rfc3339_ms(dt) == "2026-10-02T21:28:34.085Z"
    assert MS_Z.match(rfc3339_ms(datetime.now(timezone.utc)))


def test_non_utc_input_is_converted_and_round_trips():
    dt = datetime(2026, 10, 2, 14, 28, 34, 85000, tzinfo=timezone(timedelta(hours=-7)))
    s = rfc3339_ms(dt)
    assert s == "2026-10-02T21:28:34.085Z"
    assert datetime.fromisoformat(s) == dt


def test_scan_payload_signs_millisecond_z_times():
    from src.api.public_scan_router import _build_scan_payload
    data = {
        "trust_score": 90, "trust_tier": "trusted", "scan_result": "clean", "findings": {},
        "positive_signals": [], "metadata": {"files_scanned": 1, "primary_language": "Python"},
        "recommended_limits": {},
    }
    p = _build_scan_payload("owner/repo", data)
    for k in ("scannedAt", "issuedAt", "expiresAt"):
        assert MS_Z.match(p[k]), (k, p[k])
