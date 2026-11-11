"""'Fixed in' names a release on the scanned version's own line (gap audit A4).

server-everything (GHSA-mvf5-2qqv-rg3c): 1.0.0 to before 2.0.1 is fixed in 2.0.1, and
the date-numbered releases 2025.9.24 to 2026.8.31 have no fix. A user on 2026.1.14 must
not be told "fixed in 2.0.1", and a year must not outrank 2.x as "the highest fix"."""
from __future__ import annotations

from src.bridges import mcp_streamable as ms
from src.scanner import incident_history as ih
from src.scanner import verdict as v


def _vuln(*ranges):
    return {"id": "GHSA-mvf5-2qqv-rg3c", "affected": [
        {"package": {"ecosystem": "npm", "name": "@modelcontextprotocol/server-everything"},
         "ranges": [{"type": "SEMVER", "events": list(r)} for r in ranges]}]}


ONE_RANGE = _vuln([{"introduced": "1.0.0"}, {"fixed": "2.0.1"},
                   {"introduced": "2025.9.24"}])
TWO_RANGES = _vuln([{"introduced": "1.0.0"}, {"fixed": "2.0.1"}],
                   [{"introduced": "2025.9.24"}, {"last_affected": "2026.8.31"}])
NAME = "@modelcontextprotocol/server-everything"


def test_semver_line_gets_its_own_fix():
    for vul in (ONE_RANGE, TWO_RANGES):
        assert ih._fixed_in(vul, "npm", NAME, "1.5.0") == "2.0.1"


def test_date_line_without_a_fix_names_none():
    for vul in (ONE_RANGE, TWO_RANGES):
        assert ih._fixed_in(vul, "npm", NAME, "2026.1.14") is None


def test_unaffected_or_unknown_version_keeps_context_fix():
    assert ih._fixed_in(TWO_RANGES, "npm", NAME, "2.2.1") == "2.0.1"
    assert ih._fixed_in(TWO_RANGES, "npm", NAME, None) == "2.0.1"


def test_multi_line_advisory_still_picks_the_right_line():
    vul = _vuln([{"introduced": "8.10.0"}, {"fixed": "8.10.3"},
                 {"introduced": "9.0.0"}, {"fixed": "9.1.2"}])
    assert ih._fixed_in(vul, "npm", NAME, "9.0.5") == "9.1.2"
    assert ih._fixed_in(vul, "npm", NAME, "8.10.1") == "8.10.3"


def test_highest_fix_never_mixes_schemes():
    for mod in (v, ms):
        assert mod._highest_fix([{"fixed_in": "2.0.1"}, {"fixed_in": "2026.9.1"}]) is None
        assert mod._highest_fix([{"fixed_in": "1.9.2"}, {"fixed_in": "1.10.0"}]) == "1.10.0"
        assert mod._highest_fix([{"fixed_in": "2025.9.24"},
                                 {"fixed_in": "2026.1.14"}]) == "2026.1.14"
        assert mod._highest_fix([]) is None


def test_date_version_detection():
    assert v._is_date_version("2026.8.31") and v._is_date_version("v2025.1.0")
    assert not v._is_date_version("2.0.1") and not v._is_date_version("20260101")
    assert not v._is_date_version("9999.1")
