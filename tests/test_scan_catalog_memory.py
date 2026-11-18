"""The catalog caches hold rows as compact ``StoredRow`` objects, not pydantic models.

A ``StoredRow`` must read, copy, compare and serialize exactly like the ``CatalogRow`` it
was built from, so the API output does not change; it must stay small; and repeated
values within one load must share one object."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

import src.api.scan_catalog_router as m
from src.api.scan_catalog_router import (
    CatalogFinding,
    CatalogRow,
    CatalogSandbox,
    StoredRow,
    _compact,
    _normalize_row,
    as_catalog_row,
)

WHEN = datetime(2026, 11, 2, 3, 4, 5, tzinfo=timezone.utc)


def _rows() -> list[CatalogRow]:
    return [
        _normalize_row("x402", {
            "endpoint_url": "https://a.example/x", "trust_score": 70, "decision": "safe",
            "decision_reason": "listing only", "critical": 0, "high": 0, "medium": 2,
            "low": 1, "price_usd": "0.01", "testnet_only": True, "scanned_at": WHEN.isoformat(),
            "top_findings": [{"severity": "medium", "name": "costs more than $1 per call"},
                             {"severity": "low", "name": "no description"}]}),
        _normalize_row("x402", {"endpoint_url": "https://b.example", "http_status": 402,
                                "has_x402_header": True}),
        _normalize_row("x402", {"endpoint_url": "https://c.example", "trust_score": 90,
                                "critical": 0, "high": 0}),  # empty top_findings
        _normalize_row("openclaw", {"repo": "acme/skill", "trust_score": 96,
                                    "critical_count": 0, "high_count": 0, "stars": 12}),
        _normalize_row("mcp", {"name": "io.github.acme/srv", "full_name": "acme/srv",
                               "trust_score": 40, "critical": 1, "high": 2,
                               "is_mcp_server": True, "primary_language": "Python"}),
        _normalize_row("npm", {"name": "left-pad", "scan_error": "fetch failed"}),
        CatalogRow(surface="github", name="o/r", full_name="o/r", trust_score=88, grade="A+",
                   decision="safe", decision_reason="stored", last_scanned_at=WHEN,
                   scan_source="live",
                   sandbox=CatalogSandbox(ran=True, exercised=False, findings=2)),
    ]


@pytest.mark.parametrize("i", range(7))
def test_round_trip_is_field_for_field(i):
    row = _rows()[i]
    stored = _compact(row, {})
    assert isinstance(stored, StoredRow)
    back = stored.to_model()
    assert isinstance(back, CatalogRow)
    assert back.model_dump() == row.model_dump()
    assert back.model_dump_json() == row.model_dump_json()
    assert stored.model_dump(mode="json") == row.model_dump(mode="json")
    for f in CatalogRow.model_fields:
        assert getattr(stored, f) == getattr(row, f), f


def test_top_findings_read_back_as_models():
    stored = _compact(_rows()[0], {})
    assert stored.top_findings == [
        CatalogFinding(severity="medium", name="costs more than $1 per call"),
        CatalogFinding(severity="low", name="no description")]
    assert _compact(_rows()[2], {}).top_findings == []
    assert _compact(_rows()[1], {}).top_findings is None


@pytest.mark.parametrize("update", [
    None,
    {"sandbox": CatalogSandbox(ran=True, findings=1)},
    {"surface": "mcp", "category": "Data", "is_mcp_server": True},
    {"trust_score": 12, "critical": 3, "decision": "do_not_connect", "decision_reason": "x"},
    {"top_findings": [CatalogFinding(severity="high", name="n")]},
])
def test_model_copy_matches_pydantic(update):
    for row in _rows():
        stored = _compact(row, {})
        copied = stored.model_copy(update=update)
        assert isinstance(copied, StoredRow) and copied is not stored
        assert copied.model_dump() == row.model_copy(update=update).model_dump()
        assert stored == _compact(row, {})  # the original is untouched


def test_deep_copy_does_not_share_nested_values():
    stored = _compact(_rows()[6], {})
    deep = stored.model_copy(deep=True)
    assert deep == stored and deep.sandbox is not stored.sandbox


def test_equality():
    a, b = _compact(_rows()[4], {}), _compact(_rows()[4], {})
    assert a == b and a is not b
    assert a != b.model_copy(update={"trust_score": 41})
    assert a != _compact(_rows()[3], {})
    assert (a == _rows()[4]) is False  # never equal to a different type


def test_attribute_writes_and_missing_attributes():
    s = _compact(_rows()[4], {})
    s.category = "Data"
    s.endpoint_url = "https://e.example"
    assert s.to_model().category == "Data" and s.to_model().endpoint_url == "https://e.example"
    assert getattr(s, "owner", "") == ""  # the list's q= search reads it with a default


def test_stored_row_is_small():
    # A pydantic CatalogRow is ~3.4 KB with its __dict__ and fields-set; this is ~300 B.
    s = _compact(_rows()[4], {})
    assert not hasattr(s, "__dict__")
    assert sys.getsizeof(s) < 400


def test_pool_shares_repeated_values():
    pool: dict = {}
    r1 = _normalize_row("npm", {"name": "a", "scan_error": "fetch " + "failed",
                                "scanned_at": WHEN.isoformat()})
    r2 = _normalize_row("npm", {"name": "b", "scan_error": "".join(["fetch ", "failed"]),
                                "scanned_at": WHEN.isoformat()})
    assert r1.scan_error is not r2.scan_error
    s1, s2 = _compact(r1, pool), _compact(r2, pool)
    assert s1.scan_error is s2.scan_error
    assert s1.last_scanned_at is s2.last_scanned_at


def test_pool_never_merges_datetimes_that_serialize_differently():
    pool: dict = {}
    a = CatalogRow(surface="github", name="a", last_scanned_at=WHEN)
    b = CatalogRow(surface="github", name="b",
                   last_scanned_at=WHEN.astimezone(timezone(timedelta(hours=2))))
    assert a.last_scanned_at == b.last_scanned_at  # the same instant...
    sa, sb = _compact(a, pool), _compact(b, pool)
    assert sb.to_model().model_dump_json() == b.model_dump_json()  # ...kept as written
    assert sa.to_model().model_dump_json() == a.model_dump_json()


def test_as_catalog_row_passes_models_through():
    row = _rows()[3]
    assert as_catalog_row(row) is row
    assert as_catalog_row(_compact(row)).model_dump() == row.model_dump()


def test_load_surface_stores_compact_rows(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"results": [
        {"name": f"s{i}", "full_name": f"acme/s{i}", "trust_score": 80, "critical": 0,
         "high": 0, "primary_language": "Python"} for i in range(3)]}))
    rows = m._load_surface("mcp", path)
    assert rows and all(isinstance(r, StoredRow) for r in rows)
    assert rows[0].primary_language is rows[2].primary_language
    assert rows[1].page_path == "/check/acme/s1" and rows[1].decision == "safe"


@pytest.mark.asyncio
async def test_list_response_rows_are_catalog_rows(monkeypatch):
    rows = [_compact(r, {}) for r in _rows()]
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(rows))

    async def _none(db):
        return []
    monkeypatch.setattr(m, "_community_rows", _none)
    out = await m._catalog_view(None, None, None, None, None, None, "name", 50, 0, None)
    assert out.rows and all(isinstance(r, CatalogRow) for r in out.rows)
    by_name = {r.name: r for r in out.rows}
    assert by_name["o/r"].sandbox == CatalogSandbox(ran=True, exercised=False, findings=2)
    # the same rows as pydantic models give the same response
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_rows()))
    ref = await m._catalog_view(None, None, None, None, None, None, "name", 50, 0, None)
    assert out.model_dump_json() == ref.model_dump_json()


def test_release_free_heap_never_raises():
    m._release_free_heap()
