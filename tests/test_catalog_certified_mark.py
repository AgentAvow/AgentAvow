"""Catalog rows carry the Certified mark as ``certified_mark``, never as a raw stored A+.

Before #119 a stored A+ followed ``certified.eligible`` (it could sit on a pending
sandbox or a thin-coverage scan); those rows read A until re-scanned (fail closed).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.api.scan_catalog_router import (
    CERTIFIED_MARK_SINCE,
    CatalogRow,
    _stored_grade_for_mark,
)


def test_a_plus_written_under_the_mark_rule_keeps_the_mark():
    after = CERTIFIED_MARK_SINCE + timedelta(minutes=5)
    assert _stored_grade_for_mark("A+", after) == "A+"


def test_a_plus_written_before_the_mark_rule_reads_a():
    before = CERTIFIED_MARK_SINCE - timedelta(hours=1)
    assert _stored_grade_for_mark("A+", before) == "A"
    assert _stored_grade_for_mark("A+", None) == "A"


def test_naive_timestamp_is_read_as_utc():
    naive = (CERTIFIED_MARK_SINCE + timedelta(minutes=1)).replace(tzinfo=None)
    assert _stored_grade_for_mark("A+", naive) == "A+"


def test_other_grades_pass_through():
    assert _stored_grade_for_mark("B", datetime(2020, 1, 1, tzinfo=timezone.utc)) == "B"
    assert _stored_grade_for_mark(None, None) is None


def test_catalog_row_certified_mark_follows_the_gated_grade():
    row = CatalogRow(surface="npm", name="semver", full_name="npm/semver",
                     trust_score=92, grade="A+", critical=0, high=0)
    assert row.certified_mark is True
    plain = CatalogRow(surface="npm", name="x", full_name="npm/x",
                       trust_score=92, grade="A", critical=0, high=0)
    assert plain.certified_mark is False


# --- pre-rule A+ rows re-checked against the cached scan they came from ---------------

import pytest  # noqa: E402

from src.api import scan_catalog_router as _scr  # noqa: E402


def _cached(score=92, files=40, eligible=True, critical=0, high=0, pending=False):
    data = {
        "trust_score": score,
        "certified": {"eligible": eligible},
        "metadata": {"files_scanned": files},
        "findings": {"critical": critical, "high": high, "items": []},
    }
    if pending:
        data["behavioral"] = {"pending": True}
    return data


def test_pre_rule_a_plus_detection():
    before = CERTIFIED_MARK_SINCE - timedelta(hours=1)
    after = CERTIFIED_MARK_SINCE + timedelta(minutes=1)
    assert _scr._is_pre_rule_a_plus("A+", before) is True
    assert _scr._is_pre_rule_a_plus("A+", None) is True
    assert _scr._is_pre_rule_a_plus("A+", after) is False
    assert _scr._is_pre_rule_a_plus("A", before) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cached, row_score, expected",
    [
        (_cached(), 92, True),                    # passes certified_mark at the same score
        (_cached(files=5), 92, False),            # thin coverage: never the mark
        (_cached(score=70), 70, False),           # under 81
        (_cached(eligible=False), 92, False),     # not eligible
        (_cached(high=1), 92, False),             # not Safe
        (_cached(), 88, False),                   # row and cache disagree: fail closed
        (None, 92, False),                        # nothing cached: fail closed
        (_cached(pending=True), 92, True),        # stored grade is static: sandbox ignored
    ],
)
async def test_mark_from_cached_scan(monkeypatch, cached, row_score, expected):
    from src import cache

    seen = {}

    async def fake_get(key):
        seen["key"] = key
        return cached

    monkeypatch.setattr(cache, "get", fake_get)
    assert await _scr._mark_from_cached_scan("npm", "semver", row_score) is expected
    assert seen["key"] == "public_scan_stale:npm/semver"


@pytest.mark.asyncio
async def test_mark_from_cached_scan_fails_closed_on_error(monkeypatch):
    from src import cache

    async def boom(key):
        raise RuntimeError("redis down")

    monkeypatch.setattr(cache, "get", boom)
    assert await _scr._mark_from_cached_scan("npm", "semver", 92) is False
