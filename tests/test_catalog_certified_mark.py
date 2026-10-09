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
