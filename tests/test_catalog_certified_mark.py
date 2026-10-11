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


# --- lists show the mark only when the row's own page does (sandbox final + clean) ----

from src.api import public_scan_router as _psr  # noqa: E402

_CLEAN_RUN = {"ran": True, "pending": False, "findings": [], "unexpected_egress": []}


def _patch_sandbox(monkeypatch, *, enabled=True, target=("pypi", "idna"), cached=None,
                   age=None):
    from src.config import settings
    from src.scanner.behavioral import slots

    monkeypatch.setattr(settings, "scanner_behavioral_enabled", enabled, raising=False)
    monkeypatch.setattr(_psr, "_behavioral_target", lambda data: target)
    monkeypatch.setattr(_psr, "_declared_egress", lambda data: set())
    monkeypatch.setattr(_psr, "_behavioral_plan", lambda data, surface: None)

    async def fake_cached(surface, name, declared=None, plan=None):
        return cached

    async def fake_age(member):
        return age

    monkeypatch.setattr(_psr, "_get_cached_behavioral", fake_cached)
    monkeypatch.setattr(slots, "peek_pending_age", fake_age)


@pytest.mark.asyncio
async def test_peek_returns_the_cached_run(monkeypatch):
    _patch_sandbox(monkeypatch, cached=_CLEAN_RUN)
    assert await _psr._behavioral_peek(_cached()) == _CLEAN_RUN


@pytest.mark.asyncio
async def test_peek_reads_pending_when_no_run_is_cached(monkeypatch):
    _patch_sandbox(monkeypatch, cached=None, age=None)
    block = await _psr._behavioral_peek(_cached())
    assert block["pending"] is True


@pytest.mark.asyncio
async def test_peek_reads_unavailable_past_the_pending_age(monkeypatch):
    from src.scanner.behavioral import slots
    _patch_sandbox(monkeypatch, cached=None, age=slots.PENDING_MAX_AGE + 60)
    block = await _psr._behavioral_peek(_cached())
    assert block["pending"] is False and block["state"] == "unavailable"


@pytest.mark.asyncio
async def test_peek_is_none_without_a_sandbox_target_or_tier(monkeypatch):
    _patch_sandbox(monkeypatch, target=None)
    assert await _psr._behavioral_peek(_cached()) is None
    _patch_sandbox(monkeypatch, enabled=False)
    assert await _psr._behavioral_peek(_cached()) is None


@pytest.mark.asyncio
async def test_badge_view_withholds_the_mark_while_the_sandbox_is_pending(monkeypatch):
    _patch_sandbox(monkeypatch, cached=None, age=None)
    _, mark = await _psr._badge_view(_cached(), 92)
    assert mark is False
    _patch_sandbox(monkeypatch, cached=_CLEAN_RUN)
    _, mark = await _psr._badge_view(_cached(), 92)
    assert mark is True


def _patch_scan_cache(monkeypatch, data):
    from src import cache

    async def fake_get(key):
        return data

    monkeypatch.setattr(cache, "get", fake_get)


@pytest.mark.asyncio
async def test_page_mark_none_when_nothing_cached_or_score_differs(monkeypatch):
    _patch_sandbox(monkeypatch, cached=_CLEAN_RUN)
    _patch_scan_cache(monkeypatch, None)
    assert await _scr._mark_as_page_shows("pypi", "idna", 92) is None
    _patch_scan_cache(monkeypatch, _cached(score=88))
    assert await _scr._mark_as_page_shows("pypi", "idna", 92) is None


@pytest.mark.asyncio
async def test_page_mark_follows_the_sandbox(monkeypatch):
    _patch_scan_cache(monkeypatch, _cached())
    _patch_sandbox(monkeypatch, cached=None, age=None)       # page: "after the sandbox"
    assert await _scr._mark_as_page_shows("pypi", "idna", 92) is False
    _patch_sandbox(monkeypatch, cached=_CLEAN_RUN)           # run landed clean
    assert await _scr._mark_as_page_shows("pypi", "idna", 92) is True


@pytest.mark.asyncio
async def test_page_mark_ignores_a_stale_mark_carried_in_the_cache(monkeypatch):
    stale = {**_cached(), "decision": "safe", "certified_mark": True}
    _patch_scan_cache(monkeypatch, stale)
    _patch_sandbox(monkeypatch, cached=None, age=None)
    assert await _scr._mark_as_page_shows("pypi", "idna", 92) is False
