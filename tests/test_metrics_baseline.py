"""The /admin/metrics baseline: the counting rules and the date they changed,
plus the two new headline numbers, read back through the real aggregation.
"""
from __future__ import annotations

import pytest

import src.api.metrics_dashboard_router as md
from src.usage_scope import LEGACY_HOSTS, RULES_CHANGED_ON


def test_baseline_states_each_rule_once_and_the_date():
    b = md.metrics_baseline()
    assert b["rules_changed_on"] == RULES_CHANGED_ON == "2026-10-02"
    rules = b["rules"]
    assert len(rules) == 4
    assert all(isinstance(r, str) and r.endswith(".") and len(r) < 300 for r in rules)
    text = " ".join(rules)
    for needle in ("301/302/308", "requests_redirected", "retired domain", "browser User-Agent",
                   "HyperLogLog", "48h", "cannot be joined"):
        assert needle in text, needle
    for host in LEGACY_HOSTS:
        assert host in text


@pytest.mark.asyncio
async def test_aggregate_carries_baseline_and_the_new_headline_numbers(db):
    out = await md._aggregate(db, "7d")
    assert out["baseline"] == md.metrics_baseline()
    assert isinstance(out["headline"]["requests_redirected"], int)
    assert isinstance(out["headline"]["unique_humans"], int)
    assert len(out["series"]["requests_redirected"]) == 7
    assert any("requests_redirected" in n for n in out["notes"])
    assert any("unique_humans" in n for n in out["notes"])
