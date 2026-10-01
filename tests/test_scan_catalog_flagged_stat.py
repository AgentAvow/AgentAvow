"""/public/scan-catalog/flagged-stat: exclusive severity buckets, honest denominator.

Regression for the 2026-10-01 headline bug: `flagged = crit + high` double-counted
every row that carried BOTH a critical and a high finding, and the denominator
included rows that were skipped / never scanned. The stat must agree with the
catalog list's exclusive `severity=` filter totals.

Fixture rows are injected straight into the in-memory catalog cache (no disk, no
DB); `_community_rows` is stubbed so the endpoint never touches a database.
"""
from __future__ import annotations

import pytest

import src.api.scan_catalog_router as m
from src.api.scan_catalog_router import CatalogRow, _severity_bucket


def _mcp(name: str, **kw) -> dict:
    raw = {"name": name, "full_name": f"acme/{name}", "trust_score": 90,
           "critical": 0, "high": 0, "findings_count": 0}
    raw.update(kw)
    return raw


def _fixture_rows() -> list[CatalogRow]:
    """A small corpus with every case the stat must get right."""
    raws: list[tuple[str, dict]] = [
        # mcp: one row with BOTH critical and high (the double-count case)
        ("mcp", _mcp("both", trust_score=30, critical=2, high=3, findings_count=5)),
        # mcp: critical only
        ("mcp", _mcp("crit", trust_score=40, critical=1)),
        # mcp: high only (x2)
        ("mcp", _mcp("high-a", trust_score=60, high=1)),
        ("mcp", _mcp("high-b", trust_score=65, high=4)),
        # mcp: clean, Trusted band
        ("mcp", _mcp("clean-a", trust_score=95)),
        ("mcp", _mcp("clean-b", trust_score=88)),
        # mcp: skipped (never fetched) and errored -> no verdict
        ("mcp", _mcp("skipped-1", trust_score=None, skipped="no_repo")),
        ("mcp", _mcp("skipped-2", trust_score=None, skipped="no_repo")),
        ("mcp", _mcp("errored", trust_score=0, scan_error="fetch failed")),
        # npm: one high-only, one clean, one skipped
        ("npm", _mcp("pkg-high", trust_score=55, high=2)),
        ("npm", _mcp("pkg-clean", trust_score=92)),
        ("npm", _mcp("pkg-skipped", trust_score=None, skipped="not_found")),
        # openclaw uses its own raw field names (critical_count / high_count / error)
        ("openclaw", {"repo": "acme/skill-both", "trust_score": 20,
                      "critical_count": 1, "high_count": 1}),
        ("openclaw", {"repo": "acme/skill-clean", "trust_score": 85,
                      "critical_count": 0, "high_count": 0}),
        ("openclaw", {"repo": "acme/skill-err", "trust_score": 0, "error": "private"}),
    ]
    rows = [m._normalize_row(surface, raw) for surface, raw in raws]
    # x402 rows are compliance probes, not code scans: must not touch any count.
    rows.append(m._normalize_row("x402", {"endpoint_url": "https://x.example/pay",
                                          "has_x402_header": True, "http_status": 402}))
    return rows


# Expected exclusive counts for the fixture above (hand-tallied).
EXPECTED = {
    "mcp": {"scanned_total": 6, "critical": 2, "high_only": 2, "clean": 2, "skipped": 3},
    "npm": {"scanned_total": 2, "critical": 0, "high_only": 1, "clean": 1, "skipped": 1},
    "openclaw": {"scanned_total": 2, "critical": 1, "high_only": 0, "clean": 1,
                 "skipped": 1},
}
EXPECTED_ALL = {
    k: sum(v[k] for v in EXPECTED.values())
    for k in ("scanned_total", "critical", "high_only", "clean", "skipped")
}


@pytest.fixture
def catalog(monkeypatch):
    rows = _fixture_rows()
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(rows))

    async def _no_community(db):
        return []

    monkeypatch.setattr(m, "_community_rows", _no_community)
    return rows


async def _list_total(surface: str | None, severity: str | None) -> int:
    """`total` of GET /public/scan-catalog?surface=..&severity=..&limit=1."""
    resp = await m.scan_catalog(
        surface=surface, q=None, severity=severity, grade=None, category=None,
        sort="default", limit=1, offset=0, db=None,
    )
    return resp.total


# --- bucket helper -----------------------------------------------------------------

def test_bucket_is_exclusive_and_critical_wins():
    both = CatalogRow(surface="mcp", name="b", trust_score=10, critical=1, high=5)
    assert _severity_bucket(both) == "critical"
    assert _severity_bucket(CatalogRow(surface="mcp", name="h", trust_score=50, high=1)) == "high"
    assert _severity_bucket(CatalogRow(surface="mcp", name="c", trust_score=99)) == "clean"


def test_bucket_no_verdict_is_skipped():
    assert _severity_bucket(CatalogRow(surface="mcp", name="s", skipped="no_repo")) == "skipped"
    assert _severity_bucket(
        CatalogRow(surface="mcp", name="e", trust_score=0, scan_error="boom")
    ) == "skipped"
    # a critical count on a row with no score is not a verdict either
    assert _severity_bucket(CatalogRow(surface="npm", name="n", critical=3)) == "skipped"
    assert _severity_bucket(CatalogRow(surface="x402", name="https://x")) == "n/a"


# --- the stat ----------------------------------------------------------------------

async def test_row_with_critical_and_high_is_counted_once(catalog):
    stat = await m.flagged_stat(db=None)
    rows_with_any = [
        r for r in catalog
        if r.surface != "x402" and _severity_bucket(r) != "skipped"
        and ((r.critical or 0) > 0 or (r.high or 0) > 0)
    ]
    # two rows in the fixture carry both a critical and a high: under the old
    # `crit + high` arithmetic flagged would be len(rows_with_any) + 2.
    assert stat["flagged"] == len(rows_with_any) == EXPECTED_ALL["critical"] + EXPECTED_ALL["high_only"]
    assert stat["critical"] == EXPECTED_ALL["critical"]
    assert stat["high_only"] == EXPECTED_ALL["high_only"]
    assert stat["flagged"] == stat["critical"] + stat["high_only"]


async def test_skipped_rows_are_not_in_the_denominator(catalog):
    stat = await m.flagged_stat(db=None)
    assert stat["skipped"] == EXPECTED_ALL["skipped"]
    assert stat["scanned_total"] == EXPECTED_ALL["scanned_total"]
    assert stat["total"] == stat["scanned_total"] + stat["skipped"]
    # x402 probes never enter any count
    assert stat["total"] == sum(1 for r in catalog if r.surface != "x402")
    # the buckets partition the scanned set
    assert stat["scanned_total"] == stat["critical"] + stat["high_only"] + stat["clean"]
    assert stat["clean"] == EXPECTED_ALL["clean"]
    # pct is over SCANNED rows only: 6 flagged / 10 scanned, not 6 / 15
    assert stat["pct"] == 60
    assert stat["flagged_pct"] == 60.0
    assert stat["critical_pct"] == 30.0


async def test_legacy_keys_kept_and_honest(catalog):
    stat = await m.flagged_stat(db=None)
    assert stat["scanned"] == stat["scanned_total"]
    assert stat["flagged"] == stat["critical"] + stat["high_only"]
    assert stat["pct"] == round(stat["flagged"] / stat["scanned"] * 100)


async def test_per_surface_breakdown_uses_same_exclusive_semantics(catalog):
    stat = await m.flagged_stat(db=None)
    assert set(stat["by_surface"]) == {"mcp", "npm", "openclaw"}  # no x402
    for surface, exp in EXPECTED.items():
        got = stat["by_surface"][surface]
        for k, v in exp.items():
            assert got[k] == v, (surface, k, got)
        assert got["flagged"] == got["critical"] + got["high_only"]
        assert got["total"] == got["scanned_total"] + got["skipped"]


async def test_stat_totals_equal_list_endpoint_severity_totals(catalog):
    """The headline must be the same number Browse shows when you click the filter."""
    stat = await m.flagged_stat(db=None)
    for surface in (None, "mcp", "npm", "openclaw"):
        src = stat if surface is None else stat["by_surface"][surface]
        assert src["critical"] == await _list_total(surface, "critical")
        assert src["high_only"] == await _list_total(surface, "high")
        assert src["skipped"] == await _list_total(surface, "skipped")
        # the list's "clean" additionally requires score >= 80; every clean fixture row
        # is in the Trusted band, so here the two agree exactly
        assert src["clean"] == await _list_total(surface, "clean")
        assert src["scanned_total"] == (
            await _list_total(surface, "critical")
            + await _list_total(surface, "high")
            + await _list_total(surface, "clean")
        )


async def test_list_clean_is_stricter_than_stat_clean(catalog, monkeypatch):
    """A verdict with no high/critical but a sub-Trusted score is `clean` in the stat
    (not flagged) but not `clean` in the list (not "safe to connect")."""
    rows = catalog + [m._normalize_row("mcp", _mcp("meh", trust_score=60))]
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(rows))
    stat = await m.flagged_stat(db=None)
    assert stat["by_surface"]["mcp"]["clean"] == EXPECTED["mcp"]["clean"] + 1
    assert await _list_total("mcp", "clean") == EXPECTED["mcp"]["clean"]
    assert stat["by_surface"]["mcp"]["flagged"] == EXPECTED["mcp"]["critical"] + EXPECTED["mcp"]["high_only"]


async def test_community_rows_merge_with_same_rules(catalog, monkeypatch):
    community = [
        CatalogRow(surface="github", name="o/both", full_name="o/both", trust_score=25,
                   critical=1, high=2),
        CatalogRow(surface="github", name="o/clean", full_name="o/clean", trust_score=90),
        # a community row with no score is unscanned, not a verdict
        CatalogRow(surface="npm", name="left", full_name="left", trust_score=None),
    ]

    async def _community(db):
        return community

    monkeypatch.setattr(m, "_community_rows", _community)
    stat = await m.flagged_stat(db=None)
    assert stat["by_surface"]["github"] == {
        **stat["by_surface"]["github"], "scanned_total": 2, "critical": 1, "high_only": 0,
        "clean": 1, "skipped": 0, "flagged": 1,
    }
    assert stat["by_surface"]["npm"]["skipped"] == EXPECTED["npm"]["skipped"] + 1
    assert stat["scanned_total"] == EXPECTED_ALL["scanned_total"] + 2
    assert stat["flagged"] == EXPECTED_ALL["critical"] + EXPECTED_ALL["high_only"] + 1


async def test_empty_catalog_has_null_pct(monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog([]))

    async def _none(db):
        return []

    monkeypatch.setattr(m, "_community_rows", _none)
    stat = await m.flagged_stat(db=None)
    assert stat["pct"] is None and stat["scanned_total"] == 0 and stat["flagged"] == 0


# --- summary counters (Browse strip) ---------------------------------------------

def test_summary_counters_are_exclusive_and_split_scanned_from_skipped():
    summary = m._build_catalog(_fixture_rows())["summary"]
    for surface, exp in EXPECTED.items():
        assert summary.by_surface_critical[surface] == exp["critical"]
        assert summary.by_surface_high[surface] == exp["high_only"]  # high-only, not "any high"
        assert summary.by_surface_scanned[surface] == exp["scanned_total"]
        assert summary.by_surface_skipped[surface] == exp["skipped"]
    assert summary.repo_scans_with_critical == EXPECTED_ALL["critical"]
    assert summary.repo_scans_with_high == EXPECTED_ALL["high_only"]
    assert summary.repo_scans_scanned == EXPECTED_ALL["scanned_total"]
    assert summary.repo_scans_skipped == EXPECTED_ALL["skipped"]
    # repo_scans_total keeps its meaning: every non-x402 row, graded or not
    assert summary.repo_scans_total == EXPECTED_ALL["scanned_total"] + EXPECTED_ALL["skipped"]
    assert summary.x402_endpoints_total == 1 and summary.x402_compliant == 1
