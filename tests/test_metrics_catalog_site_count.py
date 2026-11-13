"""The admin dashboard's catalog numbers count tools the way the public site does.

Live on 2026-11-13 the dashboard showed three totals for one idea: the site's answer mix
(sum of /public/scan-catalog?decision=... totals), the Growth tiles' "right now" mix
(corpus rows + every community scan, a page with both counted twice) and Catalog risk
(/flagged-stat, which also counts a skill collection's plain GitHub row that Browse
drops). ``current_catalog_mix`` now counts the Browse list's own rows, so its answered
total equals the site's; the older count stays as ``all_rows``.
"""
from __future__ import annotations

import pytest

import src.api.scan_catalog_router as m
from src.jobs import metrics_daily
from tests.test_catalog_one_row_per_page import LIVE, _corpus, _live

# A live GitHub scan of a repo the corpus lists as a skill collection: Browse shows the
# skill row only (``_lead_with_skill_collections``); /flagged-stat counts both.
COMMUNITY = [*LIVE, _live("github", "ArcReel/ArcReel", 70, decision="review")]


@pytest.fixture
def catalog(monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_corpus()))
    m._VIEW_CACHE.clear()

    async def _rows(db):
        return list(COMMUNITY)
    monkeypatch.setattr(m, "_community_rows", _rows)

    async def _skill_coll(owner, repo):
        if f"{owner}/{repo}".lower() == "arcreel/arcreel":
            return {"trust_score": 63, "findings": {"critical": 0, "high": 1}}
        return None
    monkeypatch.setattr("src.api.public_scan_router._skill_collection_data", _skill_coll)

    async def _no_sandbox(rows):
        return rows
    monkeypatch.setattr(m, "_attach_sandbox", _no_sandbox)
    yield
    m._VIEW_CACHE.clear()


async def _total(**kw) -> int:
    args = {"surface": None, "q": None, "severity": None, "grade": None, "category": None,
            "decision": None, "sort": "default", "limit": 1, "offset": 0}
    args.update(kw)
    return (await m._catalog_view(db=None, **args)).total


@pytest.mark.asyncio
async def test_dashboard_mix_equals_the_sites_answer_totals(catalog):
    mix = await metrics_daily.current_catalog_mix(None)
    site = {d: await _total(decision=d) for d in ("safe", "review", "do_not_connect")}
    assert {d: mix[d] for d in site} == site
    # Listed rows with or without an answer: the unfiltered Browse total.
    assert mix["total"] == await _total()
    assert mix["unscored"] == mix["total"] - sum(site.values())


@pytest.mark.asyncio
async def test_flagged_uses_the_same_rows(catalog):
    mix = await metrics_daily.current_catalog_mix(None)
    rows = await m.browse_listed_rows(None)
    answered = [r for r in rows if r.decision in ("safe", "review", "do_not_connect")]
    assert mix["flagged"] == sum(1 for r in answered if (r.critical or 0) or (r.high or 0))
    assert 0 < mix["flagged"] < len(answered)


@pytest.mark.asyncio
async def test_why_the_older_counts_were_larger(catalog):
    """``all_rows`` keeps the older count (corpus + every community scan before
    merging), and /flagged-stat also counts the skill collection's GitHub row."""
    mix = await metrics_daily.current_catalog_mix(None)
    catalog_ = m._get_catalog()
    old = sum(1 for r in catalog_["rows"] if r.surface != "x402") + len(COMMUNITY)
    assert mix["all_rows"] == old > mix["total"]

    answered = mix["safe"] + mix["review"] + mix["do_not_connect"]
    stat = m._compute_flagged_stat(catalog_, list(COMMUNITY))
    assert stat["scanned_total"] == answered + 1  # the dropped ArcReel GitHub row


@pytest.mark.asyncio
async def test_browse_listed_rows_leave_out_x402(catalog):
    rows = await m.browse_listed_rows(None)
    assert rows and all(r.surface != "x402" for r in rows)
    assert not any(r.surface == "github" and r.full_name == "ArcReel/ArcReel" for r in rows)
