"""Browse lists ONE row per tool page (tool-pages plan PR 1, B11 data fixes).

The live bug (2026-11-11): a one-time launch-corpus MCP registry row (skyvern 0 / Do not
connect, 7 critical) sat next to the fresh GitHub scan (87 / Safe) and both linked to
/check/skyvern-ai/skyvern, so Browse said one thing and the page another. Now a live
(community) row replaces every corpus row for its page, corpus rows for one page
collapse, every row carries a scan date and its page path, the community read has no
2,000-row cap, and the re-scan loop queues corpus rows whose page has no live scan.

Fixture rows go straight into the in-memory catalog; the community read is stubbed.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import src.api.scan_catalog_router as m
from src.api.scan_catalog_router import CatalogRow

WHEN = datetime(2026, 11, 10, tzinfo=timezone.utc)


def _corpus() -> list[CatalogRow]:
    raws = [
        # skyvern: the stale MCP registry row, 0 / Do not connect
        ("mcp", {"name": "io.github.Skyvern-AI/skyvern", "full_name": "Skyvern-AI/skyvern",
                 "repository_url": "https://github.com/Skyvern-AI/skyvern",
                 "trust_score": 0, "critical": 7, "high": 2, "findings_count": 30,
                 "stars": 23153}),
        # browser-use: same shape, different casing from the live row
        ("mcp", {"name": "com.browser-use/browser-use", "full_name": "Browser-Use/browser-use",
                 "trust_score": 0, "critical": 4, "high": 0, "stars": 117399}),
        # sceneview: two registry names for one repo, casing differs
        ("mcp", {"name": "io.github.sceneview/mcp", "full_name": "sceneview/sceneview",
                 "trust_score": 67, "critical": 0, "high": 0, "stars": 1336}),
        ("mcp", {"name": "io.github.SceneView/mcp", "full_name": "SceneView/sceneview",
                 "trust_score": 60, "critical": 0, "high": 1, "stars": 1290}),
        # npm duplicate of one package (corpus 90 vs the live 81)
        ("npm", {"name": "@modelcontextprotocol/server-filesystem", "trust_score": 90,
                 "critical": 0, "high": 0, "findings_count": 5}),
        # two skills in one repo: one page, the worst skill leads
        ("openclaw", {"repo": "ArcReel/ArcReel", "trust_score": 90, "critical_count": 0,
                      "high_count": 0, "stars": 1554}),
        ("openclaw", {"repo": "ArcReel/ArcReel", "trust_score": 63, "critical_count": 0,
                      "high_count": 1, "stars": 6406}),
        # untouched rows
        ("mcp", {"name": "io.github.acme/tool", "full_name": "acme/tool", "trust_score": 95,
                 "critical": 0, "high": 0, "stars": 10}),
        ("mcp", {"name": "io.github.acme/dnc", "full_name": "acme/dnc", "trust_score": 10,
                 "critical": 2, "high": 0, "stars": 5}),
        ("mcp", {"name": "no-repo-entry", "repository_url": None, "skipped": "no_repo"}),
    ]
    rows = [m._normalize_row(s, r) for s, r in raws]
    rows.append(m._normalize_row("x402", {"endpoint_url": "https://x.example/pay",
                                          "trust_score": 90, "critical": 0, "high": 0}))
    return rows


def _live(surface, full_name, score, *, name=None, decision=None, critical=0, high=0,
          adoption=None):
    return CatalogRow(
        surface=surface, name=name or full_name, full_name=full_name,
        repository_url=(f"https://github.com/{full_name}"
                        if surface in ("github", "openclaw") else None),
        trust_score=score, critical=critical, high=high, decision=decision,
        adoption_count=adoption, adoption_unit="stars" if adoption else None,
        last_scanned_at=WHEN, scan_source="live", category="Library",
    )


LIVE = [
    _live("github", "Skyvern-AI/skyvern", 87, decision="safe", adoption=23324),
    _live("github", "browser-use/browser-use", 61, decision="review"),
    _live("npm", "npm:@modelcontextprotocol/server-filesystem", 81,
          name="@modelcontextprotocol/server-filesystem", high=1),
    _live("github", "fresh/only-live", 77),
]


@pytest.fixture
def catalog(monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_corpus()))
    m._VIEW_CACHE.clear()

    async def _rows(db):
        return list(LIVE)
    monkeypatch.setattr(m, "_community_rows", _rows)

    async def _no_skill_coll(owner, repo):
        return None
    monkeypatch.setattr("src.api.public_scan_router._skill_collection_data", _no_skill_coll)

    async def _no_sandbox(rows):
        return rows
    monkeypatch.setattr(m, "_attach_sandbox", _no_sandbox)
    yield
    m._VIEW_CACHE.clear()


async def _view(**kw):
    args = {"surface": None, "q": None, "severity": None, "grade": None, "category": None,
            "decision": None, "sort": "default", "limit": 200, "offset": 0}
    args.update(kw)
    return await m._catalog_view(db=None, **args)


def _for(rows, path):
    return [r for r in rows if (r.page_path or "").lower() == path.lower()]


def test_page_path_is_a_port_of_listing_href():
    assert m.page_path_for("npm", "chalk", "npm:chalk") == "/check/pkg/npm/chalk"
    assert m.page_path_for("pypi", "fastmcp", "PrefectHQ/fastmcp") == "/check/pkg/pypi/fastmcp"
    assert m.page_path_for("openclaw", "a/b", "a/b") == "/check/skill/a/b"
    assert m.page_path_for("mcp", "io.github.a/b", "a/b") == "/check/a/b"
    assert (m.page_path_for("mcp", "https://h.example/mcp?x=1", None)
            == "/check/mcp?endpoint=https%3A%2F%2Fh.example%2Fmcp%3Fx%3D1")
    assert m.page_path_for("github", "a/b", "a/b") == "/check/a/b"
    assert m.page_path_for("mcp", "no-repo-entry", None) is None
    assert m.page_path_for("x402", "https://x.example/pay", None, "https://x.example/pay") is None


@pytest.mark.asyncio
async def test_skyvern_stale_dnc_registry_row_gives_way_to_the_fresh_safe_scan(catalog):
    out = await _view()
    sky = _for(out.rows, "/check/skyvern-ai/skyvern")
    assert len(sky) == 1
    assert sky[0].trust_score == 87 and sky[0].decision == "safe"
    assert sky[0].scan_source == "live" and sky[0].last_scanned_at == WHEN
    # It stays in the MCP tab (the corpus row's tab), now with the fresh answer.
    mcp = await _view(surface="mcp")
    sky = _for(mcp.rows, "/check/skyvern-ai/skyvern")
    assert len(sky) == 1 and sky[0].decision == "safe" and sky[0].is_mcp_server
    # Filtering by Do not connect no longer finds it.
    dnc = await _view(decision="do_not_connect")
    assert not _for(dnc.rows, "/check/skyvern-ai/skyvern")


@pytest.mark.asyncio
async def test_live_row_wins_across_owner_casing(catalog):
    out = await _view()
    bu = _for(out.rows, "/check/browser-use/browser-use")
    assert len(bu) == 1 and bu[0].trust_score == 61 and bu[0].decision == "review"
    # adoption the live row had not computed yet comes from the corpus row
    assert bu[0].adoption_count == 117399


@pytest.mark.asyncio
async def test_package_listed_once_with_the_live_scan(catalog):
    out = await _view()
    fs = _for(out.rows, "/check/pkg/npm/@modelcontextprotocol/server-filesystem")
    assert len(fs) == 1 and fs[0].trust_score == 81 and fs[0].scan_source == "live"


@pytest.mark.asyncio
async def test_corpus_duplicates_collapse_to_the_worst_row(catalog):
    out = await _view()
    sv = _for(out.rows, "/check/sceneview/sceneview")
    assert len(sv) == 1 and sv[0].trust_score == 60
    arc = _for(out.rows, "/check/skill/arcreel/arcreel")
    assert len(arc) == 1 and arc[0].trust_score == 63


@pytest.mark.asyncio
async def test_every_page_appears_once_and_totals_count_pages(catalog):
    out = await _view()
    keys = [m.page_key(r) for r in out.rows if r.page_path]
    assert len(keys) == len(set(keys))
    # 10 non-x402 corpus rows -> 7 pages + 1 unlinked row; 3 pages taken over by live
    # rows, 1 live-only page added. x402 stays out of the all-surface list.
    assert out.total == 8 + 1
    assert all(r.surface != "x402" for r in out.rows)
    s = out.summary
    # skyvern, browser-use (live, kept in the MCP tab), sceneview, acme/tool, acme/dnc,
    # no-repo
    assert s.by_surface["mcp"] == 6
    assert s.by_surface["community"] == len(LIVE)
    assert s.repo_scans_total == 8 - 3  # corpus rows still listed (the corpus counts)
    assert s.x402_endpoints_total == 1
    assert s.total_scans == (8 + 1) - 3 + len(LIVE)  # corpus incl. x402, minus replaced
    assert all(v > 0 for v in s.by_category.values())


@pytest.mark.asyncio
async def test_flagged_stat_counts_each_page_once(catalog):
    stat = m._compute_flagged_stat(m._get_catalog(), list(LIVE))
    # pages with a verdict: skyvern, browser-use, server-filesystem, sceneview, arcreel,
    # acme/tool, acme/dnc, fresh/only-live (no-repo is skipped, x402 excluded)
    assert stat["scanned_total"] == 8
    assert stat["skipped"] == 1
    assert stat["critical"] == 1  # acme/dnc only; skyvern's stale 7 critical is gone


def test_rows_carry_a_scan_date_and_source():
    dated = m._normalize_row("mcp", {"name": "x", "full_name": "a/b", "trust_score": 90,
                                     "scanned_at": "2026-11-01T10:00:00Z"})
    assert dated.scan_source == "launch"
    assert dated.last_scanned_at == datetime(2026, 11, 1, 10, tzinfo=timezone.utc)
    undated = m._normalize_row("mcp", {"name": "x", "full_name": "a/b", "trust_score": 90})
    assert undated.last_scanned_at is None and undated.scan_source == "launch"


def test_file_level_scan_date_dates_undated_rows(tmp_path):
    import json
    p = tmp_path / "openclaw-results.json"
    p.write_text(json.dumps({"scan_date": "2026-04-09T21:34:54Z", "repos": [
        {"repo": "a/b", "trust_score": 80, "critical_count": 0, "high_count": 0}]}))
    rows = m._load_surface("openclaw", p, results_key="repos")
    assert rows[0].last_scanned_at == datetime(2026, 4, 9, 21, 34, 54, tzinfo=timezone.utc)


class _C:
    def __init__(self, surface, owner, repo, score, day):
        self.surface, self.owner, self.repo = surface, owner, repo
        self.full_name = f"{owner}/{repo}" if surface in ("github", "openclaw") \
            else f"{surface}:{repo}"
        self.trust_score, self.grade, self.critical, self.high = score, None, 0, 0
        self.findings_count, self.primary_language = 0, None
        self.adoption_score = self.adoption_count = self.adoption_unit = None
        self.decision = self.decision_reason = None
        self.last_scanned_at = datetime(2026, 10, day, tzinfo=timezone.utc)


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _DB:
    def __init__(self, rows):
        self.rows, self.stmt = rows, None

    async def execute(self, stmt):
        self.stmt = stmt
        return _Res(self.rows)


@pytest.mark.asyncio
async def test_community_read_has_no_2000_cap_and_dates_rows():
    rows = [_C("github", "o", f"r{i}", 80, 1 + i % 28) for i in range(2500)]
    db = _DB(rows)
    out = await m._fetch_community_rows(db)
    assert len(out) == 2500
    assert db.stmt._limit_clause.value == m.COMMUNITY_ROWS_MAX
    assert all(r.scan_source == "live" and r.last_scanned_at for r in out)
    assert out[0].page_path == "/check/o/r0"


def test_stale_corpus_targets_queue_pages_with_no_live_scan(monkeypatch):
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_corpus()))
    live = {m.page_key(r) for r in LIVE}
    got = m.stale_corpus_targets(live, limit=10)
    coords = [t[1:] for t in got]
    # replaced pages are not queued; x402 and the repo-less entry never are
    assert ("github", "Skyvern-AI", "skyvern") not in coords
    assert all(t[1] != "x402" for t in got)
    # Do-not-connect rows lead their half
    assert coords[0] == ("github", "acme", "dnc")
    assert ("github", "SceneView", "sceneview") in coords
    assert ("openclaw", "ArcReel", "ArcReel") in coords
    assert ("github", "acme", "tool") in coords
    assert len(got) == len({t[0] for t in got})
    # a failed key is skipped next time
    again = m.stale_corpus_targets(live, limit=10, skip={got[0][0]})
    assert got[0][0] not in {t[0] for t in again}
    assert m.stale_corpus_targets(live, limit=0) == []


@pytest.mark.asyncio
async def test_rescan_loop_scans_stale_corpus_rows(monkeypatch):
    from contextlib import asynccontextmanager

    from src.jobs import scheduler as sch

    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(_corpus()))

    async def _fetch(db):
        return list(LIVE)
    monkeypatch.setattr(m, "_fetch_community_rows", _fetch)

    @asynccontextmanager
    async def _session():
        yield None
    monkeypatch.setattr("src.database.async_session", _session)
    scanned = []

    async def _rescan(surface, owner, repo, db):
        scanned.append((surface, owner, repo))
        return repo != "dnc"  # acme/dnc fails (a deleted repo)
    monkeypatch.setattr(sch, "_rescan_catalog_row", _rescan)
    monkeypatch.setattr(sch, "_supersede_failed", set())

    done = await sch._rescan_stale_corpus_rows(gh_ok=True, spacing=0)
    assert ("github", "acme", "dnc") in scanned and done == len(scanned) - 1
    assert sch._supersede_failed == {"/check/acme/dnc"}
    # under a low GitHub budget only non-GitHub targets run (npm is replaced here)
    scanned.clear()
    await sch._rescan_stale_corpus_rows(gh_ok=False, spacing=0)
    assert all(s not in ("github", "openclaw") for s, _o, _r in scanned)
