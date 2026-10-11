"""A GitHub repo that is a collection of agent skills leads with the collection result
(its worst skill) on the result page, badge, card, OG and in Browse, so every surface
shows one number for it. Browse lists it once, and case-only duplicate rows collapse."""
from __future__ import annotations

import pytest

from src.api import public_scan_router as psr
from src.api import scan_catalog_router as scr
from src.api.scan_catalog_router import CatalogRow

_COLL = {
    "trust_score": 67,
    "findings": {"critical": 0, "high": 1, "medium": 2, "items": [
        {"category": "skill_capability", "severity": "high", "name": "drift"}]},
    "surface_detail": {"collection": True, "worst_skill": "skills/skill-creator",
                       "skills_total": 19, "skills": [{"path": "skills/pdf"}] * 19},
    "metadata": {"files_scanned": 120},
}


def _fake_cache(store):
    async def get(key):
        return store.get(key)
    return get


@pytest.mark.asyncio
async def test_collection_data_reads_the_skill_cache(monkeypatch):
    from src import cache
    monkeypatch.setattr(cache, "get", _fake_cache({"public_scan:skill/anthropics/skills": _COLL}))

    async def no_block(_d):
        return None
    monkeypatch.setattr(psr, "_cached_behavioral_for", no_block)
    data = await psr._skill_collection_data("anthropics", "skills")
    assert data and data["trust_score"] == 67
    summary = psr._skill_collection_summary("anthropics", "skills", data)
    assert summary["trust_score"] == 67 and summary["decision"] == "review"
    assert summary["skills_total"] == 19
    assert summary["report_url"].endswith("/check/skill/anthropics/skills")


@pytest.mark.asyncio
async def test_single_skill_or_plain_repo_has_no_collection(monkeypatch):
    from src import cache
    single = {**_COLL, "surface_detail": {"collection": False}}
    monkeypatch.setattr(cache, "get", _fake_cache({"public_scan:skill/a/one": single}))
    assert await psr._skill_collection_data("a", "one") is None
    assert await psr._skill_collection_data("a", "none") is None


def _row(surface, full, score):
    return CatalogRow(surface=surface, name=full, full_name=full, trust_score=score,
                      grade=None, critical=0, high=0)


@pytest.mark.asyncio
async def test_browse_lists_a_collection_once_with_the_collection_score(monkeypatch):
    async def coll(owner, repo):
        return _COLL if f"{owner}/{repo}".lower() == "anthropics/skills" else None
    monkeypatch.setattr(psr, "_skill_collection_data", coll)
    rows = [_row("github", "anthropics/skills", 90), _row("openclaw", "anthropics/skills", 64),
            _row("github", "other/repo", 80), _row("openclaw", "solo/skill", 70),
            _row("github", "solo/skill", 75)]
    out = await scr._lead_with_skill_collections(rows)
    names = [(r.surface, r.full_name, r.trust_score) for r in out]
    assert ("github", "anthropics/skills", 90) not in names
    assert ("openclaw", "anthropics/skills", 67) in names
    assert ("github", "solo/skill", 75) in names  # not a collection: both rows stay
    assert rows[1].trust_score == 64  # cached rows are not mutated


@pytest.mark.asyncio
async def test_no_overlap_means_no_cache_reads(monkeypatch):
    calls = []

    async def coll(owner, repo):
        calls.append((owner, repo))
        return None
    monkeypatch.setattr(psr, "_skill_collection_data", coll)
    rows = [_row("openclaw", f"o/s{i}", 50) for i in range(50)] + [_row("github", "x/y", 1)]
    assert await scr._lead_with_skill_collections(rows) == rows
    assert calls == []


class _C:
    def __init__(self, surface, owner, repo, score, when):
        from datetime import datetime, timezone
        self.surface, self.owner, self.repo = surface, owner, repo
        self.full_name = f"{owner}/{repo}"
        self.trust_score, self.grade, self.critical, self.high = score, None, 0, 0
        self.findings_count, self.primary_language = 0, None
        self.adoption_score = self.adoption_count = self.adoption_unit = None
        self.last_scanned_at = datetime(2026, 10, when, tzinfo=timezone.utc)


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _DB:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _stmt):
        return _Res(self.rows)


@pytest.mark.asyncio
async def test_case_only_duplicate_community_rows_collapse_to_the_newest():
    rows = [_C("github", "chris221", "ftp-ssh-mcp", 70, 10),   # newest first
            _C("github", "Chris221", "ftp-ssh-mcp", 55, 2),
            _C("npm", "npm", "Left-Pad", 80, 9), _C("npm", "npm", "left-pad", 81, 1)]
    out = await scr._fetch_community_rows(_DB(rows))
    gh = [r for r in out if r.surface == "github"]
    assert len(gh) == 1 and gh[0].trust_score == 70
    assert len([r for r in out if r.surface == "npm"]) == 2  # packages are case-sensitive
