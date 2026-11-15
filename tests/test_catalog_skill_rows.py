"""Launch skill rows whose skill scan can't run: no SKILL.md -> listed as the repo,
deleted repo -> dropped (src/api/catalog_skill_rows.py)."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.api import catalog_skill_rows as sr
from src.api import scan_catalog_router as m
from src.jobs import scheduler as sch


def _corpus_file(tmp_path, repos):
    (tmp_path / "openclaw-results.json").write_text(json.dumps({"repos": [
        {"repo": r, "trust_score": 5, "critical_count": 1, "high_count": 0, "stars": 100}
        for r in repos]}))


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(m, "_CATALOG_CACHE", None, raising=False)
    return tmp_path


def test_miss_kind_reads_only_definitive_errors():
    assert sr.miss_kind("No SKILL.md found — this repo isn't a recognizable Agent Skill.") \
        == sr.NO_SKILL_MD
    assert sr.miss_kind("Repository not found or unreadable") == sr.REPO_GONE
    assert sr.miss_kind("Could not grade any of this repo's skills.") is None
    assert sr.miss_kind("Skill not found in this repo: pdf") is None
    assert sr.miss_kind(None) is None


def test_overlay_round_trip_and_case(data_dir):
    assert sr.load_overlay() == {}
    assert sr.record("pjasicek/OpenClaw", sr.NO_SKILL_MD)
    assert sr.record("LycheeMem/LycheeMem", sr.REPO_GONE)
    assert not sr.record("bad", sr.REPO_GONE)
    assert not sr.record("a/b", "whatever")
    assert sr.load_overlay() == {"pjasicek/openclaw": sr.NO_SKILL_MD,
                                 "lycheemem/lycheemem": sr.REPO_GONE}
    assert sr.clear("PJASICEK/openclaw")
    assert sr.load_overlay() == {"lycheemem/lycheemem": sr.REPO_GONE}


def test_unreadable_overlay_is_empty(data_dir):
    (data_dir / m._SKILL_ROWS_FILE).write_text("{not json")
    assert sr.load_overlay() == {}


def test_catalog_lists_no_skill_md_row_as_the_repo_and_drops_gone_repo(data_dir):
    _corpus_file(data_dir, ["pjasicek/OpenClaw", "LycheeMem/LycheeMem", "acme/real-skill"])
    before = {r.full_name: r for r in m._load_rows()}
    assert before["pjasicek/OpenClaw"].page_path == "/check/skill/pjasicek/OpenClaw"

    sr.record("pjasicek/OpenClaw", sr.NO_SKILL_MD)
    sr.record("lycheemem/lycheemem", sr.REPO_GONE)
    rows = {r.full_name: r for r in m._load_rows()}
    assert "LycheeMem/LycheeMem" not in rows
    game = rows["pjasicek/OpenClaw"]
    assert game.surface == "github" and game.page_path == "/check/pjasicek/OpenClaw"
    # the verdict (a repo-scanner verdict all along) is kept
    assert game.decision == before["pjasicek/OpenClaw"].decision
    real = rows["acme/real-skill"]
    assert real.surface == "openclaw" and real.page_path == "/check/skill/acme/real-skill"

    cat = m._build_catalog()
    assert cat["summary"].by_surface.get("openclaw") == 1
    assert m._rescan_target(game) == ("github", "pjasicek", "OpenClaw")


def test_overlay_write_changes_the_source_signature(data_dir):
    _corpus_file(data_dir, ["a/b"])
    sig = m._source_signature()
    sr.record("a/b", sr.NO_SKILL_MD)
    assert m._source_signature() != sig


def _use_corpus(data_dir, monkeypatch, repos):
    _corpus_file(data_dir, repos)
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog())


@pytest.mark.asyncio
async def test_note_records_no_skill_md_for_corpus_skill_rows_only(data_dir, monkeypatch):
    _use_corpus(data_dir, monkeypatch, ["itq5/OpenClaw-Admin"])
    await sr.note_skill_scan("itq5", "openclaw-admin", "No SKILL.md found — x")
    await sr.note_skill_scan("someone", "candidate", "No SKILL.md found — x")
    assert sr.load_overlay() == {"itq5/openclaw-admin": sr.NO_SKILL_MD}


@pytest.mark.asyncio
async def test_repo_gone_needs_a_github_404(data_dir, monkeypatch):
    _use_corpus(data_dir, monkeypatch, ["LycheeMem/LycheeMem", "acme/ratelimited"])
    seen = []

    async def fake_gone(owner, repo):
        seen.append(repo)
        return repo == "LycheeMem"
    monkeypatch.setattr(sr, "github_repo_gone", fake_gone)
    await sr.note_skill_scan("LycheeMem", "LycheeMem", "Repository not found or unreadable")
    await sr.note_skill_scan("acme", "ratelimited", "Repository not found or unreadable")
    assert seen == ["LycheeMem", "ratelimited"]
    assert sr.load_overlay() == {"lycheemem/lycheemem": sr.REPO_GONE}


@pytest.mark.asyncio
async def test_successful_skill_scan_clears_the_entry(data_dir, monkeypatch):
    _use_corpus(data_dir, monkeypatch, ["acme/back"])
    sr.record("acme/back", sr.NO_SKILL_MD)
    await sr.note_skill_scan("acme", "back", None)
    assert sr.load_overlay() == {}


@pytest.mark.asyncio
async def test_github_repo_gone_reads_only_404_and_451(monkeypatch):
    import httpx

    status = {"code": 404}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            if status["code"] is None:
                raise httpx.ConnectError("down")
            return SimpleNamespace(status_code=status["code"])

    async def no_token():
        return None
    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setattr("src.github_auth.get_github_token", no_token)
    for code, gone in ((404, True), (451, True), (403, False), (200, False),
                       (502, False), (None, False)):
        status["code"] = code
        assert await sr.github_repo_gone("o", "r") is gone, code


@pytest.mark.asyncio
async def test_rescan_of_a_skill_row_notes_the_failure(monkeypatch):
    noted = []

    async def fake_scan_skill(owner, repo):
        return SimpleNamespace(error="No SKILL.md found — x", trust_score=None)

    async def fake_note(owner, repo, error):
        noted.append((owner, repo, error))
    monkeypatch.setattr("src.scanner.scan.scan_skill", fake_scan_skill)
    monkeypatch.setattr(sr, "note_skill_scan", fake_note)
    ok = await sch._rescan_catalog_row("openclaw", "kwalus", "Canopy", db=None)
    assert ok is False
    assert noted == [("kwalus", "Canopy", "No SKILL.md found — x")]
