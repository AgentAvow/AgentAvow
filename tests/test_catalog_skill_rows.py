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

    async def confirmed(owner, repo):
        return True
    monkeypatch.setattr(sr, "confirm_no_skill_md", confirmed)
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
    # one 404 is only noted, never a delisting
    assert sr.load_overlay() == {}
    first = sr._load_checks(data_dir / m._SKILL_ROWS_FILE)
    assert "first_404_at" in first["lycheemem/lycheemem"]
    assert "acme/ratelimited" not in first


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


# --- no_skill_md needs a confirmed tree --------------------------------------------

class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _TreeClient:
    """meta answers ``meta``; tree answers ``tree`` (a status or a (status, body) pair)."""

    def __init__(self, meta=200, tree=(200, {"tree": [{"type": "blob", "path": "a.py"}]})):
        self.meta, self.tree = meta, tree

    async def get(self, url, headers=None, params=None):
        if "/git/trees/" in url:
            status, body = self.tree if isinstance(self.tree, tuple) else (self.tree, None)
            return _Resp(status, body)
        return _Resp(self.meta, {"default_branch": "main"})


@pytest.mark.asyncio
@pytest.mark.parametrize("client,expected", [
    (_TreeClient(), sr.NO_SKILL_MD),
    (_TreeClient(tree=(200, {"tree": [{"type": "blob", "path": "x/SKILL.md"}]})), None),
    (_TreeClient(tree=403), None),                       # rate-limited tree call
    (_TreeClient(tree=502), None),                       # outage
    (_TreeClient(tree=(200, {"tree": []})), None),       # empty tree
    (_TreeClient(tree=(200, {"tree": [{"type": "blob", "path": "a.py"}],
                              "truncated": True})), None),  # truncated tree
    (_TreeClient(meta=403), None),
    (_TreeClient(meta=404), sr.REPO_GONE),
])
async def test_classify_reads_no_skill_md_only_from_a_whole_non_empty_tree(client, expected):
    assert await sr.classify(client, {}, "o/r") == expected


@pytest.mark.asyncio
async def test_failed_tree_call_never_records_no_skill_md(data_dir, monkeypatch):
    """The scanner says "No SKILL.md found" after a failed tree call: the confirmation
    tree call fails too, so nothing is recorded."""
    import httpx

    _use_corpus(data_dir, monkeypatch, ["acme/live-skill"])
    client = _TreeClient(tree=403)

    class _Ctx:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return client

        async def __aexit__(self, *a):
            return False

    async def no_token():
        return None
    monkeypatch.setattr(httpx, "AsyncClient", _Ctx)
    monkeypatch.setattr("src.github_auth.get_github_token", no_token)
    await sr.note_skill_scan("acme", "live-skill", "No SKILL.md found — x")
    assert sr.load_overlay() == {}
    client.tree = (200, {"tree": [{"type": "blob", "path": "a.py"}], "truncated": True})
    await sr.note_skill_scan("acme", "live-skill", "No SKILL.md found — x")
    assert sr.load_overlay() == {}
    client.tree = (200, {"tree": [{"type": "blob", "path": "a.py"}]})
    await sr.note_skill_scan("acme", "live-skill", "No SKILL.md found — x")
    assert sr.load_overlay() == {"acme/live-skill": sr.NO_SKILL_MD}


# --- recovery ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delisted_row_is_rechecked_and_recovers(data_dir, monkeypatch):
    from datetime import timedelta

    _use_corpus(data_dir, monkeypatch, ["acme/grew-a-skill"])
    sr.record("acme/grew-a-skill", sr.NO_SKILL_MD)
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog())
    row = {r.full_name: r for r in m._load_rows()}["acme/grew-a-skill"]
    assert row.surface == "github"
    # still a corpus skill row for the re-scan loop, though it now opens the repo page
    assert sr.is_corpus_skill_row("acme", "grew-a-skill")

    assert sr.recheck_targets(10) == []  # just recorded: not due yet
    later = sr._now() + sr.RECHECK_AFTER + timedelta(minutes=1)
    assert sr.recheck_targets(10, now=later) == [("acme", "grew-a-skill")]

    # the loop's recovery pass skill-scans it; the scan succeeds now
    scanned = []

    async def fake_rescan(surface, owner, repo, db):
        scanned.append((surface, owner, repo))
        await sr.note_skill_scan(owner, repo, None)
        return True

    class _Session:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(sr, "recheck_targets", lambda limit: [("acme", "grew-a-skill")])
    monkeypatch.setattr(sch, "_rescan_catalog_row", fake_rescan)
    monkeypatch.setattr("src.database.async_session", lambda: _Session())
    assert await sch._recheck_skill_rows(True, 0) == 1
    assert scanned == [("openclaw", "acme", "grew-a-skill")]
    assert sr.load_overlay() == {}
    restored = {r.full_name: r for r in m._load_rows()}["acme/grew-a-skill"]
    assert restored.surface == "openclaw"
    assert restored.page_path == "/check/skill/acme/grew-a-skill"


@pytest.mark.asyncio
async def test_recheck_still_missing_keeps_entry_and_waits(data_dir, monkeypatch):
    from datetime import timedelta

    _use_corpus(data_dir, monkeypatch, ["acme/still-not"])
    sr.record("acme/still-not", sr.NO_SKILL_MD)
    later = sr._now() + sr.RECHECK_AFTER + timedelta(minutes=1)
    assert sr.recheck_targets(10, now=later) == [("acme", "still-not")]
    sr.mark_checked("acme/still-not", now=later)
    await sr.note_skill_scan("acme", "still-not", "No SKILL.md found — x")
    assert sr.load_overlay() == {"acme/still-not": sr.NO_SKILL_MD}
    assert sr.recheck_targets(10, now=later + timedelta(hours=1)) == []
    assert await sch._recheck_skill_rows(False, 0) == 0  # GitHub budget low: no rechecks


# --- repo_gone needs two 404s a gap apart ------------------------------------------

def test_two_404s_after_the_gap_record_repo_gone(data_dir):
    from datetime import timedelta

    t0 = sr._now()
    assert sr.note_404("Gone/Repo", now=t0) is False
    assert sr.load_overlay() == {}
    # a second 404 too soon does not count, and does not move the first one
    assert sr.note_404("gone/repo", now=t0 + timedelta(minutes=30)) is False
    assert sr.load_overlay() == {}
    assert sr.note_404("gone/repo", now=t0 + sr.GONE_CONFIRM_GAP) is True
    assert sr.load_overlay() == {"gone/repo": sr.REPO_GONE}
    assert "gone/repo" not in sr._load_checks(data_dir / m._SKILL_ROWS_FILE)


@pytest.mark.asyncio
async def test_non_404_between_the_two_resets(data_dir, monkeypatch):
    from datetime import timedelta

    _use_corpus(data_dir, monkeypatch, ["acme/flaky"])
    status = {"gone": True}

    async def fake_gone(owner, repo):
        return status["gone"]
    monkeypatch.setattr(sr, "github_repo_gone", fake_gone)
    t0 = sr._now()
    monkeypatch.setattr(sr, "_now", lambda: t0)
    await sr.note_skill_scan("acme", "flaky", "Repository not found or unreadable")
    assert "first_404_at" in sr._load_checks(data_dir / m._SKILL_ROWS_FILE)["acme/flaky"]

    # a 403 / outage in between resets the pending 404
    status["gone"] = False
    await sr.note_skill_scan("acme", "flaky", "Repository not found or unreadable")
    assert "acme/flaky" not in sr._load_checks(data_dir / m._SKILL_ROWS_FILE)

    # so a 404 after the gap is a FIRST 404 again, not a delisting
    status["gone"] = True
    monkeypatch.setattr(sr, "_now", lambda: t0 + sr.GONE_CONFIRM_GAP + timedelta(hours=1))
    await sr.note_skill_scan("acme", "flaky", "Repository not found or unreadable")
    assert sr.load_overlay() == {}

    # a successful scan in between resets it as well
    await sr.note_skill_scan("acme", "flaky", None)
    assert "acme/flaky" not in sr._load_checks(data_dir / m._SKILL_ROWS_FILE)


@pytest.mark.asyncio
async def test_second_404_through_note_skill_scan_delists(data_dir, monkeypatch):
    _use_corpus(data_dir, monkeypatch, ["LycheeMem/LycheeMem"])

    async def gone(owner, repo):
        return True
    monkeypatch.setattr(sr, "github_repo_gone", gone)
    t0 = sr._now()
    monkeypatch.setattr(sr, "_now", lambda: t0)
    await sr.note_skill_scan("LycheeMem", "LycheeMem", "Repository not found or unreadable")
    assert sr.load_overlay() == {}
    monkeypatch.setattr(sr, "_now", lambda: t0 + sr.GONE_CONFIRM_GAP)
    await sr.note_skill_scan("LycheeMem", "LycheeMem", "Repository not found or unreadable")
    assert sr.load_overlay() == {"lycheemem/lycheemem": sr.REPO_GONE}


# --- _write is locked --------------------------------------------------------------

def test_concurrent_writers_lose_no_entries(data_dir, monkeypatch):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from src.catalog_growth import state

    real_read = state.read_json
    barrier = threading.Barrier(8, timeout=5)

    def slow_read(path, default):
        # widen the read-modify-write window so an unlocked _write would lose entries
        out = real_read(path, default)
        time.sleep(0.01)
        return out
    monkeypatch.setattr(state, "read_json", slow_read)

    def writer(i):
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        assert sr.record(f"owner{i}/repo{i}", sr.NO_SKILL_MD)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(writer, range(40)))
    monkeypatch.setattr(state, "read_json", real_read)
    assert sr.load_overlay() == {f"owner{i}/repo{i}": sr.NO_SKILL_MD for i in range(40)}
