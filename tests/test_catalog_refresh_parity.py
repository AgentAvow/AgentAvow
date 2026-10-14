"""Catalog refresh, community re-score and Browse/page answer parity.

1. The static catalog reloads itself when a launch-scan file changes on disk, so the
   host cron scripts no longer POST the admin-only /refresh endpoint (which returned
   401 to them from 2026-10-04 and only ever reached one uvicorn worker).
2. scripts/launch_scans/rescore_community.py re-scans through the scheduler's service
   path, and the scan route functions treat an omitted ``Query(...)`` default (a truthy
   object when the function is called directly) as its real default.
3. A community row stores the answer decide() gives over the full scan result (the
   one the tool's page leads with), and Browse, the catalog API and the metrics read it.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

import src.api.scan_catalog_router as m
from src.api import public_scan_router as p

ROOT = Path(__file__).resolve().parent.parent


# ── 1. self-reloading static catalog ──────────────────────────────────────────────


def _write(path: Path, rows: list[dict], bump: int = 0) -> None:
    path.write_text(json.dumps({"results": rows}))
    st = path.stat()
    # Force a distinct mtime even on a coarse-grained filesystem clock.
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + bump * 1_000_000_000))


def _npm_row(name: str, score: int = 90) -> dict:
    return {"name": name, "full_name": f"acme/{name}", "trust_score": score,
            "critical": 0, "high": 0}


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(m, "_CATALOG_CACHE", None)
    return tmp_path


def test_catalog_reloads_when_a_source_file_changes(data_dir):
    f = data_dir / "npm-agents-results.json"
    _write(f, [_npm_row("a")])
    first = m._get_catalog()
    assert len(first["rows"]) == 1
    assert m.reload_catalog_if_sources_changed() is False  # nothing changed

    _write(f, [_npm_row("a"), _npm_row("b")], bump=5)
    assert m.reload_catalog_if_sources_changed() is True
    second = m._get_catalog()
    assert second is not first
    assert sorted(r.name for r in second["rows"]) == ["a", "b"]
    assert m.reload_catalog_if_sources_changed() is False


def test_new_source_file_triggers_reload(data_dir):
    m._get_catalog()
    _write(data_dir / "pypi-agents-results.json", [_npm_row("p")])
    assert m.reload_catalog_if_sources_changed() is True
    assert [r.surface for r in m._get_catalog()["rows"]] == ["pypi"]


def test_unparseable_file_is_retried(data_dir):
    f = data_dir / "npm-agents-results.json"
    f.write_text("{not json")
    assert m._get_catalog()["rows"] == []
    # Same bytes on disk, but the failed read is not remembered as read.
    f.write_text(json.dumps({"results": [_npm_row("ok")]}))
    os.utime(f, ns=(0, 0))  # even with an mtime that moved backwards
    assert m.reload_catalog_if_sources_changed() is True
    assert [r.name for r in m._get_catalog()["rows"]] == ["ok"]


def test_fixture_catalog_is_never_reloaded(data_dir):
    _write(data_dir / "npm-agents-results.json", [_npm_row("disk")])
    fixture = m._build_catalog([m.CatalogRow(surface="npm", name="fixture", trust_score=90)])
    m._CATALOG_CACHE = fixture
    assert m.reload_catalog_if_sources_changed() is False
    assert m._get_catalog() is fixture


async def test_flagged_stat_timer_reloads_sources(monkeypatch):
    calls = []
    monkeypatch.setattr(m, "reload_catalog_if_sources_changed", lambda: calls.append(1))

    def _boom():
        raise RuntimeError("stop here")

    monkeypatch.setattr(m, "_get_catalog", _boom)
    await m._refresh_flagged_stat()  # logs and swallows the error
    assert calls == [1]


def test_no_host_script_posts_the_admin_refresh_endpoint():
    """The endpoint is admin-only; a cron caller has no session and gets 401."""
    offenders = []
    for path in (ROOT / "scripts").rglob("*"):
        if path.suffix not in (".sh", ".py") or not path.is_file():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            if "scan-catalog/refresh" in line and re.search(r"\b(curl|wget|requests|httpx)\b",
                                                            line):
                offenders.append(f"{path.name}: {line.strip()}")
    assert offenders == []


# ── 2. community re-score + direct calls of the scan routes ──────────────────────


def _load_rescore_community():
    path = ROOT / "scripts" / "launch_scans" / "rescore_community.py"
    spec = importlib.util.spec_from_file_location("rescore_community_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("surface,owner,repo", [
    ("npm", "npm", "left-pad"),
    ("pypi", "pypi", "pytest-runner"),
    ("mcp", "mcp", "https://mcp.example.com/mcp"),
    ("openclaw", "acme", "skill"),
    (None, "acme", "repo"),  # pre-t18 row: github
])
async def test_rescore_community_goes_through_the_catalog_rescan(
    monkeypatch, surface, owner, repo,
):
    mod = _load_rescore_community()
    seen = {}

    async def fake_rescan(surf, o, r, db):
        seen["args"] = (surf, o, r)
        return True

    class _Session:
        async def __aenter__(self):
            return "db"

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr("src.jobs.scheduler._rescan_catalog_row", fake_rescan)
    monkeypatch.setattr("src.database.async_session", lambda: _Session())
    row = SimpleNamespace(surface=surface, owner=owner, repo=repo)
    assert await mod._rescore_one(row) is True
    assert seen["args"] == ((surface or "github"), owner, repo)


async def test_package_route_called_directly_uses_real_defaults(monkeypatch):
    """What rescore_community.py did: only surface/name/force/db. The omitted
    ``version`` / ``behavioral`` / ``stored`` used to arrive as truthy Query objects:
    a bogus version went to the scanner and the catalog write was skipped."""
    seen: dict = {}

    async def fake_scan_package(surface, name, version=None):
        seen["version"] = version
        return SimpleNamespace(error=None)

    async def fake_capture(owner, repo, data, db, surface="github"):
        seen["captured"] = (owner, repo, surface)

    async def fake_block(data, force=False):
        seen["behavioral_force"] = force
        return None

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr("src.scanner.scan.scan_package", fake_scan_package)
    monkeypatch.setattr(p, "_scan_result_to_dict", lambda r: {"trust_score": 90})
    monkeypatch.setattr(p, "_set_cached", _noop)
    monkeypatch.setattr(p, "_capture_community_scan", fake_capture)
    monkeypatch.setattr(p, "_behavioral_block", fake_block)
    monkeypatch.setattr(p, "_build_scan_payload", lambda full, data, *a: {"repo": full})
    monkeypatch.setattr(p, "_package_response", lambda *a, **k: "response")

    out = await p.scan_package_endpoint(
        surface="npm", name="left-pad", request=None, force=True, db=None)
    assert out == "response"
    assert seen["version"] is None
    assert seen["captured"] == ("npm", "left-pad", "npm")
    assert seen["behavioral_force"] is False


async def test_skill_routes_called_directly_pass_real_bools(monkeypatch):
    seen = []

    async def fake_skill_scan(owner, repo, skill_path, request, force, behavioral):
        seen.append((force, behavioral))
        return "ok"

    monkeypatch.setattr(p, "_skill_scan", fake_skill_scan)
    await p.scan_skill_endpoint(owner="acme", repo="skill", request=None, db=None)
    await p.scan_one_skill_endpoint(owner="acme", repo="skills", skill_path="pdf",
                                    request=None, db=None)
    assert seen == [(False, False), (False, False)]


async def test_mcp_route_called_directly_never_probes(monkeypatch):
    seen = {}

    async def fake_scan_mcp(url):
        return SimpleNamespace(error=None)

    async def fake_probe(url, *, run):
        seen["run"] = run
        return None

    async def _none(*a, **k):
        return None

    monkeypatch.setattr("src.scanner.scan.scan_mcp", fake_scan_mcp)
    monkeypatch.setattr(p, "_get_cached", _none)
    monkeypatch.setattr(p, "_get_stale_cached", _none)
    monkeypatch.setattr(p, "_set_cached", _none)
    monkeypatch.setattr(p, "_record_scan_history", _none)
    monkeypatch.setattr(p, "_mcp_live_probe_block", fake_probe)
    monkeypatch.setattr(p, "_scan_result_to_dict", lambda r: {"trust_score": 90})
    monkeypatch.setattr(p, "_build_scan_payload", lambda full, data, *a: {"repo": full})
    monkeypatch.setattr(p, "_package_response",
                        lambda *a, **k: SimpleNamespace(behavioral="unset"))
    await p.scan_mcp_endpoint(endpoint="https://mcp.example.com/mcp", request=None,
                              force=True, db=None)
    assert seen["run"] is False


# ── 3. the stored answer: page == Browse == catalog API == metrics ───────────────


def _scan(score: int = 90, **extra) -> dict:
    return {"trust_score": score, "findings": {"critical": 0, "high": 0, "total": 0,
                                                "items": []},
            "metadata": {"files_scanned": 40}, **extra}


_ADVISORY = {"incident_history": {"advisories": [
    {"id": "GHSA-gxr4-xjj5-5px2", "affects_scanned_version": True}]}}
_DEPRECATED = {"deprecation": "this package is no longer maintained"}
_MALICIOUS_DEP = {"supply_chain": {"malicious": ["MAL-2024-1234 eslint-config-x"]}}


@pytest.fixture
def no_sandbox(monkeypatch):
    async def _none(data):
        return None

    monkeypatch.setattr(p, "_cached_behavioral_for", _none)


@pytest.mark.parametrize("extra,expected,why", [
    (_ADVISORY, "review", "advisory"),
    (_DEPRECATED, "review", "deprecated"),
    (_MALICIOUS_DEP, "do_not_connect", "malicious"),
    ({}, "safe", "nothing found"),
])
async def test_page_decision_matches_the_page(no_sandbox, extra, expected, why):
    from src.scanner.verdict import decide

    data = _scan(**extra)
    dec, reason = await p._page_decision(data, ("npm", "jquery"))
    page = decide({**data, "behavioral": None})
    assert (dec, reason) == (page.decision, page.reason)
    assert dec == expected and why in reason


async def test_page_decision_folds_in_a_cached_sandbox_block(monkeypatch):
    async def _block(data):
        return {"ran": True, "pending": False, "plan": "npm",
                "findings": [{"severity": "high", "rule": "undeclared_egress",
                              "name": "Undeclared egress"}]}

    monkeypatch.setattr(p, "_cached_behavioral_for", _block)
    dec, _ = await p._page_decision(_scan(), ("npm", "x"))
    assert dec == "review"


async def test_page_decision_ignores_a_pending_block(monkeypatch):
    async def _block(data):
        return {"ran": False, "pending": True, "state": "queued"}

    monkeypatch.setattr(p, "_cached_behavioral_for", _block)
    dec, reason = await p._page_decision(_scan(), ("npm", "x"))
    assert dec == "safe" and "pending" not in reason and "queued" not in reason


async def test_capture_stores_the_answer_and_browse_reads_it(db, no_sandbox, monkeypatch):
    from src.models import CommunityScan

    monkeypatch.setattr(m, "_mark_as_page_shows", _async_none)
    await p._capture_community_scan("npm", "jquery", _scan(**_ADVISORY), db, surface="npm")
    await p._capture_community_scan("pypi", "pytest-runner", _scan(**_DEPRECATED), db,
                                    surface="pypi")
    await p._capture_community_scan("npm", "eslint-plugin-prettier",
                                    _scan(**_MALICIOUS_DEP), db, surface="npm")
    stored = {r.repo: (r.decision, r.decision_reason) for r in
              (await db.execute(select(CommunityScan))).scalars().all()}
    assert stored["jquery"][0] == "review"
    assert "advisory" in stored["jquery"][1]
    assert stored["pytest-runner"][0] == "review"
    assert stored["eslint-plugin-prettier"][0] == "do_not_connect"

    rows = {r.name: r for r in await m._fetch_community_rows(db)}
    # Score 90, no critical/high: decided from counts these all read Safe.
    assert rows["jquery"].decision == "review"
    assert rows["jquery"].decision_reason == stored["jquery"][1]
    assert rows["pytest-runner"].decision == "review"
    assert rows["eslint-plugin-prettier"].decision == "do_not_connect"

    # The catalog API filter sees the same answer.
    m.invalidate_community_rows_cache()
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog([]))
    resp = await m._catalog_view(None, None, None, None, None, "safe", "default", 50, 0, db)
    assert not {"jquery", "pytest-runner", "eslint-plugin-prettier"} & {
        r.name for r in resp.rows}
    resp = await m._catalog_view(None, None, None, None, None, "review", "default", 50, 0,
                                 db)
    assert {"jquery", "pytest-runner"} <= {r.name for r in resp.rows}
    m.invalidate_community_rows_cache()

    # The metrics dashboard's distribution counts the stored answer.
    from src.api.metrics_dashboard_router import _DECISION_CASE

    dist = dict((await db.execute(
        select(_DECISION_CASE, func.count()).where(
            CommunityScan.repo.in_(["jquery", "pytest-runner", "eslint-plugin-prettier"]))
        .group_by(_DECISION_CASE))).all())
    assert dist == {"review": 2, "do_not_connect": 1}


async def test_pre_t24_row_falls_back_to_counts(db, monkeypatch):
    from src.api.metrics_dashboard_router import _DECISION_CASE
    from src.models import CommunityScan

    monkeypatch.setattr(m, "_mark_as_page_shows", _async_none)
    db.add(CommunityScan(surface="npm", owner="npm", repo="old-row", full_name="npm:old-row",
                         trust_score=88, critical=0, high=1))
    db.add(CommunityScan(surface="npm", owner="npm", repo="old-clean",
                         full_name="npm:old-clean", trust_score=88, critical=0, high=0))
    await db.flush()
    rows = {r.name: r for r in await m._fetch_community_rows(db)}
    assert rows["old-row"].decision == "review"
    assert rows["old-clean"].decision == "safe"
    dist = dict((await db.execute(
        select(_DECISION_CASE, func.count()).where(
            CommunityScan.repo.in_(["old-row", "old-clean"])).group_by(_DECISION_CASE))).all())
    assert dist == {"review": 1, "safe": 1}


async def _async_none(*a, **k):
    return None


def test_static_corpus_row_reads_its_stored_answer():
    row = m._normalize_row("npm", {**_npm_row("request"), "decision": "review",
                                   "decision_reason": "the maintainer has deprecated"})
    assert row.decision == "review" and row.decision_reason.startswith("the maintainer")
    # An invalid or absent value is recomputed from score + counts.
    assert m._normalize_row("npm", {**_npm_row("x"), "decision": "bogus"}).decision == "safe"
    assert m._normalize_row("npm", _npm_row("y")).decision == "safe"
    oc = m._normalize_row("openclaw", {"repo": "a/b", "trust_score": 90, "critical_count": 0,
                                       "high_count": 0, "decision": "review",
                                       "decision_reason": "r"})
    assert oc.decision == "review"


def test_corpus_summary_carries_the_full_answer():
    sys.path.insert(0, str(ROOT / "scripts" / "launch_scans"))
    try:
        import _common
    finally:
        sys.path.pop(0)
    from src.scanner.scan import ScanResult

    r = ScanResult(repo="acme/request", stars=0, description="", framework="")
    r.trust_score = 90
    r.files_scanned = 40
    r.deprecation = "request has been deprecated"
    summ = _common.summarize_scan_result(r)
    assert summ["decision"] == "review"
    assert "deprecated" in summ["decision_reason"]
    r.error = "fetch failed"
    assert _common.summarize_scan_result(r)["decision"] is None
