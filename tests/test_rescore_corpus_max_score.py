"""rescore_corpus --max-score: a targeted pass over the LOW end of a results file
(stale scores after a scanner precision change). It must re-score only rows at or under
the bound, skip unscored rows, and never move the weekly grind's cursor."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "launch_scans" / "rescore_corpus.py"


def _load():
    spec = importlib.util.spec_from_file_location("rescore_corpus_under_test", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(_SCRIPT.parent))
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.asyncio
async def test_max_score_rescans_only_low_rows_and_keeps_cursor(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod._common, "DATA_DIR", tmp_path)
    rows = [
        {"full_name": "a/low", "trust_score": 4},
        {"full_name": "b/high", "trust_score": 92},
        {"full_name": "c/edge", "trust_score": 50},
        {"full_name": "d/unscored", "trust_score": None},
    ]
    (tmp_path / "npm-agents-results.json").write_text(json.dumps({"results": rows}))
    cursor = tmp_path / ".rescore-cursor-npm.json"
    cursor.write_text(json.dumps({"i": 3}))

    scanned = []

    async def fake_scan_repo(full, token=None):
        scanned.append(full)
        return SimpleNamespace()

    monkeypatch.setattr("src.scanner.scan.scan_repo", fake_scan_repo)
    monkeypatch.setattr(mod._common, "summarize_scan_result", lambda r: {"trust_score": 88})
    monkeypatch.setattr(mod._common.RateLimitPolicy, "wait", lambda self: None)

    n = await mod._rescore_surface("npm", 100, False, None, max_score=50)

    assert n == 2
    assert sorted(scanned) == ["a/low", "c/edge"]
    saved = json.loads((tmp_path / "npm-agents-results.json").read_text())["results"]
    assert {r["full_name"]: r["trust_score"] for r in saved} == {
        "a/low": 88, "b/high": 92, "c/edge": 88, "d/unscored": None,
    }
    assert json.loads(cursor.read_text()) == {"i": 3}  # grind cursor untouched
