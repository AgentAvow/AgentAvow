"""scan_x402.py streams the Bazaar listing instead of holding it.

Run 1 of the live check (11-11) was OOM-killed at 1 GB while fetching: every listing was
kept twice (raw + copied fields) and the whole 320 MB targets file was built as one
string. Now each page is written to x402-targets.jsonl and dropped, the live plan holds
only small stubs, and scoring reads the file line by line and writes rows as it goes.
"""
from __future__ import annotations

import json
import sys
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "launch_scans"))

import scan_x402 as sx  # noqa: E402

PAYEE = "0xd6fCE15298Fc9D60f867d9455D497177Da9BFB0a"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _rec(i: int, method="GET", net="eip155:8453", pad=0) -> dict:
    return {
        "resource": f"https://h{i % 7}.example/x402/item{i}",
        "type": "http", "x402Version": 2, "serviceName": f"Item {i}",
        "description": "Returns the item record. " + ("x" * pad),
        "accepts": [{"scheme": "exact", "network": net, "amount": "1000",
                     "asset": USDC, "payTo": PAYEE, "maxTimeoutSeconds": 300}],
        "extensions": {"bazaar": {"info": {
            "input": {"method": method, "type": "http"},
            "output": {"type": "json", "example": {"id": i, "blob": "y" * pad}}}}},
        "lastUpdated": "2026-11-10T19:00:00Z",
    }


class _Resp:
    def __init__(self, doc):
        self._doc = doc

    def raise_for_status(self):
        return None

    def json(self):
        return self._doc


def _pager(records, page_size):
    def get(params):
        off = params["offset"]
        return _Resp({"items": records[off:off + page_size],
                      "pagination": {"total": len(records)}})
    return get


def test_discover_streams_every_record_once_and_keeps_only_stubs(tmp_path, monkeypatch):
    monkeypatch.setattr(sx._common.RateLimitPolicy, "wait", lambda self: None)
    recs = [_rec(i) for i in range(25)] + [_rec(3)]            # a duplicate URL
    recs += [_rec(100, method="POST"), _rec(101, net="eip155:84532")]  # not eligible
    out = tmp_path / "t.jsonl"
    n, stubs = sx.discover(out, page_size=10, get=_pager(recs, 10))
    lines = out.read_text().splitlines()
    assert n == len(lines) == 27
    assert json.loads(lines[0]) == recs[0]                       # the raw record, whole
    assert len(stubs) == 25                                      # POST + testnet left out
    assert set(stubs[0]) == {"resource", "extensions", "accepts"}
    assert not (tmp_path / "t.jsonl.tmp").exists()


def test_stubs_plan_the_same_as_the_full_records():
    from src.scanner import x402_live as xl
    recs = [_rec(i) for i in range(120)]
    full = {h: [r["resource"] for r in v] for h, v in xl.plan(recs, 3).items()}
    light = {h: [r["resource"] for r in v]
             for h, v in xl.plan([sx.live_stub(r) for r in recs], 3).items()}
    assert full == light


def test_streamed_results_file_matches_the_in_memory_rows(tmp_path):
    recs = [_rec(i) for i in range(40)]
    src = tmp_path / "t.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in recs))
    out = tmp_path / "results.json"
    streamed = sx.score_all(sx.iter_targets(src), None, out_path=out)
    doc = json.loads(out.read_text())
    mem = sx.score_all(recs, None)
    assert doc["results"] == json.loads(json.dumps(mem["results"], default=str))
    assert doc["summary"] == json.loads(json.dumps(mem["summary"])) == \
        json.loads(json.dumps(streamed["summary"]))
    assert doc["summary"]["listing_records"] == 40
    assert "results" not in streamed                              # rows are not kept


def test_legacy_targets_json_is_still_readable(tmp_path, monkeypatch):
    legacy = tmp_path / "x402-targets.json"
    legacy.write_text(json.dumps({"targets": [{"raw": _rec(1), "endpoint_url": "x"}]}))
    monkeypatch.setattr(sx, "TARGETS_PATH", legacy)
    assert [r["resource"] for r in sx.iter_targets(tmp_path / "none.jsonl")] == \
        [_rec(1)["resource"]]


def _peak_scoring(tmp_path, n: int, pad: int) -> tuple[int, int]:
    src = tmp_path / f"t{n}.jsonl"
    with src.open("w") as fh:
        for i in range(n):
            fh.write(json.dumps(_rec(i, pad=pad)) + "\n")
    tracemalloc.start()
    try:
        sx.score_all(sx.iter_targets(src), None, out_path=tmp_path / f"r{n}.json")
        return tracemalloc.get_traced_memory()[1], src.stat().st_size
    finally:
        tracemalloc.stop()


def test_memory_stays_flat_while_scoring_a_large_listing(tmp_path):
    """Peak allocation does not grow with the number of listings: 4x the listings
    (several MB more on disk) adds well under a quarter of that size to the peak.
    Holding the listing would add about twice the file size; that is what OOM-killed
    the 33k-listing run, and streaming is what lets it fit in ~700 MB."""
    _peak_scoring(tmp_path, 5, 100)                     # warm-up: imports, regex caches
    small, small_size = _peak_scoring(tmp_path, 100, 3000)
    big, big_size = _peak_scoring(tmp_path, 400, 3000)
    assert big_size - small_size > 900_000
    assert big - small < 0.25 * (big_size - small_size), (small, big, small_size, big_size)


def test_peak_rss_is_reported_and_the_guard_stops_the_run(monkeypatch, capsys):
    assert sx.rss_checkpoint("test") > 0
    assert "[x402 mem] test: peak RSS" in capsys.readouterr().out
    monkeypatch.setattr(sx, "_MAX_RSS_MB", 1.0)
    import pytest
    with pytest.raises(SystemExit) as e:
        sx.rss_checkpoint("over")
    assert "over --max-rss-mb" in str(e.value)
