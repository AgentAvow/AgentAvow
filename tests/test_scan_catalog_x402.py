"""x402 rows scored from their Bazaar listing in the catalog (scan_x402.py --score).

They carry a score and the stored answer; an old probe row (no score) is unchanged;
testnet-only listings are out of the default views but findable by name; and the
headline prevalence stat never counts x402 (they are listings, not code scans)."""
from __future__ import annotations

import pytest

import src.api.scan_catalog_router as m
from src.api.scan_catalog_router import _normalize_row, _severity_bucket

REASON = "nothing found in the listing; the endpoint's code isn't visible"


def _scored(url, **kw):
    raw = {"endpoint_url": url, "name": "w", "trust_score": 74, "decision": "safe",
           "decision_reason": REASON, "critical": 0, "high": 0, "price_usd": "0.001",
           "testnet_only": False, "scanned_from": "listing"}
    raw.update(kw)
    return raw


def test_scored_row_keeps_its_stored_answer():
    r = _normalize_row("x402", _scored("https://a.example/x"))
    assert r.trust_score == 74 and r.decision == "safe" and r.decision_reason == REASON
    assert r.price_usd == "0.001" and r.testnet_only is False


def test_scored_review_row():
    r = _normalize_row("x402", _scored("http://b.example/x", trust_score=60, high=1,
                                       decision="review",
                                       decision_reason="one high finding in its listing"))
    assert r.decision == "review" and r.high == 1


def test_old_probe_row_is_unchanged():
    r = _normalize_row("x402", {"endpoint_url": "https://c.example", "http_status": 402,
                                "has_x402_header": True})
    assert r.trust_score is None and r.decision is None and r.testnet_only is None
    assert r.has_x402_header is True


def test_x402_never_enters_the_prevalence_buckets():
    r = _normalize_row("x402", _scored("http://d.example/x", trust_score=40, critical=1,
                                       decision="do_not_connect"))
    assert _severity_bucket(r) == "n/a"


@pytest.fixture
def catalog(monkeypatch):
    rows = [
        _normalize_row("x402", _scored("https://main.example/weather")),
        _normalize_row("x402", _scored("https://test.example/faucet", testnet_only=True)),
        _normalize_row("mcp", {"name": "srv", "full_name": "acme/srv", "trust_score": 40,
                               "critical": 1, "high": 0}),
    ]
    monkeypatch.setattr(m, "_CATALOG_CACHE", m._build_catalog(rows))

    async def _none(db):
        return []
    monkeypatch.setattr(m, "_community_rows", _none)
    return rows


async def _view(surface=None, q=None):
    resp = await m.scan_catalog(surface=surface, q=q, severity=None, grade=None,
                                category=None, sort="default", limit=50, offset=0, db=None)
    return [r.name for r in resp.rows]


async def test_testnet_only_is_out_of_default_views(catalog):
    assert "https://test.example/faucet" not in await _view("x402")
    assert "https://test.example/faucet" not in await _view(None)
    assert "https://main.example/weather" in await _view("x402")


async def test_testnet_only_is_findable_by_name(catalog):
    assert "https://test.example/faucet" in await _view("x402", q="faucet")


async def test_prevalence_stat_ignores_x402(catalog):
    stat = await m.flagged_stat(db=None)
    assert stat["scanned_total"] == 1 and stat["critical"] == 1


async def test_x402_is_only_under_its_own_kind(catalog):
    everything = await _view(None)
    assert not [n for n in everything if n.startswith("https://main.example")]
    assert "srv" in everything
    resp = await m.scan_catalog(surface=None, q="weather", severity=None, grade=None,
                                category=None, sort="default", limit=50, offset=0, db=None)
    assert resp.total == 0   # not even by search from the all-surfaces view
    assert "https://main.example/weather" in await _view("x402")


async def test_all_surfaces_safe_filter_has_no_x402(catalog):
    resp = await m.scan_catalog(surface=None, q=None, severity=None, grade=None,
                                category=None, decision="safe", sort="default", limit=50,
                                offset=0, db=None)
    assert all(r.surface != "x402" for r in resp.rows)


def test_scored_row_carries_medium_low_and_top_findings():
    r = _normalize_row("x402", _scored(
        "https://e.example/x", medium=2, low=1,
        top_findings=[{"severity": "medium", "name": "the listing names 2 different "
                       "recipients on eip155:8453"},
                      {"severity": "low", "name": "costs more than $1 per call"},
                      {"severity": "low"}, "junk"]))
    assert r.medium == 2 and r.low == 1
    assert [(f.severity, f.name[:8]) for f in r.top_findings] == [
        ("medium", "the list"), ("low", "costs mo")]


def test_old_probe_row_has_no_finding_detail():
    r = _normalize_row("x402", {"endpoint_url": "https://c.example", "http_status": 402})
    assert r.medium is None and r.low is None and r.top_findings is None
