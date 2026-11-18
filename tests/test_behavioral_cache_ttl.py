"""The cached sandbox block must outlive the backfill's revisit window, or an unvisited
tool loses its block (and the Certified mark) between backfill passes."""
from __future__ import annotations

from src.api import public_scan_router as psr
from src.config import settings


def test_cache_outlives_backfill_window(monkeypatch):
    monkeypatch.setattr(settings, "behavioral_backfill_retry_days", 7, raising=False)
    ttl = psr._behavioral_cache_ttl()
    assert ttl == 8 * 24 * 3600
    assert ttl > settings.behavioral_backfill_retry_days * 24 * 3600


def test_cache_follows_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "behavioral_backfill_retry_days", 3, raising=False)
    assert psr._behavioral_cache_ttl() == 4 * 24 * 3600


def test_cache_never_below_a_day(monkeypatch):
    monkeypatch.setattr(settings, "behavioral_backfill_retry_days", 0, raising=False)
    # 0 falls back to the default window (7), never a zero/negative TTL.
    assert psr._behavioral_cache_ttl() >= 24 * 3600
