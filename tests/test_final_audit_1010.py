"""Fixes from the 2026-10-10 final audit: package link previews fall back to the stale
result, one adoption source for previews and badges, the short unit always fits on
the OG card (star drawn, not spelled), the compact badge shows the unit, and the
server-rendered docs title matches the SPA's."""
from __future__ import annotations

import io

import pytest

PKG = {"trust_score": 92, "findings": {"critical": 0, "high": 0}, "files_scanned": 50,
       "certified": {"eligible": False}}


@pytest.mark.asyncio
async def test_og_package_falls_back_to_the_stale_result(monkeypatch):
    from src.api import og_router
    from src.api import public_scan_router as r

    async def _cached(surface, name):
        return None  # the 1 h cache has expired

    async def _stale(surface, name):
        return PKG if (surface, name) == ("npm", "semver") else None

    async def _adopt(owner, repo, db=None):
        return "npm", 70, 865_000_000, "downloads/wk"

    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "_get_stale_cached", _stale)
    monkeypatch.setattr(r, "_card_adoption", _adopt)
    html = (await og_router.og_package(surface="npm", name="semver")).body.decode()
    assert "92/100" in html
    assert "score=92" in html and "grade=&" not in html
    assert "adoption_unit=downloads" in html


@pytest.mark.asyncio
async def test_og_package_without_any_result_has_no_empty_score(monkeypatch):
    from src.api import og_router
    from src.api import public_scan_router as r

    async def _none(surface, name):
        return None

    monkeypatch.setattr(r, "_get_cached", _none)
    monkeypatch.setattr(r, "_get_stale_cached", _none)
    html = (await og_router.og_package(surface="npm", name="nope")).body.decode()
    assert "scored — on AgentAvow" not in html
    assert "Safe to connect, Review before you connect, or Do not connect" in html


@pytest.mark.asyncio
async def test_og_adoption_uses_the_badge_source(monkeypatch):
    from src.api import og_router
    from src.api import public_scan_router as r

    seen = []

    async def _adopt(owner, repo, db=None):
        seen.append((owner, repo))
        return "npm", 41, 12_000, "downloads/wk"

    monkeypatch.setattr(r, "_card_adoption", _adopt)
    assert await og_router._adoption_for("npm", "npm", "chalk") == (41, 12_000, "downloads/wk")
    assert seen == [("npm", "chalk")]


@pytest.mark.parametrize("count,unit", [(865_000_000, "downloads/wk"), (143_100, "stars"),
                                         (1_234_567_890, "downloads/mo")])
def test_og_png_renders_wide_counts_with_units(count, unit):
    from PIL import Image

    from src.api.og_image import render_og_png
    png = render_og_png(title="x/y", grade="A", score=92, subtitle="t", decision="safe",
                        certified=False, adoption=count, adoption_unit=unit,
                        adoption_pct=70, adoption_known=True)
    assert Image.open(io.BytesIO(png)).size == (1200, 630)


def test_og_star_shape():
    from PIL import Image, ImageDraw

    from src.api.og_image import _star
    img = Image.new("RGB", (40, 40))
    _star(ImageDraw.Draw(img), 20, 20, 13, (255, 255, 255))
    assert img.getpixel((20, 20)) == (255, 255, 255)


def test_compact_badge_shows_the_short_unit():
    from src.api.badge_avow import render_avow_badge
    svg = render_avow_badge(style="compact", decision="safe", score=92,
                            adoption=865_000_000, adoption_unit="downloads/wk",
                            adoption_pct=70)
    assert "dl/wk" in svg
    no_unit = render_avow_badge(style="compact", decision="safe", score=92,
                                adoption=None, adoption_unit="downloads/wk")
    assert "dl/wk" not in no_unit


def test_ssr_docs_title_matches_the_spa():
    from src.api import docs_content_router as mod
    html = mod._page("Run locally & in CI · Docs · AgentAvow", "d", "https://x", "<p>b</p>")
    assert "<title>Run locally &amp; in CI · Docs · AgentAvow</title>" in html
    assert "AgentAvow Docs</title>" not in html
