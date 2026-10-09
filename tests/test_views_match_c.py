"""The large views in the badge design (option C): the OG/social PNG, the watch email's
trust mark, and the Certified mark only via certified_mark."""
from __future__ import annotations

import io

import pytest

PIL = pytest.importorskip("PIL")


def _png(**kw):
    from PIL import Image

    from src.api.og_image import render_og_png
    data = render_og_png(grade="", **kw)
    img = Image.open(io.BytesIO(data))
    assert img.size == (1200, 630)
    return img


@pytest.mark.parametrize("kw", [
    dict(title="npm:semver", score=92, decision="safe", certified=True,
         adoption=867_000_000, adoption_unit="downloads/wk", adoption_pct=48,
         adoption_known=True),
    dict(title="vercel/next.js", score=51, decision="review", adoption=143_000,
         adoption_unit="stars", adoption_pct=30, adoption_known=True),
    dict(title="oraios/serena", score=34, decision="do_not_connect", adoption=30_100,
         adoption_known=True),
    dict(title="https://mcp.example.com/mcp", score=74, decision="safe",
         adoption_known=True),
    dict(title="npm:x", score=88, decision="safe"),
    dict(title="you/your-repo", score=None),
    dict(title="a" * 300, score=90, decision="safe", subtitle="b " * 400),
])
def test_og_png_renders_every_state(kw):
    _png(**kw)


def test_og_accent_rule_is_the_gradient_only_with_the_mark():
    cert = _png(title="t", score=95, decision="safe", certified=True)
    plain = _png(title="t", score=95, decision="safe", certified=False)
    left, right = cert.getpixel((5, 3)), cert.getpixel((1194, 3))
    assert left != right  # teal → magenta across the rule
    assert plain.getpixel((5, 3)) == plain.getpixel((1194, 3))
    # Review never carries the mark, even when the caller says certified
    review = _png(title="t", score=85, decision="review", certified=True)
    assert review.getpixel((5, 3)) == review.getpixel((1194, 3))


def test_og_adoption_column_only_when_known():
    with_adopt = _png(title="t", score=80, decision="safe", adoption=5000,
                      adoption_known=True)
    without = _png(title="t", score=80, decision="safe")
    # the divider between the trust and adoption columns
    assert with_adopt.getpixel((600, 430)) != without.getpixel((600, 430))


def test_og_png_route_accepts_adoption_params():
    from fastapi.testclient import TestClient

    from src.main import app
    c = TestClient(app)
    r = c.get("/api/v1/public/scan/og.png", params={
        "title": "npm:semver", "score": "92", "decision": "safe", "certified": "1",
        "adoption": "867000000", "adoption_unit": "downloads/wk", "adoption_pct": "48"})
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    r = c.get("/api/v1/public/scan/og.png", params={"title": "x", "adoption": "nope"})
    assert r.status_code == 200  # lenient: a bad value just leaves adoption out


def test_og_router_uses_the_certified_mark():
    from src.api.og_router import _og_image_url
    eligible_review = {
        "trust_score": 90, "certified": {"eligible": True},
        "metadata": {"files_scanned": 40},
        "findings": {"items": [{"category": "code_safety", "severity": "high",
                                "kind": "defect", "shipped": True}], "high": 1},
    }
    url = _og_image_url("o/r", "", 90, "s", eligible_review)
    assert "certified=1" not in url and "decision=review" in url
    url = _og_image_url("o/r", "", 90, "s", None, adoption=(48, 867000, "stars"))
    assert "adoption=867000" in url and "adoption_pct=48" in url


def test_watch_email_trust_mark_is_the_vertical_bar_with_the_score_beside_it():
    from src.email import render_watch_notification
    _, html = render_watch_notification("drop", "o", "r", 90, 61,
                                        decision={"decision": "review"})
    # 10 vertical segments (one per row), 6 lit in the tier colour, the rest slate
    assert html.count('<tr><td style="width:16px;height:7px;') == 10
    assert html.count("background-color:#5BBF3A") == 6
    assert ">Standard</div>" in html and "61<span" in html
