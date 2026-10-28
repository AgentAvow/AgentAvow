"""The shared badge design system: the website-embed card and the README compact badge."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from src.api.badge_avow import (
    AVOW_STYLES,
    LOGO_INNER,
    _arc,
    adoption_level,
    adoption_pct_from_count,
    render_avow_badge,
)
from src.bridges.mcp_app_view import TRUST_CARD_HTML

CASES = [
    ("safe", 92, False),
    ("review", 61, False),
    ("do_not_connect", 18, False),
    ("safe", 97, True),
    (None, None, False),
]


def _render(style, decision, score, certified, theme="auto", adoption=1234, pct=40,
            unit="stars"):
    return render_avow_badge(style=style, decision=decision, score=score,
                             certified=certified, theme=theme, coordinate="owner/repo",
                             adoption=adoption, adoption_unit=unit, adoption_pct=pct)


@pytest.mark.parametrize("style", AVOW_STYLES)
@pytest.mark.parametrize("theme", ["auto", "light", "dark"])
@pytest.mark.parametrize("decision,score,certified", CASES)
def test_every_variant_is_well_formed_and_camo_safe(style, theme, decision, score, certified):
    svg = _render(style, decision, score, certified, theme)
    root = ET.fromstring(svg)  # well-formed XML
    assert root.tag.endswith("svg")
    low = svg.lower()
    for banned in ("<script", "foreignobject", "<image", 'href="http', "@import",
                   "<animate", "@keyframes", "url(http"):
        assert banned not in low, banned
    assert "<title>" in svg


def test_logo_is_the_trust_card_logo_byte_for_byte():
    assert LOGO_INNER in TRUST_CARD_HTML
    assert 'd="M12 21l6 6 12-13"' in LOGO_INNER and 'r="16.3"' in LOGO_INNER
    for style in AVOW_STYLES:
        assert LOGO_INNER in _render(style, "safe", 92, False)


def test_compact_keeps_the_shields_height():
    for decision, score, certified in CASES:
        head = _render("compact", decision, score, certified).split(">", 1)[0]
        assert 'height="20"' in head


def test_card_size_is_fixed():
    head = _render("card", "safe", 92, False).split(">", 1)[0]
    assert 'width="360"' in head and 'height="230"' in head
    stacked = _render("card-stacked", "safe", 92, False).split(">", 1)[0]
    assert 'width="360"' in stacked and 'height="290"' in stacked


def _text_y(svg: str, content: str) -> str:
    m = re.search(r'<text x="[^"]+" y="([^"]+)"[^>]*>' + re.escape(content) + "<", svg)
    assert m, content
    return m.group(1)


def test_card_columns_share_baselines_with_text_right_of_the_meters():
    """Option C: the score sits right of the trust bar, the count right of the dial,
    and both columns use the same caplabel / number / word baselines."""
    svg = _render("card", "safe", 92, False, adoption=3100, pct=42, unit="stars")
    assert _text_y(svg, "92") == _text_y(svg, "3.1k")
    assert _text_y(svg, "Trusted") == _text_y(svg, "Established")
    assert _text_y(svg, "TRUST") == _text_y(svg, "ADOPTION")
    assert _text_y(svg, "★") == _text_y(svg, "3.1k")  # short unit beside the count
    # text sits to the right of its meter
    bar_x = float(re.search(r'<rect x="([\d.]+)" y="[\d.]+" width="15" height="5.5"',
                            svg).group(1))
    num_x = float(re.search(r'<text x="([\d.]+)" y="[^"]+"[^>]*>92<', svg).group(1))
    assert num_x > bar_x + 15
    dial_x = float(re.search(r'<svg x="([\d.]+)" y="[^"]+" width="60"', svg).group(1))
    count_x = float(re.search(r'<text x="([\d.]+)" y="[^"]+"[^>]*>3\.1k<', svg).group(1))
    assert count_x > dial_x + 60


def test_trust_is_the_heavier_column():
    """Trust is the primary signal: its column is at least as wide as adoption's and
    its numeral is larger than the adoption count."""
    svg = _render("card", "safe", 92, False, adoption=3100, pct=42, unit="stars")
    split = float(re.search(r'<rect x="([\d.]+)" y="[\d.]+" width="1" height="80"',
                            svg).group(1))
    assert split - 14 >= (360 - 14) - split
    t_size = float(re.search(r'font-size="([\d.]+)" font-weight="700" fill="#22C55E"'
                             r'[^>]*>92<', svg).group(1))
    a_size = float(re.search(r'font-size="([\d.]+)"[^>]*>3\.1k<', svg).group(1))
    assert t_size > a_size


def test_card_unit_shortens_before_it_drops():
    svg = _render("card", "safe", 97, True, adoption=412_000_000, pct=96,
                  unit="downloads/wk")
    assert ">412M<" in svg and ">dl/wk<" in svg
    assert "412M downloads/wk" in svg  # the full unit stays in the accessible title


def _lit_cells(svg: str, fill: str) -> int:
    return len(re.findall(rf'<rect [^>]*fill="{re.escape(fill)}"', svg))


def test_trust_bar_fills_to_the_score_on_both_styles():
    for style in AVOW_STYLES:
        svg = _render(style, "safe", 72, False, theme="dark", pct=40)
        assert _lit_cells(svg, "#5BBF3A") == 7  # Standard tier colour, 7 of 10 segments


def test_adoption_is_a_gauge_not_a_bar():
    """The card's renderAdopt: arc 180°→360° (cx 100, cy 88, r 74), gradient fill arc
    (8px, round cap) over the track, 9 ticks (the middle one longer), a teal needle
    (3.4px) and a 5.5 hub."""
    svg = _render("card-stacked", "safe", 92, False, theme="dark", pct=50)
    assert 'viewBox="0 0 200 94"' in svg
    # pct 50 → 270°: the filled arc and the track remainder, precomputed server-side
    assert f'd="{_arc(100, 88, 74, 180, 270)}" fill="none" stroke="url(#agrad)" ' \
           'stroke-width="8" stroke-linecap="round"' in svg
    assert f'd="{_arc(100, 88, 74, 270, 360)}"' in svg
    assert svg.count('opacity="0.4"/>') == 9
    assert svg.count('stroke-width="1.6"') == 1
    assert 'stroke="#2dd4bf" stroke-width="3.4" stroke-linecap="round"' in svg
    assert 'r="5.5" fill="#2dd4bf"' in svg
    assert 'x1="26.0" y1="0.0" x2="174.0"' in svg  # agrad spans the arc, like the card
    assert "url(#gA)" not in svg  # no adoption bar


def test_card_dial_is_heavier_and_nothing_clips():
    """Option C (final): the dial's arc is close to the trust segments' visual weight
    (16 units at 60px ≈ 4.8px vs 5.5px segments), round caps on fill and track, the
    ticks inside the stroke and a needle heavy enough for it."""
    svg = _render("card", "safe", 92, False, theme="dark", pct=50)
    assert 'stroke-width="16" stroke-linecap="round"' in svg
    assert svg.count('stroke-width="16"') == 2  # fill + track
    assert 'stroke-width="6.5" stroke-linecap="round"' in svg and 'r="9.5"' in svg
    # outer edge of the arc stays inside the 200×94 viewBox (cx 100, cy 88, r 72)
    assert 100 - 72 - 8 >= 0 and 88 - 72 - 8 >= 0
    # ticks start inside the stroke's inner edge (r - 8)
    ticks = re.findall(r'<line x1="([\d.]+)" y1="([\d.]+)"[^>]*opacity="0.4"', svg)
    assert len(ticks) == 9
    for x, y in ticks:
        assert ((float(x) - 100) ** 2 + (float(y) - 88) ** 2) ** 0.5 < 72 - 8
    # the small README badge keeps the thinner arc
    compact = _render("compact", "safe", 92, False, theme="dark", pct=50)
    assert 'stroke-width="2.4" stroke-linecap="round"' in compact
    assert 'stroke-width="3.6"' not in compact and 'stroke-width="16"' not in compact


def test_arc_maths_matches_the_card():
    # JS: ARC(100,88,74,180,270) → "M26.0 88.0 A74 74 0 0 1 100.0 14.0"
    assert _arc(100, 88, 74, 180, 270) == "M26.0 88.0 A74 74 0 0 1 100.0 14.0"
    assert "function ARC(cx,cy,r,a0,a1)" in TRUST_CARD_HTML


def test_card_adoption_shows_count_unit_and_gradient_level():
    svg = _render("card", "safe", 97, True, adoption=1_200_000, pct=91,
                  unit="downloads/wk")
    assert ">1.2M<" in svg and ">dl/wk<" in svg  # always the short unit
    assert 'fill="url(#gW)"' in svg and "Load-bearing" in svg
    stacked = _render("card-stacked", "safe", 97, True, adoption=1_200_000, pct=91,
                      unit="downloads/wk")
    assert ">1.2M<tspan" in stacked and ">dl/wk</tspan>" in stacked


def test_compact_adoption_is_a_small_needle_gauge():
    svg = _render("compact", "safe", 92, False, theme="dark", adoption=82400, pct=71)
    assert 'stroke="url(#cA)"' in svg and 'stroke="#2dd4bf"' in svg  # arc + needle
    assert ">82.4k<" in svg
    assert 'height="8" rx=".8" fill="url(#cA)"' not in svg  # no adoption bar


def test_card_names_both_scores_and_the_full_phrase():
    svg = _render("card", "do_not_connect", 18, False, adoption=82400, pct=70)
    assert "Do not connect" in svg and ">18<" in svg and "82.4k" in svg
    assert "Widely relied" in svg and "Restricted" in svg  # adoption level + tier word
    assert "trust 18/100" in svg and "adoption 82.4k stars" in svg  # accessible title


def test_compact_names_the_answer_and_both_numbers():
    svg = _render("compact", "review", 61, False, adoption=3100)
    assert "⚠ Review" in svg and ">61<" in svg and ">3.1k<" in svg


def test_adoption_new_when_no_signal():
    for style in AVOW_STYLES:
        svg = _render(style, "safe", 90, False, adoption=None, pct=None)
        assert ">New<" in svg
        assert 'stroke="#2dd4bf"' not in svg  # no needle
        assert 'opacity="0.3"' in svg  # the muted hub
    assert "no signal yet" in _render("card", "safe", 90, False, adoption=None, pct=None)


def test_adoption_pct_falls_back_to_the_cards_log_scale():
    assert adoption_pct_from_count(None) == 0
    assert adoption_pct_from_count(1_000_000) == 67  # round(log10(1e6+1)/9*100)
    assert adoption_pct_from_count(10**12) == 100
    assert "Math.log10(c+1)/9*100" in TRUST_CARD_HTML


def test_certified_renders_only_on_a_safe_answer():
    for style in AVOW_STYLES:
        assert "CERTIFIED" in _render(style, "safe", 97, True)
        # A certified-eligible tool whose answer is Review never reads "Review · Certified".
        rev = _render(style, "review", 85, True)
        assert "CERTIFIED" not in rev and "Certified" not in rev


def test_unscanned_states():
    assert "not scanned" in _render("compact", None, None, False)
    card = _render("card", None, None, False)
    assert "Not scanned yet" in card and "not scanned" in card


def test_auto_theme_switches_inside_the_image():
    svg = _render("card", "safe", 92, False, theme="auto")
    assert "prefers-color-scheme:light" in svg
    assert "prefers-color-scheme" not in _render("card", "safe", 92, False, theme="dark")


def test_text_is_escaped():
    svg = render_avow_badge(style="card", decision="safe", score=90, coordinate="a<b>/c&d")
    ET.fromstring(svg)
    assert "a&lt;b&gt;/c&amp;d" in svg


def test_adoption_levels_match_the_trust_card():
    assert [adoption_level(p) for p in (90, 70, 50, 20, 5)] == [
        "Load-bearing", "Widely relied", "Established", "Rising", "New"]
    assert 'p>=88?"Load-bearing":p>=65?"Widely relied"' in TRUST_CARD_HTML


def test_unknown_style_rejected():
    with pytest.raises(ValueError):
        render_avow_badge(style="nope", decision="safe", score=90)


@pytest.fixture
def _patched(monkeypatch):
    from src.api import public_scan_router as r

    async def _no_entity(*a, **k):
        return None

    async def _cached(owner, repo):
        return {"trust_score": 96, "decision": "safe", "certified": {"eligible": True},
                "metadata": {"files_scanned": 40}}

    async def _adopt(*a, **k):
        return (70, 5000, "stars")

    async def _no_full(*a, **k):
        return None

    monkeypatch.setattr(r, "_get_entity_trust", _no_entity)
    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "surface_adoption_summary", _adopt)
    monkeypatch.setattr(r, "scan_adoption", _no_full)
    return r


@pytest.mark.asyncio
async def test_badge_route_compact_and_card_with_open_cors(_patched):
    r = _patched
    resp = await r.scan_badge(owner="o", repo="r", metric="trust", style="compact",
                              theme="auto", db=None)
    body = resp.body.decode()
    assert resp.media_type == "image/svg+xml"
    assert resp.headers["access-control-allow-origin"] == "*"
    assert 'height="20"' in body.split(">", 1)[0] and "CERTIFIED" in body and ">5k<" in body
    card = await r.scan_badge(owner="o", repo="r", metric="trust", style="card",
                              theme="dark", db=None)
    assert 'width="360"' in card.body.decode()


def test_badge_route_defaults():
    import inspect

    from src.api import public_scan_router as r
    assert inspect.signature(r.scan_badge).parameters["style"].default.default == "compact"
    assert inspect.signature(r.scan_card).parameters["style"].default.default == "card"


@pytest.mark.asyncio
async def test_badge_route_classic_and_adoption_metric_still_work(_patched):
    r = _patched
    classic = await r.scan_badge(owner="o", repo="r", metric="trust", style="classic",
                                 theme="auto", db=None)
    assert "✓ Certified 96" in classic.body.decode()
    adopt = await r.scan_badge(owner="o", repo="r", metric="adoption", style="compact",
                               theme="auto", db=None)
    assert "Adopted: 5k stars" in adopt.body.decode()


@pytest.mark.asyncio
async def test_card_svg_route_serves_the_new_card_and_keeps_classic(_patched):
    r = _patched
    new = await r.scan_card(owner="o", repo="r", style="card", theme="light", db=None)
    body = new.body.decode()
    assert new.headers["access-control-allow-origin"] == "*"
    assert 'width="360"' in body and "ADOPTION" in body and LOGO_INNER in body
    old = await r.scan_card(owner="o", repo="r", style="classic", theme="auto", db=None)
    assert "ADOPTION · REACH" in old.body.decode()


# ── route × state matrix ──────────────────────────────────────────────────────

def _scan(score=96, *, eligible=True, files=40, pending=False, items=(), high=0,
          critical=0):
    d = {"trust_score": score, "certified": {"eligible": eligible},
         "metadata": {"files_scanned": files},
         "findings": {"items": list(items), "critical": critical, "high": high}}
    if pending:
        d["behavioral"] = {"pending": True}
    return d


_HIGH = {"category": "code_safety", "severity": "high", "kind": "defect",
         "shipped": True, "file": "src/x.py", "line": 1}

ROUTE_STATES = {
    "certified": (_scan(96), True),
    "safe_not_eligible": (_scan(92, eligible=False), False),
    "review_eligible": (_scan(85, items=[_HIGH], high=1), False),
    "pending_sandbox": (_scan(96, pending=True), False),
    "thin_coverage": (_scan(96, files=3), False),
    "score_below_81": (_scan(78), False),
}


def _shows_cert(body: str) -> bool:
    return "ertified" in re.sub(r"<!--.*?-->", "", body, flags=re.S)


def _route_patch(monkeypatch, scan, *, entity=None, adoption=(70, 5000, "stars")):
    from src.api import public_scan_router as r

    async def _entity(*a, **k):
        return entity

    async def _cached(owner, repo):
        return scan

    async def _adopt(*a, **k):
        return adoption

    async def _no_full(*a, **k):
        return None

    async def _boom(*a, **k):
        raise RuntimeError("scan failed")

    monkeypatch.setattr(r, "_get_entity_trust", _entity)
    monkeypatch.setattr(r, "_get_cached", _cached)
    monkeypatch.setattr(r, "surface_adoption_summary", _adopt)
    monkeypatch.setattr(r, "scan_adoption", _no_full)
    monkeypatch.setattr(r, "public_scan", _boom)

    # The sandbox block comes from the sandbox cache (cache-only), not the scan dict:
    # serve the fixture's block from there, as production does.
    async def _beh(data):
        return (data or {}).get("behavioral")

    monkeypatch.setattr(r, "_cached_behavioral_for", _beh)
    return r


@pytest.mark.asyncio
@pytest.mark.parametrize("state", list(ROUTE_STATES))
@pytest.mark.parametrize("style", ["compact", "card", "card-stacked", "classic"])
@pytest.mark.parametrize("theme", ["auto", "light", "dark"])
async def test_badge_route_state_matrix(monkeypatch, state, style, theme):
    scan, mark = ROUTE_STATES[state]
    r = _route_patch(monkeypatch, scan)
    resp = await r.scan_badge(owner="o", repo="r", metric="trust", style=style,
                              theme=theme, db=None)
    body = resp.body.decode()
    ET.fromstring(body)
    assert resp.media_type == "image/svg+xml"
    assert resp.headers["access-control-allow-origin"] == "*"
    assert resp.headers["cache-control"] == "public, max-age=3600, s-maxage=86400"
    assert _shows_cert(body) is mark, state  # Certified / CERTIFIED only with the mark
    assert len(body) < 40_000


@pytest.mark.asyncio
@pytest.mark.parametrize("style", ["card", "card-stacked", "classic"])
@pytest.mark.parametrize("state", list(ROUTE_STATES))
async def test_card_route_state_matrix(monkeypatch, style, state):
    scan, mark = ROUTE_STATES[state]
    r = _route_patch(monkeypatch, scan)
    resp = await r.scan_card(owner="o", repo="r", style=style, theme="auto", db=None)
    body = resp.body.decode()
    ET.fromstring(body)
    assert resp.headers["cache-control"] == "public, max-age=300, s-maxage=3600"
    assert resp.headers["access-control-allow-origin"] == "*"
    assert _shows_cert(body) is mark, state


@pytest.mark.asyncio
@pytest.mark.parametrize("style", ["compact", "card", "classic"])
async def test_unscanned_and_scan_error_render_not_scanned(monkeypatch, style):
    r = _route_patch(monkeypatch, None)  # cache miss, regenerate raises
    resp = await r.scan_badge(owner="o", repo="nope", metric="trust", style=style,
                              theme="auto", db=None)
    body = resp.body.decode()
    ET.fromstring(body)
    assert resp.status_code == 200 and "ot scanned" in body


@pytest.mark.asyncio
async def test_entity_composite_never_carries_the_mark(monkeypatch):
    r = _route_patch(monkeypatch, _scan(96),
                     entity={"imported": True, "composite_score": 97, "grade": "A"})
    for style in ("compact", "card", "classic"):
        resp = await r.scan_badge(owner="o", repo="r", metric="trust", style=style,
                                  theme="dark", db=None)
        assert "ertified" not in resp.body.decode()


@pytest.mark.asyncio
async def test_no_adoption_signal_route(monkeypatch):
    r = _route_patch(monkeypatch, _scan(92, eligible=False), adoption=(None, None, None))
    card = (await r.scan_badge(owner="o", repo="r", metric="trust", style="card",
                               theme="dark", db=None)).body.decode()
    assert "no signal yet" in card
    compact = (await r.scan_badge(owner="o", repo="r", metric="trust", style="compact",
                                  theme="dark", db=None)).body.decode()
    assert ">New<" in compact


@pytest.mark.asyncio
async def test_combined_and_adoption_metrics_keep_working(monkeypatch):
    r = _route_patch(monkeypatch, _scan(92, eligible=False))
    combined = (await r.scan_badge(owner="o", repo="r", metric="combined",
                                   style="compact", theme="auto", db=None)).body.decode()
    assert 'height="20"' in combined.split(">", 1)[0]
    adopt = (await r.scan_badge(owner="o", repo="r", metric="adoption", style="compact",
                                theme="auto", db=None)).body.decode()
    assert "Adopted: 5k stars" in adopt


def test_very_long_coordinate_is_truncated_on_the_card():
    long = "an-organisation-with-a-long-name/" + "x" * 80
    svg = render_avow_badge(style="card", decision="safe", score=90, coordinate=long)
    ET.fromstring(svg)
    shown = re.search(r'font-size="12"[^>]*>([^<]+)<', svg).group(1)
    assert shown.endswith("…") and len(shown) <= 44
    assert long in svg  # the full name stays in the accessible title


def test_route_patterns_accept_old_and_new_params():
    import inspect

    from src.api import public_scan_router as r
    badge = inspect.signature(r.scan_badge).parameters
    for v in ("compact", "card", "card-stacked", "classic"):
        assert re.fullmatch(badge["style"].default.metadata[0].pattern, v)
    assert re.fullmatch(badge["metric"].default.metadata[0].pattern, "combined")
