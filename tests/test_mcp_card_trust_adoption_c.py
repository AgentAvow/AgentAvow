"""The Claude/ChatGPT trust card's trust + adoption pair follows the badge design
(option C) while everything a host or a directory review reads stays fixed: the same
resource URI, byte-identical resource ``_meta``, an unchanged ``tools/list`` digest,
and the card's data paths (tool-result, window.openai hydration, ui/initialize, size
reporting, the report button's ui/open-link) untouched."""
from __future__ import annotations

import asyncio
import hashlib
import json

from src.bridges import mcp_streamable as m
from src.bridges.mcp_app_view import TRUST_CARD_HTML, trust_card_html


def test_tools_list_digest_is_unchanged():
    tools = asyncio.run(m._list_tools())
    doc = [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools]
    digest = hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    assert digest == "935a3240011a3d45"


def test_same_resource_uri_and_byte_identical_meta():
    assert m._CARD_URI == "ui://agentavow/trust-card-v13.html"
    assert m._CARD_CONTENTS_META == {
        "openai/widgetDomain": "https://agentavow.com",
        "openai/widgetCSP": {"connect_domains": [], "resource_domains": [],
                             "redirect_domains": ["https://agentavow.com"]},
        "openai/widgetPrefersBorder": True,
        "openai/ui": {"availableDisplayModes": ["inline"]},
        "openai/widgetDescription": (
            "An AgentAvow trust card: the answer (Safe to connect, Review before you "
            "connect, or Do not connect) with its reason, the 0-100 trust score, the "
            "adoption score, the top findings, and a link to the signed report."),
    }
    assert m._CARD_META == {
        "ui": {"resourceUri": m._CARD_URI},
        "ui/resourceUri": m._CARD_URI,
        "openai/outputTemplate": m._CARD_URI,
        "openai/widgetDomain": "https://agentavow.com",
        "openai/widgetCSP": m._WIDGET_CSP,
    }
    res = asyncio.run(m._read_resource(m._CARD_URI))
    assert res[0].meta == m._CARD_CONTENTS_META
    assert res[0].content == trust_card_html(m.HEADLINE_FOLLOWS_DECISION)


def test_data_paths_are_untouched():
    for needle in (
        'm.method==="ui/notifications/tool-result"',
        "window.openai.toolOutput",
        '"openai:set_globals"',
        'request("ui/initialize"',
        '"ui/notifications/size-changed"',
        'request("ui/open-link",{url:reportUrl})',
    ):
        assert needle in TRUST_CARD_HTML, needle


def test_card_is_self_contained():
    low = TRUST_CARD_HTML.lower()
    for banned in ("src=\"http", "href=\"http", "@import", "url(http", "<link "):
        assert banned not in low, banned


def test_trust_and_adoption_follow_option_c():
    # trust: the segmented bar with the score + tier word beside it (one row)
    assert '<div class="pair"><div class="segs">' in TRUST_CARD_HTML
    assert '<div class="num tnum"' in TRUST_CARD_HTML
    # adoption: the heavier dial (16-unit arc, round caps) with count + level beside it
    assert '<div class="pair"><svg class="dial"' in TRUST_CARD_HTML
    assert TRUST_CARD_HTML.count('stroke-width="16" stroke-linecap="round"') == 2
    assert 'stroke-width="6.5"' in TRUST_CARD_HTML and 'r="9.5"' in TRUST_CARD_HTML
    assert 'class="num anum"' in TRUST_CARD_HTML and "no signal yet" in TRUST_CARD_HTML
    # trust's numeral leads the adoption count
    assert ".num.tnum { font-size:30px; }" in TRUST_CARD_HTML
    assert ".num.anum { font-size:21px;" in TRUST_CARD_HTML
