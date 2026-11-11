"""The AgentAvow trust-verdict A2A extension (https://agentavow.com/ext/trust-verdict/v1).

A card that declares it must point at AgentAvow's verdict for THAT card. Our own card
declares it and reads clean; every borrowed or forged form is a medium finding."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from urllib.parse import quote

import pytest

from src.scanner.a2a_scan import (
    TRUST_VERDICT_EXT_URI,
    analyze_a2a_card,
    trust_verdict_url_ok,
)

OURS = "https://agentavow.com/.well-known/agent-card.json"
CARD = json.loads((Path(__file__).resolve().parent.parent / "web" / "public" /
                   ".well-known" / "agent-card.json").read_text())


def _v(card_url: str) -> str:
    return "https://agentavow.com/api/v1/public/scan/a2a?card=" + quote(card_url, safe="")


def _with_ext(card: dict, verdict_url) -> dict:
    c = copy.deepcopy(card)
    c["capabilities"]["extensions"] = [{"uri": TRUST_VERDICT_EXT_URI,
                                        "params": {"verdict_url": verdict_url}}]
    return c


def _ext_findings(res):
    return [f for f in res.findings if "AgentAvow verdict" in f.name]


def test_our_card_declares_it_and_reads_clean():
    exts = CARD["capabilities"]["extensions"]
    assert exts[0]["uri"] == TRUST_VERDICT_EXT_URI
    assert exts[0]["params"]["verdict_url"] == _v(OURS)
    res = analyze_a2a_card(CARD, card_url=OURS)
    assert not _ext_findings(res)
    assert "The card links its own AgentAvow verdict" in res.positive_signals


@pytest.mark.parametrize("verdict_url", [
    _v(OURS),
    _v(OURS).replace("%3A%2F%2F", "%3A//").replace("%2F", "/"),   # unencoded slashes
    "https://agentavow.com:443/api/v1/public/scan/a2a?card=" + quote(OURS, safe=""),
])
def test_valid_forms(verdict_url):
    assert trust_verdict_url_ok(verdict_url, OURS)


@pytest.mark.parametrize("verdict_url", [
    _v("https://other.example/.well-known/agent-card.json"),     # another card's verdict
    _v(OURS).replace("agentavow.com/api", "agentavow.com.evil.example/api"),
    _v(OURS).replace("https://agentavow.com", "https://evil.example"),
    _v(OURS).replace("https://", "http://"),
    _v(OURS) + "&force=true",                                     # extra parameter
    _v(OURS).replace("/scan/a2a", "/scan/mcp"),
    "https://user:pw@agentavow.com/api/v1/public/scan/a2a?card=" + quote(OURS, safe=""),
    _v(OURS) + "#frag",
    "", None, 42,
])
def test_borrowed_or_forged_forms(verdict_url):
    assert not trust_verdict_url_ok(verdict_url, OURS)


def test_card_pointing_at_another_cards_verdict_is_medium():
    other = "https://agent.example/.well-known/agent-card.json"
    card = _with_ext(CARD, _v(OURS))   # copies OUR verdict onto THEIR card
    res = analyze_a2a_card(card, card_url=other)
    (f,) = _ext_findings(res)
    assert f.severity == "medium" and f.file_path.startswith("card:extension:")


def test_missing_verdict_url_is_medium():
    res = analyze_a2a_card(_with_ext(CARD, None), card_url=OURS)
    assert [f.severity for f in _ext_findings(res)] == ["medium"]


def test_other_extensions_are_untouched():
    card = copy.deepcopy(CARD)
    card["capabilities"]["extensions"] = [{"uri": "https://example.org/ext/x/v1",
                                           "params": {"verdict_url": "https://x"}}]
    res = analyze_a2a_card(card, card_url=OURS)
    assert not _ext_findings(res)


def test_params_are_bounded_scalars():
    from src.source_import.a2a_fetcher import parse_agent_card
    card = copy.deepcopy(CARD)
    card["capabilities"]["extensions"][0]["params"]["nested"] = {"a": 1}
    card["capabilities"]["extensions"][0]["params"]["huge"] = "x" * 5000
    parsed = parse_agent_card(card)
    params = parsed["capabilities"]["extensions"][0]["params"]
    assert "nested" not in params and "huge" not in params and "verdict_url" in params


def test_our_card_has_no_default_valued_extension_fields():
    # Keeps the as-served bytes equal to the A2A 1.0 §8.4.1 presence form, so every
    # verifier reading of the signature agrees (tests/test_agent_card_wellknown.py).
    for e in CARD["capabilities"]["extensions"]:
        assert "required" not in e


def test_spec_page_names_both_jwks_hosts():
    """The API's jwks_url names agentgraph.co; the spec names agentavow.com. Both
    serve the same keys, and the spec must say either works."""
    from pathlib import Path

    page = (Path(__file__).resolve().parent.parent / "web" / "public" / "ext"
            / "trust-verdict" / "v1" / "index.html").read_text()
    assert "https://agentavow.com/.well-known/jwks.json" in page
    assert "https://agentgraph.co/.well-known/jwks.json" in page
    assert "either works" in page
