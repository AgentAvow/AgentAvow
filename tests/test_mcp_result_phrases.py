"""The hosted MCP connector's scan RESULTS lead with the three phrases (Safe to connect /
Review before you connect / Do not connect) and the reason, plus " · Certified" when
certified. structuredContent gains decision / decision_final / decision_reason beside
the unchanged binary verdict. HEADLINE_FOLLOWS_DECISION decides what leads where the
phrase and the binary verdict disagree (a thin-coverage 74). tools/list and the
initialize instructions are pinned separately (test_mcp_tools_list_snapshot.py)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from src.bridges import mcp_app_view as view
from src.bridges import mcp_streamable as ms

RP, API = "/check/pkg/npm/x", "/api/v1/public/scan/package/npm/x"

CERTIFIED = {"trust_score": 98, "trust_tier": "verified", "metadata": {"files_scanned": 40},
             "findings": {"items": [], "total": 0, "critical": 0, "high": 0},
             "certified": {"eligible": True, "checks": {"no_critical_or_high": True}},
             "jws": "x.y.z"}
THIN = {"trust_score": 74, "trust_tier": "standard", "metadata": {"files_scanned": 3},
        "findings": {"items": [], "total": 0}, "certified": {"eligible": False}}
REVIEW = {"trust_score": 70, "trust_tier": "standard", "metadata": {"files_scanned": 120},
          "findings": {"total": 1, "high": 1, "items": [
              {"severity": "high", "category": "code_safety", "name": "Unsafe eval call",
               "file_path": "a.py", "line_number": 3}]},
          "certified": {"eligible": False}}
BLOCK = {"trust_score": 40, "trust_tier": "restricted", "metadata": {"files_scanned": 120},
         "findings": {"total": 1, "critical": 1, "items": [
             {"severity": "critical", "category": "secret_hygiene",
              "name": "Hardcoded AWS key", "file_path": "b.py", "line_number": 9}]},
         "certified": {"eligible": False}}
PENDING = dict(CERTIFIED, certified={"eligible": False},
               behavioral={"pending": True, "ran": False})


def _first(data: dict) -> str:
    return ms._scan_block(data, "use", RP, "x · npm").split("\n", 1)[0]


def _struct(data: dict) -> dict:
    return ms._scan_struct(data, "x", "npm", RP, API, None)


@pytest.fixture(params=[False, True], ids=["agreeing-only", "always"])
def follows(request, monkeypatch):
    monkeypatch.setattr(ms, "HEADLINE_FOLLOWS_DECISION", request.param)
    return request.param


# ── text headline ─────────────────────────────────────────────────────────────────

def test_safe_certified_leads_with_the_phrase_and_suffix(follows):
    first = _first(CERTIFIED)
    assert first.startswith("✅ Safe to connect · Certified — nothing found in 40 files. "
                            "x · npm: trust 98/100.")
    assert "Adoption:" in first
    text = ms._scan_block(CERTIFIED, "use", RP, "x · npm")
    assert "98/100  ✅ Safe to connect · Certified" in text  # the monospace card
    assert "✔ SAFE" not in text and "letter grade" not in text.lower()


def test_review_leads_with_the_phrase_and_reason(follows):
    first = _first(REVIEW)
    assert first.startswith("⚠️ Review before you connect — one high finding: unsafe eval "
                            "call. x · npm: trust 70/100.")
    text = ms._scan_block(REVIEW, "use", RP, "x · npm")
    assert "⚠ REVIEW" not in text and "**Top findings:**" in text


def test_do_not_connect_leads_with_the_phrase_and_reason(follows):
    first = _first(BLOCK)
    assert first.startswith("⛔ Do not connect — one critical finding: hardcoded AWS key. "
                            "x · npm: trust 40/100.")
    text = ms._scan_block(BLOCK, "use", RP, "x · npm", install_hint="npm install x")
    assert "npm install x" not in text


def test_thin_coverage_keeps_the_old_wording_unless_the_flag_is_on(follows):
    first = _first(THIN)
    if follows:
        assert first.startswith("✅ Safe to connect — nothing found; little code to inspect. "
                                "x · npm: trust 74/100. Score capped because")
    else:
        # decision=safe but verdict=needs_review: the headline must not say "safe" while
        # the frozen instructions say >=81 is safe.
        assert first.startswith("◍ Clean, limited coverage — x · npm, 74/100.")
        assert "Safe to connect" not in first


def test_api_decision_fields_are_preferred_over_recomputing(follows):
    data = dict(REVIEW, decision="review", decision_final=True,
                decision_reason="a reason the API chose")
    assert _first(data).startswith("⚠️ Review before you connect — a reason the API chose.")
    assert _struct(data)["decision_reason"] == "a reason the API chose"


def test_pending_sandbox_is_provisional(follows):
    first = _first(PENDING)
    assert first.startswith("✅ Safe to connect — nothing found in 40 files; sandbox still "
                            "running.")
    s = _struct(PENDING)
    assert s["decision"] == "safe" and s["decision_final"] is False
    assert s["decision_reason"].endswith("; sandbox still running")


def test_flag_defaults_to_always_leading_with_the_phrase():
    assert ms.HEADLINE_FOLLOWS_DECISION is True
    assert "'Safe to connect', 'Review before you connect', or 'Do not connect'" in \
        ms._INSTRUCTIONS and ">=81" not in ms._INSTRUCTIONS


# ── structuredContent ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("data,decision,verdict", [
    (CERTIFIED, "safe", "safe"), (THIN, "safe", "needs_review"),
    (REVIEW, "review", "needs_review"), (BLOCK, "do_not_connect", "needs_review"),
])
def test_struct_carries_the_decision_beside_the_unchanged_verdict(follows, data, decision,
                                                                  verdict):
    s = _struct(data)
    assert s["decision"] == decision and s["decision_final"] is True
    assert isinstance(s["decision_reason"], str) and s["decision_reason"]
    assert s["verdict"] == verdict  # binary verdict keeps its meaning
    for k in ("verdict_reason", "certified", "certified_mark", "trust_score", "tier",
              "critical", "high", "top_findings", "subscores", "install", "adoption",
              "report_url", "report_json_url", "verify_url", "sandbox", "incident"):
        assert k in s
    assert _struct(CERTIFIED)["certified"] is True and _struct(CERTIFIED)["certified_mark"]


# ── about_agentavow result ────────────────────────────────────────────────────────

def test_about_names_the_three_phrases_and_both_scores():
    for p in ("Safe to connect", "Review before you connect", "Do not connect",
              "· Certified", "trust (0-100) and adoption"):
        assert p in ms._ABOUT
    assert "letter grade" not in ms._ABOUT.lower()


# ── the card (ui://agentavow/trust-card-v13.html) ─────────────────────────────────

def test_card_uri_and_meta_unchanged():
    assert ms._CARD_URI == "ui://agentavow/trust-card-v13.html"
    assert ms._CARD_META["openai/widgetCSP"] == {
        "connect_domains": [], "resource_domains": [], "redirect_domains": []}


def test_card_template_is_fully_substituted():
    for flag in (False, True):
        html = view.trust_card_html(flag)
        assert not re.search(r"__[A-Z_]+__", html)
        assert f"DECISION_LEADS={'true' if flag else 'false'}" in html
        assert '"do_not_connect":{"phrase":"Do not connect"' in html
    assert view.TRUST_CARD_HTML == view.trust_card_html(True)


def test_card_resource_follows_the_flag(monkeypatch):
    import asyncio
    for flag in (True, False):
        monkeypatch.setattr(ms, "HEADLINE_FOLLOWS_DECISION", flag)
        out = asyncio.run(ms._read_resource(ms._CARD_URI))
        assert f"DECISION_LEADS={'true' if flag else 'false'}" in out[0].content


_HARNESS = r"""
const html = require("fs").readFileSync(0, "utf8");
const src = html.match(/<script>([\s\S]*)<\/script>/)[1];
const sc = JSON.parse(process.argv[1]);
const els = {};
function el(id){ return els[id] || (els[id] = {id, style:{}, innerHTML:"", textContent:"",
  className:"", scrollHeight:100, addEventListener(){}}); }
const document = { getElementById: el, body:{scrollWidth:400},
  documentElement:{dataset:{}} };
const window = { parent:{postMessage(){}}, addEventListener(){}, openai:{toolOutput:sc} };
const navigator = {};
new Function("window","document","navigator","setTimeout", src)(
  window, document, navigator, function(){});
const pick = id => ({display: el(id).style.display, html: el(id).innerHTML,
  text: el(id).textContent, cls: el(id).className});
console.log(JSON.stringify({lead: pick("lead"), pill: pick("pill"), why: pick("why"),
  target: pick("target"), accent: el("accent").style.background}));
"""


def _render(sc: dict, flag: bool = False) -> dict:
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    proc = subprocess.run(["node", "-e", _HARNESS, json.dumps(sc)],
                          input=view.trust_card_html(flag), capture_output=True, text=True,
                          timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_card_leads_with_phrase_reason_and_certified():
    out = _render(_struct(CERTIFIED))
    assert out["lead"]["display"] == "block"
    assert "Safe to connect" in out["lead"]["html"]
    assert "· Certified" in out["lead"]["html"]
    assert "nothing found in 40 files" in out["lead"]["html"]
    assert out["pill"]["text"] == "✓ CERTIFIED"  # Certified stays


def test_card_review_and_do_not_connect():
    r = _render(_struct(REVIEW))
    assert "Review before you connect" in r["lead"]["html"]
    assert "one high finding: unsafe eval call" in r["lead"]["html"]
    assert r["pill"]["display"] == "none" and r["accent"] == "#F59E0B"
    b = _render(_struct(BLOCK))
    assert "Do not connect" in b["lead"]["html"] and b["accent"] == "#EF4444"
    assert "review these before you connect" not in b["why"]["text"]


def test_card_thin_coverage_follows_the_flag():
    sc = _struct(THIN)
    off = _render(sc, False)
    assert off["lead"]["display"] == "none" and off["pill"]["text"] == "◍ LIMITED"
    on = _render(sc, True)
    assert "Safe to connect" in on["lead"]["html"]
    assert "little code to inspect" in on["lead"]["html"]


def test_card_without_decision_falls_back_to_the_old_wording():
    for data, pill in ((CERTIFIED, "✓ CERTIFIED"), (REVIEW, "⚠ REVIEW"), (THIN, "◍ LIMITED")):
        sc = _struct(data)
        for k in ("decision", "decision_final", "decision_reason"):
            sc.pop(k)
        for flag in (False, True):
            out = _render(sc, flag)
            assert out["lead"]["display"] == "none", (data, flag)
            assert out["pill"]["text"] == pill
            assert out["target"]["text"].startswith("x")
    sc = _struct(CERTIFIED)
    for k in ("decision", "decision_final", "decision_reason"):
        sc.pop(k)
    assert "No blocking issues found" in _render(sc)["why"]["text"]
