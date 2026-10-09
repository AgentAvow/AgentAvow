"""The hosted MCP connector's scan RESULTS lead with the three phrases (Safe to connect /
Review before you connect / Do not connect) and the reason, plus " · Certified" when
certified. structuredContent gains decision / decision_final / decision_reason beside
the binary verdict (which follows decide() since 2026-10-08). HEADLINE_FOLLOWS_DECISION decides what leads where the
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


def test_thin_coverage_reads_safe_with_its_reason(follows):
    # Since the binary verdict follows decide() (2026-10-08), decision and verdict agree
    # for thin coverage too, so both flag settings lead with the phrase.
    first = _first(THIN)
    assert first.startswith("✅ Safe to connect — nothing found; little code to inspect. "
                            "x · npm: trust 74/100.")
    # The capped-score explanation rides on the Next line (not repeated here).
    assert "capped because" in _next(THIN)


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
    (CERTIFIED, "safe", "safe"), (THIN, "safe", "safe"),
    (REVIEW, "review", "needs_review"), (BLOCK, "do_not_connect", "needs_review"),
])
def test_struct_verdict_agrees_with_the_decision(follows, data, decision, verdict):
    s = _struct(data)
    assert s["decision"] == decision and s["decision_final"] is True
    assert isinstance(s["decision_reason"], str) and s["decision_reason"]
    assert s["verdict"] == verdict  # follows decide(): safe iff decision == safe
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
    # v1.1: the card's "Open report" link (agentavow.com) is allow-listed for ChatGPT;
    # it fetches nothing, so connect/resource stay empty.
    assert ms._CARD_META["openai/widgetCSP"] == {
        "connect_domains": [], "resource_domains": [],
        "redirect_domains": ["https://agentavow.com"]}


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


def test_card_thin_coverage_leads_with_the_phrase():
    sc = _struct(THIN)
    for flag in (False, True):  # decision and verdict agree, so the flag no longer matters
        out = _render(sc, flag)
        assert "Safe to connect" in out["lead"]["html"]
        assert "little code to inspect" in out["lead"]["html"]


def test_card_without_decision_falls_back_to_the_old_wording():
    for data, pill in ((CERTIFIED, "✓ CERTIFIED"), (REVIEW, "⚠ REVIEW"), (THIN, "✓ SAFE")):
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


# ── Next line, counts, install, metadata wording (Kenne: same across the board) ───

def _next(data: dict, hint: str = "") -> str:
    text = ms._scan_block(data, "use", RP, "x · npm", install_hint=hint)
    return next(ln for ln in text.splitlines() if ln.startswith("**Next:**"))


def test_next_line_per_decision():
    assert _next(CERTIFIED, "npm install x") == "**Next:** Safe to connect: install it as usual."
    assert _next(CERTIFIED) == "**Next:** Safe to connect: connect it as usual."
    thin = _next(THIN)
    assert thin.startswith("**Next:** Safe to connect: connect it as usual. The score is "
                           "capped because there's little code to inspect (3 files)")
    review = _next(REVIEW)
    assert review.startswith("**Next:** Review before you connect (one high finding: unsafe "
                             "eval call): read the findings above")
    block = _next(BLOCK, "npm install x")
    assert block.startswith("**Next:** Do not connect or install it (one critical finding: "
                            "hardcoded AWS key). The full report has the evidence: ")
    assert "/check/pkg/npm/x" in block and "alternative" in block


def test_no_line_counts_blocking_findings_against_a_severity_headline():
    data = dict(BLOCK, findings={"total": 4, "critical": 3, "high": 1, "items": [
        {"severity": "critical", "name": "curl piped to shell", "file_path": "a"}] * 3 + [
        {"severity": "high", "name": "shell subprocess", "file_path": "b"}]})
    text = ms._scan_block(data, "use", RP, "x · npm")
    assert text.startswith("⛔ Do not connect — 3 critical findings")
    assert "blocking" not in text
    sandbox = dict(data, behavioral={"ran": True, "plan": "pypi", "canary_exfil": [
        {"via": "dns", "host": "c2.evil.net"}], "findings": []})
    first = ms._scan_block(sandbox, "use", RP, "x · npm").split("\n", 1)[0]
    assert "Plus 3 critical and 1 high static findings." in first


def test_struct_install_is_null_on_do_not_connect():
    mal = dict(CERTIFIED, incident_history={"has_incident": True,
                                            "current_version_affected": True})
    s = _struct(mal)
    assert s["decision"] == "do_not_connect" and s["install"] is None
    assert _struct(dict(CERTIFIED))["install"] == "npm install x"


def test_metadata_text_describes_the_three_answers():
    import asyncio
    texts = {
        "instructions": ms._INSTRUCTIONS,
        "claude": ms._instructions_for("claude"),
        "get_started": asyncio.run(ms._get_prompt("agentavow_get_started", None))
        .messages[0].content.text,
        "check": asyncio.run(ms._get_prompt("agentavow_check_my_connections", None))
        .messages[0].content.text,
        "about": ms._ABOUT,
    }
    for name, t in texts.items():
        for p in ("Safe to connect", "Review before you connect", "Do not connect"):
            assert p in t, (name, p)
        assert "adoption" in t.lower() and "0-100" in t or name == "check", name
        assert "needs review" not in t and "needs-review" not in t, name
        assert "letter grade" not in t.lower() and ">=81" not in t and "81+" not in t, name
    assert "Certified" in texts["claude"] and "Certified" in texts["get_started"]


# vercel/next.js on claude.ai: the reason named a high finding in the tool's own code
# while top_findings led with three critical dependency advisories.
NEXTJS_SHAPE = {
    "trust_score": 58, "trust_tier": "standard", "metadata": {"files_scanned": 200},
    "findings": {"total": 10, "critical": 0, "high": 1, "items": [
        *[{"severity": "critical", "category": "dependency",
           "name": f"Vulnerable dependency: handlebars@4.7.9 (GHSA-{n})",
           "file_path": "lockfile", "line_number": 1, "shipped": True, "kind": "defect",
           "installed": True} for n in range(3)],
        *[{"severity": "high", "category": "dependency", "name": "Vulnerable dependency: tar",
           "file_path": "lockfile", "line_number": 1, "shipped": True, "kind": "defect",
           "installed": True}] * 5,
        {"severity": "high", "category": "unsafe_exec", "name": "execSync / spawn (Node.js)",
         "file_path": "packages/next/x.js", "line_number": 4, "shipped": True,
         "kind": "defect", "installed": True},
        {"severity": "medium", "category": "fs_access", "name": "fs write",
         "file_path": "packages/next/y.js", "line_number": 2, "shipped": True,
         "kind": "defect", "installed": True},
    ]},
    "certified": {"eligible": False},
}


def test_top_findings_lead_with_what_decided():
    items = NEXTJS_SHAPE["findings"]["items"]
    rows = ms._grouped_findings(items, 3)
    assert [r["what"] for r in rows] == [
        "execSync / spawn (Node.js)",
        "Vulnerable dependency: handlebars@4.7.9 (GHSA-0)",
        "Vulnerable dependency: handlebars@4.7.9 (GHSA-1)",
    ]
    assert set(rows[0]) == {"severity", "category", "what", "where", "remediation", "count"}
    sc = ms._scan_struct(NEXTJS_SHAPE, "vercel/next.js", "github", RP, API, None)
    assert len(sc["top_findings"]) == 3
    assert sc["top_findings"][0]["what"] == "execSync / spawn (Node.js)"
    assert sc["decision_reason"] == ("one high finding in its code: execSync / spawn (Node.js);"
                                     " plus 3 critical and 5 high in dependencies")
    text = ms._scan_block(NEXTJS_SHAPE, "use", RP, "vercel/next.js")
    top = text.split("**Top findings:**", 1)[1].strip().splitlines()
    assert "execSync / spawn (Node.js)" in top[0]
    assert "Vulnerable dependency: tar (×5)" in "\n".join(top[:5])


def test_top_findings_without_decision_inputs_stay_severity_first():
    rows = ms._grouped_findings([
        {"severity": "medium", "category": "fs_access", "name": "m"},
        {"severity": "critical", "category": "dependency", "name": "Vulnerable dependency: a"},
    ], 3)
    assert [r["severity"] for r in rows] == ["critical", "medium"]
