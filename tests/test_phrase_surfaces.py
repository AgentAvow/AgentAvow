"""Every surface leads with the three-phrase decision + reason, and the Certified mark
survives on each surface that carried it (Kenne, 2026-10-07: "Certified stays")."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

CERT = {"eligible": True, "checks": {"no_critical_or_high": True}}


def _data(score=92, files=120, items=(), crit=0, high=0, **extra):
    return {
        "trust_score": score, "grade": "A", "trust_tier": "trusted",
        "recommended_limits": {"requests_per_minute": 60, "max_tokens_per_call": 8192,
                               "require_user_confirmation": False},
        "scan_result": "clean",
        "findings": {"critical": crit, "high": high, "medium": 0, "total": len(items),
                     "categories": {}, "suppressed_lines": 0, "items": list(items)},
        "metadata": {"files_scanned": files, "files_total": files, "sampled": False,
                     "primary_language": "Python", "has_readme": True,
                     "has_license": True, "has_tests": True, "is_mcp_server": False},
        "positive_signals": [], "scanned_at": "2026-10-07T00:00:00+00:00", **extra,
    }


def _high(name="Shell command built from user input"):
    return {"category": "unsafe_exec", "name": name, "severity": "high",
            "file_path": "src/x.py", "line_number": 3, "shipped": True,
            "kind": "defect", "installed": True}


# ── API ─────────────────────────────────────────────────────────────────────────

def test_package_response_carries_the_unsigned_decision():
    from src.api.public_scan_router import _package_response
    resp = _package_response("o/r", _data(85, items=[_high()], high=1), "jws", False)
    assert (resp.decision, resp.decision_final) == ("review", True)
    assert resp.decision_reason == "one high finding: shell command built from user input"
    # the binary verdict keeps its meaning beside it
    assert resp.verdict == "needs_review"


def test_package_response_reads_the_applied_behavioral_block():
    from src.api.public_scan_router import _package_response
    pending = {"ran": False, "pending": True}
    resp = _package_response("o/r", _data(), "jws", False, behavioral=pending)
    assert resp.behavioral == pending
    assert (resp.decision, resp.decision_final) == ("safe", False)
    assert resp.decision_reason.endswith("; sandbox still running")
    leak = {"ran": True, "canary_exfil": [{"host": "x"}], "findings": []}
    resp = _package_response("o/r", _data(45), "jws", False, behavioral=leak)
    assert resp.decision == "do_not_connect"
    assert resp.decision_reason == "a planted credential left the sandbox"


def test_decision_is_not_in_the_signed_payload():
    from src.api.public_scan_router import _build_scan_payload
    payload = _build_scan_payload("o/r", _data())
    blob = json.dumps(payload)
    assert "decision" not in blob and "Safe to connect" not in blob


# ── badges ──────────────────────────────────────────────────────────────────────

def test_scan_badges_lead_with_the_short_label_and_keep_certified():
    from src.api.public_scan_router import (
        _certified_badge_response,
        _combined_badge_response,
    )
    cert = _certified_badge_response(98, "safe").body.decode()
    assert "Safe · ✓ Certified 98" in cert and "url(#agcert)" in cert
    combo = _combined_badge_response(92, 1200, certified=False, decision="review").body.decode()
    assert "Review · 92/100" in combo and "#F59E0B" in combo
    combo_cert = _combined_badge_response(98, 1200, certified=True, decision="safe").body.decode()
    assert "Safe · ✓ Certified 98" in combo_cert


def test_badge_decision_prefers_the_scan():
    from src.api.public_scan_router import _badge_decision
    assert _badge_decision(_data(95, items=[_high()], high=1), 95) == "review"
    assert _badge_decision({"decision": "do_not_connect"}, 95) == "do_not_connect"
    assert _badge_decision(None, 95) == "safe" and _badge_decision(None, 40) == "review"


def test_embed_badge_value_leads_with_the_label():
    from src.api.badge_embed_router import _render_embed_badge_svg
    svg = _render_embed_badge_svg("tool", 0.92, True, decision="safe")
    assert "Safe · 92" in svg


def test_entity_badge_scan_segment_is_the_short_label():
    from src.api.badge_router import _scan_badge_info
    assert _scan_badge_info("do_not_connect") == ("Blocked", "#EF4444")
    assert _scan_badge_info("review")[0] == "Review"
    assert _scan_badge_info("clean")[0].startswith("scan")  # legacy value still renders


# ── cards ───────────────────────────────────────────────────────────────────────

def test_card_svg_leads_with_phrase_and_keeps_certified():
    from src.api.card_svg import render_card_svg
    svg = render_card_svg(coordinate="o/r", score=98, adoption_display="1.2k",
                          adoption_pct=50, adoption_tier=None, decision="safe",
                          certified=True)
    assert "Safe to connect · Certified" in svg and "Verified" in svg  # tier as detail
    svg = render_card_svg(coordinate="o/r", score=85, adoption_display=None,
                          adoption_pct=0, adoption_tier=None, decision="review")
    assert "Review before you connect" in svg


def test_og_png_renders_with_a_decision():
    pytest.importorskip("PIL")
    from src.api.og_image import render_og_png
    png = render_og_png(title="o/r", grade="", score=98, subtitle="x",
                        decision="safe", certified=True)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert render_og_png(title="o/r", grade="", score=None)[:4] == b"\x89PNG"


def test_og_svg_fallback_uses_the_headline():
    from src.api.public_scan_router import _render_og_svg
    svg = _render_og_svg(owner="o", repo="r", grade="A", score=92, critical=0, high=0,
                         medium=0, verdict="Safe to connect · Certified", decision="safe")
    assert "Safe to connect · Certified" in svg and "#22C55E" in svg


# ── email + webhook ─────────────────────────────────────────────────────────────

def test_watch_email_leads_with_phrase_and_keeps_certified():
    from src.email import render_watch_notification
    subj, html = render_watch_notification(
        "drop", "o", "r", 90, 70,
        decision={"decision": "review", "decision_reason": "one high finding: x",
                  "certified": False})
    assert "now Review before you connect" in subj
    assert "Review before you connect" in html and "one high finding: x" in html
    subj, html = render_watch_notification(
        "improve", "o", "r", 80, 98,
        decision={"decision": "safe", "decision_reason": "nothing found in 9 files",
                  "certified": True})
    assert "Safe to connect · Certified" in html
    # no decision passed: decided from the new score
    subj, _ = render_watch_notification("drift", "o", "r", 90, 40)
    assert subj.endswith("now Review before you connect")


def test_watch_decision_folds_the_sandbox_first():
    from src.jobs.scheduler import _watch_decision, w_decision_phrase
    d = _watch_decision(_data(), {"ran": True, "canary_exfil": [{"host": "x"}],
                                  "findings": []})
    assert d["decision"] == "do_not_connect" and d["certified"] is False
    d = _watch_decision(_data(98, certified=CERT), None)
    assert w_decision_phrase(d) == "Safe to connect · Certified (nothing found in 120 files)"


# ── catalog, preflight, gateway ─────────────────────────────────────────────────

def test_catalog_row_carries_the_decision():
    from src.api.scan_catalog_router import CatalogRow
    row = CatalogRow(surface="npm", name="x", trust_score=40, critical=1, high=0)
    assert row.decision == "do_not_connect" and row.decision_reason == "one critical finding"
    assert CatalogRow(surface="npm", name="y", trust_score=None).decision is None
    assert CatalogRow(surface="npm", name="z", trust_score=88).decision == "safe"


# ── local CLI ───────────────────────────────────────────────────────────────────

def test_local_cli_human_line_leads_with_phrase_and_certified(tmp_path):
    import io

    from src.scanner.local_scan import _print_human, scan_local
    (tmp_path / "app.py").write_text("def hello():\n    return 1\n")
    result = scan_local(str(tmp_path))
    result.certified = {"eligible": True}
    buf = io.StringIO()
    _print_human(result, stream=buf)
    line = [ln for ln in buf.getvalue().splitlines() if "Verdict" in ln][0]
    assert "· Certified — " in line
    assert any(p in line for p in ("Safe to connect", "Review before you connect"))


def test_local_cli_fail_on_decision(tmp_path):
    from src.scanner.local_scan import main
    (tmp_path / "app.py").write_text("def hello():\n    return 1\n")
    assert main(["scan", str(tmp_path), "--quiet", "--fail-on", "do_not_connect"]) == 0


def test_local_cli_fail_on_repeats(tmp_path):
    """GitLab passes an answer gate and a severity gate together; either can fail."""
    from src.scanner.local_scan import main
    (tmp_path / "app.py").write_text(
        "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    base = ["scan", str(tmp_path), "--quiet", "--fail-on", "do_not_connect"]
    assert main(base) == 0
    assert main(base + ["--fail-on", "medium"]) == 1


# ── tool gate ───────────────────────────────────────────────────────────────────

def test_tool_gate_messages_lead_with_the_phrase():
    from src.bridges.tool_gate import Grade, evaluate
    g = Grade.from_response("o/r", {"trust_score": 85, "trust_tier": "trusted",
                                    "decision": "review",
                                    "decision_reason": "one high finding: x",
                                    "findings": {"high": 1, "items": []}})
    d = evaluate("t", "o/r", g)
    assert not d.allow and d.decision == "review"
    assert "Review before you connect (one high finding: x) · 85/100" in d.reason
    assert d.as_dict()["decision"] == "review"
    g = Grade.from_response("o/r", {"trust_score": 98, "certified": CERT,
                                    "metadata": {"files_scanned": 50}})
    d = evaluate("t", "o/r", g)
    assert d.allow and "Safe to connect · Certified" in d.reason


# ── stdio MCP package ───────────────────────────────────────────────────────────

def test_stdio_mcp_server_result_leads_with_the_phrase():
    import sys
    sys.path.insert(0, str(ROOT / "sdk" / "mcp-server"))
    try:
        from agentgraph_trust import server
    finally:
        sys.path.pop(0)
    out = server._scan_result(
        {"trust_score": 98, "verdict": "safe", "verdict_reason": "clean",
         "certified": CERT, "decision": "safe", "decision_reason": "nothing found in 3 files",
         "trust_tier": "verified"},
        "o/r", "repo", "https://x", "/api")
    assert out["decision"] == "safe" and out["verdict"] == "safe"
    assert out["summary"].startswith("Safe to connect · Certified — nothing found")
    assert out["certified"] is True and out["certified_mark"] is True
    old = server._scan_result({"trust_score": 70, "findings": {"critical": 1}},
                              "o/r", "repo", "https://x", "/api")
    assert old["decision"] == "do_not_connect"


# ── no stale wording ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("rel", [
    "src/scanner/verdict.py", "src/trust_tiers.py", "src/api/public_scan_router.py",
    "src/api/og_router.py", "src/api/card_svg.py", "src/email.py",
    "src/templates/watch_notification.html", "src/scanner/local_scan.py",
    "src/bridges/tool_gate.py", "github-action/scan.sh", "github-action/README.md",
    "web/src/rebrand/lib/summarize.ts",
    "web/src/rebrand/components/TrustMark.tsx",
])
def test_no_caution_phrase(rel):
    """"Caution" stays retired as a phrase (the five-word scheme)."""
    assert "Caution" not in (ROOT / rel).read_text()
