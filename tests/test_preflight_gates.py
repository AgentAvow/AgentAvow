"""Tests for the pure Connector Preflight gate evaluator."""
from __future__ import annotations

from src.preflight.gates import MIN_DIRECTORY_SCORE, evaluate_gates


def _mcp_data(*, score=92, categories=None, lethal=False, blast="low",
              has_readme=True, has_license=True, certified=False):
    return {
        "trust_score": score,
        "trust_tier": "trusted",  # the API value (lowercase), as /public/scan emits it
        "grade": "A",
        "findings": {"categories": categories or {}, "items": []},
        "surface_detail": {"surface": "mcp", "lethal_trifecta": lethal,
                           "blast_radius": {"level": blast}},
        "metadata": {"has_readme": has_readme, "has_license": has_license,
                     "is_mcp_server": True},
        "certified": {"eligible": certified},
        "scanned_at": "2026-08-18T00:00:00+00:00",
    }


def _gate(report, gate_id):
    return next(g for g in report["gates"] if g["id"] == gate_id)


def test_clean_mcp_is_directory_ready():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth={"oauth_discovered": True})
    assert r["directory_ready"] is True
    assert r["headline"] == "Directory-Ready"
    assert _gate(r, "no_secrets")["status"] == "pass"
    assert _gate(r, "auth_declared")["status"] == "pass"
    assert r["summary"]["blockers_failed"] == 0


def test_secret_finding_blocks():
    r = evaluate_gates(_mcp_data(categories={"secret": 2}), surface="mcp", auth=None)
    assert r["directory_ready"] is False
    g = _gate(r, "no_secrets")
    assert g["status"] == "fail" and g["severity"] == "blocker"


def test_injection_blocks():
    r = evaluate_gates(_mcp_data(categories={"prompt_injection": 1}), surface="mcp", auth=None)
    assert r["directory_ready"] is False
    assert _gate(r, "no_injection")["status"] == "fail"


def _with_items(data, *items):
    data["findings"]["items"] = list(items)
    return data


def test_annotation_lie_with_evidence_blocks():
    """HIGH = evidence (a command/script param on a read-only tool, or the sandbox
    watched it write): a predicted rejection."""
    d = _with_items(_mcp_data(categories={"annotation_lie": 1}),
                    {"category": "annotation_lie", "severity": "high"})
    r = evaluate_gates(d, surface="mcp", auth=None)
    g = _gate(r, "truthful_annotations")
    assert g["status"] == "fail" and g["severity"] == "blocker"
    assert r["directory_ready"] is False


def test_annotation_lie_from_wording_only_warns():
    """MEDIUM = inferred from description wording alone: a warning, not a blocker
    (Kenne, 2026-10-08)."""
    d = _with_items(_mcp_data(categories={"annotation_lie": 2}),
                    {"category": "annotation_lie", "severity": "medium"},
                    {"category": "annotation_lie", "severity": "medium"})
    r = evaluate_gates(d, surface="mcp", auth=None)
    g = _gate(r, "truthful_annotations")
    assert g["status"] == "warn" and g["severity"] == "warning"
    assert "2 read-only tool(s)" in g["detail"]
    assert r["directory_ready"] is True
    assert r["summary"]["warnings"] >= 1


def test_annotation_lie_mixed_blocks_on_the_high_one():
    d = _with_items(_mcp_data(categories={"annotation_lie": 2}),
                    {"category": "annotation_lie", "severity": "high"},
                    {"category": "annotation_lie", "severity": "medium"})
    g = _gate(evaluate_gates(d, surface="mcp", auth=None), "truthful_annotations")
    assert g["status"] == "fail" and g["detail"].startswith("1 tool(s)")


def test_lethal_trifecta_blocks():
    r = evaluate_gates(_mcp_data(lethal=True), surface="mcp", auth=None)
    assert _gate(r, "no_lethal_trifecta")["status"] == "fail"
    assert r["directory_ready"] is False


def test_low_score_blocks():
    r = evaluate_gates(_mcp_data(score=MIN_DIRECTORY_SCORE - 1), surface="mcp", auth=None)
    assert _gate(r, "trust_score")["status"] == "fail"
    assert r["directory_ready"] is False


def test_unknown_auth_warns_not_blocks():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=None)
    assert _gate(r, "auth_declared")["status"] == "unknown"
    assert r["directory_ready"] is True          # warnings never block
    assert r["summary"]["warnings"] >= 1


def test_high_blast_radius_warns():
    r = evaluate_gates(_mcp_data(blast="critical"), surface="mcp", auth={"open": True})
    assert _gate(r, "destructive_hinted")["status"] == "warn"
    assert r["directory_ready"] is True


def test_missing_readme_license_warns():
    r = evaluate_gates(_mcp_data(has_license=False), surface="mcp", auth=None)
    assert _gate(r, "listing_complete")["status"] == "warn"


def test_repo_surface_skips_mcp_only_gates():
    data = _mcp_data()
    data["surface_detail"] = {}
    r = evaluate_gates(data, surface="repo", auth=None)
    ids = {g["id"] for g in r["gates"]}
    assert "no_lethal_trifecta" not in ids
    assert "auth_declared" not in ids
    assert "no_secrets" in ids and "trust_score" in ids
    assert r["directory_ready"] is True
