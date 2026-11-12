"""Certified check 4 (`no_critical_or_high`) counts a live sandbox critical/high.

The scanner computes `certified` before the sandbox answers, so the check read True beside
an answer citing a sandbox high (server-puppeteer 2025.5.12, 2026-11-11). The served block
now applies the same rule as decide(): a run that ran, is not pending and is not the
advisory live probe. The field is unsigned; the JWS payload never carries it.
"""
from __future__ import annotations

import copy

from src.api import public_scan_router as psr
from src.scanner.verdict import certified_with_sandbox, decide

CHECKS = {"artifact_scanned": True, "provenance_verified": True, "no_drift": True,
          "no_critical_or_high": True, "recompute_ready": True, "full_coverage": True}
CERT = {"eligible": True, "checks": CHECKS}
SANDBOX_HIGH = {"ran": True, "plan": "npm-mcp", "attestation": {"jws": "x"},
                "findings": [{"rule": "undeclared_network", "severity": "high",
                              "title": "undeclared network call"}]}


def _cached(certified=CERT, items=None, **extra):
    return {"trust_score": 88, "trust_tier": "trusted", "scan_result": "clean",
            "recommended_limits": psr.recommended_limits(88),
            "findings": {"critical": 0, "high": 0, "medium": 0, "total": len(items or []),
                         "categories": {}, "items": items or []},
            "metadata": {"files_scanned": 120, "total_scannable_files": 120,
                         "sampled": False, "primary_language": "TypeScript"},
            "positive_signals": [], "certified": certified,
            "scanned_at": "2026-11-11T00:00:00+00:00", **extra}


def test_puppeteer_shape_sandbox_high_fails_the_check():
    out = certified_with_sandbox(CERT, SANDBOX_HIGH)
    assert out["checks"]["no_critical_or_high"] is False
    assert out["eligible"] is False
    # the other five checks are untouched
    assert {k: v for k, v in out["checks"].items() if k != "no_critical_or_high"} == \
        {k: v for k, v in CHECKS.items() if k != "no_critical_or_high"}
    # and it agrees with the answer, which cites the sandbox high
    d = decide({**_cached(), "behavioral": SANDBOX_HIGH})
    assert d.decision != "safe"


def test_a_leaked_canary_fails_the_check():
    leak = {"ran": True, "canary_exfil": True, "findings": []}
    assert certified_with_sandbox(CERT, leak)["checks"]["no_critical_or_high"] is False


def test_static_only_high_is_left_as_the_scanner_computed_it():
    static = {"eligible": False, "checks": {**CHECKS, "no_critical_or_high": False}}
    assert certified_with_sandbox(static, None) == static
    assert certified_with_sandbox(static, {"ran": True, "findings": []}) == static


def test_pending_sandbox_is_unchanged():
    pending = {"ran": False, "pending": True}
    assert certified_with_sandbox(CERT, pending) == CERT
    # even a pending block that somehow carries findings does not count yet
    assert certified_with_sandbox(CERT, {**SANDBOX_HIGH, "pending": True}) == CERT


def test_advisory_live_probe_is_unchanged():
    probe = {**SANDBOX_HIGH, "plan": "live-probe"}
    assert certified_with_sandbox(CERT, probe) == CERT
    assert certified_with_sandbox(CERT, {**SANDBOX_HIGH, "advisory": True}) == CERT


def test_medium_sandbox_finding_and_no_block_are_unchanged():
    med = {"ran": True, "findings": [{"rule": "x", "severity": "medium"}]}
    assert certified_with_sandbox(CERT, med) == CERT
    assert certified_with_sandbox(CERT, None) == CERT
    assert certified_with_sandbox(None, SANDBOX_HIGH) == {}


def test_input_is_not_modified():
    before = copy.deepcopy(CERT)
    certified_with_sandbox(CERT, SANDBOX_HIGH)
    assert CERT == before


def test_api_response_serves_the_sandbox_aware_check():
    r = psr._package_response("npm:@modelcontextprotocol/server-puppeteer", _cached(),
                              "jws", False, behavioral=SANDBOX_HIGH)
    assert r.decision != "safe"
    assert r.certified["checks"]["no_critical_or_high"] is False
    assert r.certified["eligible"] is False
    assert r.certified_mark is False
    clean = psr._package_response("npm:x", _cached(), "jws", False, behavioral=None)
    assert clean.certified["checks"]["no_critical_or_high"] is True


def test_the_signed_payload_never_carries_certified():
    """The check is a response field computed from signed inputs, not a signed claim:
    old attestations are unaffected and no payload version changes."""
    payload = psr._build_scan_payload("npm:x", _cached())
    assert "certified" not in payload and "certified" not in payload["scan"]
