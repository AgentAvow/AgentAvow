"""The signed sandbox observation moves the trust score deterministically, and the
attestation records enough to recompute it."""
from __future__ import annotations

import pytest

from src.scanner.behavioral.score_effect import (
    CLEAN_EXERCISE_BONUS,
    CRITICAL_CEILING,
    HIGH_CEILING,
    behavioral_score_effect,
)

SIGNED = {"jws": "aaa.bbb.ccc", "kid": "k", "observed_at": "2026-10-02T00:00:00+00:00"}


def _blk(**kw):
    b = {"ran": True, "plan": "npm-mcp", "findings": [], "canary_exfil": [],
         "exercise": {"launch_ok": True, "calls": [{"tool": "a"}, {"tool": "b"}]},
         "attestation": dict(SIGNED)}
    b.update(kw)
    return b


@pytest.mark.parametrize("block, static, expected", [
    (_blk(), 74, 74 + CLEAN_EXERCISE_BONUS),                              # clean full run
    (_blk(), 99, 100),                                                    # capped at 100
    (_blk(canary_exfil=[{"via": "dns", "host": "x"}]), 90, CRITICAL_CEILING),
    (_blk(findings=[{"rule": "credential_canary_exfiltrated", "severity": "critical"}]),
     88, CRITICAL_CEILING),
    (_blk(findings=[{"rule": "annotation_readonly_violated", "severity": "high"}]),
     90, HIGH_CEILING),                                                   # 80 → ceiling 70
    (_blk(findings=[{"rule": "behavioral_undeclared_egress", "severity": "high"}]),
     60, 50),                                                             # −10
    (_blk(findings=[{"rule": "canary_echoed_in_result", "severity": "medium"}]), 80, 75),
    (_blk(findings=[{"rule": "tool_call_crashed_server", "severity": "low"}]), 80, 80),
])
def test_rules(block, static, expected):
    eff = behavioral_score_effect(static, block)
    assert eff["score"] == expected
    assert eff["applied"] is (expected != static)
    if eff["applied"]:
        assert eff["evidence"]["staticScore"] == static
        assert eff["evidence"]["delta"] == expected - static


@pytest.mark.parametrize("block", [
    None, {}, {"ran": False}, {"ran": True, "pending": True},
    _blk(attestation=None),                                   # unsigned → never moves a score
    _blk(exercise={"launch_ok": False, "calls": []}),         # not started → no effect
    _blk(exercise=None, plan="npm"),                          # install-only clean → no effect
])
def test_no_effect(block):
    eff = behavioral_score_effect(70, block)
    assert eff["applied"] is False and eff["score"] == 70 and eff["delta"] == 0


def test_deterministic_and_recomputable():
    b = _blk(findings=[{"rule": "x", "severity": "high"}, {"rule": "a", "severity": "medium"}])
    one, two = behavioral_score_effect(88, b), behavioral_score_effect(88, b)
    assert one == two
    ev = one["evidence"]
    assert ev["findings"] == [{"rule": "a", "severity": "medium"}, {"rule": "x", "severity": "high"}]
    import hashlib
    assert ev["observationSha256"] == hashlib.sha256(b"aaa.bbb.ccc").hexdigest()
    # recompute from the recorded evidence alone
    again = behavioral_score_effect(ev["staticScore"], _blk(
        findings=ev["findings"], canary_exfil=[] if not ev["canaryExfil"] else [{}]))
    assert again["score"] == one["score"]


def test_router_folds_it_into_the_signed_payload():
    from src.api import public_scan_router as r
    data = {"trust_score": 90, "grade": "A", "trust_tier": "trusted",
            "recommended_limits": {}, "findings": {"critical": 0, "high": 0, "items": []},
            "certified": {}}
    scored = r._apply_behavioral_score(data, _blk(
        findings=[{"rule": "annotation_readonly_violated", "severity": "high"}]))
    assert scored["trust_score"] == HIGH_CEILING and data["trust_score"] == 90
    assert scored["trust_tier"] != "trusted" or scored["trust_score"] < 81
    assert scored["behavioral_score_effect"]["delta"] == HIGH_CEILING - 90
    assert scored["behavioral_evidence"]["rules"] == "behavioral-score-v1"
    clean = r._apply_behavioral_score(data, None)
    assert clean["trust_score"] == 90 and "behavioral_evidence" not in clean
    assert clean["behavioral_score_effect"]["applied"] is False
