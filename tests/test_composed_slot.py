"""Tests for the AgentGraph slot emitter (agentgraph-scan-v1-structural).

The slot shape is a published interop contract coordinated with
haroldmalikfrimpong-ops/agentid-aps-interop#5 and a2aproject/A2A#1734.
These tests pin the locked field names and behaviors so downstream
verifiers don't break when we refactor internals.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.attestation.composed_slot import (
    CANONICALIZATION_SPEC,
    ISSUER_DID,
    ISSUER_KEY_ID,
    SCANNER_NAME,
    SLOT_SCHEMA_VERSION,
    ScanInputs,
    build_agentgraph_slot,
    compute_evidence_hash,
    normalize_subject_did,
    score_to_letter,
    sign_slot_v2,
)

# ---------------------------------------------------------------------------
# Locked constants — changing these breaks external verifiers.
# ---------------------------------------------------------------------------


def test_schema_version_locked():
    assert SLOT_SCHEMA_VERSION == "agentgraph-scan-v1-structural"


def test_issuer_did_locked():
    assert ISSUER_DID == "did:web:agentgraph.co"


def test_issuer_key_id_locked():
    assert ISSUER_KEY_ID == "did:web:agentgraph.co#agentgraph-security-v1"


def test_scanner_name_locked():
    assert SCANNER_NAME == "agentgraph-trust-scanner"


def test_canonicalization_spec_matches_aps():
    """Must match APS + CTEF so chained verification works."""
    assert CANONICALIZATION_SPEC == "jcs-rfc8785+sha256"


# ---------------------------------------------------------------------------
# score_to_letter — public A-F rubric
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,expected", [
    (100, "A+"),
    (96, "A+"),
    (95, "A"),
    (81, "A"),
    (80, "B"),
    (61, "B"),
    (60, "C"),
    (41, "C"),
    (40, "D"),
    (21, "D"),
    (20, "F"),
    (0, "F"),
    (-5, "F"),     # clamp
    (150, "A+"),   # clamp
])
def test_score_to_letter_thresholds(score, expected):
    assert score_to_letter(score) == expected


# ---------------------------------------------------------------------------
# normalize_subject_did
# ---------------------------------------------------------------------------


def test_normalize_subject_did_prefers_existing():
    result = normalize_subject_did("abc-123", existing_did="did:web:external.com:agent:42")
    assert result == "did:web:external.com:agent:42"


def test_normalize_subject_did_falls_back_to_entity_id():
    result = normalize_subject_did("abc-123", existing_did=None)
    assert result == "did:web:agentgraph.co:entities:abc-123"


# ---------------------------------------------------------------------------
# compute_evidence_hash
# ---------------------------------------------------------------------------


def test_evidence_hash_format():
    h = compute_evidence_hash(b"hello world")
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_evidence_hash_stable_on_bytes():
    h1 = compute_evidence_hash(b"payload")
    h2 = compute_evidence_hash(b"payload")
    assert h1 == h2


def test_evidence_hash_uses_strict_jcs_not_legacy():
    """B6: the slot advertises jcs-rfc8785+sha256, so a dict must be hashed with the
    STRICT RFC 8785 canonicalizer (nulls preserved, non-ASCII emitted literally) —
    not the legacy null-stripping/ASCII-escaping one — or an external verifier
    following the advertised spec computes a different digest and rejects a valid sig."""
    import hashlib

    from src.signing import canonicalize, canonicalize_jcs_strict

    # A payload that exercises exactly where the two canonicalizers diverge:
    # a null value and a non-ASCII character.
    payload = {"nullable": None, "name": "café", "score": 1}
    got = compute_evidence_hash(payload)
    strict = "sha256:" + hashlib.sha256(canonicalize_jcs_strict(payload)).hexdigest()
    legacy = "sha256:" + hashlib.sha256(canonicalize(payload)).hexdigest()
    assert got == strict, "evidence hash must use strict RFC 8785 JCS (the advertised spec)"
    assert got != legacy, "strict and legacy must differ here — proves B6 is actually fixed"


# ---------------------------------------------------------------------------
# build_agentgraph_slot — full slot emission
# ---------------------------------------------------------------------------


def _base_inputs(**overrides) -> ScanInputs:
    defaults = dict(
        entity_id="11111111-2222-3333-4444-555555555555",
        entity_did=None,
        source_url="https://github.com/example/repo",
        source_type="github",
        framework="native",
        artifact_ref="git:sha256:abc123",
        scanned_at=datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc),
        scanner_version="2.3.1",
        trust_score_0_to_100=78,
        category_scores={"code_quality": 82, "secrets": 100, "dependencies": 65},
        findings={"high": 3, "critical": 0, "secrets": 0, "dep_critical": 1, "dep_high": 4},
        evidence_hash="sha256:deadbeef",
        evidence_url="https://agentgraph.co/verify/deadbeef",
    )
    defaults.update(overrides)
    return ScanInputs(**defaults)


def test_slot_has_locked_top_level_keys():
    slot = build_agentgraph_slot(_base_inputs())
    assert set(slot.keys()) == {
        "version", "subject_did", "issuer_did", "scan_target", "scanner",
        "scanned_at", "gates", "overall_grade", "evidence_url",
        "evidence_hash", "canonicalization_spec",
    }


def test_slot_version_is_schema_version():
    slot = build_agentgraph_slot(_base_inputs())
    assert slot["version"] == SLOT_SCHEMA_VERSION


def test_slot_issuer_is_locked():
    slot = build_agentgraph_slot(_base_inputs())
    assert slot["issuer_did"] == ISSUER_DID


def test_slot_uses_derived_subject_did_when_entity_did_missing():
    slot = build_agentgraph_slot(_base_inputs(entity_did=None))
    assert slot["subject_did"] == (
        "did:web:agentgraph.co:entities:11111111-2222-3333-4444-555555555555"
    )


def test_slot_uses_existing_subject_did_when_provided():
    slot = build_agentgraph_slot(_base_inputs(entity_did="did:web:foo.com:agent:x"))
    assert slot["subject_did"] == "did:web:foo.com:agent:x"


def test_slot_scan_target_github_maps_to_repo():
    slot = build_agentgraph_slot(_base_inputs(source_type="github"))
    assert slot["scan_target"]["type"] == "repo"


def test_slot_scan_target_mcp_framework_overrides_type():
    slot = build_agentgraph_slot(_base_inputs(framework="mcp", source_type="github"))
    assert slot["scan_target"]["type"] == "mcp_server"


def test_slot_scan_target_npm_maps_to_package():
    slot = build_agentgraph_slot(_base_inputs(source_type="npm", framework=None))
    assert slot["scan_target"]["type"] == "package"


def test_slot_scan_target_pypi_maps_to_package():
    slot = build_agentgraph_slot(_base_inputs(source_type="pypi", framework=None))
    assert slot["scan_target"]["type"] == "package"


def test_slot_scan_target_api_maps_to_api_endpoint():
    slot = build_agentgraph_slot(_base_inputs(source_type="api", framework=None))
    assert slot["scan_target"]["type"] == "api_endpoint"


def test_slot_scan_target_unknown_falls_back_to_repo():
    slot = build_agentgraph_slot(_base_inputs(source_type="something-weird", framework=None))
    assert slot["scan_target"]["type"] == "repo"


def test_slot_artifact_ref_passes_through():
    slot = build_agentgraph_slot(_base_inputs(artifact_ref="pkg:npm@1.2.3"))
    assert slot["scan_target"]["artifact_ref"] == "pkg:npm@1.2.3"


def test_slot_scanned_at_is_iso_z_suffix():
    """RFC 3339 Z form so external verifiers don't choke on +00:00."""
    slot = build_agentgraph_slot(_base_inputs())
    assert slot["scanned_at"].endswith("Z")
    assert "T" in slot["scanned_at"]


def test_slot_naive_datetime_assumed_utc():
    naive = datetime(2026, 4, 21, 12, 0, 0)  # no tzinfo
    slot = build_agentgraph_slot(_base_inputs(scanned_at=naive))
    assert slot["scanned_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Gates — published vocabulary
# ---------------------------------------------------------------------------


def test_slot_has_three_gates_in_v1_structural():
    slot = build_agentgraph_slot(_base_inputs())
    assert set(slot["gates"].keys()) == {
        "static_analysis", "secret_scan", "dependency_audit",
    }


def test_static_analysis_gate_shape():
    slot = build_agentgraph_slot(_base_inputs())
    g = slot["gates"]["static_analysis"]
    assert set(g.keys()) == {"grade", "score", "issue_count"}
    assert g["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert 0.0 <= g["score"] <= 1.0


def test_secret_scan_gate_shape():
    slot = build_agentgraph_slot(_base_inputs())
    g = slot["gates"]["secret_scan"]
    assert set(g.keys()) == {"grade", "score", "issue_count"}


def test_dependency_audit_gate_shape():
    """Dep gate surfaces critical/high counts specifically."""
    slot = build_agentgraph_slot(_base_inputs())
    g = slot["gates"]["dependency_audit"]
    assert set(g.keys()) == {"grade", "score", "critical", "high"}
    assert g["critical"] == 1
    assert g["high"] == 4


def test_gate_score_is_fraction_of_one():
    slot = build_agentgraph_slot(_base_inputs(
        category_scores={"code_quality": 84, "secrets": 100, "dependencies": 60},
    ))
    assert slot["gates"]["static_analysis"]["score"] == 0.84
    assert slot["gates"]["secret_scan"]["score"] == 1.0
    assert slot["gates"]["dependency_audit"]["score"] == 0.6


# ---------------------------------------------------------------------------
# overall_grade is declared proprietary — but must be stable shape
# ---------------------------------------------------------------------------


def test_overall_grade_is_letter():
    slot = build_agentgraph_slot(_base_inputs(trust_score_0_to_100=78))
    assert slot["overall_grade"] == "B"


def test_overall_grade_at_f_boundary():
    slot = build_agentgraph_slot(_base_inputs(trust_score_0_to_100=10))
    assert slot["overall_grade"] == "F"


# ---------------------------------------------------------------------------
# Scoring rubric privacy — the slot must NOT expose internal weights
# ---------------------------------------------------------------------------


def test_slot_does_not_leak_positive_signals():
    """positive_signals is our proprietary list — it must not appear in the slot.

    (It's in the native attestation; it must NOT be in the interop slot.)
    """
    slot = build_agentgraph_slot(_base_inputs())
    def _walk(obj):
        if isinstance(obj, dict):
            assert "positive_signals" not in obj
            assert "positiveSignals" not in obj
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)
    _walk(slot)


def test_slot_does_not_leak_suppression_rules():
    """Suppression is anti-gaming internals — never in public slot."""
    slot = build_agentgraph_slot(_base_inputs())
    flat = repr(slot).lower()
    assert "suppress" not in flat
    assert "allowlist" not in flat
    assert "weight" not in flat


# ---------------------------------------------------------------------------
# v2-signed preview — shape only, don't require key material
# ---------------------------------------------------------------------------


def test_sign_slot_v2_changes_version_label():
    slot = build_agentgraph_slot(_base_inputs())
    try:
        signed = sign_slot_v2(slot)
    except Exception:
        pytest.skip("signing keys not available in test env")
        return
    assert signed["version"].endswith("-signed")
    assert "signature" in signed
    assert signed["signer_key_id"] == ISSUER_KEY_ID


def test_sign_slot_v2_preserves_payload_fields():
    slot = build_agentgraph_slot(_base_inputs())
    try:
        signed = sign_slot_v2(slot)
    except Exception:
        pytest.skip("signing keys not available in test env")
        return
    # Every original field still present (modulo version relabel)
    for key in slot:
        assert key in signed
