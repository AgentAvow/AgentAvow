"""Trust Score Envelope v2.0 — substrate conformance tests.

Tests:
1. Build + sign + verify round-trip (each fixture envelope)
2. Tamper detection (mutate trust_score, mutate contribution, mutate proof)
3. Freshness check (within TTL vs past TTL)
4. JCS canonicalization byte-stability across fixtures
5. Negative ERC-8004 floor (-0.20)
6. Contested-signal preservation
7. Single-source diversity-weight case
8. Envelope hash determinism (same input → same hash)

The 5 reference fixtures cover the conformance cases from spec §7:
1. all_positive — typical 5-contribution aggregate
2. negative_feedback_floor — ERC-8004 negative pushes score toward floor
3. contested_signal — two providers disagree >0.30
4. freshness_decay_edge — contribution past its TTL
5. single_source_only — diversity weight 0.7 case

Fixtures live at tests/standards/fixtures/trust-score-envelope-v2.0/.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from src.trust import envelope_v2 as ev2


@pytest.fixture
def keypair():
    """Fresh Ed25519 keypair for signing tests (per-test isolation)."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture
def fixed_time():
    """Deterministic timestamp so fixtures are reproducible byte-for-byte."""
    return datetime(2026, 6, 12, 14, 32, 1, tzinfo=timezone.utc)


# ---------- The 5 reference fixtures ----------


def _fixture_all_positive(now):
    """#1 — Typical 5-contribution aggregate, all positive signals."""
    contribs = [
        ev2.Contribution(
            source="ctef_attestation", raw_signal=0.92,
            weighted_contribution=0.18, freshness_ttl_seconds=86400,
            source_attestation_hash="a" * 64, claim_type="authority",
            evidence_type="third-party",
            source_provider_did="did:web:hivetrust.tech",
        ),
        ev2.Contribution(
            source="erc8004_reputation", raw_signal=0.78,
            weighted_contribution=0.12, freshness_ttl_seconds=3600,
            source_attestation_hash="b" * 64,
        ),
        ev2.Contribution(
            source="scan_corpus", raw_signal=0.85,
            weighted_contribution=0.20, freshness_ttl_seconds=604800,
            source_attestation_hash="c" * 64,
            metadata={"malware_classification": "clean", "findings_count": 0},
        ),
        ev2.Contribution(
            source="third_party_observer", raw_signal=0.81,
            weighted_contribution=0.10, freshness_ttl_seconds=86400,
            source_attestation_hash="d" * 64,
            source_provider_did="did:web:dominionobservatory.com",
        ),
        ev2.Contribution(
            source="community_signal", raw_signal=0.60,
            weighted_contribution=0.06, freshness_ttl_seconds=86400,
        ),
    ]
    return ev2.build_envelope(
        subject_did="did:web:example-agent.com",
        subject_kind="agent",
        contributions=contribs,
        computed_at=now,
        freshness_ttl_seconds=3600,
    )


def _fixture_negative_feedback_floor(now):
    """#2 — ERC-8004 negative feedback dominates, score pushed toward floor."""
    contribs = [
        ev2.Contribution(
            source="erc8004_reputation", raw_signal=-0.80,
            weighted_contribution=-0.50, freshness_ttl_seconds=3600,
            source_attestation_hash="e" * 64,
        ),
        ev2.Contribution(
            source="scan_corpus", raw_signal=0.40,
            weighted_contribution=0.08, freshness_ttl_seconds=604800,
            source_attestation_hash="f" * 64,
        ),
        ev2.Contribution(
            source="community_signal", raw_signal=0.30,
            weighted_contribution=0.03, freshness_ttl_seconds=86400,
        ),
    ]
    return ev2.build_envelope(
        subject_did="did:web:provably-bad-agent.com",
        subject_kind="agent",
        contributions=contribs,
        computed_at=now,
        freshness_ttl_seconds=3600,
    )


def _fixture_contested_signal(now):
    """#3 — Two providers disagree by >0.30 on same (claim_type, ...) — flagged."""
    contribs = [
        ev2.Contribution(
            source="ctef_attestation", raw_signal=0.90,
            weighted_contribution=0.16, freshness_ttl_seconds=86400,
            source_attestation_hash="1" * 64, claim_type="continuity",
            evidence_type="behavioral",
            source_provider_did="did:web:nobulex.com",
        ),
        ev2.Contribution(
            source="ctef_attestation", raw_signal=0.45,
            weighted_contribution=0.06, freshness_ttl_seconds=86400,
            source_attestation_hash="2" * 64, claim_type="continuity",
            evidence_type="behavioral",
            source_provider_did="did:web:dominionobservatory.com",
            contested_signal=True,
        ),
        ev2.Contribution(
            source="scan_corpus", raw_signal=0.80,
            weighted_contribution=0.18, freshness_ttl_seconds=604800,
            source_attestation_hash="3" * 64,
        ),
    ]
    return ev2.build_envelope(
        subject_did="did:web:disputed-agent.com",
        subject_kind="agent",
        contributions=contribs,
        computed_at=now,
        freshness_ttl_seconds=3600,
    )


def _fixture_freshness_decay_edge(now):
    """#4 — Contribution past its TTL; envelope freshness reflects min(TTL)."""
    contribs = [
        ev2.Contribution(
            source="ctef_attestation", raw_signal=0.85,
            weighted_contribution=0.12, freshness_ttl_seconds=60,  # 1 min!
            source_attestation_hash="4" * 64, claim_type="identity",
            evidence_type="cryptographic",
            source_provider_did="did:web:erc8004.io",
        ),
        ev2.Contribution(
            source="scan_corpus", raw_signal=0.70,
            weighted_contribution=0.14, freshness_ttl_seconds=604800,
            source_attestation_hash="5" * 64,
        ),
    ]
    return ev2.build_envelope(
        subject_did="did:web:fresh-then-stale.com",
        subject_kind="agent",
        contributions=contribs,
        computed_at=now,
        freshness_ttl_seconds=60,  # mirrors min contribution TTL
    )


def _fixture_single_source_only(now):
    """#5 — Single source means diversity weight 0.7 (per §4)."""
    contribs = [
        ev2.Contribution(
            source="scan_corpus", raw_signal=0.95,
            weighted_contribution=0.14,  # = 0.20 raw * 0.7 diversity
            freshness_ttl_seconds=604800,
            source_attestation_hash="6" * 64,
            metadata={"malware_classification": "clean"},
        ),
    ]
    return ev2.build_envelope(
        subject_did="did:web:single-source-agent.com",
        subject_kind="service",
        contributions=contribs,
        computed_at=now,
        freshness_ttl_seconds=3600,
    )


ALL_FIXTURE_BUILDERS = [
    ("all_positive", _fixture_all_positive),
    ("negative_feedback_floor", _fixture_negative_feedback_floor),
    ("contested_signal", _fixture_contested_signal),
    ("freshness_decay_edge", _fixture_freshness_decay_edge),
    ("single_source_only", _fixture_single_source_only),
]


# ---------- Tests ----------


@pytest.mark.parametrize("name,builder", ALL_FIXTURE_BUILDERS)
def test_build_sign_verify_roundtrip(name, builder, keypair, fixed_time):
    """Every reference fixture survives build → sign → verify."""
    priv, pub = keypair
    unsigned = builder(fixed_time)
    signed = ev2.sign_envelope(unsigned, priv)
    assert ev2.verify_envelope(signed, pub) is True, f"{name} failed verify"


@pytest.mark.parametrize("name,builder", ALL_FIXTURE_BUILDERS)
def test_envelope_hash_deterministic(name, builder, fixed_time):
    """Same input always produces the same hash (JCS byte-stability)."""
    e1 = builder(fixed_time)
    e2 = builder(fixed_time)
    assert ev2.envelope_hash(e1) == ev2.envelope_hash(e2), (
        f"{name}: hash should be deterministic"
    )


def test_tamper_trust_score_detected(keypair, fixed_time):
    priv, pub = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    tampered = dict(signed)
    tampered["trust_score"] = 0.99
    assert ev2.verify_envelope(tampered, pub) is False


def test_tamper_contribution_detected(keypair, fixed_time):
    priv, pub = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    tampered = dict(signed)
    tampered["contributions"] = list(signed["contributions"])
    tampered["contributions"][0] = dict(tampered["contributions"][0])
    tampered["contributions"][0]["weighted_contribution"] = 0.99
    assert ev2.verify_envelope(tampered, pub) is False


def test_tamper_proof_jws_detected(keypair, fixed_time):
    priv, pub = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    tampered = dict(signed)
    tampered["proof"] = dict(signed["proof"])
    # flip a bit in the signature
    jws_parts = tampered["proof"]["jws"].split(".")
    tampered["proof"]["jws"] = f"{jws_parts[0]}..AAAAAAAA"
    assert ev2.verify_envelope(tampered, pub) is False


def test_wrong_pubkey_detected(keypair, fixed_time):
    priv, _ = keypair
    other_pub = Ed25519PrivateKey.generate().public_key()
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    assert ev2.verify_envelope(signed, other_pub) is False


def test_freshness_within_ttl(keypair, fixed_time):
    """Envelope is fresh immediately after issue."""
    priv, _ = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    # check_at = computed_at + 30 minutes; ttl = 3600s = 1 hour → fresh
    check_at = fixed_time + timedelta(minutes=30)
    assert ev2.is_fresh(signed, now=check_at) is True


def test_freshness_past_ttl(keypair, fixed_time):
    priv, _ = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    # check_at = computed_at + 2 hours; ttl = 1 hour → stale
    check_at = fixed_time + timedelta(hours=2)
    assert ev2.is_fresh(signed, now=check_at) is False


def test_negative_feedback_floor(fixed_time):
    """Score never goes below 0.0 after summation with -0.20 floor."""
    env = _fixture_negative_feedback_floor(fixed_time)
    # contributions sum to -0.50 + 0.08 + 0.03 = -0.39
    # floored at -0.20, then clamped to 0.0
    assert env["trust_score"] == 0.0


def test_all_positive_score_correct(fixed_time):
    """Score is the (clamped) sum of weighted contributions."""
    env = _fixture_all_positive(fixed_time)
    expected = 0.18 + 0.12 + 0.20 + 0.10 + 0.06  # 0.66
    assert env["trust_score"] == pytest.approx(expected)  # float sum; avoid exact-equality


def test_contested_signal_preserved(fixed_time):
    """contested_signal=True survives serialization."""
    env = _fixture_contested_signal(fixed_time)
    contested = [c for c in env["contributions"] if c.get("contested_signal")]
    assert len(contested) == 1, "expected exactly one contested contribution"


def test_canonicalization_strips_proof(keypair, fixed_time):
    """Canonical bytes do NOT include the proof block (spec §2)."""
    priv, _ = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    canon = ev2.canonicalize(signed)
    assert b'"proof"' not in canon, "proof block must be stripped before canonicalization"


def test_canonicalization_keys_sorted(fixed_time):
    """JCS sorts keys at every depth — verify top-level."""
    env = _fixture_all_positive(fixed_time)
    canon = ev2.canonicalize(env).decode()
    # canonicalization is "jcs-rfc8785-v1" comes BEFORE computed_at? alphabetical
    canon_idx = canon.find('"canonicalization"')
    computed_idx = canon.find('"computed_at"')
    assert 0 < canon_idx < computed_idx, "JCS should sort keys lexicographically"


def test_build_rejects_no_contributions():
    with pytest.raises(ev2.EnvelopeError, match="at least one"):
        ev2.build_envelope(
            subject_did="did:web:empty.com", subject_kind="agent",
            contributions=[],
        )


def test_build_rejects_invalid_subject_kind():
    with pytest.raises(ev2.EnvelopeError, match="invalid subject_kind"):
        ev2.build_envelope(
            subject_did="did:web:x.com", subject_kind="robot",  # not valid
            contributions=[_make_minimal_contrib()],
        )


def test_build_rejects_non_did_subject():
    with pytest.raises(ev2.EnvelopeError, match="must be a DID"):
        ev2.build_envelope(
            subject_did="https://example.com", subject_kind="agent",
            contributions=[_make_minimal_contrib()],
        )


def test_sign_rejects_already_signed(keypair, fixed_time):
    priv, _ = keypair
    signed = ev2.sign_envelope(_fixture_all_positive(fixed_time), priv)
    with pytest.raises(ev2.EnvelopeError, match="already has proof"):
        ev2.sign_envelope(signed, priv)


def _make_minimal_contrib():
    return ev2.Contribution(
        source="community_signal", raw_signal=0.5,
        weighted_contribution=0.05, freshness_ttl_seconds=3600,
    )
