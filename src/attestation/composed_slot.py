"""AgentGraph slot emitter for the composed-v1 interop envelope.

Published shape: ``agentgraph-scan-v1-structural``

Coordinated with:
  - haroldmalikfrimpong-ops/agentid-aps-interop#5 (three-signal composition)
  - a2aproject/A2A#1734 (CTEF envelope — outer composition_version)

Design notes:
  * This module emits the *published interop shape*. It does NOT expose
    the scoring formula. The mapping from (findings, positive_signals,
    category_scores) → overall_grade lives in ``src/scanner/scan.py``
    and is AgentGraph's proprietary composite methodology.
  * Score-to-letter is the public A-F rubric (same mapping shown on
    badges and /check pages). Publishing the letter-grade thresholds
    is fine; publishing the *weights* that produce the score is not.
  * The slot schema contract covers: ``subject_did``, ``issuer_did``,
    ``scan_target.url``, ``scan_target.artifact_ref``, ``scanned_at``,
    ``gates``, ``evidence_hash``. Consumers MAY treat ``overall_grade``
    as opaque.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# Schema version — bump when we add/rename/remove top-level fields.
SLOT_SCHEMA_VERSION = "agentgraph-scan-v1-structural"

# Issuer identity. Must stay stable — external verifiers pin to this DID.
ISSUER_DID = "did:web:agentgraph.co"
ISSUER_KEY_ID = "did:web:agentgraph.co#agentgraph-security-v1"

# Scanner identity. Version bumps signal a rubric change to consumers.
SCANNER_NAME = "agentgraph-trust-scanner"

# Canonicalization spec — must match APS + CTEF so chained verification works.
CANONICALIZATION_SPEC = "jcs-rfc8785+sha256"


# ---------------------------------------------------------------------------
# Letter-grade mapping — PUBLIC (already visible on badges and /check pages).
# Mirrors web/src/lib/gradeSystem.ts and src/api/badge_router.py.
# The WEIGHTS that produce the 0-100 score are NOT exposed by this module.
# ---------------------------------------------------------------------------

_GRADE_THRESHOLDS = (
    (96, "A+"),
    (81, "A"),
    (61, "B"),
    (41, "C"),
    (21, "D"),
    (0,  "F"),
)


def score_to_letter(score_0_to_100: int | float) -> str:
    """Map a 0-100 score to the public A+/A/B/C/D/F rubric.

    This mapping is public. The function that *produces* the 0-100 score
    from raw findings is private to src/scanner/scan.py.
    """
    s = max(0, min(100, int(round(float(score_0_to_100)))))
    for threshold, letter in _GRADE_THRESHOLDS:
        if s >= threshold:
            return letter
    return "F"  # unreachable; defensive


# ---------------------------------------------------------------------------
# Scan-target type resolver
# ---------------------------------------------------------------------------


def _resolve_scan_target_type(source_type: str | None, framework: str | None) -> str:
    """Map internal source_type/framework to the published target-type enum.

    Published enum (locked by the slot contract):
        "repo" | "package" | "mcp_server" | "api_endpoint"
    """
    if framework == "mcp":
        return "mcp_server"
    source = (source_type or "").lower()
    if source in {"github", "gitlab", "bitbucket"}:
        return "repo"
    if source in {"npm", "pypi", "cargo", "rubygems", "docker"}:
        return "package"
    if source in {"api", "endpoint", "http"}:
        return "api_endpoint"
    # Fallback — prefer "repo" since that's the most common source.
    return "repo"


# ---------------------------------------------------------------------------
# Gate rollups — map internal category scores to the published gate vocabulary
# ---------------------------------------------------------------------------

# Published gate names (locked by the slot contract). v1-structural exposes
# three; v2 will add identity_anchor, capability_manifest, runtime_attestation.
PUBLISHED_GATES_V1 = ("static_analysis", "secret_scan", "dependency_audit")


def _gate_static_analysis(
    category_scores: dict[str, int],
    findings: dict[str, int],
) -> dict[str, Any]:
    """Roll static-analysis category into the published gate shape.

    Exposes: grade (letter), score (0.0-1.0), issue_count.
    Does NOT expose: the internal rubric that produced the score.
    """
    raw = int(category_scores.get("code_quality", category_scores.get("static_analysis", 0)))
    return {
        "grade": score_to_letter(raw),
        "score": round(raw / 100.0, 4),
        "issue_count": int(findings.get("static_analysis", findings.get("high", 0))),
    }


def _gate_secret_scan(
    category_scores: dict[str, int],
    findings: dict[str, int],
) -> dict[str, Any]:
    """Roll secret-scan category into the published gate shape."""
    raw = int(category_scores.get("secrets", category_scores.get("secret_scan", 100)))
    return {
        "grade": score_to_letter(raw),
        "score": round(raw / 100.0, 4),
        "issue_count": int(findings.get("secrets", 0)),
    }


def _gate_dependency_audit(
    category_scores: dict[str, int],
    findings: dict[str, int],
) -> dict[str, Any]:
    """Roll dependency-audit category into the published gate shape.

    Only this gate surfaces critical/high counts because that's the
    meaningful dimension for dep CVEs.
    """
    raw = int(category_scores.get("dependencies", category_scores.get("dependency_audit", 100)))
    return {
        "grade": score_to_letter(raw),
        "score": round(raw / 100.0, 4),
        "critical": int(findings.get("dep_critical", findings.get("critical", 0))),
        "high": int(findings.get("dep_high", findings.get("high", 0))),
    }


# ---------------------------------------------------------------------------
# Evidence hash
# ---------------------------------------------------------------------------


def compute_evidence_hash(evidence_payload: dict[str, Any] | bytes) -> str:
    """Return ``sha256:<hex>`` over the canonical evidence payload.

    Callers pass either the already-canonicalized JCS bytes or a dict
    that will be canonicalized via src.signing.canonicalize. The returned
    hash is stable across serializations.
    """
    if isinstance(evidence_payload, (bytes, bytearray)):
        data = bytes(evidence_payload)
    else:
        # Lazy import to keep this module test-friendly without the
        # signing module side effects.
        from src.signing import canonicalize
        data = canonicalize(evidence_payload)
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Subject DID normalization
# ---------------------------------------------------------------------------


def normalize_subject_did(entity_id: str, existing_did: str | None = None) -> str:
    """Return the AgentGraph subject DID for a given entity.

    If an entity already has a DID (e.g., imported from did:web:foo.com),
    use that. Otherwise, derive one from the entity id.
    """
    if existing_did:
        return existing_did
    return f"did:web:agentgraph.co:entities:{entity_id}"


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanInputs:
    """Inputs required to render the slot.

    Deliberately narrow — the builder should NOT receive the raw scan
    engine output with its internal heuristics. It receives only what
    the slot needs to emit, keeping the internal rubric off the public path.
    """

    entity_id: str
    entity_did: str | None
    source_url: str
    source_type: str | None
    framework: str | None
    artifact_ref: str | None  # e.g., "git:sha256:<commit>" or "pkg:npm@1.2.3"
    scanned_at: datetime
    scanner_version: str
    trust_score_0_to_100: int
    category_scores: dict[str, int]
    findings: dict[str, int]
    evidence_hash: str  # pre-computed "sha256:<hex>"
    evidence_url: str
    # Phase 0 recompute discipline: the coverage{} block (surface, scan_depth,
    # db_snapshots, evidence_anchors, point_in_time). Optional + additive — when
    # absent the slot emits exactly as before, so older scans stay valid.
    coverage: dict[str, Any] | None = None


def build_agentgraph_slot(inputs: ScanInputs) -> dict[str, Any]:
    """Return the agentgraph-scan-v1-structural slot as a plain dict.

    The returned dict is JCS-canonicalization-ready (ordered keys,
    no None values). Callers that need a signed envelope should
    canonicalize + sign externally.
    """
    scanned_at = inputs.scanned_at
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=timezone.utc)

    slot: dict[str, Any] = {
        "version": SLOT_SCHEMA_VERSION,
        "subject_did": normalize_subject_did(inputs.entity_id, inputs.entity_did),
        "issuer_did": ISSUER_DID,
        "scan_target": {
            "url": inputs.source_url,
            "type": _resolve_scan_target_type(inputs.source_type, inputs.framework),
            "artifact_ref": inputs.artifact_ref or "",
            "fetched_at": scanned_at.isoformat().replace("+00:00", "Z"),
        },
        "scanner": {
            "name": SCANNER_NAME,
            "version": inputs.scanner_version,
        },
        "scanned_at": scanned_at.isoformat().replace("+00:00", "Z"),
        "gates": {
            "static_analysis": _gate_static_analysis(
                inputs.category_scores, inputs.findings,
            ),
            "secret_scan": _gate_secret_scan(
                inputs.category_scores, inputs.findings,
            ),
            "dependency_audit": _gate_dependency_audit(
                inputs.category_scores, inputs.findings,
            ),
        },
        # overall_grade is proprietary composite — consumers MAY treat as opaque.
        "overall_grade": score_to_letter(inputs.trust_score_0_to_100),
        "evidence_url": inputs.evidence_url,
        "evidence_hash": inputs.evidence_hash,
        "canonicalization_spec": CANONICALIZATION_SPEC,
    }
    # Phase 0: disclose surface + external-DB coverage so a consumer knows exactly
    # what the grade covers and can recompute it offline "as-of DB@<date>" (§4.4).
    if inputs.coverage:
        slot["coverage"] = inputs.coverage
    return slot


# ---------------------------------------------------------------------------
# Signing helper (v2-signed preview — not active in v1-structural emission)
# ---------------------------------------------------------------------------


def sign_slot_v2(slot: dict[str, Any]) -> dict[str, Any]:
    """Produce the v2-signed variant of a slot.

    Not used in v1-structural emission, but tested here so the shape
    stays honest when v2 activates across all three slots in lockstep.
    """
    from src.signing import canonicalize, create_jws

    # Signed bytes = canonical slot with signature field removed.
    unsigned = {k: v for k, v in slot.items() if k != "signature"}
    canonical = canonicalize(unsigned)
    # Compact JWS — reuse existing signer. v2-slot field convention uses
    # detached signature, but for v2-structural we return the compact JWS
    # so consumers can verify without a separate canonical replay.
    jws = create_jws(canonical)
    signed = dict(slot)
    signed["version"] = slot["version"].replace("structural", "signed")
    signed["signature"] = jws
    signed["signer_key_id"] = ISSUER_KEY_ID
    return signed
