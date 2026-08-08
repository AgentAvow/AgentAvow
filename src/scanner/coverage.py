"""Phase 0 — recompute discipline: the signed-verdict ``coverage{}`` block.

The whole roadmap rests on *recomputability*: pin the exact bytes graded and the
dated snapshot of every external DB queried, so any verifier can re-derive the
identical grade offline "as-of DB@<date>". This module builds the ``coverage``
block (§4.4) and owns the evidence-anchor slot names wired into the attestation.

It is pure and side-effect free — callers hand it what they measured and it emits
an ordered, JCS-ready dict (no ``None`` values, so canonicalization is stable).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Evidence-anchor slot names. The static-analysis anchor already exists; SBOM +
# provenance are new *scaffolding* slots (Phase 0 wires the names + structure;
# Phase 2/3 populate them with a real Syft SBOM digest and Sigstore bundle refs).
# ---------------------------------------------------------------------------
EVIDENCE_ANCHOR_STATIC = "evidence-anchor-static-analysis-v0"
EVIDENCE_ANCHOR_SBOM = "evidence-anchor-sbom-cyclonedx-v0"
EVIDENCE_ANCHOR_PROVENANCE = "evidence-anchor-provenance-v0"

# scan_depth vocabulary (§4.4). Repo-only is all Phase 0/1 can claim; artifact /
# artifact+live / declared-only land with the sandboxed artifact worker (Phase 2+).
SCAN_DEPTH_REPO_ONLY = "repo-only"
SCAN_DEPTH_ARTIFACT = "artifact"
SCAN_DEPTH_ARTIFACT_LIVE = "artifact+live"
SCAN_DEPTH_DECLARED_ONLY = "declared-only"

# provenance_binding vocabulary (§2.C). We don't verify provenance yet (Phase 3),
# so a repo-only scan is "n/a" — deliberately NOT "absent" (which implies we
# looked and found none) and never treated as a signing-axis penalty.
PROV_BINDING_NA = "n/a"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_evidence_anchors(
    *,
    has_sbom: bool = False,
    has_provenance: bool = False,
) -> list[str]:
    """Return the ordered evidence-anchor slot list for a verdict.

    The static-analysis anchor is always present. SBOM/provenance anchors are
    appended only once those evidence artifacts actually exist — until then the
    slot *names* are reserved here (scaffolding) but not asserted, so a consumer
    never sees an anchor it can't resolve.
    """
    anchors = [EVIDENCE_ANCHOR_STATIC]
    if has_sbom:
        anchors.append(EVIDENCE_ANCHOR_SBOM)
    if has_provenance:
        anchors.append(EVIDENCE_ANCHOR_PROVENANCE)
    return anchors


def build_coverage(
    *,
    surface: str = "github",
    artifact_digest: str | None = None,
    repo_url: str | None = None,
    commit: str | None = None,
    scan_depth: str = SCAN_DEPTH_REPO_ONLY,
    db_snapshots: dict[str, str] | None = None,
    provenance_binding: str = PROV_BINDING_NA,
    live_observed: bool = False,
    point_in_time: str | None = None,
) -> dict[str, Any]:
    """Build the ``coverage{}`` block for a signed verdict (§4.4).

    ``artifact_digest`` is the exact-bytes recompute anchor. When we don't have a
    published-artifact digest yet (repo-only scans), we fall back to a
    ``repo@commit`` identifier so the verdict still names *what* it graded.

    ``db_snapshots`` pins the dated version of every external DB queried (OSV
    export date, Scorecard export, deps.dev fetch timestamp, …) so the CVE/
    supply-chain subscore stays offline-recomputable.
    """
    anchor = artifact_digest
    linked_repo: dict[str, str] | None = None
    if repo_url:
        linked_repo = {"url": repo_url}
        if commit:
            linked_repo["commit"] = commit
        # binding describes HOW the repo is bound to the artifact; "declared"
        # means we took the coordinate at face value (no provenance proof yet).
        linked_repo["binding"] = (
            "slsa-provenance" if provenance_binding == "verified" else "declared"
        )
    if not anchor:
        # Fall back to a stable repo+commit content identifier.
        if repo_url and commit:
            anchor = f"repo:{repo_url}@{commit}"
        elif repo_url:
            anchor = f"repo:{repo_url}"

    coverage: dict[str, Any] = {
        "surface": surface,
        "scan_depth": scan_depth,
        "provenance_binding": provenance_binding,
        "db_snapshots": dict(db_snapshots or {}),
        "live_observed": bool(live_observed),
        "point_in_time": point_in_time or _utc_now_iso(),
    }
    if anchor:
        coverage["artifact_digest"] = anchor
    if linked_repo:
        coverage["linked_repo"] = linked_repo
    return coverage
