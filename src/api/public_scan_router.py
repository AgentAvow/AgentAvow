"""Public scan API — trust-tiered security scanning for any GitHub repo.

No authentication required. Rate-limited by IP. Results cached 1 hour.
Designed for framework integrations (Claude Code, Cursor, OpenClaw, etc.)
to pre-check tools before execution.

Endpoints:
    GET /public/scan/{owner}/{repo}   — scan a repo, return trust tier + JWS
    GET /public/scan/{owner}/{repo}/badge — SVG badge for README embedding
    GET /public/scan/{owner}/{repo}/og-image — 1200x630 OG preview card
"""
from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.rate_limit import (
    rate_limit_history_reads,
    rate_limit_reads,
    rate_limit_scans,
)
from src.config import settings
from src.database import get_db
from src.signing import (
    KID,
    canonicalize,
    create_jws,
    get_trust_v2_kid,
    get_trust_v2_signing_key,
)
from src.trust.aggregate_sources import components_to_contributions
from src.trust.envelope_v2 import Contribution, EnvelopeError, build_envelope, sign_envelope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public/scan", tags=["public-scan"])


# ── Trust Tiers ─────────────────────────────────────────────────────────

TRUST_TIERS = [
    # (min_score, tier_name, requests_per_min, max_tokens, require_confirmation)
    (96, "verified",    -1,   -1,   False),  # -1 = unlimited
    (81, "trusted",     60,   8192, False),
    (51, "standard",    30,   4096, False),
    (31, "minimal",     15,   2048, True),
    (11, "restricted",  5,    1024, True),
    (0,  "blocked",     0,    0,    True),
]


def _compute_tier(score: int) -> dict:
    """Map a trust score (0-100) to a tier with recommended limits."""
    for min_score, name, rpm, tokens, confirm in TRUST_TIERS:
        if score >= min_score:
            return {
                "tier": name,
                "recommended_limits": {
                    "requests_per_minute": rpm if rpm >= 0 else None,
                    "max_tokens_per_call": tokens if tokens >= 0 else None,
                    "require_user_confirmation": confirm,
                },
            }
    return {
        "tier": "blocked",
        "recommended_limits": {
            "requests_per_minute": 0,
            "max_tokens_per_call": 0,
            "require_user_confirmation": True,
        },
    }


# ── Response Models ──────────────────────────────────────────────────────

class ScanFinding(BaseModel):
    """One individual finding surfaced in the public scan response (no raw snippet)."""

    category: str
    name: str
    severity: str  # critical | high | medium | low
    file_path: str
    line_number: int
    remediation: str = ""


class FindingsSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    total: int = 0
    categories: dict[str, int] = {}
    suppressed_lines: int = 0  # Lines with ag-scan:ignore — transparency
    items: list[ScanFinding] = []  # individual findings (capped, severity-sorted)


class RecommendedLimits(BaseModel):
    requests_per_minute: int | None = None
    max_tokens_per_call: int | None = None
    require_user_confirmation: bool = False


class ScanMetadata(BaseModel):
    files_scanned: int = 0
    # Coverage disclosure in PLAIN JSON (not just the signed attestation): the
    # total scannable files before the 200-file sample cap, and whether the
    # grade is only a sample of a large repo. Mirrors filesTotal/sampled in the JWS.
    files_total: int = 0
    sampled: bool = False
    primary_language: str = ""
    has_readme: bool = False
    has_license: bool = False
    has_tests: bool = False
    is_mcp_server: bool = False  # context-aware: expected tool patterns discounted


class ScoreTimelinePoint(BaseModel):
    recorded_at: str
    score: int


class FrameworkScanItem(BaseModel):
    framework: str
    scan_result: str
    scanned_at: str
    vulnerabilities_count: int


class ScanHistoryResponse(BaseModel):
    repo: str
    entity_id: str | None = None
    score_timeline: list[ScoreTimelinePoint] = []
    framework_scans: list[FrameworkScanItem] = []
    jws: str | None = None
    algorithm: str = "EdDSA"
    key_id: str = KID
    jwks_url: str = "https://agentgraph.co/.well-known/jwks.json"


class PublicScanResponse(BaseModel):
    repo: str
    trust_score: int  # Security scan score (0-100) — code-level analysis only
    security_score: int = 0  # Alias for trust_score (clearer naming)
    trust_tier: str
    recommended_limits: RecommendedLimits
    scan_result: str  # clean, warnings, critical, error
    findings: FindingsSummary
    positive_signals: list[str] = []
    grade: str = ""  # letter grade with the A+ certified gate applied (roadmap §7)
    certified: dict = {}  # A+ certified-tier eligibility {eligible, checks} (roadmap §7)
    coverage: dict = {}  # scan_depth / provenance_binding / db_snapshots (recompute discipline)
    provenance: dict = {}  # verified build-provenance summary (Phase 3), if any
    surface_detail: dict = {}  # per-surface detail (skill allowed_tools, MCP capabilities, …)
    category_scores: dict[str, int] = {}  # per-category 0-100 sub-scores
    metadata: ScanMetadata
    scanned_at: str
    cached: bool = False
    # #8 tool-definition pinning — signed into the JWS `scan` block
    tool_manifest_digest: str | None = None
    tool_digests: dict[str, str] = {}
    tool_drift: dict | None = None  # digest diff vs the previous scan (rug-pull signal)
    jws: str  # Signed attestation (EdDSA, RFC 7515)
    algorithm: str = "EdDSA"
    key_id: str = KID
    jwks_url: str = "https://agentgraph.co/.well-known/jwks.json"
    # Entity trust (full composite) — only available for imported entities
    entity_trust: dict | None = None
    # Signed Trust Score v2 envelope (design §5.2): full aggregate for an
    # imported entity (Case B), else a scan-only single-contribution envelope
    # (Case A). Verifiable against the JWKS in jwks_url.
    trust_envelope: dict | None = None
    score_note: str = (
        "trust_score is the security scan score (code analysis only). "
        "For full entity trust including identity and external signals, "
        "import this bot to AgentAvow or use the gateway: "
        "POST /api/v1/gateway/check"
    )
    # Proxy gateway hint
    gateway_info: dict = {
        "status": "available",
        "docs": "https://agentgraph.co/docs/trust-gateway",
        "description": "Trust-tiered rate limiting gateway for AI agent tool execution",
    }


# ── Helpers ──────────────────────────────────────────────────────────────

_CACHE_PREFIX = "public_scan:"
_CACHE_TTL = 3600  # 1 hour

# Stale copy retained far longer than the 1h fresh TTL, so graceful degradation
# can serve a last-known-good grade when GitHub's budget is too low to re-scan.
_STALE_CACHE_PREFIX = "public_scan_stale:"
_STALE_CACHE_TTL = 7 * 24 * 3600  # 7 days


async def _get_entity_trust(repo: str, db: AsyncSession) -> dict | None:
    """Look up full entity trust score for an imported repo.

    If repo matches an entity on AgentGraph (via source_url), return
    the composite trust score, grade, and profile URL. Otherwise None.
    """
    from src.models import Entity, TrustScore

    # Match by source_url containing the repo path
    entity = (await db.execute(
        select(Entity).where(
            Entity.is_active.is_(True),
            Entity.source_url.ilike(f"%github.com/{repo}%"),
        ).limit(1)
    )).scalar_one_or_none()

    if not entity:
        return {
            "imported": False,
            "import_url": f"https://agentgraph.co/bots/import?url=https://github.com/{repo}",
            "message": (
                "Import this bot to AgentAvow for a full trust profile "
                "with identity verification, external signals, and "
                "trust-tiered rate limits."
            ),
            "benefits": [
                "Full trust grade (A-F) combining identity + external + security",
                "Signed EdDSA attestation with entity DID",
                "Trust gateway enforcement (rate limits by tier)",
                "README badge linking to trust profile",
                "Discoverability in search, discover, and rankings",
            ],
        }

    # Entity exists — get trust score
    ts = (await db.execute(
        select(TrustScore).where(TrustScore.entity_id == entity.id)
    )).scalar_one_or_none()

    if not ts:
        return {"imported": True, "entity_id": str(entity.id), "score": None}

    score100 = round(ts.score * 100)
    grade = (
        "A+" if score100 >= 96 else "A" if score100 >= 81
        else "B" if score100 >= 61 else "C" if score100 >= 41
        else "D" if score100 >= 21 else "F"
    )

    return {
        "imported": True,
        "entity_id": str(entity.id),
        "composite_score": score100,
        "grade": grade,
        "profile_url": f"https://agentgraph.co/profile/{entity.id}",
        "trust_detail_url": f"https://agentgraph.co/trust/{entity.id}",
    }


async def _get_cached(owner: str, repo: str) -> dict | None:
    """Check Redis cache for a previous scan result."""
    from src import cache
    return await cache.get(f"{_CACHE_PREFIX}{owner}/{repo}")


async def _set_cached(owner: str, repo: str, data: dict) -> None:
    """Store scan result in Redis cache (fresh 1h copy + long-lived stale copy).

    The stale copy (7d) is what graceful degradation serves when GitHub's budget
    is too low to run a fresh scan — a last-known-good grade beats erroring.
    """
    from src import cache
    await cache.set(f"{_CACHE_PREFIX}{owner}/{repo}", data, ttl=_CACHE_TTL)
    await cache.set(f"{_STALE_CACHE_PREFIX}{owner}/{repo}", data, ttl=_STALE_CACHE_TTL)


async def _get_stale_cached(owner: str, repo: str) -> dict | None:
    """Read the long-lived stale scan copy (for graceful degradation)."""
    from src import cache
    return await cache.get(f"{_STALE_CACHE_PREFIX}{owner}/{repo}")


async def _cached_scan_response(
    owner: str, repo: str, cached: dict, db: AsyncSession,
) -> PublicScanResponse:
    """Build a PublicScanResponse from a cached/stale scan dict (re-signs fresh).

    Shared by the graceful-degradation path; the attestation is always minted
    fresh (it expires) even though the underlying scan evidence is cached.
    """
    full_name = f"{owner}/{repo}"
    payload = _build_scan_payload(full_name, cached)
    jws = create_jws(canonicalize(payload))
    entity_trust = await _get_entity_trust(full_name, db)
    trust_envelope = await _build_scan_envelope(owner, repo, cached, db)
    return PublicScanResponse(
        repo=full_name,
        trust_score=cached["trust_score"],
        security_score=cached["trust_score"],
        trust_tier=cached["trust_tier"],
        recommended_limits=RecommendedLimits(**cached["recommended_limits"]),
        scan_result=cached["scan_result"],
        certified=cached.get("certified") or {},
        findings=FindingsSummary(**cached["findings"]),
        positive_signals=cached.get("positive_signals", []),
        category_scores=cached.get("category_scores", {}),
        metadata=ScanMetadata(**cached["metadata"]),
        scanned_at=cached["scanned_at"],
        cached=True,
        jws=jws,
        tool_manifest_digest=cached.get("tool_manifest_digest"),
        tool_digests=cached.get("tool_digests", {}),
        entity_trust=entity_trust,
        trust_envelope=trust_envelope,
    )


async def _capture_community_scan(
    owner: str, repo: str, data: dict, db: AsyncSession, surface: str = "github",
) -> None:
    """Persist an on-demand scan so the browsable catalog grows beyond the static
    launch corpus. Upsert one row per (surface, owner, repo) — latest scan wins,
    scan_count++. `surface` defaults to github so existing repo callers are
    unchanged; npm/pypi/mcp/openclaw claims publish under their real surface."""
    from sqlalchemy import func as safunc
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from src.models import CommunityScan

    findings = data.get("findings") or {}
    meta = data.get("metadata") or {}
    lang = (meta.get("primary_language") or None)
    if lang:
        lang = lang[:120]
    # The gated letter grade (A+ only when certified) — stored so Browse is accurate.
    _score = data.get("trust_score")
    _grade = data.get("grade") or (
        _display_grade(_score, (data.get("certified") or {}).get("eligible"))
        if _score is not None else None
    )
    surface = (surface or "github").lower()
    if surface in ("npm", "pypi"):
        _full = f"{surface}:{repo}"
    elif surface == "mcp":
        _full = repo
    else:  # github / openclaw
        _full = f"{owner}/{repo}"
    values = dict(
        surface=surface,
        owner=owner,
        repo=repo,
        full_name=_full,
        trust_score=_score,
        grade=_grade,
        critical=findings.get("critical"),
        high=findings.get("high"),
        findings_count=findings.get("total"),
        primary_language=lang,
        scan_count=1,
    )
    stmt = pg_insert(CommunityScan).values(**values).on_conflict_do_update(
        constraint="uq_community_scan_target",
        set_=dict(
            trust_score=values["trust_score"],
            grade=values["grade"],
            critical=values["critical"],
            high=values["high"],
            findings_count=values["findings_count"],
            primary_language=lang,
            last_scanned_at=safunc.now(),
            scan_count=CommunityScan.scan_count + 1,
        ),
    )
    await db.execute(stmt)
    await db.commit()

    # Append a score-history point (Redis list, capped) so the timeline grows
    # over time — each fresh scan / daily re-scan adds a datapoint.
    if values["trust_score"] is not None:
        try:
            import json as _json
            import time as _time

            from src.redis_client import get_redis

            r = get_redis()
            key = f"scorehist:{owner}/{repo}"
            point = _json.dumps({"score": values["trust_score"], "at": int(_time.time())})
            await r.rpush(key, point)
            await r.ltrim(key, -60, -1)
        except Exception:
            pass


_SCAN_FRESHNESS_TTL = 604800  # 7 days — scan evidence freshness (design §3)


async def _build_scan_envelope(
    owner: str, repo: str, scan_data: dict, db: AsyncSession
) -> dict | None:
    """Build a signed Trust Score v2 envelope for a scanned repo (design §5.2).

    Case B — repo maps to a known entity: full aggregate from the entity's
    weighted v1 components (same shape as GET /aggregate/{did}).
    Case A — no entity: a scan-only envelope carrying a single scan_corpus
    contribution (score = the scan score), with a synthetic did:web subject
    identifying the GitHub repo. Returns None if no contribution is available.
    """
    from src.models import EntityType
    from src.trust.score import compute_trust_score

    full_name = f"{owner}/{repo}"
    entity = await _lookup_entity_by_repo(full_name, db)

    if entity is not None:
        ts = await compute_trust_score(db, entity.id)
        contributions = components_to_contributions(
            ts.components,
            is_human=(entity.type == EntityType.HUMAN),
            framework_modifier=getattr(entity, "framework_trust_modifier", None),
        )
        subject_did = entity.did_web
        subject_kind = "human" if entity.type == EntityType.HUMAN else "agent"
    else:
        score01 = max(0.0, min(1.0, scan_data["trust_score"] / 100.0))
        if score01 == 0:
            return None
        contributions = [
            Contribution(
                source="scan_corpus",
                raw_signal=round(score01, 4),
                weighted_contribution=round(score01, 4),
                freshness_ttl_seconds=_SCAN_FRESHNESS_TTL,
                metadata={
                    "scan_result": scan_data.get("scan_result"),
                    "findings": scan_data.get("findings", {}).get("total"),
                },
            )
        ]
        # Synthetic did:web subject identifying the repo (not a published DID
        # doc — just a stable content identifier for the scan-only envelope).
        subject_did = f"did:web:github.com:{owner}:{repo}"
        subject_kind = "service"

    if not contributions:
        return None
    try:
        unsigned = build_envelope(
            subject_did=subject_did,
            subject_kind=subject_kind,
            contributions=contributions,
            freshness_ttl_seconds=_SCAN_FRESHNESS_TTL,
        )
    except EnvelopeError:
        return None
    vm = f"did:web:agentgraph.co#{get_trust_v2_kid()}"
    return sign_envelope(unsigned, get_trust_v2_signing_key(), vm)


def _build_scan_payload(repo: str, result_data: dict, drift: dict | None = None) -> dict:
    """Build the JWS attestation payload for a public scan.

    Timestamps follow the insumer WG convention:
    - scannedAt: when the security analysis actually ran (evidence freshness)
    - issuedAt:  when this JWS attestation was minted (signature freshness)
    - expiresAt: when the attestation expires (24h TTL)
    Consumers can diff scannedAt vs issuedAt to assess evidence staleness.

    #8: the signed ``scan`` block pins ``toolManifestDigest`` + per-file
    ``toolDigests`` (canonical hashes of the tool/skill/MCP definitions). A
    consumer who saved a prior attestation can prove drift by diffing the digest
    — the tool definition changed after it was trusted (rug-pull), even if the
    code still scans clean. ``toolDrift`` records drift vs the previous scan.
    """
    now = datetime.now(timezone.utc)
    _meta = result_data["metadata"]
    scan_block = {
        "trustScore": result_data["trust_score"],
        "trustTier": result_data["trust_tier"],
        "result": result_data["scan_result"],
        "findings": result_data["findings"],
        "positiveSignals": result_data["positive_signals"],
        "filesScanned": _meta["files_scanned"],
        # Coverage disclosure: the 200-file sample cap means a large repo is only
        # partially scanned. filesTotal (= total_scannable_files) + sampled make
        # partial coverage explicit in the signed attestation, not just implied.
        "filesTotal": _meta.get("total_scannable_files", _meta["files_scanned"]),
        "sampled": bool(_meta.get("sampled", False)),
        "primaryLanguage": _meta["primary_language"],
        "categoryScores": result_data.get("category_scores", {}),
        "toolManifestDigest": result_data.get("tool_manifest_digest"),
        "toolDigests": result_data.get("tool_digests", {}),
    }
    # Phase 0/1: pin the recompute-discipline coverage block (surface,
    # scan_depth, db_snapshots, evidence_anchors) into the SIGNED payload so the
    # supply-chain subscore is offline-recomputable "as-of DB@<date>". Additive —
    # older cached scans without a coverage block simply omit it.
    _coverage = result_data.get("coverage") or {}
    if _coverage:
        scan_block["coverage"] = _coverage
    _supply_chain = result_data.get("supply_chain") or {}
    if _supply_chain:
        scan_block["supplyChain"] = _supply_chain
    payload = {
        "@context": "https://schema.agentgraph.co/attestation/security/v1",
        "type": "SecurityPostureAttestation",
        "issuer": {
            "id": "did:web:agentgraph.co",
            "name": "AgentAvow",
            "url": "https://agentgraph.co",
        },
        "subject": {
            "id": f"github:{repo}",
            "repo": repo,
        },
        "scannedAt": result_data.get("scanned_at", now.isoformat()),
        "issuedAt": now.isoformat(),
        "expiresAt": (now + timedelta(hours=24)).isoformat(),
        "scan": scan_block,
        "recommendedLimits": result_data["recommended_limits"],
    }
    if drift:
        payload["toolDrift"] = drift
    return payload


def _scan_result_to_dict(result: object) -> dict:
    """Convert a ScanResult dataclass to a cacheable dict."""
    # Determine scan result label
    if result.critical_count > 0:
        scan_result = "critical"
    elif result.high_count > 0:
        scan_result = "warnings"
    else:
        scan_result = "clean"

    # Category counts
    categories: dict[str, int] = {}
    for f in result.findings:
        categories[f.category] = categories.get(f.category, 0) + 1

    # Individual findings — severity-sorted, capped, NO raw snippet (avoid leaking any
    # matched secret value into the public API; file_path + line_number are public).
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finding_items = [
        {
            "category": f.category,
            "name": f.name,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "remediation": f.remediation or "",
        }
        for f in sorted(result.findings, key=lambda x: _sev_rank.get(x.severity, 5))
    ][:100]

    tier_info = _compute_tier(result.trust_score)

    # Coverage: total scannable files before the 200-file cap (falls back to
    # files_scanned until ScanResult grows the field). Surfaced in plain JSON as
    # both total_scannable_files (attestation payload) and files_total (public model).
    _total_scannable = getattr(result, "total_scannable_files", None)
    if _total_scannable is None:
        _total_scannable = result.files_scanned
    _sampled = bool(getattr(result, "sampled", False))

    _certified = getattr(result, "certified", {}) or {}
    return {
        "trust_score": result.trust_score,
        # Letter grade with the A+ certified gate applied (flag-gated; == score-only
        # grade when the gate is off). Stored so every consumer reads one grade.
        "grade": _display_grade(result.trust_score, _certified.get("eligible")),
        "trust_tier": tier_info["tier"],
        "recommended_limits": tier_info["recommended_limits"],
        "scan_result": scan_result,
        "findings": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "total": len(result.findings),
            "categories": categories,
            "suppressed_lines": result.suppressed_count,
            "items": finding_items,
        },
        "certified": _certified,
        "provenance": getattr(result, "provenance", {}) or {},
        # Per-surface detail (npm/pypi digest; MCP tool_count/capabilities; skill
        # allowed_tools/hooks) so a surface view can show what it actually graded.
        "surface_detail": getattr(result, "artifact_scan", {}) or {},
        "positive_signals": list(set(result.positive_signals)),
        "metadata": {
            "files_scanned": result.files_scanned,
            # total_scannable_files + sampled disclose partial coverage (200-file
            # cap OR a truncated large-monorepo tree). files_total mirrors
            # total_scannable_files under the name the public ScanMetadata exposes.
            "total_scannable_files": _total_scannable,
            "files_total": _total_scannable,
            "sampled": _sampled,
            "primary_language": result.primary_language,
            "has_readme": result.has_readme,
            "has_license": result.has_license,
            "has_tests": result.has_tests,
            "is_mcp_server": getattr(result, "is_mcp_server", False),
        },
        "category_scores": getattr(result, "category_scores", {}),
        "tool_digests": getattr(result, "tool_digests", {}) or {},
        "tool_manifest_digest": getattr(result, "tool_manifest_digest", None),
        # Phase 0/1: recompute-discipline coverage block (surface, scan_depth,
        # db_snapshots, evidence_anchors) + the OSV/deps.dev supply-chain summary.
        "coverage": getattr(result, "coverage", {}) or {},
        "supply_chain": getattr(result, "supply_chain", {}) or {},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _compute_tool_drift(old: dict | None, new: dict) -> dict | None:
    """#8 — diff pinned tool digests between the previous scan and this one.

    A changed digest means a tool/skill/manifest definition was altered after it was
    last attested — the rug-pull signal, even when the code still scans clean. Returns
    None when there's no prior scan or nothing changed.
    """
    if not old:
        return None
    old_digests = old.get("tool_digests") or {}
    new_digests = new.get("tool_digests") or {}
    if not old_digests and not new_digests:
        return None
    changed = sorted(
        p for p in old_digests.keys() & new_digests.keys()
        if old_digests[p] != new_digests[p]
    )
    added = sorted(new_digests.keys() - old_digests.keys())
    removed = sorted(old_digests.keys() - new_digests.keys())
    if not (changed or added or removed):
        return None
    return {
        "drift_detected": bool(changed or removed),  # added-only = new tool, not drift
        "changed": changed,
        "added": added,
        "removed": removed,
        "previous_manifest_digest": old.get("tool_manifest_digest"),
        "previous_scanned_at": old.get("scanned_at"),
    }


# ── Endpoints ────────────────────────────────────────────────────────────

# NOTE: the package + wallet routes MUST come before /{owner}/{repo} so the
# 2-segment catch-all doesn't shadow them.


def _package_response(full: str, data: dict, jws: str, cached: bool) -> PublicScanResponse:
    """Build a PublicScanResponse from a native-package scan dict (mirrors the
    repo path, minus entity_trust/envelope which are GitHub-repo concepts)."""
    return PublicScanResponse(
        repo=full,
        trust_score=data["trust_score"],
        security_score=data["trust_score"],
        trust_tier=data["trust_tier"],
        recommended_limits=RecommendedLimits(**data["recommended_limits"]),
        scan_result=data["scan_result"],
        findings=FindingsSummary(**data["findings"]),
        grade=data.get("grade") or _grade_from_score(data["trust_score"]),
        certified=data.get("certified") or {},
        coverage=data.get("coverage", {}),
        provenance=data.get("provenance", {}),
        surface_detail=data.get("surface_detail", {}),
        positive_signals=data.get("positive_signals", []),
        category_scores=data.get("category_scores", {}),
        metadata=ScanMetadata(**data["metadata"]),
        scanned_at=data["scanned_at"],
        cached=cached,
        jws=jws,
        tool_manifest_digest=data.get("tool_manifest_digest"),
        tool_digests=data.get("tool_digests", {}),
    )


@router.get(
    "/package/{surface}/{name:path}",
    response_model=PublicScanResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def scan_package_endpoint(
    surface: str,
    name: str,
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
    version: str | None = Query(None, description="Exact version; default = latest"),
    db: AsyncSession = Depends(get_db),
) -> PublicScanResponse:
    """Grade a PUBLISHED **npm** or **PyPI** package directly by coordinate — no
    GitHub repo required. The signed A+..F grade is computed over the real artifact
    bytes (``scan_depth = artifact``) with the package's own build provenance
    verified. E.g. ``/public/scan/package/npm/chalk`` or
    ``/public/scan/package/pypi/requests?version=2.32.5``. Cached 1h."""
    surface = (surface or "").strip().lower()
    if surface == "python":
        surface = "pypi"
    elif surface in ("crate", "cargo", "rust"):
        surface = "crates"
    if surface not in ("npm", "pypi", "crates"):
        raise HTTPException(404, "surface must be 'npm', 'pypi', or 'crates'")
    name = (name or "").strip().strip("/")
    if not name or len(name) > 214 or any(c in name for c in ("..", " ", "\t")):
        raise HTTPException(400, "Invalid package name")

    full = f"{surface}:{name}" + (f"@{version}" if version else "")
    cache_owner = surface
    cache_repo = f"{name}@{version}" if version else name

    if not force:
        cached = await _get_cached(cache_owner, cache_repo)
        if cached:
            jws = create_jws(canonicalize(_build_scan_payload(full, cached)))
            return _package_response(full, cached, jws, cached=True)

    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)

    from src.scanner.scan import scan_package

    try:
        result = await asyncio.wait_for(scan_package(surface, name, version), timeout=90)
    except asyncio.TimeoutError:
        raise HTTPException(
            503, "Scan is taking longer than expected — please retry shortly.",
            headers={"Retry-After": "30"},
        )
    if result.error:
        low = result.error.lower()
        code = 404 if ("not found" in low or "version not found" in low) else 502
        raise HTTPException(code, f"Scan error: {result.error}")

    data = _scan_result_to_dict(result)
    await _set_cached(cache_owner, cache_repo, data)
    jws = create_jws(canonicalize(_build_scan_payload(full, data)))
    return _package_response(full, data, jws, cached=False)


@router.get(
    "/skill/{owner}/{repo}",
    response_model=PublicScanResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def scan_skill_endpoint(
    owner: str,
    repo: str,
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
    db: AsyncSession = Depends(get_db),
) -> PublicScanResponse:
    """Grade an **OpenClaw / Agent Skill** in a GitHub repo — the capability surface
    a repo scan misses: the auto-exec `allowed-tools` grant, always-loaded-
    description injection, lifecycle-hook escalation, and env-exfil in bundled
    scripts. `coverage.surface = openclaw`. E.g. `/public/scan/skill/owner/repo`."""
    if not all(c.isalnum() or c in "-_." for c in owner):
        raise HTTPException(400, "Invalid owner")
    if not repo.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "Invalid repo name")
    full = f"skill:{owner}/{repo}"

    if not force:
        cached = await _get_cached("skill", f"{owner}/{repo}")
        if cached:
            jws = create_jws(canonicalize(_build_scan_payload(full, cached)))
            return _package_response(full, cached, jws, cached=True)

    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)

    from src.scanner.scan import scan_skill

    try:
        result = await asyncio.wait_for(scan_skill(owner, repo), timeout=60)
    except asyncio.TimeoutError:
        raise HTTPException(
            503, "Scan is taking longer than expected — please retry shortly.",
            headers={"Retry-After": "30"},
        )
    if result.error:
        low = result.error.lower()
        code = 404 if ("not found" in low or "no skill.md" in low) else 502
        raise HTTPException(code, f"Scan error: {result.error}")

    data = _scan_result_to_dict(result)
    await _set_cached("skill", f"{owner}/{repo}", data)
    jws = create_jws(canonicalize(_build_scan_payload(full, data)))
    return _package_response(full, data, jws, cached=False)


@router.get(
    "/mcp",
    response_model=PublicScanResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def scan_mcp_endpoint(
    endpoint: str = Query(..., description="The MCP server's Streamable-HTTP URL"),
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
    db: AsyncSession = Depends(get_db),
) -> PublicScanResponse:
    """Grade a LIVE **MCP server** by its endpoint URL — enumerates the served
    `tools/list` and scores the capability surface (tool-poisoning, schema risk,
    dangerous-capability taxonomy + lethal trifecta, annotation truthfulness).
    `coverage.surface = mcp`, live-observed (point-in-time). Streamable-HTTP only.
    E.g. `/public/scan/mcp?endpoint=https://mcp.example.com/mcp`."""
    import hashlib

    from src.ssrf import validate_url_https

    try:
        url = validate_url_https(endpoint, field_name="endpoint")
    except Exception:
        raise HTTPException(400, "endpoint must be a valid https:// URL")
    full = f"mcp:{url}"
    key = "mcp_" + hashlib.sha256(url.encode()).hexdigest()[:22]

    if not force:
        cached = await _get_cached("mcp", key)
        if cached:
            jws = create_jws(canonicalize(_build_scan_payload(full, cached)))
            return _package_response(full, cached, jws, cached=True)

    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit
        await enforce_fresh_scan_limit(request)

    from src.scanner.scan import scan_mcp

    try:
        result = await asyncio.wait_for(scan_mcp(url), timeout=45)
    except asyncio.TimeoutError:
        raise HTTPException(
            503, "MCP handshake timed out — please retry shortly.",
            headers={"Retry-After": "20"},
        )
    if result.error:
        # An unreachable / non-Streamable-HTTP endpoint is a bad USER input, not a
        # server fault — return 422 (client error) so it doesn't page us as a 5xx.
        raise HTTPException(422, f"Scan error: {result.error}")

    data = _scan_result_to_dict(result)
    await _set_cached("mcp", key, data)
    jws = create_jws(canonicalize(_build_scan_payload(full, data)))
    return _package_response(full, data, jws, cached=False)


@router.get(
    "/wallet/{wallet_address}",
    dependencies=[Depends(rate_limit_reads)],
    response_model=None,
)
async def scan_by_wallet(
    wallet_address: str,
    chain: str = "ethereum",
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Resolve a wallet address to an entity and return its trust data.

    Part of the insumer multi-attestation WG unified query interface.
    Each issuer accepts ``?wallet=&chain=`` for cross-provider lookup.

    If no entity maps to the wallet, returns ``found: false``.
    If the entity has a linked GitHub repo, triggers a scan.
    """
    from src.models import LinkedAccount, WalletBinding

    stmt = select(WalletBinding).where(
        WalletBinding.wallet_address == wallet_address,
        WalletBinding.chain == chain,
    )
    result = await db.execute(stmt)
    binding = result.scalar_one_or_none()

    if not binding:
        return {
            "found": False,
            "wallet": wallet_address,
            "chain": chain,
            "reason": "no_entity_mapping",
        }

    # Find linked GitHub account for this entity
    stmt = select(LinkedAccount).where(
        LinkedAccount.entity_id == binding.entity_id,
        LinkedAccount.provider == "github",
    )
    result = await db.execute(stmt)
    github_account = result.scalar_one_or_none()

    if not github_account or not github_account.provider_username:
        return {
            "found": True,
            "wallet": wallet_address,
            "chain": chain,
            "entity_id": str(binding.entity_id),
            "scan": None,
            "reason": "no_linked_github_repo",
        }

    # Resolve to repo and scan
    # provider_user_id typically contains "owner/repo" for GitHub
    repo_id = github_account.provider_user_id
    if "/" not in repo_id:
        return {
            "found": True,
            "wallet": wallet_address,
            "chain": chain,
            "entity_id": str(binding.entity_id),
            "scan": None,
            "reason": "github_account_not_repo",
        }
    owner, repo = repo_id.split("/", 1)

    # Delegate to the main scan endpoint
    scan_result = await public_scan(owner=owner, repo=repo, db=db)
    return {
        "found": True,
        "wallet": wallet_address,
        "chain": chain,
        "entity_id": str(binding.entity_id),
        "scan": scan_result.dict(),
    }


@router.get(
    "/{owner}/{repo}",
    response_model=PublicScanResponse,
    dependencies=[Depends(rate_limit_reads), Depends(rate_limit_scans)],
)
async def public_scan(
    owner: str,
    repo: str,
    request: Request = None,
    force: bool = Query(False, description="Bypass cache and force a fresh scan"),
    db: AsyncSession = Depends(get_db),
) -> PublicScanResponse:
    """Scan a GitHub repo and return trust tier with recommended rate limits.

    No authentication required. Results are cached for 1 hour.
    Returns a signed JWS attestation (EdDSA, RFC 7515) verifiable
    against the public JWKS at ``/.well-known/jwks.json``.

    **Trust Tiers:**
    - ``verified`` (96-100): unlimited execution
    - ``trusted`` (81-95): 60 req/min, 8K tokens
    - ``standard`` (51-80): 30 req/min, 4K tokens
    - ``minimal`` (31-50): 15 req/min, 2K tokens, user confirmation
    - ``restricted`` (11-30): 5 req/min, 1K tokens, user confirmation
    - ``blocked`` (0-10): execution denied
    """
    full_name = f"{owner}/{repo}"

    # Validate inputs
    if not owner.isalnum() and not all(c.isalnum() or c in "-_." for c in owner):
        raise HTTPException(400, "Invalid owner")
    if not repo.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "Invalid repo name")

    # Check cache
    if not force:
        cached = await _get_cached(owner, repo)
        if cached:
            # Re-sign (attestation expires, so sign fresh)
            payload = _build_scan_payload(full_name, cached)
            payload_bytes = canonicalize(payload)
            jws = create_jws(payload_bytes)

            # Look up entity trust (full composite) if this repo is imported
            entity_trust = await _get_entity_trust(full_name, db)
            trust_envelope = await _build_scan_envelope(owner, repo, cached, db)

            return PublicScanResponse(
                repo=full_name,
                trust_score=cached["trust_score"],
                security_score=cached["trust_score"],
                trust_tier=cached["trust_tier"],
                recommended_limits=RecommendedLimits(**cached["recommended_limits"]),
                scan_result=cached["scan_result"],
                findings=FindingsSummary(**cached["findings"]),
                positive_signals=cached.get("positive_signals", []),
                grade=cached.get("grade") or _grade_from_score(cached["trust_score"]),
                certified=cached.get("certified", {}),
                coverage=cached.get("coverage", {}),
                provenance=cached.get("provenance", {}),
                category_scores=cached.get("category_scores", {}),
                metadata=ScanMetadata(**cached["metadata"]),
                scanned_at=cached["scanned_at"],
                cached=True,
                jws=jws,
                tool_manifest_digest=cached.get("tool_manifest_digest"),
                tool_digests=cached.get("tool_digests", {}),
                entity_trust=entity_trust,
                trust_envelope=trust_envelope,
            )

    # Fetch previous cached score before running a fresh scan (for change detection)
    old_cached = await _get_cached(owner, repo)
    old_score: int | None = old_cached["trust_score"] if old_cached else None

    # --- Graceful degradation when GitHub's budget is low --------------------
    # The real-time inspector (scan path) or the periodic probe sets a Redis flag
    # when GitHub's remaining core budget drops below the floor. Rather than
    # spend the last of the budget on a fresh scan, serve stale cache if we have
    # ANY (even past the 1h TTL), else tell the caller to retry shortly. This is
    # a cheap flag read on the hot path (fails open if Redis is down).
    from src.jobs.scan_health import is_github_budget_low

    if await is_github_budget_low():
        stale = old_cached or await _get_stale_cached(owner, repo)
        if stale:
            logger.info(
                "GitHub budget low — serving stale cache for %s (deferred fresh scan)",
                full_name,
            )
            return await _cached_scan_response(owner, repo, stale, db)
        logger.warning(
            "GitHub budget low — deferring fresh scan for %s (no stale cache)",
            full_name,
        )
        raise HTTPException(
            503,
            "AgentAvow is temporarily rate-limited by GitHub — please try again shortly.",
            headers={"Retry-After": "120"},
        )

    # --- Self-imposed fresh-scan rate limit (per-IP + global) ----------------
    # Only reached on a cache-miss / force=true scan, so cached (1h) hits never
    # consume it. Protects the shared GitHub budget from user traffic. Skipped
    # for internal callers (no request — the watch/badge/wallet paths call
    # public_scan() directly and have their own caps).
    if request is not None:
        from src.api.rate_limit import enforce_fresh_scan_limit

        await enforce_fresh_scan_limit(request)

    # Run scan
    from src.github_auth import get_github_token
    from src.scanner.scan import scan_repo

    token = await get_github_token()
    try:
        # Cap the synchronous scan so a large repo can't hold a uvicorn worker
        # until nginx cuts the upstream (→ 502). On timeout we degrade
        # gracefully below instead of hanging the worker.
        result = await asyncio.wait_for(
            scan_repo(
                full_name=full_name,
                stars=0,
                description="",
                framework="",
                token=token,
            ),
            timeout=90,
        )
    except asyncio.TimeoutError:
        logger.warning("Public scan timed out for %s after 90s", full_name)
        # Prefer serving a stale cached result over failing the request.
        stale = await _get_cached(owner, repo)
        if stale:
            payload = _build_scan_payload(full_name, stale)
            jws = create_jws(canonicalize(payload))
            entity_trust = await _get_entity_trust(full_name, db)
            trust_envelope = await _build_scan_envelope(owner, repo, stale, db)
            return PublicScanResponse(
                repo=full_name,
                trust_score=stale["trust_score"],
                security_score=stale["trust_score"],
                trust_tier=stale["trust_tier"],
                recommended_limits=RecommendedLimits(**stale["recommended_limits"]),
                scan_result=stale["scan_result"],
                findings=FindingsSummary(**stale["findings"]),
                positive_signals=stale.get("positive_signals", []),
                grade=stale.get("grade") or _grade_from_score(stale["trust_score"]),
                certified=stale.get("certified", {}),
                coverage=stale.get("coverage", {}),
                provenance=stale.get("provenance", {}),
                category_scores=stale.get("category_scores", {}),
                metadata=ScanMetadata(**stale["metadata"]),
                scanned_at=stale["scanned_at"],
                cached=True,
                jws=jws,
                tool_manifest_digest=stale.get("tool_manifest_digest"),
                tool_digests=stale.get("tool_digests", {}),
                entity_trust=entity_trust,
                trust_envelope=trust_envelope,
            )
        # No cache to fall back on — tell the caller to retry, don't hang or 502.
        raise HTTPException(
            503,
            "Scan is taking longer than expected — please retry shortly.",
            headers={"Retry-After": "30"},
        )
    except httpx.HTTPError as exc:
        # A genuine GitHub/upstream network failure — 502 is accurate here.
        logger.warning("GitHub upstream error scanning %s: %s", full_name, exc)
        raise HTTPException(502, "Scan failed — GitHub API may be unavailable")
    except Exception:
        # An internal bug, not an upstream outage — don't mislabel it a 502.
        logger.exception("Public scan internal error for %s", full_name)
        raise HTTPException(500, "Internal error while scanning repository")

    if result.error:
        raise HTTPException(
            404 if "not found" in (result.error or "").lower() else 502,
            f"Scan error: {result.error}",
        )

    # Convert to dict and cache
    data = _scan_result_to_dict(result)
    await _set_cached(owner, repo, data)

    # Persist to the community catalog so on-demand scans grow the browsable
    # dataset (best-effort — never let this break a scan response).
    try:
        await _capture_community_scan(owner, repo, data, db)
    except Exception:
        logger.debug("community scan capture failed for %s", full_name, exc_info=True)

    # Notify outbound webhooks if score changed (fire-and-forget)
    new_score = data["trust_score"]
    if new_score != old_score:
        try:
            from src.trust.outbound_webhooks import notify_scan_change

            asyncio.create_task(notify_scan_change(full_name, new_score, old_score))
        except Exception:
            logger.debug("Failed to dispatch scan-change webhook for %s", full_name)

    # #8 — detect tool-definition drift vs the previous scan (rug-pull signal)
    drift = _compute_tool_drift(old_cached, data)

    # Sign (JCS-canonical payload for cross-implementation verification)
    payload = _build_scan_payload(full_name, data, drift)
    payload_bytes = canonicalize(payload)
    jws = create_jws(payload_bytes)

    # Look up entity trust (full composite) if this repo is imported
    entity_trust = await _get_entity_trust(full_name, db)
    trust_envelope = await _build_scan_envelope(owner, repo, data, db)

    return PublicScanResponse(
        repo=full_name,
        trust_score=data["trust_score"],
        security_score=data["trust_score"],
        trust_tier=data["trust_tier"],
        recommended_limits=RecommendedLimits(**data["recommended_limits"]),
        scan_result=data["scan_result"],
        findings=FindingsSummary(**data["findings"]),
        grade=data.get("grade") or _grade_from_score(data["trust_score"]),
        certified=data.get("certified") or {},
        coverage=data.get("coverage", {}),
        provenance=data.get("provenance", {}),
        positive_signals=data["positive_signals"],
        category_scores=data.get("category_scores", {}),
        metadata=ScanMetadata(**data["metadata"]),
        scanned_at=data["scanned_at"],
        cached=False,
        jws=jws,
        tool_manifest_digest=data.get("tool_manifest_digest"),
        tool_digests=data.get("tool_digests", {}),
        tool_drift=drift,
        entity_trust=entity_trust,
        trust_envelope=trust_envelope,
    )


_HISTORY_CACHE_PREFIX = "public_scan_history:"
_HISTORY_CACHE_TTL = 3600  # 1 hour


async def _lookup_entity_by_repo(repo: str, db: AsyncSession):
    """Resolve an `owner/repo` slug to an Entity row, or None."""
    from src.models import Entity

    return (
        await db.execute(
            select(Entity).where(
                Entity.is_active.is_(True),
                Entity.source_url.ilike(f"%github.com/{repo}%"),
            ).limit(1)
        )
    ).scalar_one_or_none()


@router.get(
    "/{owner}/{repo}/history",
    response_model=ScanHistoryResponse,
    dependencies=[Depends(rate_limit_history_reads)],
)
async def public_scan_history(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> ScanHistoryResponse:
    """Return the score timeline + per-framework scan history for a repo.

    Living-record proof: AgentGraph publishes the trail of every score
    change and every framework-level scan, not a one-shot PDF. If the
    repo is not yet imported as an AgentGraph entity, returns an empty
    payload (HTTP 200) — the page will show a "first scan" empty state.
    """
    full_name = f"{owner}/{repo}"

    if not all(c.isalnum() or c in "-_." for c in owner):
        raise HTTPException(400, "Invalid owner")
    if not repo.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "Invalid repo name")

    from src import cache

    cache_key = f"{_HISTORY_CACHE_PREFIX}{full_name}"
    cached = await cache.get(cache_key)
    if cached:
        payload = dict(cached)
        payload_for_jws = {
            "@context": "https://schema.agentgraph.co/attestation/scan-history/v1",
            "type": "ScanHistoryAttestation",
            "subject": {"id": f"github:{full_name}", "repo": full_name},
            "issuedAt": datetime.now(timezone.utc).isoformat(),
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "history": {
                "entityId": payload.get("entity_id"),
                "scoreTimeline": payload.get("score_timeline", []),
                "frameworkScans": payload.get("framework_scans", []),
            },
        }
        jws = create_jws(canonicalize(payload_for_jws))
        return ScanHistoryResponse(
            repo=full_name,
            entity_id=payload.get("entity_id"),
            score_timeline=[ScoreTimelinePoint(**p) for p in payload.get("score_timeline", [])],
            framework_scans=[FrameworkScanItem(**f) for f in payload.get("framework_scans", [])],
            jws=jws,
        )

    entity = await _lookup_entity_by_repo(full_name, db)
    if entity is None:
        empty_payload = {"entity_id": None, "score_timeline": [], "framework_scans": []}
        await cache.set(cache_key, empty_payload, ttl=_HISTORY_CACHE_TTL)
        empty_for_jws = {
            "@context": "https://schema.agentgraph.co/attestation/scan-history/v1",
            "type": "ScanHistoryAttestation",
            "subject": {"id": f"github:{full_name}", "repo": full_name},
            "issuedAt": datetime.now(timezone.utc).isoformat(),
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "history": {
                "entityId": None,
                "scoreTimeline": [],
                "frameworkScans": [],
            },
        }
        jws = create_jws(canonicalize(empty_for_jws))
        return ScanHistoryResponse(repo=full_name, entity_id=None, jws=jws)

    from src.models import FrameworkSecurityScan, TrustScoreHistory

    score_rows = (
        await db.execute(
            select(TrustScoreHistory)
            .where(TrustScoreHistory.entity_id == entity.id)
            .order_by(TrustScoreHistory.recorded_at.asc())
        )
    ).scalars().all()

    scan_rows = (
        await db.execute(
            select(FrameworkSecurityScan)
            .where(FrameworkSecurityScan.entity_id == entity.id)
            .order_by(FrameworkSecurityScan.scanned_at.asc())
        )
    ).scalars().all()

    score_timeline = [
        {
            "recorded_at": row.recorded_at.isoformat() if row.recorded_at else "",
            "score": round((row.score or 0.0) * 100) if (row.score or 0.0) <= 1 else int(row.score),
        }
        for row in score_rows
    ]
    framework_scans = [
        {
            "framework": row.framework,
            "scan_result": row.scan_result,
            "scanned_at": row.scanned_at.isoformat() if row.scanned_at else "",
            "vulnerabilities_count": (
                len(row.vulnerabilities) if isinstance(row.vulnerabilities, list) else 0
            ),
        }
        for row in scan_rows
    ]

    payload = {
        "entity_id": str(entity.id),
        "score_timeline": score_timeline,
        "framework_scans": framework_scans,
    }
    await cache.set(cache_key, payload, ttl=_HISTORY_CACHE_TTL)

    payload_for_jws = {
        "@context": "https://schema.agentgraph.co/attestation/scan-history/v1",
        "type": "ScanHistoryAttestation",
        "subject": {"id": f"github:{full_name}", "repo": full_name},
        "issuedAt": datetime.now(timezone.utc).isoformat(),
        "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "history": {
            "entityId": payload["entity_id"],
            "scoreTimeline": score_timeline,
            "frameworkScans": framework_scans,
        },
    }
    jws = create_jws(canonicalize(payload_for_jws))

    return ScanHistoryResponse(
        repo=full_name,
        entity_id=payload["entity_id"],
        score_timeline=[ScoreTimelinePoint(**p) for p in score_timeline],
        framework_scans=[FrameworkScanItem(**f) for f in framework_scans],
        jws=jws,
    )


def _grade_from_score(score: int) -> str:
    """Return letter grade from a 0-100 score."""
    if score >= 96:
        return "A+"
    if score >= 81:
        return "A"
    if score >= 61:
        return "B"
    if score >= 41:
        return "C"
    if score >= 21:
        return "D"
    return "F"


def _display_grade(score: int, certified_eligible: bool | None) -> str:
    """The LETTER grade, with the A+ 'Certified' gate applied (roadmap §7).

    A+ is not "a high score" — it's a distinct, earned certification (artifact-
    scanned + verified provenance + no drift + zero crit/high + recompute-clean).
    So when the gate is enabled:
      - a certified scan in the A band (score >= 81) earns **A+**;
      - a NON-certified scan, however clean (score >= 96), is capped at **A** —
        a repo-only scan can never be A+.
    This adjusts only the LABEL, never the 0-100 score or the trust tier. With the
    flag OFF (default), this is exactly ``_grade_from_score`` — no behavior change.
    """
    if not getattr(settings, "scanner_certified_grade_gate", False):
        return _grade_from_score(score)
    if certified_eligible and score >= 81:
        return "A+"
    base = _grade_from_score(score)
    return "A" if base == "A+" else base  # 96+ but uncertified → A, not A+


def _grade_color(grade: str) -> str:
    """Return badge color for a letter grade."""
    return {
        "A+": "#14B8A6",
        "A": "#2DD4BF",
        "B": "#22C55E",
        "C": "#F59E0B",
        "D": "#F97316",
        "F": "#EF4444",
    }.get(grade, "#6b7280")


@router.get(
    "/{owner}/{repo}/badge",
    dependencies=[Depends(rate_limit_reads)],
    response_class=Response,
)
async def scan_badge(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Return an SVG trust-tier badge for README embedding.

    Shows the composite trust score when the repo has been imported to
    AgentGraph (label: "Trust: A 92"). Falls back to the security scan
    score otherwise (label: "Scan: B 74").

    Usage in markdown:
    ```
    ![Trust Score](https://agentgraph.co/api/v1/public/scan/owner/repo/badge)
    ```
    """
    full_name = f"{owner}/{repo}"

    # Check if this repo is imported as an AgentGraph entity
    entity_trust = await _get_entity_trust(full_name, db)

    # Determine which score to show: composite trust vs security scan
    if (
        entity_trust
        and entity_trust.get("imported")
        and entity_trust.get("composite_score") is not None
    ):
        # Entity exists on AgentGraph — show composite trust score
        score = entity_trust["composite_score"]
        grade = entity_trust["grade"]
        score_type = "Trust"
    else:
        # No entity — fall back to security scan score
        cached = await _get_cached(owner, repo)
        if cached:
            score = cached["trust_score"]
            _elig = (cached.get("certified") or {}).get("eligible")
            grade = cached.get("grade") or _display_grade(score, _elig)
            score_type = "Scan"
        else:
            # Cache miss: regenerate on demand rather than decaying to a grey
            # "not scanned" pill. A README badge is hit long after the 1h cache
            # expires; without this it silently breaks in strangers' READMEs
            # (codecov/shields regenerate on every request). Reuse the tested
            # scan path, which also repopulates the cache for subsequent hits.
            try:
                fresh = await public_scan(owner=owner, repo=repo, force=False, db=db)
                score = fresh.security_score
                grade = fresh.grade or _grade_from_score(score)
                score_type = "Scan"
            except Exception:
                logger.warning("badge regenerate failed for %s/%s", owner, repo, exc_info=True)
                score = None
                grade = None
                score_type = None

    # Build badge
    if score is not None:
        color = _grade_color(grade)
        label = f"{score_type}: {grade} {score}"
    else:
        color = "#6b7280"
        label = "not scanned"

    label_width = len(label) * 7 + 10
    total_width = 80 + label_width

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <rect width="80" height="20" fill="#555" rx="3"/>
  <rect x="80" width="{label_width}" height="20" fill="{color}" rx="3"/>
  <rect x="80" width="4" height="20" fill="{color}"/>
  <text x="40" y="14" fill="#fff" font-family="Verdana,sans-serif" font-size="11"
        text-anchor="middle">{settings.badge_brand}</text>
  <text x="{80 + label_width // 2}" y="14" fill="#fff" font-family="Verdana,sans-serif"
        font-size="11" text-anchor="middle">{label}</text>
</svg>'''

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=3600, s-maxage=86400",
            "Access-Control-Allow-Origin": "*",
        },
    )


async def _github_stars(owner: str, repo: str) -> int | None:
    """Public star count for a repo (no claim needed). Cached 24h in Redis."""
    from src.redis_client import get_redis

    key = f"stars:{owner}/{repo}"
    try:
        r = get_redis()
        cached = await r.get(key)
        if cached is not None:
            return int(cached)
    except Exception:
        r = None
    try:
        import httpx

        from src.github_auth import get_github_token

        headers = {"Accept": "application/vnd.github+json"}
        token = await get_github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=6) as client:
            resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if resp.status_code != 200:
            return None
        stars = int(resp.json().get("stargazers_count", 0))
        if r is not None:
            await r.set(key, stars, ex=86400)
        return stars
    except Exception:
        return None


@router.get("/{owner}/{repo}/checks", dependencies=[Depends(rate_limit_reads)])
async def scan_checks(
    owner: str,
    repo: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Real adoption signals — AgentAvow check count, active watchers, GitHub stars
    (public, no claim needed), and the score-history timeline. Increments checks.

    The raw ``checks`` INCR is retained as a vanity number only; the credible,
    hard-to-inflate signal is ``unique_checkers`` — a HyperLogLog of distinct
    authed identities (fallback hashed IP+UA) used by the adoption metric."""
    import json as _json

    from sqlalchemy import func as safunc
    from sqlalchemy import select

    from src.models import ToolWatch

    checks = 0
    history: list[dict] = []
    try:
        from src.redis_client import get_redis

        r = get_redis()
        checks = int(await r.incr(f"checks:{owner}/{repo}"))
        raw = await r.lrange(f"scorehist:{owner}/{repo}", 0, -1)
        for item in raw:
            try:
                history.append(_json.loads(item))
            except Exception:
                pass
    except Exception:
        checks = 0

    # First-party adoption axis-D: dedup on identity (never inflatable). Best-
    # effort — a Redis miss leaves unique_checkers at 0 and never fails the call.
    unique_checkers = 0
    try:
        from src.api.rate_limit import _get_client_ip, _get_entity_id
        from src.scanner.adoption_sources import (
            checker_identity,
            get_unique_checkers,
            record_unique_checker,
        )

        identity = checker_identity(
            _get_entity_id(request),
            _get_client_ip(request),
            request.headers.get("user-agent", ""),
        )
        await record_unique_checker(owner, repo, identity)
        unique_checkers = await get_unique_checkers(owner, repo)
    except Exception:
        unique_checkers = 0

    watchers = await db.scalar(
        select(safunc.count()).select_from(ToolWatch).where(
            ToolWatch.owner == owner,
            ToolWatch.repo == repo,
            ToolWatch.active.is_(True),
        )
    ) or 0
    stars = await _github_stars(owner, repo)
    return {
        "checks": checks,
        "unique_checkers": unique_checkers,
        "watchers": int(watchers),
        "stars": stars,
        "history": history,
    }


@router.get("/{owner}/{repo}/adoption", dependencies=[Depends(rate_limit_reads)])
async def scan_adoption(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Adoption / engagement score — DISTINCT from the trust grade.

    Adoption answers "do real, independent parties rely on this?"; the trust
    letter answers "is it safe?". This endpoint never returns or affects the
    trust grade — it is a separate score with its own tier and "rising" vs
    "established" badge. First-party raw counts are kept internal; the published
    formula and per-axis breakdown are returned. Fail-open across every source.
    """
    from src.scanner.adoption import (
        build_axis_dependents,
        build_axis_downloads,
        build_axis_first_party,
        build_axis_stars,
        compute_adoption,
    )
    from src.scanner.adoption_sources import (
        fetch_ecosystems_dependents,
        fetch_npm_downloads,
        get_badge_embed_domains,
        get_graph_connections,
        get_unique_checkers,
        get_verify_pulls,
    )

    axes = []
    raw_inputs: dict = {}

    # (A) registry downloads — try npm by repo name (best-effort, fail-open).
    dl = await fetch_npm_downloads(repo)
    # (B) reverse-dependents — ecosyste.ms npm registry.
    dep = await fetch_ecosystems_dependents("npmjs.org", repo)

    dep_pkgs = (dep or {}).get("dependent_packages")
    dep_repos = (dep or {}).get("dependent_repos")

    if dl:
        raw_inputs["A"] = dl
        axes.append(
            build_axis_downloads(
                total_downloads=dl.get("total"),
                series=dl.get("series"),
                dependents_for_ratio=int(dep_pkgs or 0) + int(dep_repos or 0),
            )
        )
    if dep:
        raw_inputs["B"] = dep
        axes.append(
            build_axis_dependents(
                dependent_packages=dep_pkgs,
                dependent_repos=dep_repos,
            )
        )

    # (C) social stars velocity.
    stars = await _github_stars(owner, repo)
    if stars is not None:
        raw_inputs["C"] = {"source": "github:stargazers_count", "stars": stars}
        axes.append(build_axis_stars(stars=stars))

    # (D) first-party (ours) — unique checkers, badge-embed domains, verify pulls.
    from src.models import Entity

    uniq = await get_unique_checkers(owner, repo)
    domains = 0
    entity = await db.scalar(
        select(Entity).where(
            Entity.is_active.is_(True),
            Entity.source_url.ilike(f"%github.com/{owner}/{repo}%"),
        )
    )
    if entity is not None:
        domains = await get_badge_embed_domains(str(entity.id))
    verify_pulls = await get_verify_pulls(owner, repo)
    graph_conn = await get_graph_connections(owner, repo)
    fp_axis, fp_volume = build_axis_first_party(
        unique_checkers=uniq,
        badge_embed_domains=domains,
        verify_pulls=verify_pulls,
        graph_connections=graph_conn,
    )
    if fp_axis.present:
        axes.append(fp_axis)

    # (E) MCP / agent-registry usage — from cached community signals if present.
    # (Wired via source_import fetchers; absent here unless the tool is an MCP
    # server with cached Smithery/PulseMCP data.)

    result = compute_adoption(axes, first_party_volume_factor=fp_volume)
    return result.to_public_dict()


async def _surface_adoption_axes(surface: str, owner: str, repo: str):
    """(axes, headline) for a surface coordinate — the shared adoption builder used by
    the /adoption endpoint AND the catalog loop's persistence. npm/PyPI = registry
    downloads + reverse-dependents; github/openclaw (a skill IS a repo) = GitHub stars.
    MCP (bare endpoint) has no reliable registry signal → absent, not fabricated."""
    from src.scanner.adoption import (
        build_axis_dependents,
        build_axis_downloads,
        build_axis_stars,
    )
    from src.scanner.adoption_sources import (
        fetch_ecosystems_dependents,
        fetch_npm_downloads,
        fetch_pypi_downloads,
    )

    s = (surface or "github").lower()
    axes: list = []
    headline: dict | None = None

    if s in ("npm", "pypi"):
        pkg = repo.strip()
        dl = await (fetch_npm_downloads(pkg) if s == "npm" else fetch_pypi_downloads(pkg))
        dep = await fetch_ecosystems_dependents(
            "npmjs.org" if s == "npm" else "pypi.org", pkg,
        )
        dep_pkgs = (dep or {}).get("dependent_packages")
        dep_repos = (dep or {}).get("dependent_repos")
        if dl:
            series = dl.get("series") or []
            weekly = int(sum(series[-7:])) if series else None
            headline = {
                "count": weekly if weekly is not None else dl.get("total"),
                "unit": "downloads/wk" if weekly is not None else "downloads/yr",
            }
            axes.append(build_axis_downloads(
                total_downloads=dl.get("total"), series=series,
                dependents_for_ratio=int(dep_pkgs or 0) + int(dep_repos or 0),
            ))
        if dep:
            if headline is None and (dep_pkgs or dep_repos):
                headline = {"count": int(dep_pkgs or 0) + int(dep_repos or 0), "unit": "dependents"}
            axes.append(build_axis_dependents(
                dependent_packages=dep_pkgs, dependent_repos=dep_repos,
            ))
    elif s in ("github", "openclaw"):
        stars = await _github_stars(owner.strip(), repo.strip())
        if stars is not None:
            headline = {"count": stars, "unit": "stars"}
            axes.append(build_axis_stars(stars=stars))
    return axes, headline


async def surface_adoption_summary(
    surface: str, owner: str, repo: str,
) -> tuple[int | None, int | None, str | None]:
    """(adoption_score_100, headline_count, unit) for community_scans persistence.
    Fail-open → (None, None, None) so a fetch hiccup never blocks a catalog re-scan."""
    try:
        from src.scanner.adoption import compute_adoption

        axes, headline = await _surface_adoption_axes(surface, owner, repo)
        if not axes and not headline:
            return None, None, None
        score = compute_adoption(axes).to_public_dict().get("adoption_score_100")
        return (
            score,
            (headline or {}).get("count"),
            (headline or {}).get("unit"),
        )
    except Exception:
        return None, None, None


@router.get("/adoption", dependencies=[Depends(rate_limit_reads)])
async def scan_adoption_surface(
    surface: str = "github",
    owner: str = "",
    repo: str = "",
) -> dict:
    """Surface-aware adoption — 'do real, independent parties rely on this?' — for the
    non-GitHub surfaces the repo `/adoption` endpoint can't serve. Returns the published
    axis breakdown plus a `headline` {count, unit} for the adoption ring."""
    from src.scanner.adoption import compute_adoption

    axes, headline = await _surface_adoption_axes(surface, owner, repo)
    out = compute_adoption(axes).to_public_dict()
    out["headline"] = headline
    return out


def _verdict_text(grade: str) -> str:
    """Return a consumer-friendly safety verdict for a letter grade."""
    if grade in ("A+", "A"):
        return "Safe to Use"
    if grade == "B":
        return "Generally Safe"
    if grade == "C":
        return "Use with Caution"
    if grade == "D":
        return "Significant Risks"
    return "Not Recommended"


def _render_og_svg(
    owner: str,
    repo: str,
    grade: str,
    score: int,
    critical: int,
    high: int,
    medium: int,
    verdict: str,
) -> str:
    """Render a 1200x630 SVG Open Graph preview card.

    Clean single-ring "attestation trust" card. Adoption/usage counts are not
    in scope for this function's inputs, so a single centered grade ring is
    rendered (twin-ring layout is reserved for callers that have adoption data).
    """
    color = _grade_color(grade)

    # Escape XML entities in repo name (matches existing badge escaping)
    display_name = f"{owner}/{repo}".replace("&", "&amp;").replace("<", "&lt;")

    # Ring geometry
    circ = 2 * math.pi * 100
    dash = max(0.0, min(score, 100)) / 100 * circ

    svg_open = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'width="1200" height="630" viewBox="0 0 1200 630">'
    )
    return f'''{svg_open}
  <defs>
    <radialGradient id="glow" cx="0.5" cy="0" r="1">
      <stop offset="0%" stop-color="{color}" stop-opacity="0.16"/>
      <stop offset="100%" stop-color="{color}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="brand" x1="0" y1="0" x2="1" y2="1">
      <stop stop-color="#2DD4BF"/>
      <stop offset="1" stop-color="#E879F9"/>
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="1200" height="630" fill="#0B1220"/>
  <!-- Subtle radial glow at top -->
  <rect width="1200" height="360" fill="url(#glow)"/>

  <!-- Brand lockup (top-left) -->
  <g transform="translate(70,66)">
    <circle cx="20" cy="20" r="18" fill="none" stroke="url(#brand)" stroke-width="3.4"/>
    <path d="M12 21l6 6 12-13" fill="none" stroke="url(#brand)" stroke-width="4"
          stroke-linecap="round" stroke-linejoin="round"/>
    <text x="52" y="30" fill="#F8FAFC" font-family="system-ui,-apple-system,sans-serif"
          font-size="30" font-weight="700" letter-spacing="-0.5">AgentAvow</text>
  </g>

  <!-- Repo name (top-right) -->
  <text x="1130" y="88" text-anchor="end" fill="#94A3B8"
        font-family="monospace" font-size="24">{display_name}</text>

  <!-- Verdict / tier (centered) -->
  <text x="600" y="176" text-anchor="middle" fill="#CBD5E1"
        font-family="system-ui,-apple-system,sans-serif"
        font-size="34" font-weight="800">{verdict}</text>

  <!-- Attestation trust ring (centered) -->
  <g transform="translate(600,360)">
    <circle cx="0" cy="0" r="100" fill="none" stroke="#1b2b2b" stroke-width="20"/>
    <circle cx="0" cy="0" r="100" fill="none" stroke="{color}" stroke-width="20"
            stroke-linecap="round" stroke-dasharray="{dash:.2f} {circ:.2f}"
            transform="rotate(-90)"/>
    <text x="0" y="18" text-anchor="middle" fill="{color}"
          font-family="system-ui,-apple-system,sans-serif"
          font-size="86" font-weight="800">{grade}</text>
    <text x="0" y="52" text-anchor="middle" fill="#94A3B8"
          font-family="monospace" font-size="24">{score}/100</text>
  </g>

  <!-- Ring label -->
  <text x="600" y="500" text-anchor="middle" fill="{color}"
        font-family="monospace" font-size="18">ATTESTATION TRUST</text>
  <text x="600" y="528" text-anchor="middle" fill="#94A3B8"
        font-family="system-ui,-apple-system,sans-serif"
        font-size="18">signed &#183; verifiable now</text>

  <!-- Footer -->
  <text x="600" y="596" text-anchor="middle" fill="#64748B"
        font-family="monospace"
        font-size="18">Signed &#183; Ed25519 &#183; verify offline at agentavow.com</text>
</svg>'''


@router.get(
    "/{owner}/{repo}/og-image",
    dependencies=[Depends(rate_limit_reads)],
    response_class=Response,
)
async def scan_og_image(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Return a 1200x630 SVG Open Graph preview card for social sharing.

    Shows the letter grade, score, safety verdict, and findings summary.
    Used as the ``og:image`` in ``/check/:owner/:repo`` pages so that
    links shared on Twitter, Slack, Discord, and iMessage render a rich
    preview card with the trust grade.
    """
    full_name = f"{owner}/{repo}"

    # Check if this repo is imported as an AgentGraph entity
    entity_trust = await _get_entity_trust(full_name, db)

    # Determine score source: composite trust vs security scan
    critical = 0
    high = 0
    medium = 0
    if (
        entity_trust
        and entity_trust.get("imported")
        and entity_trust.get("composite_score") is not None
    ):
        score = entity_trust["composite_score"]
        grade = entity_trust["grade"]
    else:
        cached = await _get_cached(owner, repo)
        if cached:
            score = cached["trust_score"]
            _elig = (cached.get("certified") or {}).get("eligible")
            grade = cached.get("grade") or _display_grade(score, _elig)
            findings = cached.get("findings", {})
            critical = findings.get("critical", 0)
            high = findings.get("high", 0)
            medium = findings.get("medium", 0)
        else:
            # No scan data — return a generic "not scanned" card
            score = 0
            grade = "?"
            critical = 0
            high = 0
            medium = 0

    verdict = _verdict_text(grade) if grade != "?" else "Not Yet Scanned"

    svg = _render_og_svg(
        owner=owner,
        repo=repo,
        grade=grade,
        score=score,
        critical=critical,
        high=high,
        medium=medium,
        verdict=verdict,
    )

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=3600, s-maxage=86400",
            "Access-Control-Allow-Origin": "*",
        },
    )
