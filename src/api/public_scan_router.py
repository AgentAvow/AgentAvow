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
    owner: str, repo: str, data: dict, db: AsyncSession
) -> None:
    """Persist an on-demand scan so the browsable catalog grows beyond the static
    launch corpus. Upsert one row per owner/repo (latest scan wins, scan_count++)."""
    from sqlalchemy import func as safunc
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from src.models import CommunityScan

    findings = data.get("findings") or {}
    meta = data.get("metadata") or {}
    lang = (meta.get("primary_language") or None)
    if lang:
        lang = lang[:120]
    values = dict(
        owner=owner,
        repo=repo,
        full_name=f"{owner}/{repo}",
        trust_score=data.get("trust_score"),
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

    return {
        "trust_score": result.trust_score,
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

# NOTE: wallet route MUST come before /{owner}/{repo} to avoid the catch-all
# matching "wallet" as an owner name.

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
            grade = _grade_from_score(score)
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
                grade = _grade_from_score(score)
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
async def scan_checks(owner: str, repo: str, db: AsyncSession = Depends(get_db)) -> dict:
    """Real adoption signals — AgentAvow check count, active watchers, GitHub stars
    (public, no claim needed), and the score-history timeline. Increments checks."""
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
        "watchers": int(watchers),
        "stars": stars,
        "history": history,
    }


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
            grade = _grade_from_score(score)
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
