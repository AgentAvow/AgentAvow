"""A2A Trust Middleware — AgentGraph's trust layer on top of A2A protocol.

AIP (AgentGraph Identity Protocol) operates ON TOP OF A2A (Agent-to-Agent
Protocol). A2A handles the communication plumbing (delegation, discovery,
capability exchange). AIP adds the trust/identity/accountability layer.

This middleware intercepts A2A interactions to:
1. Verify both parties' DIDs and trust scores
2. Enforce minimum trust thresholds per interaction type
3. Log audit events for every interaction
4. Inject trust metadata into A2A envelopes
5. Block interactions that fail trust checks

Architecture:
    A2A Request → [Trust Middleware] → Process → [Trust Middleware] → A2A Response
                  ├── verify_identities()
                  ├── check_trust_threshold()
                  ├── log_audit_event()
                  └── inject_trust_metadata()
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.interaction_safety import INTERACTION_THRESHOLDS as _SHARED_THRESHOLDS

logger = logging.getLogger(__name__)


# --- Trust Thresholds per Interaction Type ---

# Minimum trust scores required to initiate each A2A interaction type (0-1 scale for the
# protocol layer). Derived from the shared 0-100 source of truth
# (src/interaction_safety.py) so this map can never drift from the MCP surfaces.
# Still overridable via config or per-entity settings.
DEFAULT_TRUST_THRESHOLDS: dict[str, float] = {
    k: _SHARED_THRESHOLDS[k] / 100
    for k in ("delegate", "negotiate", "collaborate", "discover",
              "capability_exchange", "data_transfer", "financial")
}


@dataclass
class TrustContext:
    """Trust metadata injected into A2A interactions."""

    initiator_entity_id: str
    target_entity_id: str
    initiator_trust_score: float | None = None
    target_trust_score: float | None = None
    initiator_did: str | None = None
    target_did: str | None = None
    interaction_type: str = "unknown"
    trust_threshold: float = 0.0
    passes_threshold: bool = False
    framework_modifier: float = 1.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    correlation_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )


@dataclass
class TrustVerdict:
    """Result of trust middleware evaluation."""

    allowed: bool
    reason: str
    context: TrustContext
    warnings: list[str] = field(default_factory=list)


async def verify_interaction(
    initiator_id: str,
    target_id: str,
    interaction_type: str,
    db: Any = None,
    custom_threshold: float | None = None,
) -> TrustVerdict:
    """Evaluate whether an A2A interaction should be allowed.

    This is the main entry point for the trust middleware. It:
    1. Resolves both entities and their trust scores
    2. Checks trust thresholds for the interaction type
    3. Builds a TrustContext with full audit metadata
    4. Returns a TrustVerdict with allow/deny and reasoning

    Args:
        initiator_id: UUID of the entity initiating the interaction
        target_id: UUID of the target entity
        interaction_type: Type of A2A interaction (delegate, negotiate, etc.)
        db: Optional async database session
        custom_threshold: Override the default threshold for this type

    Returns:
        TrustVerdict with allowed=True/False and full context
    """
    threshold = custom_threshold or DEFAULT_TRUST_THRESHOLDS.get(
        interaction_type, 0.5
    )

    context = TrustContext(
        initiator_entity_id=initiator_id,
        target_entity_id=target_id,
        interaction_type=interaction_type,
        trust_threshold=threshold,
    )

    warnings: list[str] = []

    # Resolve trust scores if DB is available
    if db is not None:
        try:
            initiator_score, initiator_did, init_modifier = await _resolve_trust(
                db, initiator_id
            )
            target_score, target_did, _ = await _resolve_trust(db, target_id)

            context.initiator_trust_score = initiator_score
            context.target_trust_score = target_score
            context.initiator_did = initiator_did
            context.target_did = target_did
            context.framework_modifier = init_modifier

            # Apply framework modifier to effective score
            effective_score = (initiator_score or 0.0) * init_modifier

            if initiator_score is None:
                warnings.append("Initiator has no trust score record")
            if target_score is None:
                warnings.append("Target has no trust score record")

            # Check if initiator meets threshold
            context.passes_threshold = effective_score >= threshold

        except Exception:
            logger.exception("Failed to resolve trust scores")
            context.passes_threshold = False
            warnings.append("Trust score resolution failed")
    else:
        # Without DB, we can't verify — deny by default for non-discovery
        context.passes_threshold = interaction_type == "discover"
        if not context.passes_threshold:
            warnings.append("No database session — trust verification unavailable")

    # Build verdict
    if context.passes_threshold:
        reason = (
            f"Trust check passed: initiator score "
            f"{context.initiator_trust_score or 0:.2f} × "
            f"modifier {context.framework_modifier:.2f} >= "
            f"threshold {threshold:.2f} for '{interaction_type}'"
        )
        allowed = True
    else:
        reason = (
            f"Trust check failed: initiator score "
            f"{context.initiator_trust_score or 0:.2f} × "
            f"modifier {context.framework_modifier:.2f} < "
            f"threshold {threshold:.2f} for '{interaction_type}'"
        )
        allowed = False

    verdict = TrustVerdict(
        allowed=allowed,
        reason=reason,
        context=context,
        warnings=warnings,
    )

    # Log audit event
    await _log_trust_event(db, verdict)

    return verdict


async def inject_trust_metadata(
    a2a_envelope: dict[str, Any],
    context: TrustContext,
) -> dict[str, Any]:
    """Inject trust metadata into an A2A message envelope.

    Adds an `agentgraph_trust` section to the envelope containing
    trust scores, verification status, and correlation ID for audit.

    Args:
        a2a_envelope: The A2A message dict to enrich
        context: TrustContext from verify_interaction()

    Returns:
        Enriched A2A envelope with trust metadata
    """
    a2a_envelope["agentgraph_trust"] = {
        "initiator_trust_score": context.initiator_trust_score,
        "target_trust_score": context.target_trust_score,
        "initiator_did": context.initiator_did,
        "target_did": context.target_did,
        "interaction_type": context.interaction_type,
        "passes_threshold": context.passes_threshold,
        "framework_modifier": context.framework_modifier,
        "correlation_id": context.correlation_id,
        "verified_at": context.timestamp,
    }
    return a2a_envelope


# --- Internal Helpers ---


async def _resolve_trust(
    db: Any, entity_id: str
) -> tuple[float | None, str | None, float]:
    """Resolve trust score, DID, and framework modifier for an entity.

    Returns (trust_score, did_web, framework_modifier).
    """
    from sqlalchemy import select

    from src.models import Entity, TrustScore

    entity = await db.get(Entity, uuid.UUID(entity_id))
    if entity is None:
        return None, None, 1.0

    # Get trust score
    score_row = await db.scalar(
        select(TrustScore.score).where(TrustScore.entity_id == entity.id)
    )

    modifier = entity.framework_trust_modifier or 1.0
    return score_row, entity.did_web, modifier


async def _log_trust_event(
    db: Any | None, verdict: TrustVerdict
) -> None:
    """Log a trust middleware evaluation to both audit log and analytics."""
    if db is None:
        logger.info(
            "Trust middleware: %s — %s",
            "ALLOWED" if verdict.allowed else "DENIED",
            verdict.reason,
        )
        return

    try:
        from src.audit import log_action

        await log_action(
            db,
            action="a2a.trust_check",
            entity_id=uuid.UUID(verdict.context.initiator_entity_id),
            resource_type="a2a_interaction",
            resource_id=uuid.UUID(verdict.context.correlation_id),
            details={
                "target_entity_id": verdict.context.target_entity_id,
                "interaction_type": verdict.context.interaction_type,
                "allowed": verdict.allowed,
                "reason": verdict.reason,
                "initiator_score": verdict.context.initiator_trust_score,
                "target_score": verdict.context.target_trust_score,
                "threshold": verdict.context.trust_threshold,
                "framework_modifier": verdict.context.framework_modifier,
                "warnings": verdict.warnings,
            },
        )
    except Exception:
        logger.exception("Failed to log trust middleware event")

    # Log interaction event for analytics
    await _log_interaction_event(db, verdict)


async def _log_interaction_event(
    db: Any, verdict: TrustVerdict
) -> None:
    """Record an interaction event for analytics (framework-pair tracking).

    Uses the existing InteractionEvent model, storing A2A-specific trust
    data in the JSONB `context` column.
    """
    try:
        from src.models import Entity, InteractionEvent

        ctx = verdict.context

        # Resolve framework sources for cross-framework tracking
        initiator_fw = None
        target_fw = None
        try:
            initiator = await db.get(
                Entity, uuid.UUID(ctx.initiator_entity_id)
            )
            target = await db.get(Entity, uuid.UUID(ctx.target_entity_id))
            if initiator:
                initiator_fw = initiator.framework_source
            if target:
                target_fw = target.framework_source
        except Exception:
            pass  # Best-effort framework resolution

        is_cross = (
            initiator_fw is not None
            and target_fw is not None
            and initiator_fw != target_fw
        )

        event = InteractionEvent(
            id=uuid.uuid4(),
            entity_a_id=uuid.UUID(ctx.initiator_entity_id),
            entity_b_id=uuid.UUID(ctx.target_entity_id),
            interaction_type=f"a2a.{ctx.interaction_type}",
            context={
                "correlation_id": ctx.correlation_id,
                "initiator_trust_score": ctx.initiator_trust_score,
                "target_trust_score": ctx.target_trust_score,
                "trust_threshold": ctx.trust_threshold,
                "framework_modifier": ctx.framework_modifier,
                "allowed": verdict.allowed,
                "initiator_framework": initiator_fw,
                "target_framework": target_fw,
                "is_cross_framework": is_cross,
            },
        )
        db.add(event)
        await db.flush()
    except Exception:
        logger.exception("Failed to log interaction event")
