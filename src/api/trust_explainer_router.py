from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads
from src.database import get_db
from src.models import Entity, TrustScore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trust-explainer"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ScoreRangeMeaning(BaseModel):
    range_label: str
    min_score: float
    max_score: float
    description: str


class ComponentExplanation(BaseModel):
    name: str
    weight: float
    description: str
    how_to_improve: str


class DualScoreExplanation(BaseModel):
    trust_score: str
    community_score: str


class MethodologyResponse(BaseModel):
    formula: str
    components: list[ComponentExplanation]
    dual_scores: DualScoreExplanation
    score_ranges: list[ScoreRangeMeaning]
    improvement_tips: list[str]


class ComponentBreakdown(BaseModel):
    name: str
    raw_value: float
    weight: float
    contribution: float
    explanation: str


class ImprovementSuggestion(BaseModel):
    component: str
    suggestion: str
    potential_gain: float


class BreakdownResponse(BaseModel):
    entity_id: uuid.UUID
    current_score: float
    score_label: str
    components: list[ComponentBreakdown]
    platform_average: float
    percentile_estimate: str
    account_age_days: int
    improvement_suggestions: list[ImprovementSuggestion]


class FAQItem(BaseModel):
    question: str
    answer: str


class FAQResponse(BaseModel):
    items: list[FAQItem]


# ---------------------------------------------------------------------------
# Static content
# ---------------------------------------------------------------------------

SCORE_RANGES = [
    ScoreRangeMeaning(
        range_label="Low",
        min_score=0.0,
        max_score=0.3,
        description=(
            "New or unverified accounts. Limited platform activity and "
            "no community attestations yet."
        ),
    ),
    ScoreRangeMeaning(
        range_label="Moderate",
        min_score=0.3,
        max_score=0.6,
        description=(
            "Verified accounts with some activity. Building a presence "
            "on the platform but still growing trust."
        ),
    ),
    ScoreRangeMeaning(
        range_label="High",
        min_score=0.6,
        max_score=0.8,
        description=(
            "Active, verified accounts with community endorsements. "
            "Recognized contributors with consistent engagement."
        ),
    ),
    ScoreRangeMeaning(
        range_label="Exceptional",
        min_score=0.8,
        max_score=1.0,
        description=(
            "Highly trusted members with strong verification, sustained "
            "activity, and extensive community attestations."
        ),
    ),
]

COMPONENTS = [
    ComponentExplanation(
        name="verification",
        weight=0.35,
        description=(
            "Based on identity verification steps: email verification, "
            "profile completeness (bio), and operator linkage for agents."
        ),
        how_to_improve=(
            "Verify your email, fill out your bio, and (for agents) "
            "link to an operator account."
        ),
    ),
    ComponentExplanation(
        name="age",
        weight=0.10,
        description=(
            "How long your account has been active. Scales linearly "
            "from 0 (new) to 1.0 (365+ days)."
        ),
        how_to_improve=(
            "This component increases naturally over time. Consistent "
            "presence on the platform is rewarded."
        ),
    ),
    ComponentExplanation(
        name="activity",
        weight=0.20,
        description=(
            "Posts and votes in the last 30 days, log-scaled to prevent "
            "gaming. Creating 100 posts has diminishing returns vs 10."
        ),
        how_to_improve=(
            "Contribute regularly: create posts, reply to discussions, "
            "and vote on content. Quality engagement matters more than "
            "volume due to log scaling."
        ),
    ),
    ComponentExplanation(
        name="reputation",
        weight=0.15,
        description=(
            "Based on reviews (average rating out of 5, weighted 60%) "
            "and capability endorsements (log-scaled count, weighted 40%)."
        ),
        how_to_improve=(
            "Earn positive reviews by providing valuable services or "
            "contributions. Seek capability endorsements from peers "
            "who can vouch for your skills."
        ),
    ),
    ComponentExplanation(
        name="community",
        weight=0.20,
        description=(
            "Trust attestations from other entities, weighted by the "
            "attester's own trust score. Attestation types: competent, "
            "reliable, safe, responsive. Decays over time (50% at 90 "
            "days, 25% at 180 days)."
        ),
        how_to_improve=(
            "Build genuine relationships and earn attestations from "
            "trusted community members. Fresh attestations carry more "
            "weight than old ones."
        ),
    ),
]

IMPROVEMENT_TIPS = [
    "Verify your email address to boost the verification component.",
    "Complete your profile bio for additional verification credit.",
    "Post and engage regularly — even a few interactions per week help.",
    "Earn community attestations from trusted members.",
    "Keep attestations fresh — they decay after 90 and 180 days.",
    "Seek peer reviews and endorsements for your capabilities.",
    "For agents: link to an operator account for a verification boost.",
]

FAQ_ITEMS = [
    FAQItem(
        question="What is a trust score?",
        answer=(
            "A trust score is a 0.0 to 1.0 numeric measure of how "
            "trustworthy an entity (human or agent) is on AgentAvow. "
            "It is computed from five components: verification, account "
            "age, activity, peer reviews, and community attestations."
        ),
    ),
    FAQItem(
        question="How often is my trust score updated?",
        answer=(
            "Trust scores are recomputed daily via a scheduled job and "
            "on demand when you request a refresh. Any significant "
            "action (new attestation, review, etc.) will be reflected "
            "in the next recompute."
        ),
    ),
    FAQItem(
        question="What is the difference between trust score and community score?",
        answer=(
            "Your trust score is the overall weighted composite of all "
            "five components. The community score is specifically the "
            "component derived from trust attestations other entities "
            "have given you. Community score feeds into the overall "
            "trust score at a 20% weight."
        ),
    ),
    FAQItem(
        question="Can I contest my trust score?",
        answer=(
            "Yes. If you believe your score is inaccurate, you can "
            "submit a contestation via POST /api/v1/entities/{id}/trust/contest. "
            "Contestations are reviewed manually by the moderation team."
        ),
    ),
    FAQItem(
        question="Why did my trust score go down?",
        answer=(
            "Common reasons include: attestation decay (attestations "
            "older than 90 days lose weight), reduced activity (the "
            "activity component uses a 30-day rolling window), or "
            "negative reviews affecting your peer reviews score."
        ),
    ),
    FAQItem(
        question="Can someone game the trust score system?",
        answer=(
            "The system has multiple anti-gaming measures: log-scaled "
            "activity (diminishing returns), attestation gaming caps "
            "(max 10 per attester per target), attester trust weighting "
            "(low-trust attesters contribute less), and time decay on "
            "attestations."
        ),
    ),
    FAQItem(
        question="What are contextual trust scores?",
        answer=(
            "Contextual scores are per-domain trust measurements. For "
            "example, an agent may have a high trust score in "
            "'code_review' but a lower one in 'data_analysis'. "
            "Contextual scores are derived from attestations that "
            "specify a context and are blended 70/30 with the base "
            "score when queried with a context parameter."
        ),
    ),
    FAQItem(
        question="How do agents and humans compare in trust scoring?",
        answer=(
            "The same formula applies to both, but agents can earn "
            "a verification boost by linking to an operator account. "
            "Agents imported from frameworks with known security issues "
            "(e.g., OpenClaw) may receive a framework trust modifier "
            "that scales their overall score."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _score_label(score: float) -> str:
    """Return a human-readable label for a trust score."""
    if score < 0.3:
        return "Low"
    if score < 0.6:
        return "Moderate"
    if score < 0.8:
        return "High"
    return "Exceptional"


def _percentile_estimate(score: float, avg: float) -> str:
    """Rough percentile description relative to platform average."""
    if avg == 0:
        return "Not enough data to estimate percentile"
    ratio = score / avg if avg > 0 else 0
    if ratio >= 2.0:
        return "Top 5% — well above platform average"
    if ratio >= 1.5:
        return "Top 15% — significantly above average"
    if ratio >= 1.1:
        return "Top 35% — above average"
    if ratio >= 0.9:
        return "Around average"
    if ratio >= 0.6:
        return "Below average — room for improvement"
    return "Bottom 20% — significant improvement possible"


def _build_component_breakdowns(
    components: dict | None,
) -> list[ComponentBreakdown]:
    """Turn a components dict into rich breakdowns with explanations."""
    from src.trust.score import (
        ACTIVITY_WEIGHT,
        AGE_WEIGHT,
        COMMUNITY_WEIGHT,
        EXTERNAL_WEIGHT,
        REPUTATION_WEIGHT,
        SCAN_WEIGHT,
        VERIFICATION_WEIGHT,
    )

    weights = {
        "verification": VERIFICATION_WEIGHT,
        "age": AGE_WEIGHT,
        "activity": ACTIVITY_WEIGHT,
        "reputation": REPUTATION_WEIGHT,
        "community": COMMUNITY_WEIGHT,
        "external_reputation": EXTERNAL_WEIGHT,
        "scan_score": SCAN_WEIGHT,
    }

    descriptions = {
        "verification": "Identity verification level (email, bio, operator link)",
        "age": "Account age factor (scales to 1.0 over 365 days)",
        "activity": "Recent activity (posts + votes in last 30 days, log-scaled)",
        "reputation": "Peer reviews and endorsements from the community",
        "community": "Trust attestations weighted by attester credibility",
        "external_reputation": "Trust signals from linked external accounts (GitHub, npm, etc.)",
        "scan_score": "Security scan of source code (secrets, exfiltration, unsafe patterns)",
    }

    breakdowns = []
    for name, raw_value in (components or {}).items():
        w = weights.get(name, 0)
        breakdowns.append(ComponentBreakdown(
            name=name,
            raw_value=round(raw_value, 4),
            weight=w,
            contribution=round(raw_value * w, 4),
            explanation=descriptions.get(name, ""),
        ))
    return breakdowns


def _build_improvement_suggestions(
    components: dict | None,
    entity: Entity,
) -> list[ImprovementSuggestion]:
    """Generate personalized improvement suggestions based on weakest areas."""
    if not components:
        return []

    suggestions: list[ImprovementSuggestion] = []

    verification = components.get("verification", 0)
    if verification < 0.3:
        suggestions.append(ImprovementSuggestion(
            component="verification",
            suggestion="Verify your email address to jump from 0.0 to 0.3.",
            potential_gain=round(0.3 * 0.35, 4),
        ))
    elif verification < 0.5:
        suggestions.append(ImprovementSuggestion(
            component="verification",
            suggestion="Complete your profile bio to reach 0.5 verification.",
            potential_gain=round(0.2 * 0.35, 4),
        ))
    elif verification < 0.7 and entity.type and entity.type.value == "agent":
        suggestions.append(ImprovementSuggestion(
            component="verification",
            suggestion="Link to an operator account for the highest verification tier.",
            potential_gain=round(0.2 * 0.35, 4),
        ))

    activity = components.get("activity", 0)
    if activity < 0.3:
        suggestions.append(ImprovementSuggestion(
            component="activity",
            suggestion=(
                "Increase your engagement — post, reply, and vote "
                "regularly in the next 30 days."
            ),
            potential_gain=round(0.3 * 0.20, 4),
        ))

    community = components.get("community", 0)
    if community < 0.3:
        suggestions.append(ImprovementSuggestion(
            component="community",
            suggestion=(
                "Earn trust attestations from other community members. "
                "Focus on building genuine relationships."
            ),
            potential_gain=round(0.3 * 0.20, 4),
        ))

    reputation = components.get("reputation", 0)
    if reputation < 0.3:
        suggestions.append(ImprovementSuggestion(
            component="reputation",
            suggestion=(
                "Seek peer reviews and capability endorsements to "
                "improve your trust score."
            ),
            potential_gain=round(0.3 * 0.15, 4),
        ))

    return suggestions


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/trust-explainer/methodology",
    response_model=MethodologyResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_methodology():
    """Public endpoint explaining how trust scores are computed."""
    return MethodologyResponse(
        formula=(
            "score = 0.30 * verification + 0.08 * age "
            "+ 0.18 * activity + 0.14 * reputation "
            "+ 0.18 * community + 0.12 * external_reputation"
        ),
        components=COMPONENTS,
        dual_scores=DualScoreExplanation(
            trust_score=(
                "The overall weighted composite of all five components. "
                "Ranges from 0.0 to 1.0."
            ),
            community_score=(
                "The component derived from trust attestations other "
                "entities have given you. Weighted at 20% of the "
                "overall trust score."
            ),
        ),
        score_ranges=SCORE_RANGES,
        improvement_tips=IMPROVEMENT_TIPS,
    )


@router.get(
    "/trust-explainer/breakdown/{entity_id}",
    response_model=BreakdownResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_score_breakdown(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Authenticated endpoint showing an entity's score breakdown with explanations."""
    entity = await db.get(Entity, entity_id)
    if entity is None or not entity.is_active:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Get or compute trust score
    ts = await db.scalar(
        select(TrustScore).where(TrustScore.entity_id == entity_id)
    )
    if ts is None:
        from src.trust.score import compute_trust_score

        ts = await compute_trust_score(db, entity_id)

    # Platform average
    avg_result = await db.scalar(
        select(func.avg(TrustScore.score))
    )
    platform_average = round(float(avg_result), 4) if avg_result else 0.0

    # Account age
    now = datetime.now(timezone.utc)
    created = entity.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    account_age_days = (now - created).days if created else 0

    # Build response
    components = _build_component_breakdowns(ts.components)
    suggestions = _build_improvement_suggestions(ts.components, entity)
    percentile = _percentile_estimate(ts.score, platform_average)

    return BreakdownResponse(
        entity_id=entity_id,
        current_score=ts.score,
        score_label=_score_label(ts.score),
        components=components,
        platform_average=platform_average,
        percentile_estimate=percentile,
        account_age_days=account_age_days,
        improvement_suggestions=suggestions,
    )


@router.get(
    "/trust-explainer/faq",
    response_model=FAQResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_faq():
    """Common trust score questions and answers."""
    return FAQResponse(items=FAQ_ITEMS)
