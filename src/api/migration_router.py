"""Migration API router — endpoints for migrating bots from other platforms.

Currently supports Moltbook migration. Migrated bots undergo security
scanning and start with reduced trust modifiers.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import Entity

router = APIRouter(prefix="/migration", tags=["migration"])


# --- Request/Response schemas ---


class MoltbookProfile(BaseModel):
    """Moltbook bot profile for migration."""

    username: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=100)
    name: str | None = Field(default=None, max_length=100)
    bio: str | None = Field(default=None, max_length=5000)
    description: str | None = Field(default=None, max_length=5000)
    skills: list[Any] | None = Field(default=None)
    capabilities: list[Any] | None = Field(default=None)
    avatar_url: str | None = Field(default=None, max_length=500)
    moltbook_id: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default="1.0.0", max_length=50)
    api_tokens: list[str] | None = Field(default=None)


class MoltbookMigrationResult(BaseModel):
    """Result of a Moltbook bot migration."""

    entity_id: str
    display_name: str
    did_web: str
    framework_source: str
    framework_trust_modifier: float
    capabilities: list[str]
    badges: list[str]
    claim_token: str
    security_scan: dict[str, Any]
    social_proof_badge_url: str


class MoltbookValidationResult(BaseModel):
    """Result of a dry-run validation of a Moltbook profile."""

    valid: bool
    errors: list[str]
    translated_profile: dict[str, Any] | None = None
    security_scan: dict[str, Any] | None = None


# --- Endpoints ---


@router.post(
    "/moltbook",
    response_model=MoltbookMigrationResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def migrate_moltbook_bot(
    profile: MoltbookProfile,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> MoltbookMigrationResult:
    """Migrate a Moltbook bot to AgentAvow.

    Accepts a Moltbook profile JSON, validates it, runs security scanning,
    and creates a provisional AgentAvow entity. The authenticated operator
    becomes the bot's owner.

    The migrated bot receives:
    - A 'migrated_from_moltbook' badge
    - A reduced trust modifier of 0.65 (due to Moltbook's breach)
    - A claim token for ownership verification
    - A social proof badge URL
    """
    from src.audit import log_action
    from src.bridges.moltbook.adapter import (
        import_moltbook_bot,
        validate_moltbook_profile,
    )
    from src.bridges.moltbook.security import scan_moltbook_bot

    profile_dict = profile.model_dump(exclude_none=True)

    # Validate
    errors = validate_moltbook_profile(profile_dict)
    if errors:
        raise HTTPException(status_code=422, detail=errors)

    # Security scan
    scan_result = scan_moltbook_bot(profile_dict)

    # If leaked credentials found, still allow migration but warn
    # The trust penalty is applied automatically via the modifier

    # Import the bot
    result = await import_moltbook_bot(
        db=db,
        profile=profile_dict,
        operator_id=current_entity.id,
    )

    # If scan found leaked credentials, apply the harsher penalty
    if scan_result["leaked_credentials"]:
        from src.models import Entity as EntityModel

        entity = await db.get(EntityModel, result["id"])
        if entity is not None:
            entity.framework_trust_modifier = scan_result["trust_penalty"]
            await db.flush()
            result["framework_trust_modifier"] = scan_result["trust_penalty"]

    # Audit log
    await log_action(
        db,
        action="migration.moltbook.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=result["id"],
        details={
            "bot_name": result["display_name"],
            "risk_level": scan_result["risk_level"],
            "leaked_credentials": scan_result["leaked_credentials"],
            "framework": "moltbook",
        },
    )

    # Social proof badge URL
    badge_url = f"/api/v1/badges/social-proof/moltbook/{result['id']}"

    return MoltbookMigrationResult(
        entity_id=result["id"],
        display_name=result["display_name"],
        did_web=result["did_web"],
        framework_source=result["framework_source"],
        framework_trust_modifier=result["framework_trust_modifier"],
        capabilities=result["capabilities"],
        badges=result["badges"],
        claim_token=result["claim_token"],
        security_scan=scan_result,
        social_proof_badge_url=badge_url,
    )


@router.get(
    "/moltbook/validate",
    response_model=MoltbookValidationResult,
    dependencies=[Depends(rate_limit_reads)],
)
async def validate_moltbook_profile_endpoint(
    username: str | None = None,
    display_name: str | None = None,
    name: str | None = None,
    bio: str | None = None,
    description: str | None = None,
    moltbook_id: str | None = None,
    current_entity: Entity = Depends(get_current_entity),
) -> MoltbookValidationResult:
    """Dry-run validation of a Moltbook profile without creating anything.

    Validates the profile fields and runs a security scan, returning
    the results without persisting any data. Requires authentication
    so we can rate-limit appropriately.
    """
    from src.bridges.moltbook.adapter import (
        translate_moltbook_profile,
        validate_moltbook_profile,
    )
    from src.bridges.moltbook.security import scan_moltbook_bot

    profile_dict: dict[str, Any] = {}
    if username is not None:
        profile_dict["username"] = username
    if display_name is not None:
        profile_dict["display_name"] = display_name
    if name is not None:
        profile_dict["name"] = name
    if bio is not None:
        profile_dict["bio"] = bio
    if description is not None:
        profile_dict["description"] = description
    if moltbook_id is not None:
        profile_dict["moltbook_id"] = moltbook_id

    errors = validate_moltbook_profile(profile_dict)
    if errors:
        return MoltbookValidationResult(
            valid=False,
            errors=errors,
            translated_profile=None,
            security_scan=None,
        )

    translated = translate_moltbook_profile(profile_dict)
    scan_result = scan_moltbook_bot(profile_dict)

    return MoltbookValidationResult(
        valid=True,
        errors=[],
        translated_profile=translated,
        security_scan=scan_result,
    )
