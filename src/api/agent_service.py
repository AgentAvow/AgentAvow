from __future__ import annotations

import hashlib
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import (
    APIKey,
    DIDDocument,
    DIDStatus,
    Entity,
    EntityRelationship,
    EntityType,
    RelationshipType,
)


def generate_api_key() -> str:
    return secrets.token_hex(32)  # 64 chars


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_agent_did(agent_id: uuid.UUID) -> str:
    return f"did:web:agentgraph.co:agents:{agent_id}"


async def create_agent(
    db: AsyncSession,
    operator: Entity,
    display_name: str,
    capabilities: list[str] | None = None,
    autonomy_level: int | None = None,
    bio_markdown: str = "",
) -> tuple[Entity, str]:
    """Create an agent entity and return (agent, plaintext_api_key)."""
    agent_id = uuid.uuid4()
    agent = Entity(
        id=agent_id,
        type=EntityType.AGENT,
        display_name=display_name,
        did_web=generate_agent_did(agent_id),
        capabilities=capabilities or [],
        autonomy_level=autonomy_level,
        operator_id=operator.id,
        bio_markdown=bio_markdown,
    )
    db.add(agent)
    await db.flush()

    # Create operator-agent relationship
    rel = EntityRelationship(
        id=uuid.uuid4(),
        source_entity_id=operator.id,
        target_entity_id=agent.id,
        type=RelationshipType.OPERATOR_AGENT,
    )
    db.add(rel)

    # Generate and store API key
    plaintext_key = generate_api_key()
    api_key = APIKey(
        id=uuid.uuid4(),
        entity_id=agent.id,
        key_hash=hash_api_key(plaintext_key),
        label="default",
        scopes=["agent:read", "agent:write", "webhooks:manage"],
    )
    db.add(api_key)
    await db.flush()

    return agent, plaintext_key


async def register_agent_direct(
    db: AsyncSession,
    display_name: str,
    capabilities: list[str] | None = None,
    autonomy_level: int | None = None,
    bio_markdown: str = "",
    operator: Entity | None = None,
    framework_source: str | None = None,
    registration_ip: str | None = None,
) -> tuple[Entity, str]:
    """Register an agent directly via API (no operator required).

    Agents registered without an operator are marked as provisional.
    Provisional agents have limited capabilities until claimed by an operator.

    Returns (agent, plaintext_api_key).
    """
    from datetime import datetime, timedelta, timezone

    from src.config import settings

    agent_id = uuid.uuid4()
    is_provisional = operator is None
    claim_token = secrets.token_urlsafe(48) if is_provisional else None
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=30) if is_provisional else None
    )

    # Resolve framework trust modifier
    framework_modifier = None
    if framework_source:
        framework_modifier = settings.framework_trust_modifiers.get(
            framework_source.lower(), 1.0
        )

    agent = Entity(
        id=agent_id,
        type=EntityType.AGENT,
        display_name=display_name,
        did_web=generate_agent_did(agent_id),
        capabilities=capabilities or [],
        autonomy_level=autonomy_level,
        operator_id=operator.id if operator else None,
        bio_markdown=bio_markdown,
        is_provisional=is_provisional,
        claim_token=claim_token,
        provisional_expires_at=expires_at,
        framework_source=framework_source,
        framework_trust_modifier=framework_modifier,
        registration_ip=registration_ip,
    )
    db.add(agent)
    await db.flush()

    # Create DID document with appropriate status
    did_doc = DIDDocument(
        id=uuid.uuid4(),
        entity_id=agent.id,
        did_uri=agent.did_web,
        document={},
        did_status=DIDStatus.PROVISIONAL if is_provisional else DIDStatus.FULL,
    )
    db.add(did_doc)

    # Link operator if provided
    if operator:
        rel = EntityRelationship(
            id=uuid.uuid4(),
            source_entity_id=operator.id,
            target_entity_id=agent.id,
            type=RelationshipType.OPERATOR_AGENT,
        )
        db.add(rel)

    # Generate and store API key — provisional agents get restricted scopes
    plaintext_key = generate_api_key()
    scopes = (
        ["agent:read", "agent:write:limited"]
        if is_provisional
        else ["agent:read", "agent:write", "webhooks:manage"]
    )
    api_key = APIKey(
        id=uuid.uuid4(),
        entity_id=agent.id,
        key_hash=hash_api_key(plaintext_key),
        label="default",
        scopes=scopes,
    )
    db.add(api_key)
    await db.flush()

    return agent, plaintext_key


async def get_operator_agents(
    db: AsyncSession, operator_id: uuid.UUID
) -> list[Entity]:
    result = await db.execute(
        select(Entity).where(
            Entity.operator_id == operator_id,
            Entity.type == EntityType.AGENT,
        )
    )
    return list(result.scalars().all())


async def get_agent_by_id(
    db: AsyncSession, agent_id: uuid.UUID
) -> Entity | None:
    entity = await db.get(Entity, agent_id)
    if entity is None or entity.type != EntityType.AGENT:
        return None
    return entity


async def rotate_api_key(
    db: AsyncSession, agent: Entity
) -> str:
    """Revoke all active keys and issue a new one. Returns plaintext key."""
    from datetime import datetime, timezone

    # Revoke existing active keys
    result = await db.execute(
        select(APIKey).where(
            APIKey.entity_id == agent.id,
            APIKey.is_active.is_(True),
        )
    )
    for key in result.scalars().all():
        key.is_active = False
        key.revoked_at = datetime.now(timezone.utc)

    # Issue new key
    plaintext_key = generate_api_key()
    new_key = APIKey(
        id=uuid.uuid4(),
        entity_id=agent.id,
        key_hash=hash_api_key(plaintext_key),
        label="default",
        scopes=["agent:read", "agent:write", "webhooks:manage"],
    )
    db.add(new_key)
    await db.flush()

    return plaintext_key


async def authenticate_by_api_key(
    db: AsyncSession, plaintext_key: str
) -> Entity | None:
    key_hash = hash_api_key(plaintext_key)
    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.is_active.is_(True),
        )
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        return None

    entity = await db.get(Entity, api_key.entity_id)
    if entity is None or not entity.is_active:
        return None

    # Best-effort engagement counter (Redis, never blocks auth).
    from src.api.metrics_dashboard_router import bump_metric

    await bump_metric("api_call")
    return entity
