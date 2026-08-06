"""User-facing API key management for the AgentAvow account.

The APIKey model + org-scoped endpoints already existed; this adds the
per-user (entity) create / list / revoke a developer needs to call the public
scan API programmatically. Keys are shown once on creation (only the hash is
stored).
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import APIKey, Entity

router = APIRouter(prefix="/account/api-keys", tags=["account"])


class CreateKeyRequest(BaseModel):
    label: str = Field("default", max_length=100)


def _serialize(k: APIKey) -> dict:
    return {
        "id": str(k.id),
        "label": k.label,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    }


@router.post("", status_code=201)
async def create_key(
    body: CreateKeyRequest,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Create a personal API key. The plaintext key is returned once — store it."""
    raw_key = f"ag_live_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = APIKey(entity_id=entity.id, key_hash=key_hash, label=body.label[:100])
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)
    return {**_serialize(api_key), "key": raw_key}


@router.get("")
async def list_keys(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    """List the caller's active API keys (hashes only — the raw key is never stored)."""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.entity_id == entity.id, APIKey.is_active.is_(True))
        .order_by(APIKey.created_at.desc())
    )
    return {"keys": [_serialize(k) for k in result.scalars().all()]}


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: uuid.UUID,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Revoke (deactivate) a personal API key."""
    from sqlalchemy import func as safunc

    key = await db.get(APIKey, key_id)
    if key is None or key.entity_id != entity.id:
        raise HTTPException(status_code=404, detail="Key not found")
    key.is_active = False
    key.revoked_at = safunc.now()
    await db.flush()
