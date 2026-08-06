"""Per-account alert webhook — set/clear/test a URL that receives grade-change
alerts for the user's watched tools (webhook alert-delivery)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import AlertWebhook, Entity

router = APIRouter(prefix="/account/alert-webhook", tags=["account"])


class SetWebhookRequest(BaseModel):
    url: HttpUrl


def _serialize(w: AlertWebhook | None) -> dict:
    if w is None:
        return {"url": None, "active": False, "last_status": None}
    return {
        "url": w.url,
        "active": w.active,
        "last_status": w.last_status,
        "last_delivery_at": w.last_delivery_at.isoformat() if w.last_delivery_at else None,
    }


async def _get(entity_id, db: AsyncSession) -> AlertWebhook | None:
    result = await db.execute(select(AlertWebhook).where(AlertWebhook.entity_id == entity_id))
    return result.scalar_one_or_none()


@router.get("")
async def get_webhook(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reads),
):
    return _serialize(await _get(entity.id, db))


@router.put("")
async def set_webhook(
    body: SetWebhookRequest,
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    existing = await _get(entity.id, db)
    if existing is None:
        existing = AlertWebhook(entity_id=entity.id, url=str(body.url), active=True)
        db.add(existing)
    else:
        existing.url = str(body.url)
        existing.active = True
    await db.flush()
    await db.refresh(existing)
    return _serialize(existing)


@router.delete("", status_code=204)
async def delete_webhook(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    existing = await _get(entity.id, db)
    if existing is not None:
        await db.delete(existing)
        await db.flush()


@router.post("/test")
async def test_webhook(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Send a sample payload so the user can confirm their endpoint receives it."""
    hook = await _get(entity.id, db)
    if hook is None:
        raise HTTPException(status_code=404, detail="No webhook configured")
    payload = {
        "type": "agentavow.alert.test",
        "message": "Test alert from AgentAvow — your webhook is wired up.",
        "owner": "agentavow",
        "repo": "example",
        "old_score": 92,
        "new_score": 74,
        "reason": "grade dropped",
    }
    status = None
    try:
        import httpx

        async with httpx.AsyncClient(timeout=6) as client:
            resp = await client.post(hook.url, json=payload)
        status = resp.status_code
    except Exception:
        status = 0
    from sqlalchemy import func as safunc

    hook.last_status = status
    hook.last_delivery_at = safunc.now()
    await db.flush()
    ok = status is not None and 200 <= status < 300
    return {"delivered": ok, "status": status}
