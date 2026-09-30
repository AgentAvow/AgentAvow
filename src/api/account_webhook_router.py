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


async def deliver_alert_webhook(url: str, payload: dict) -> int:
    """POST an alert to an account's webhook URL. Returns the HTTP status, or 0 when
    the request was refused or failed.

    The URL is supplied by the account holder, so it is never fetched with a plain
    client: it must be a public https:// address, the connection is pinned to the
    address that was validated (no DNS rebind), and redirects are not followed.
    Validation happens here as well as when the URL is saved, because a hostname
    that was public then can point somewhere internal now.
    """
    from src.ssrf import ssrf_safe_async_client, validate_url_https

    try:
        validate_url_https(url, field_name="url")
        async with ssrf_safe_async_client(timeout=6, follow_redirects=False) as client:
            resp = await client.post(url, json=payload)
        return resp.status_code
    except Exception:
        return 0


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
    from src.ssrf import validate_url_https

    try:
        url = validate_url_https(str(body.url), field_name="url")
    except ValueError:
        raise HTTPException(status_code=422, detail="url must be a public https:// address")
    existing = await _get(entity.id, db)
    if existing is None:
        existing = AlertWebhook(entity_id=entity.id, url=url, active=True)
        db.add(existing)
    else:
        existing.url = url
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
        "reason": "score dropped",
    }
    status = await deliver_alert_webhook(hook.url, payload)
    from sqlalchemy import func as safunc

    hook.last_status = status
    hook.last_delivery_at = safunc.now()
    await db.flush()
    return {"delivered": 200 <= status < 300, "status": status}
