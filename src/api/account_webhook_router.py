"""Per-account alert webhook — set/clear/test a URL that receives grade-change
alerts for the user's watched tools (webhook alert-delivery)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import AlertWebhook, Entity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/account/alert-webhook", tags=["account"])


class SetWebhookRequest(BaseModel):
    url: HttpUrl


SIGNATURE_HEADER = "X-AgentAvow-Signature"
TIMESTAMP_HEADER = "X-AgentAvow-Timestamp"


def new_signing_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def sign_alert(secret: str, timestamp: str, body: bytes) -> str:
    """``sha256=<hex>``: HMAC-SHA256 over ``<timestamp>.<body>`` with the webhook's
    secret. The timestamp is inside the MAC so a captured delivery cannot be replayed
    later under a fresh one."""
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body,
                   hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def webhook_secret(hook: AlertWebhook) -> str | None:
    """The plaintext signing secret for ``hook``, or None if it has none."""
    if not hook.signing_key:
        return None
    from src.encryption import decrypt_secret

    return decrypt_secret(hook.signing_key)


async def deliver_alert_webhook(url: str, payload: dict, secret: str | None = None) -> int:
    """POST an alert to an account's webhook URL. Returns the HTTP status, or 0 when
    the request was refused or failed.

    With ``secret`` the delivery carries ``X-AgentAvow-Timestamp`` and
    ``X-AgentAvow-Signature``; the signature covers the exact bytes sent.

    The URL is supplied by the account holder, so it is never fetched with a plain
    client: it must be a public https:// address, the connection is pinned to the
    address that was validated (no DNS rebind), and redirects are not followed.
    Validation happens here as well as when the URL is saved, because a hostname
    that was public then can point somewhere internal now.
    """
    from src.ssrf import ssrf_safe_async_client, validate_url_https

    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "AgentAvow-Alert/1.0"}
    if secret:
        timestamp = str(int(time.time()))
        headers[TIMESTAMP_HEADER] = timestamp
        headers[SIGNATURE_HEADER] = sign_alert(secret, timestamp, body)
    try:
        validate_url_https(url, field_name="url")
        async with ssrf_safe_async_client(timeout=6, follow_redirects=False) as client:
            resp = await client.post(url, content=body, headers=headers)
        return resp.status_code
    except Exception:
        return 0


def _serialize(w: AlertWebhook | None) -> dict:
    if w is None:
        return {"url": None, "active": False, "signed": False, "last_status": None}
    return {
        "url": w.url,
        "active": w.active,
        "signed": bool(w.signing_key),
        "last_status": w.last_status,
        "last_delivery_at": w.last_delivery_at.isoformat() if w.last_delivery_at else None,
    }


async def _get(entity_id, db: AsyncSession) -> AlertWebhook | None:
    result = await db.execute(select(AlertWebhook).where(AlertWebhook.entity_id == entity_id))
    return result.scalar_one_or_none()


async def deliver_to_hook(hook: AlertWebhook, payload: dict) -> int:
    """Deliver to a saved webhook, signed with its secret. A webhook whose secret
    cannot be read is not delivered at all: sending it unsigned would look, to a
    receiver that checks signatures, like a forgery."""
    try:
        secret = webhook_secret(hook)
    except Exception:
        logger.error("alert webhook %s: signing secret unreadable, not delivered", hook.id)
        return 0
    return await deliver_alert_webhook(hook.url, payload, secret)


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
    # A webhook without a secret gets one now. It is returned in this response only.
    issued = None if existing.signing_key else _issue_secret(existing)
    await db.flush()
    await db.refresh(existing)
    out = _serialize(existing)
    if issued:
        out["signing_secret"] = issued
    return out


def _issue_secret(hook: AlertWebhook) -> str:
    from src.encryption import encrypt_secret

    secret = new_signing_secret()
    try:
        hook.signing_key = encrypt_secret(secret)
    except RuntimeError:
        # WEBHOOK_ENCRYPTION_KEY is not configured: refuse rather than store the
        # secret in plaintext or deliver unsigned.
        raise HTTPException(status_code=503, detail="Webhook signing is not configured")
    return secret


@router.post("/rotate-secret")
async def rotate_secret(
    entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_writes),
):
    """Replace the signing secret. The new one is shown once; the old one stops
    verifying immediately."""
    hook = await _get(entity.id, db)
    if hook is None:
        raise HTTPException(status_code=404, detail="No webhook configured")
    secret = _issue_secret(hook)
    await db.flush()
    return {"signing_secret": secret}


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
    status = await deliver_to_hook(hook, payload)
    from sqlalchemy import func as safunc

    hook.last_status = status
    hook.last_delivery_at = safunc.now()
    await db.flush()
    return {"delivered": 200 <= status < 300, "status": status}
