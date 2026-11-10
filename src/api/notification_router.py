"""In-app notification endpoints.

Provides notification management for entity activities like
follows, replies, votes, and mentions. Persisted to database.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.audit import log_action
from src.database import get_db
from src.models import Entity, EntityType, Notification, NotificationPreference

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

_background_tasks: set[asyncio.Task] = set()


# --- Public helper for creating notifications from other modules ---


_KIND_TO_PREF = {
    "follow": "follow_enabled",
    "reply": "reply_enabled",
    "vote": "vote_enabled",
    "mention": "mention_enabled",
    "endorsement": "endorsement_enabled",
    "review": "review_enabled",
    "moderation": "moderation_enabled",
    "message": "message_enabled",
    "issue_resolution": "issue_resolution_enabled",
}

_KIND_TO_WEBHOOK_EVENT = {
    "follow": "entity.followed",
    "reply": "post.replied",
    "vote": "post.voted",
    "mention": "entity.mentioned",
    "endorsement": "entity.mentioned",
    "review": "entity.mentioned",
    "moderation": "moderation.flagged",
    "message": "entity.messaged",
}


async def create_notification(
    db: AsyncSession,
    entity_id: uuid.UUID,
    kind: str,
    title: str,
    body: str,
    reference_id: str | None = None,
    actor_entity_id: uuid.UUID | None = None,
) -> Notification | None:
    """Create a notification for an entity (persisted to DB).

    Also dispatches webhooks for the event (regardless of notification
    preferences) and broadcasts via WebSocket.

    If actor_entity_id is provided, checks privacy tier: if the actor
    is PRIVATE and the recipient does not follow them, the notification
    body is masked to hide the actor's identity.

    Returns None if the entity has disabled this notification kind.
    """
    # Privacy masking: if the actor is PRIVATE, mask their name
    # for recipients who don't follow them
    if actor_entity_id is not None:
        from src.api.privacy import check_privacy_access

        actor = await db.get(Entity, actor_entity_id)
        recipient = await db.get(Entity, entity_id)
        if actor and recipient:
            has_access = await check_privacy_access(actor, recipient, db)
            if not has_access:
                body = _mask_actor_name(body, actor.display_name)
                title = _mask_actor_name(title, actor.display_name)
    # Dispatch webhooks (always, regardless of notification preferences)
    webhook_event = _KIND_TO_WEBHOOK_EVENT.get(kind)
    if webhook_event:
        try:
            from src.events import dispatch_webhooks

            await dispatch_webhooks(
                db,
                webhook_event,
                {
                    "entity_id": str(entity_id),
                    "kind": kind,
                    "title": title,
                    "body": body,
                    "reference_id": reference_id,
                },
            )
        except Exception:
            logger.warning("Webhook delivery failed", exc_info=True)

    # Check notification preferences
    pref_field = _KIND_TO_PREF.get(kind)
    if pref_field:
        pref = await db.scalar(
            select(NotificationPreference).where(
                NotificationPreference.entity_id == entity_id,
            )
        )
        if pref and not getattr(pref, pref_field, True):
            return None

    notif = Notification(
        id=uuid.uuid4(),
        entity_id=entity_id,
        kind=kind,
        title=title,
        body=body,
        reference_id=reference_id,
    )
    db.add(notif)
    await db.flush()

    # Invalidate unread count cache
    from src import cache
    await cache.invalidate(f"notif:unread:{entity_id}")

    # Broadcast via WebSocket if available
    try:
        from src.ws import manager

        await manager.send_to_entity(
            str(entity_id),
            "notifications",
            {
                "type": "notification",
                "notification": {
                    "id": str(notif.id),
                    "kind": kind,
                    "title": title,
                    "body": body,
                    "reference_id": reference_id,
                },
            },
        )
    except Exception:
        logger.warning("WebSocket delivery failed", exc_info=True)

    # Send email notification for social events (fire-and-forget)
    # Per-kind email toggles: field name + default value
    # Only DMs, moderation, mentions, and issue resolution send emails by default.
    # Replies, endorsements, reviews, follows, and votes do NOT send emails.
    kind_email_prefs: dict[str, tuple[str, bool]] = {
        # Replies, endorsements, reviews, follows, votes — email disabled until
        # cheaper provider (SES) is available. See taskmaster task for re-enablement.
        "mention": ("email_mention_enabled", True),
        "moderation": ("email_moderation_enabled", True),
        "message": ("email_message_enabled", True),
        "issue_resolution": ("email_issue_resolution_enabled", True),
    }
    if kind in kind_email_prefs or kind == "issue_resolution":
        try:
            email_pref = pref if pref_field else None
            # Determine if email should be sent
            should_email = True
            if email_pref and not getattr(email_pref, "email_notifications_enabled", True):
                should_email = False  # global email disabled
            elif kind in kind_email_prefs:
                field, default = kind_email_prefs[kind]
                should_email = getattr(email_pref, field, default) if email_pref else default

            if should_email:
                entity = await db.get(Entity, entity_id)
                if (
                    entity
                    and entity.email_verified
                    and entity.type == EntityType.HUMAN
                    and entity.email
                ):
                    import asyncio

                    from src.config import settings
                    from src.email import send_social_notification_email

                    action_url = f"{settings.base_url}/notifications"
                    if kind == "message":
                        action_url = f"{settings.base_url}/messages"
                    elif kind == "moderation":
                        action_url = f"{settings.base_url}/settings"
                    elif reference_id:
                        action_url = f"{settings.base_url}/post/{reference_id}"

                    _task = asyncio.create_task(
                        send_social_notification_email(
                            to=entity.email,
                            entity_name=entity.display_name or "there",
                            title=title,
                            body=body,
                            action_url=action_url,
                        )
                    )
                    _background_tasks.add(_task)
                    _task.add_done_callback(_background_tasks.discard)
        except Exception:
            logger.warning("Social email dispatch failed", exc_info=True)

    return notif


# --- Schemas ---


class NotificationResponse(BaseModel):
    id: uuid.UUID
    kind: str
    title: str
    body: str
    reference_id: str | None
    is_read: bool
    created_at: str

    model_config = {"from_attributes": True}


class NotificationListResponse(BaseModel):
    notifications: list[NotificationResponse]
    unread_count: int
    total: int


# --- Endpoints ---

_MAX_KINDS = 20


def _parse_kinds(kind: str | None) -> list[str]:
    """``kind`` takes one kind or a comma-separated list (``watch_alert,watch_good_news``).

    A single value behaves exactly as before. Blank entries are dropped; an all-blank
    value means "no filter".
    """
    if not kind:
        return []
    kinds = list(dict.fromkeys(k.strip() for k in kind.split(",") if k.strip()))
    if len(kinds) > _MAX_KINDS:
        raise HTTPException(status_code=422, detail=f"At most {_MAX_KINDS} kinds")
    return kinds



@router.get(
    "", response_model=NotificationListResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_notifications(
    unread_only: bool = Query(False),
    kind: str | None = Query(None, max_length=500),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get notifications for the current entity. Filter by kind (e.g. follow, reply,
    vote), or by several kinds as a comma-separated list
    (``kind=watch_alert,watch_good_news``). ``total`` and ``unread_count`` stay
    account-wide."""
    query = select(Notification).where(
        Notification.entity_id == current_entity.id,
    )
    if unread_only:
        query = query.where(Notification.is_read.is_(False))
    kinds = _parse_kinds(kind)
    if len(kinds) == 1:
        query = query.where(Notification.kind == kinds[0])
    elif kinds:
        query = query.where(Notification.kind.in_(kinds))

    query = query.order_by(Notification.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    notifications = result.scalars().all()

    # Get counts
    total = await db.scalar(
        select(func.count()).select_from(Notification).where(
            Notification.entity_id == current_entity.id,
        )
    ) or 0

    unread_count = await db.scalar(
        select(func.count()).select_from(Notification).where(
            Notification.entity_id == current_entity.id,
            Notification.is_read.is_(False),
        )
    ) or 0

    return NotificationListResponse(
        notifications=[
            NotificationResponse(
                id=n.id,
                kind=n.kind,
                title=n.title,
                body=n.body,
                reference_id=n.reference_id,
                is_read=n.is_read,
                created_at=n.created_at.isoformat(),
            )
            for n in notifications
        ],
        unread_count=unread_count,
        total=total,
    )


@router.post("/{notification_id}/read", dependencies=[Depends(rate_limit_writes)])
async def mark_as_read(
    notification_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Mark a notification as read."""
    notif = await db.get(Notification, notification_id)
    if notif is None or notif.entity_id != current_entity.id:
        raise HTTPException(
            status_code=404, detail="Notification not found",
        )

    notif.is_read = True
    await db.flush()

    from src import cache
    await cache.invalidate(f"notif:unread:{current_entity.id}")

    await log_action(
        db,
        action="notification.read",
        entity_id=current_entity.id,
        resource_type="notification",
        resource_id=notification_id,
    )

    return {"message": "Marked as read"}


@router.post("/read-all", dependencies=[Depends(rate_limit_writes)])
async def mark_all_as_read(
    kind: str | None = Query(None, max_length=500),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Mark all notifications as read, or only those of the given kind(s)
    (one kind or a comma-separated list, as on GET)."""
    stmt = update(Notification).where(
        Notification.entity_id == current_entity.id,
        Notification.is_read.is_(False),
    )
    kinds = _parse_kinds(kind)
    if kinds:
        stmt = stmt.where(Notification.kind.in_(kinds))
    result = await db.execute(stmt.values(is_read=True))
    count = result.rowcount
    await db.flush()

    from src import cache
    await cache.invalidate(f"notif:unread:{current_entity.id}")

    await log_action(
        db,
        action="notification.read_all",
        entity_id=current_entity.id,
        resource_type="notification",
        details={"count": count, **({"kinds": kinds} if kinds else {})},
    )

    return {"message": f"Marked {count} notifications as read"}


@router.delete("/{notification_id}", dependencies=[Depends(rate_limit_writes)])
async def delete_notification(
    notification_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Delete a notification."""
    notif = await db.get(Notification, notification_id)
    if notif is None or notif.entity_id != current_entity.id:
        raise HTTPException(
            status_code=404, detail="Notification not found",
        )

    await db.delete(notif)
    await db.flush()

    await log_action(
        db,
        action="notification.delete",
        entity_id=current_entity.id,
        resource_type="notification",
        resource_id=notification_id,
    )

    return {"message": "Notification deleted"}


@router.get("/unread-count", dependencies=[Depends(rate_limit_reads)])
async def unread_count(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the count of unread notifications."""
    from src import cache

    cache_key = f"notif:unread:{current_entity.id}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    count = await db.scalar(
        select(func.count()).select_from(Notification).where(
            Notification.entity_id == current_entity.id,
            Notification.is_read.is_(False),
        )
    ) or 0
    result = {"unread_count": count}
    await cache.set(cache_key, result, cache.TTL_SHORT)
    return result


# --- Notification Preferences ---


class NotificationPreferencesResponse(BaseModel):
    follow_enabled: bool = True
    reply_enabled: bool = True
    vote_enabled: bool = True
    mention_enabled: bool = True
    endorsement_enabled: bool = True
    review_enabled: bool = True
    moderation_enabled: bool = True
    message_enabled: bool = True
    issue_resolution_enabled: bool = True
    email_notifications_enabled: bool = True
    email_mention_enabled: bool = True
    email_moderation_enabled: bool = True
    email_message_enabled: bool = True
    email_issue_resolution_enabled: bool = True


class UpdatePreferencesRequest(BaseModel):
    follow_enabled: bool | None = None
    reply_enabled: bool | None = None
    vote_enabled: bool | None = None
    mention_enabled: bool | None = None
    endorsement_enabled: bool | None = None
    review_enabled: bool | None = None
    moderation_enabled: bool | None = None
    message_enabled: bool | None = None
    issue_resolution_enabled: bool | None = None
    email_notifications_enabled: bool | None = None
    email_mention_enabled: bool | None = None
    email_moderation_enabled: bool | None = None
    email_message_enabled: bool | None = None
    email_issue_resolution_enabled: bool | None = None


@router.get(
    "/preferences", response_model=NotificationPreferencesResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_notification_preferences(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get notification preferences for the current entity."""
    pref = await db.scalar(
        select(NotificationPreference).where(
            NotificationPreference.entity_id == current_entity.id,
        )
    )
    if pref is None:
        return NotificationPreferencesResponse()

    return NotificationPreferencesResponse(
        follow_enabled=pref.follow_enabled,
        reply_enabled=pref.reply_enabled,
        vote_enabled=pref.vote_enabled,
        mention_enabled=pref.mention_enabled,
        endorsement_enabled=pref.endorsement_enabled,
        review_enabled=pref.review_enabled,
        moderation_enabled=pref.moderation_enabled,
        message_enabled=getattr(pref, "message_enabled", True),
        issue_resolution_enabled=getattr(pref, "issue_resolution_enabled", True),
        email_notifications_enabled=getattr(pref, "email_notifications_enabled", True),
        email_mention_enabled=getattr(pref, "email_mention_enabled", True),
        email_moderation_enabled=getattr(pref, "email_moderation_enabled", True),
        email_message_enabled=getattr(pref, "email_message_enabled", True),
        email_issue_resolution_enabled=getattr(pref, "email_issue_resolution_enabled", True),
    )


@router.patch(
    "/preferences", response_model=NotificationPreferencesResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def update_notification_preferences(
    body: UpdatePreferencesRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Update notification preferences."""
    pref = await db.scalar(
        select(NotificationPreference).where(
            NotificationPreference.entity_id == current_entity.id,
        )
    )
    if pref is None:
        pref = NotificationPreference(
            id=uuid.uuid4(),
            entity_id=current_entity.id,
        )
        db.add(pref)

    update_fields = body.model_dump(exclude_unset=True)
    for field, value in update_fields.items():
        setattr(pref, field, value)

    await db.flush()
    await db.refresh(pref)

    await log_action(
        db,
        action="notification.preferences_update",
        entity_id=current_entity.id,
        resource_type="notification_preference",
        details={"fields": list(update_fields.keys())},
    )

    return NotificationPreferencesResponse(
        follow_enabled=pref.follow_enabled,
        reply_enabled=pref.reply_enabled,
        vote_enabled=pref.vote_enabled,
        mention_enabled=pref.mention_enabled,
        endorsement_enabled=pref.endorsement_enabled,
        review_enabled=pref.review_enabled,
        moderation_enabled=pref.moderation_enabled,
        message_enabled=getattr(pref, "message_enabled", True),
        issue_resolution_enabled=getattr(pref, "issue_resolution_enabled", True),
        email_notifications_enabled=getattr(pref, "email_notifications_enabled", True),
        email_mention_enabled=getattr(pref, "email_mention_enabled", True),
        email_moderation_enabled=getattr(pref, "email_moderation_enabled", True),
        email_message_enabled=getattr(pref, "email_message_enabled", True),
        email_issue_resolution_enabled=getattr(pref, "email_issue_resolution_enabled", True),
    )


def _mask_actor_name(text: str, display_name: str) -> str:
    """Replace an actor's display name with 'Someone' for privacy masking."""
    if display_name and display_name in text:
        return text.replace(display_name, "Someone")
    return text
