"""Admin endpoints for the operator recruitment dashboard."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity, require_admin
from src.database import get_db
from src.models import Entity, RecruitmentProspect

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/recruitment", tags=["admin-recruitment"])


class ProspectOut(BaseModel):
    id: str
    platform: str
    platform_id: str
    owner_login: str
    repo_name: str | None
    stars: int | None
    description: str | None
    framework_detected: str | None
    status: str
    contacted_at: str | None
    issue_url: str | None
    notes: str | None
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class ProspectUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None


class RecruitmentStats(BaseModel):
    total: int
    discovered: int
    contacted: int
    visited: int
    registered: int
    onboarded: int
    active: int
    skipped: int
    declined: int


def _prospect_to_out(p: RecruitmentProspect) -> ProspectOut:
    return ProspectOut(
        id=str(p.id),
        platform=p.platform,
        platform_id=p.platform_id,
        owner_login=p.owner_login,
        repo_name=p.repo_name,
        stars=p.stars,
        description=p.description,
        framework_detected=p.framework_detected,
        status=p.status or "discovered",
        contacted_at=p.contacted_at.isoformat() if p.contacted_at else None,
        issue_url=p.issue_url,
        notes=p.notes,
        created_at=p.created_at.isoformat() if p.created_at else "",
        updated_at=p.updated_at.isoformat() if p.updated_at else "",
    )


@router.get("/prospects")
async def list_prospects(
    status: str | None = Query(None),
    platform: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List recruitment prospects with optional filters."""
    require_admin(current_entity)

    q = select(RecruitmentProspect).order_by(
        RecruitmentProspect.stars.desc().nullslast(),
    )
    count_q = select(func.count(RecruitmentProspect.id))

    if status:
        q = q.where(RecruitmentProspect.status == status)
        count_q = count_q.where(RecruitmentProspect.status == status)
    if platform:
        q = q.where(RecruitmentProspect.platform == platform)
        count_q = count_q.where(RecruitmentProspect.platform == platform)

    total = await db.scalar(count_q) or 0
    results = (await db.scalars(q.offset(offset).limit(limit))).all()

    return {
        "prospects": [_prospect_to_out(p) for p in results],
        "total": total,
        "has_more": offset + limit < total,
    }


@router.get("/stats")
async def recruitment_stats(
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> RecruitmentStats:
    """Get recruitment funnel stats."""
    require_admin(current_entity)

    rows = (
        await db.execute(
            select(
                RecruitmentProspect.status,
                func.count(RecruitmentProspect.id),
            ).group_by(RecruitmentProspect.status)
        )
    ).all()

    counts: dict[str, int] = {row[0]: row[1] for row in rows}
    total = sum(counts.values())

    return RecruitmentStats(
        total=total,
        discovered=counts.get("discovered", 0),
        contacted=counts.get("contacted", 0),
        visited=counts.get("visited", 0),
        registered=counts.get("registered", 0),
        onboarded=counts.get("onboarded", 0),
        active=counts.get("active", 0),
        skipped=counts.get("skipped", 0),
        declined=counts.get("declined", 0),
    )


@router.patch("/prospects/{prospect_id}")
async def update_prospect(
    prospect_id: uuid.UUID,
    body: ProspectUpdate,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> ProspectOut:
    """Update a recruitment prospect's status or notes."""
    require_admin(current_entity)

    prospect = await db.get(RecruitmentProspect, prospect_id)
    if not prospect:
        raise HTTPException(status_code=404, detail="Prospect not found")

    if body.status is not None:
        valid_statuses = {
            "discovered", "queued", "contacted", "visited", "registered",
            "onboarded", "active", "promoting", "declined", "skipped",
        }
        if body.status not in valid_statuses:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status. Must be one of: {sorted(valid_statuses)}",
            )
        prospect.status = body.status
    if body.notes is not None:
        prospect.notes = body.notes

    await db.flush()
    await db.refresh(prospect)
    return _prospect_to_out(prospect)


@router.post("/radar/run")
async def run_radar(
    limit: int = Query(25, le=100),
    discover: bool = Query(True),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fire one developer-radar cycle in the background: refresh GitHub discovery,
    then scan + rank new prospects into the ``queued`` outreach list. Human-gated —
    it NEVER contacts anyone. Poll ``/radar/queue`` for results."""
    require_admin(current_entity)

    import asyncio

    from src.database import async_session
    from src.jobs.developer_radar import run_developer_radar

    async def _bg() -> None:
        try:
            async with async_session() as s:
                await run_developer_radar(s, discover=discover, limit=limit)
        except Exception:
            logger.exception("radar background cycle failed")

    asyncio.create_task(_bg())
    return {"ok": True, "status": "started",
            "note": "Radar running in the background — poll /admin/recruitment/radar/queue."}


@router.get("/radar/queue")
async def radar_queue(
    limit: int = Query(50, le=200),
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """The ranked outreach queue — scored prospects, highest outreach-priority first.
    Each item carries the score, whether it already shows shields, the recommended
    channel (badge-ask vs value-first/fix), and the angle. Kenne sends manually."""
    require_admin(current_entity)

    import json

    rows = (await db.scalars(
        select(RecruitmentProspect)
        .where(RecruitmentProspect.status == "queued")
        .limit(limit)
    )).all()

    items = []
    for p in rows:
        try:
            enr = json.loads(p.notes) if p.notes else {}
        except Exception:
            enr = {}
        items.append({
            "full_name": p.platform_id, "owner": p.owner_login, "repo": p.repo_name,
            "stars": p.stars, "framework": p.framework_detected, **enr,
        })
    items.sort(key=lambda x: x.get("priority", 0), reverse=True)
    return {"queue": items, "total": len(items)}
