"""Tool-watch / alert API — watch a tool for grade or signed-definition changes.

The re-scan + notification loop lives in src/jobs/scheduler.py (_watch_rescan_loop).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.database import get_db
from src.models import Entity, ToolWatch

router = APIRouter(tags=["watches"])


class WatchCreate(BaseModel):
    owner: str
    repo: str


def _serialize(w: ToolWatch) -> dict:
    return {
        "id": str(w.id),
        "owner": w.owner,
        "repo": w.repo,
        "last_score": w.last_score,
        "active": w.active,
    }


@router.post("/watches", status_code=status.HTTP_201_CREATED)
async def add_watch(
    body: WatchCreate,
    current: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    watcher_id = current.id  # snapshot before any awaits that may shift the session
    owner = body.owner.strip().strip("/")
    repo = body.repo.strip().strip("/")
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="owner and repo are required")

    existing = (
        await db.execute(
            select(ToolWatch).where(
                ToolWatch.watcher_id == watcher_id,
                ToolWatch.owner == owner,
                ToolWatch.repo == repo,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if not existing.active:
            existing.active = True
            await db.commit()
        return _serialize(existing)

    # Best-effort baseline scan so the first change is measured against a known score.
    last_score = None
    last_digest = None
    try:
        from src.api.public_scan_router import public_scan

        res = await public_scan(owner=owner, repo=repo, force=False, db=db)
        last_score = res.trust_score
        last_digest = res.tool_manifest_digest
    except Exception:
        pass  # loop will populate the baseline on its first run

    watch = ToolWatch(
        watcher_id=watcher_id,
        owner=owner,
        repo=repo,
        last_score=last_score,
        last_manifest_digest=last_digest,
    )
    db.add(watch)
    await db.commit()
    await db.refresh(watch)
    return _serialize(watch)


@router.get("/watches")
async def list_watches(
    current: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    rows = (
        await db.execute(
            select(ToolWatch)
            .where(ToolWatch.watcher_id == current.id, ToolWatch.active.is_(True))
            .order_by(ToolWatch.created_at.desc())
        )
    ).scalars().all()
    return [_serialize(w) for w in rows]


@router.delete("/watches/{watch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_watch(
    watch_id: uuid.UUID,
    current: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> None:
    watch = await db.get(ToolWatch, watch_id)
    if watch is None or watch.watcher_id != current.id:
        raise HTTPException(status_code=404, detail="Watch not found")
    await db.delete(watch)
    await db.commit()
