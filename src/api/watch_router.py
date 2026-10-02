"""Tool-watch / alert API — watch a tool for grade or signed-definition changes.

The re-scan + notification loop lives in src/jobs/scheduler.py (_watch_rescan_loop).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.database import get_db
from src.models import Entity, ToolWatch

router = APIRouter(tags=["watches"])


class WatchCreate(BaseModel):
    # 'github' (owner/repo) · 'npm'/'pypi'/'docker' (owner=surface, repo=pkg) · 'mcp'
    # (owner='mcp', repo=url) · 'openclaw' (owner/repo skill). Default github.
    surface: str = "github"
    owner: str
    repo: str


def _serialize(w: ToolWatch) -> dict:
    return {
        "id": str(w.id),
        "surface": getattr(w, "surface", "github") or "github",
        "owner": w.owner,
        "repo": w.repo,
        "last_score": w.last_score,
        "active": w.active,
    }


@dataclass
class WatchScan:
    """One re-scan of a watch target. ``data`` carries just the scan fields the
    behavioral (sandbox) lookup keys on — package coordinate, declared scope, artifact
    detail, env reads — plus the ``behavioral`` block itself when the scan path already
    resolved it (the GitHub public_scan path does). Empty for surfaces with no sandbox
    tier (mcp, openclaw)."""

    score: int | None
    digest: str | None
    data: dict = field(default_factory=dict)


def _package_scan_data(surface: str, name: str, r) -> dict:
    return {
        "package_coordinate": {"surface": surface, "name": name},
        "declared_scope": getattr(r, "declared_scope", {}) or {},
        "artifact_scan": getattr(r, "artifact_scan", {}) or {},
        "env_reads": list(getattr(r, "env_reads", []) or []),
    }


async def scan_watch_target_detail(
    surface: str, owner: str, repo: str, db: AsyncSession,
) -> WatchScan:
    """Scan a watch target by surface → WatchScan(score, tool_manifest_digest, data).
    Fail-open (score None on error); the loop retries next cycle."""
    surface = (surface or "github").lower()
    try:
        if surface in ("npm", "pypi", "docker"):
            from src.scanner.scan import scan_package
            r = await scan_package(surface, repo)
            return WatchScan(
                None if r.error else r.trust_score, None,
                {} if r.error else _package_scan_data(surface, repo, r),
            )
        if surface == "mcp":
            from src.scanner.scan import scan_mcp
            r = await scan_mcp(repo)
            return WatchScan(
                (None if r.error else r.trust_score),
                (getattr(r, "tool_manifest_digest", None) or None),
            )
        if surface == "openclaw":
            from src.scanner.scan import scan_skill
            r = await scan_skill(owner, repo)
            return WatchScan(None if r.error else r.trust_score, r.tool_manifest_digest or None)
        # default: github repo
        from src.api.public_scan_router import public_scan
        res = await public_scan(owner=owner, repo=repo, force=False, db=db)
        data = {
            "package_coordinate": getattr(res, "package_coordinate", {}) or {},
            "declared_scope": getattr(res, "declared_scope", {}) or {},
            "artifact_scan": getattr(res, "surface_detail", {}) or {},
            "env_reads": list(getattr(res, "env_reads", []) or []),
        }
        behavioral = getattr(res, "behavioral", None)
        if isinstance(behavioral, dict):
            data["behavioral"] = behavioral
        return WatchScan(res.trust_score, res.tool_manifest_digest, data)
    except Exception:
        return WatchScan(None, None)


async def scan_watch_target(
    surface: str, owner: str, repo: str, db: AsyncSession,
) -> tuple[int | None, str | None]:
    """Scan a watch target by surface → (trust_score, tool_manifest_digest).
    Fail-open (returns (None, None) on error); the loop retries next cycle."""
    ws = await scan_watch_target_detail(surface, owner, repo, db)
    return ws.score, ws.digest


@router.post("/watches", status_code=status.HTTP_201_CREATED)
async def add_watch(
    body: WatchCreate,
    current: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
) -> dict:
    watcher_id = current.id  # snapshot before any awaits that may shift the session
    surface = (body.surface or "github").strip().lower()
    if surface not in ("github", "npm", "pypi", "docker", "mcp", "openclaw"):
        raise HTTPException(status_code=400, detail="unsupported surface")
    owner = body.owner.strip().strip("/")
    repo = body.repo.strip().strip("/") if surface != "mcp" else body.repo.strip()
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="owner and repo are required")

    existing = (
        await db.execute(
            select(ToolWatch).where(
                ToolWatch.watcher_id == watcher_id,
                ToolWatch.surface == surface,
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
    last_score, last_digest = await scan_watch_target(surface, owner, repo, db)

    watch = ToolWatch(
        watcher_id=watcher_id,
        surface=surface,
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
