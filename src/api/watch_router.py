"""Tool-watch / alert API — watch a tool for grade or signed-definition changes.

The re-scan + notification loop lives in src/jobs/scheduler.py (_watch_rescan_loop).
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.database import get_db
from src.models import Entity, ToolWatch

logger = logging.getLogger(__name__)

router = APIRouter(tags=["watches"])


class WatchCreate(BaseModel):
    # 'github' (owner/repo) · 'npm'/'pypi'/'crates'/'huggingface'/'docker'
    # (owner=surface, repo=pkg) · 'mcp'
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
    """One re-scan of a watch target. ``data`` is the full static scan result, the
    dict the public scan endpoint builds (``_scan_result_to_dict``: trust_score,
    findings counts and items, metadata, coverage_gaps, supply_chain, certified …), so
    the watch loop decides the answer over the same inputs ``/public/scan`` does. On
    top of it sit the fields the behavioral (sandbox) lookup keys on (package
    coordinate, declared scope, artifact detail, env reads) and, for GitHub, the
    ``behavioral`` block the public scan resolved. Empty when the scan failed.

    ``decision`` is set only when the answer could not be derived from ``data`` (a
    GitHub scan whose static result was not readable from the cache): the public
    response's own answer, or None when even that was provisional."""

    score: int | None
    digest: str | None
    data: dict = field(default_factory=dict)
    decision: dict | None = None
    # Live MCP only: the unsigned icon fingerprint (src/scanner/mcp_icons.py) and the
    # icon findings of this scan, for the "icon changed" alert. None/[] elsewhere.
    icon_digest: str | None = None
    icon_findings: list = field(default_factory=list)


def _full_scan_data(r) -> dict:
    """The public scan endpoint's dict for a ScanResult: the answer's inputs. {} when
    it cannot be built; the watch loop then records no answer this cycle (it never
    decides one without a score), and the score and digest checks still run."""
    try:
        from src.api.public_scan_router import _scan_result_to_dict
        return _scan_result_to_dict(r)
    except Exception:
        logger.warning("watch: scan result not shaped for the answer", exc_info=True)
        return {}


def _package_scan_data(surface: str, name: str, r) -> dict:
    return {
        **_full_scan_data(r),
        "package_coordinate": {"surface": surface, "name": name},
        "declared_scope": getattr(r, "declared_scope", {}) or {},
        "artifact_scan": getattr(r, "artifact_scan", {}) or {},
        "env_reads": list(getattr(r, "env_reads", []) or []),
    }


def _response_decision(res) -> dict | None:
    """The answer a public scan response leads with, shaped like the watch loop's
    ``_watch_decision``. None while it is provisional (a sandbox run pending): a
    pending run withholds the Certified mark, and a baseline taken then would read as
    the mark coming off and back."""
    d = getattr(res, "decision", None)
    if not isinstance(d, str) or not getattr(res, "decision_final", False):
        return None
    return {
        "decision": d,
        "decision_final": True,
        "decision_reason": getattr(res, "decision_reason", "") or "",
        "certified": bool(getattr(res, "certified_mark", False)),
    }


# Surfaces a watch can re-scan. Package surfaces go through scan_package (owner is the
# surface, repo the package name); the rest have their own branch below. POST /watches
# and the auto-watch on a verified claim (account_claims_router._ensure_watch) both
# check this list.
_PACKAGE_WATCH_SURFACES = ("npm", "pypi", "crates", "huggingface", "docker")
WATCH_SURFACES = ("github", *_PACKAGE_WATCH_SURFACES, "mcp", "openclaw")


async def scan_watch_target_detail(
    surface: str, owner: str, repo: str, db: AsyncSession,
) -> WatchScan:
    """Scan a watch target by surface → WatchScan(score, tool_manifest_digest, data).
    Fail-open (score None on error); the loop retries next cycle."""
    surface = (surface or "github").lower()
    try:
        if surface not in WATCH_SURFACES:
            # Never fall through to the GitHub scan: a crates claim once auto-watched
            # with owner "crates" and read as the GitHub repo crates/<name>.
            return WatchScan(None, None)
        if surface in _PACKAGE_WATCH_SURFACES:
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
                {} if r.error else _full_scan_data(r),
                icon_digest=None if r.error else (getattr(r, "icon_fingerprint", None) or None),
                icon_findings=[] if r.error else [
                    {"severity": f.severity, "name": f.name, "where": f.file_path}
                    for f in (getattr(r, "findings", None) or [])
                    if str(getattr(f, "file_path", "") or "").endswith(":icons")
                ],
            )
        if surface == "openclaw":
            from src.scanner.scan import scan_skill
            r = await scan_skill(owner, repo)
            return WatchScan(
                None if r.error else r.trust_score, r.tool_manifest_digest or None,
                {} if r.error else _full_scan_data(r),
            )
        # default: github repo
        from src.api.public_scan_router import public_scan
        res = await public_scan(owner=owner, repo=repo, force=False, db=db)
        # The response's trust_score already has the sandbox folded in; the answer is
        # decided over the STATIC result (which public_scan just read or wrote in the
        # cache) with the sandbox block folded in by the watch loop, as the endpoint does.
        from src.api.public_scan_router import _get_cached
        try:
            static = await _get_cached(owner, repo)
        except Exception:
            static = None
        data = {
            **(static if isinstance(static, dict) else {}),
            "package_coordinate": getattr(res, "package_coordinate", {}) or {},
            "declared_scope": getattr(res, "declared_scope", {}) or {},
            "artifact_scan": getattr(res, "surface_detail", {}) or {},
            "env_reads": list(getattr(res, "env_reads", []) or []),
        }
        behavioral = getattr(res, "behavioral", None)
        if isinstance(behavioral, dict):
            data["behavioral"] = behavioral
        decision = None
        if not isinstance(static, dict):
            decision = _response_decision(res)
        return WatchScan(res.trust_score, res.tool_manifest_digest, data, decision=decision)
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
    if surface not in WATCH_SURFACES:
        raise HTTPException(status_code=400, detail="unsupported surface")
    owner = body.owner.strip().strip("/")
    repo = body.repo.strip().strip("/") if surface != "mcp" else body.repo.strip()
    if surface == "mcp":
        # A watch stores and re-scans the endpoint: never keep a token, tenant or
        # user:pass@ from the URL (see src/ssrf.mcp_endpoint_identity).
        from src.ssrf import CredentialedURLError, mcp_endpoint_identity
        try:
            repo = mcp_endpoint_identity(repo)
        except CredentialedURLError:
            raise HTTPException(
                status_code=400,
                detail="endpoint path looks like a credential; remove it and retry",
            )
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
    baseline = await scan_watch_target_detail(surface, owner, repo, db)
    last_score, last_digest = baseline.score, baseline.digest

    watch = ToolWatch(
        watcher_id=watcher_id,
        surface=surface,
        owner=owner,
        repo=repo,
        last_score=last_score,
        last_manifest_digest=last_digest,
        last_icon_digest=baseline.icon_digest,
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
