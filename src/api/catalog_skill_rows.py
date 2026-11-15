"""Launch-corpus skill rows whose skill scan can no longer run: reclassify or drop them.

The launch "OpenClaw skills" corpus (``openclaw-results.json``) came from
``scripts/scan_openclaw_batch.py``: GitHub searches (``topic:openclaw``,
``"openclaw in:name"``, ...) graded with the REPO scanner. Nothing required a SKILL.md, so
repos that only mention OpenClaw (a control panel, a CLI, a C++ game remake named
OpenClaw) were listed as Agent skills with a /check/skill/... page. That page runs the
skill scanner, which answers "No SKILL.md found", so Browse showed a Do-not-connect skill
row that opened an error page. A repo deleted since launch kept its old verdict too: the
catalog re-scan loop drops a failed scan silently, so the corpus row stayed listed.

When the re-scan loop's skill scan of a launch-corpus skill row fails definitively, this
module records it in ``skill-rows.json`` next to the corpus files (the same overlay pattern
as ``mcp-endpoints.json``), and the catalog loader applies it:

* ``no_skill_md``: the repo exists and its tree has no SKILL.md. The row becomes a plain
  GitHub repo row (/check/<owner>/<repo>). Its verdict came from the repo scanner
  anyway, so nothing is lost, and the repo page renders. A later successful skill scan
  clears the entry.
* ``repo_gone``: GitHub's repo API answers 404 / 451 (deleted, private, or blocked). The
  row leaves the catalog instead of showing a stale verdict. A rate limit or outage
  (403 / 5xx / network error) is never read as gone.

Only launch-corpus skill rows are recorded (the coordinate must open a corpus skill
page), so discovery candidates that turn out not to be skills don't grow the file.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

NO_SKILL_MD = "no_skill_md"
REPO_GONE = "repo_gone"
_REASONS = (NO_SKILL_MD, REPO_GONE)
# GitHub's repo API statuses that mean the repo is not there for anyone.
_GONE_STATUSES = (404, 451)


def _default_path() -> Path:
    from src.api import scan_catalog_router as scr
    return scr._DATA_DIR / scr._SKILL_ROWS_FILE


def miss_kind(error: Any) -> str | None:
    """What a skill-scan error says about the repo: ``no_skill_md``, a possible
    ``repo_gone`` (to confirm with :func:`github_repo_gone`), or None (a transient or
    unrelated failure that must not change the catalog)."""
    if not isinstance(error, str):
        return None
    if error.startswith("No SKILL.md found"):
        return NO_SKILL_MD
    if error.startswith("Repository not found or unreadable"):
        return REPO_GONE
    return None


async def github_repo_gone(owner: str, repo: str) -> bool:
    """True only when GitHub's repo API answers 404 or 451. Any other status, or a
    network error, is False: a rate limit must never delist a tool."""
    import httpx

    from src.github_auth import get_github_token

    headers = {"Accept": "application/vnd.github+json"}
    try:
        token = await get_github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}",
                                    headers=headers)
    except Exception:
        logger.debug("skill rows: repo check failed for %s/%s", owner, repo, exc_info=True)
        return False
    return resp.status_code in _GONE_STATUSES


def load_overlay(path: Path | None = None) -> dict[str, str]:
    """``{lowercased owner/repo: reason}``; {} when absent or unreadable."""
    from src.catalog_growth.state import read_json

    doc = read_json(path or _default_path(), {})
    repos = doc.get("repos") if isinstance(doc, dict) else None
    out: dict[str, str] = {}
    for name, entry in (repos or {}).items() if isinstance(repos, dict) else []:
        reason = entry.get("reason") if isinstance(entry, dict) else None
        if isinstance(name, str) and "/" in name and reason in _REASONS:
            out[name.lower()] = reason
    return out


def _write(update: dict[str, dict[str, str] | None], path: Path | None) -> bool:
    """Apply ``{name: entry or None (remove)}`` to the overlay file. False when the
    directory is read-only (logged, never raised)."""
    from src.catalog_growth.state import read_json, write_json_atomic

    p = path or _default_path()
    doc = read_json(p, {})
    repos = doc.get("repos") if isinstance(doc, dict) else None
    repos = dict(repos) if isinstance(repos, dict) else {}
    changed = False
    for name, entry in update.items():
        key = name.lower()
        if entry is None:
            changed |= repos.pop(key, None) is not None
        elif (repos.get(key) or {}).get("reason") != entry["reason"]:
            repos[key] = entry
            changed = True
    if not changed:
        return True
    try:
        write_json_atomic(p, {"repos": repos,
                              "updated_at": datetime.now(timezone.utc).isoformat()})
        return True
    except OSError:
        logger.warning("skill rows: %s is not writable; overlay not updated", p)
        return False


def record(full_name: str, reason: str, path: Path | None = None) -> bool:
    if reason not in _REASONS or "/" not in full_name:
        return False
    return _write({full_name: {"reason": reason,
                               "at": datetime.now(timezone.utc).isoformat()}}, path)


def clear(full_name: str, path: Path | None = None) -> bool:
    return _write({full_name: None}, path)


def is_corpus_skill_row(owner: str, repo: str) -> bool:
    """Whether owner/repo opens a launch-corpus skill page (cached catalog lookup).
    A skill row reclassified by the overlay no longer counts, so its later re-scans
    don't flip it back and forth."""
    from src.api import scan_catalog_router as scr

    try:
        by_key = scr._get_catalog().get("static_by_key") or {}
    except Exception:
        return False
    row = by_key.get(scr._path_key(f"/check/skill/{owner}/{repo}"))
    return row is not None and row.surface == "openclaw"


def apply_overlay(rows: list[Any], overlay: dict[str, str]) -> list[Any]:
    """The corpus rows with the overlay applied: a ``no_skill_md`` skill row becomes a
    GitHub repo row, a ``repo_gone`` skill row is dropped. Other rows are untouched."""
    if not overlay:
        return rows
    from src.api.scan_catalog_router import page_path_for

    out: list[Any] = []
    for r in rows:
        reason = overlay.get((r.full_name or "").lower()) if r.surface == "openclaw" else None
        if reason == REPO_GONE:
            continue
        if reason == NO_SKILL_MD:
            r = r.model_copy(update={
                "surface": "github",
                "page_path": page_path_for("github", r.name, r.full_name, None)})
        out.append(r)
    return out


async def note_skill_scan(owner: str, repo: str, error: Any) -> None:
    """Called by the catalog re-scan loop after a skill scan of owner/repo. Records a
    definitive miss for a launch-corpus skill row, or clears its entry on success.
    Fail-open: never raises."""
    try:
        if error is None:
            if f"{owner}/{repo}".lower() in load_overlay():
                clear(f"{owner}/{repo}")
            return
        kind = miss_kind(error)
        if kind is None or not is_corpus_skill_row(owner, repo):
            return
        if kind == REPO_GONE and not await github_repo_gone(owner, repo):
            return
        record(f"{owner}/{repo}", kind)
    except Exception:
        logger.debug("skill rows: could not note %s/%s", owner, repo, exc_info=True)
