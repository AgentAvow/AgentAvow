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
  anyway, so nothing is lost, and the repo page renders. The scanner's "No SKILL.md
  found" is not enough on its own (a failed or truncated tree call reads the same), so
  it is confirmed first with :func:`classify`: a 200 tree that is non-empty, not
  truncated and has no SKILL.md.
* ``repo_gone``: GitHub's repo API answers 404 / 451 (deleted, private, or blocked) twice,
  at least ``GONE_CONFIRM_GAP`` apart. The first 404 is only noted (with its time) in the
  checks file; any other answer in between resets it. A rate limit or outage
  (403 / 5xx / network error) is never read as gone.

Recovery: a reclassified row is listed as a GitHub repo, so the corpus loop no longer
skill-scans it. :func:`recheck_targets` hands the loop the ``no_skill_md`` entries whose
last check is older than ``RECHECK_AFTER``; a successful skill scan clears the entry and
the skill row comes back on the next catalog reload.

Bookkeeping that should not reload the catalog (first-404 times, last-check times) lives
in a second file, ``skill-rows-checks.json``, outside the catalog's source signature.
Both files are read-modify-written under one lock (a thread lock plus ``flock`` on a
sidecar file), so concurrent writers never lose an entry.

Only launch-corpus skill rows are recorded (the coordinate must open a corpus skill
page), so discovery candidates that turn out not to be skills don't grow the file.
"""
from __future__ import annotations

import contextlib
import fcntl
import logging
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

NO_SKILL_MD = "no_skill_md"
REPO_GONE = "repo_gone"
_REASONS = (NO_SKILL_MD, REPO_GONE)
# GitHub's repo API statuses that mean the repo is not there for anyone.
_GONE_STATUSES = (404, 451)
# Two 404s at least this far apart before a row is dropped as gone.
GONE_CONFIRM_GAP = timedelta(hours=3)
# How often a no_skill_md row is skill-scanned again so it can recover.
RECHECK_AFTER = timedelta(days=7)
_CHECKS_FILE = "skill-rows-checks.json"

_thread_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(ts) if isinstance(ts, str) else None
    except ValueError:
        return None
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _default_path() -> Path:
    from src.api import scan_catalog_router as scr
    return scr._DATA_DIR / scr._SKILL_ROWS_FILE


def _checks_path(overlay_path: Path) -> Path:
    return overlay_path.with_name(_CHECKS_FILE)


def miss_kind(error: Any) -> str | None:
    """What a skill-scan error says about the repo: a possible ``no_skill_md`` (to
    confirm with :func:`confirm_no_skill_md`), a possible ``repo_gone`` (to confirm with
    :func:`github_repo_gone`, twice), or None (a transient or unrelated failure that must
    not change the catalog)."""
    if not isinstance(error, str):
        return None
    if error.startswith("No SKILL.md found"):
        return NO_SKILL_MD
    if error.startswith("Repository not found or unreadable"):
        return REPO_GONE
    return None


async def _github_headers() -> dict[str, str]:
    from src.github_auth import get_github_token

    headers = {"Accept": "application/vnd.github+json"}
    token = await get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def classify(client: Any, headers: dict, full_name: str) -> str | None:
    """``no_skill_md`` / ``repo_gone`` / None (a skill, or unknown) from GitHub's repo and
    tree APIs. ``no_skill_md`` only for a 200 tree that is non-empty, not truncated and
    has no SKILL.md; ``repo_gone`` means this one call answered 404 / 451."""
    meta = await client.get(f"https://api.github.com/repos/{full_name}", headers=headers)
    if meta.status_code in _GONE_STATUSES:
        return REPO_GONE
    if meta.status_code != 200:
        return None
    branch = (meta.json() or {}).get("default_branch") or "HEAD"
    tree = await client.get(
        f"https://api.github.com/repos/{full_name}/git/trees/{branch}",
        headers=headers, params={"recursive": "1"})
    if tree.status_code != 200:
        return None
    body = tree.json() or {}
    if body.get("truncated"):
        return None
    paths = [it.get("path", "") for it in body.get("tree") or [] if it.get("type") == "blob"]
    if not paths:
        return None
    return None if any(p.lower().endswith("skill.md") for p in paths) else NO_SKILL_MD


async def confirm_no_skill_md(owner: str, repo: str) -> bool:
    """True only when :func:`classify` says ``no_skill_md``. Any error is False."""
    import httpx

    try:
        headers = await _github_headers()
        async with httpx.AsyncClient(timeout=20.0) as client:
            return await classify(client, headers, f"{owner}/{repo}") == NO_SKILL_MD
    except Exception:
        logger.debug("skill rows: tree check failed for %s/%s", owner, repo, exc_info=True)
        return False


async def github_repo_gone(owner: str, repo: str) -> bool:
    """True only when GitHub's repo API answers 404 or 451. Any other status, or a
    network error, is False: a rate limit must never delist a tool."""
    import httpx

    try:
        headers = await _github_headers()
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


def _load_checks(overlay_path: Path) -> dict[str, dict[str, Any]]:
    from src.catalog_growth.state import read_json

    doc = read_json(_checks_path(overlay_path), {})
    repos = doc.get("repos") if isinstance(doc, dict) else None
    return {k: dict(v) for k, v in repos.items()
            if isinstance(k, str) and isinstance(v, dict)} if isinstance(repos, dict) else {}


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """One writer at a time across threads (thread lock) and processes (``flock`` on a
    sidecar ``.lock`` file). If the lock file can't be created (read-only directory),
    only the thread lock is held; the write itself will then fail and be logged."""
    with _thread_lock:
        fh = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(path.with_name(path.name + ".lock"), "a")  # noqa: SIM115
            fcntl.flock(fh, fcntl.LOCK_EX)
        except OSError:
            fh = None
        try:
            yield
        finally:
            if fh is not None:
                fcntl.flock(fh, fcntl.LOCK_UN)
                fh.close()


def _mutate(fn: Callable[[dict[str, dict], dict[str, dict]], tuple[bool, bool]],
            path: Path | None) -> bool:
    """Read both files, let ``fn(repos, checks)`` edit them in place (returning which of
    the two changed), and write the changed ones, all under :func:`_locked`. False when
    the directory is read-only (logged, never raised)."""
    from src.catalog_growth.state import read_json, write_json_atomic

    p = path or _default_path()
    with _locked(p):
        doc = read_json(p, {})
        repos = doc.get("repos") if isinstance(doc, dict) else None
        repos = {k: dict(v) for k, v in repos.items() if isinstance(v, dict)} \
            if isinstance(repos, dict) else {}
        checks = _load_checks(p)
        repos_changed, checks_changed = fn(repos, checks)
        now = _now().isoformat()
        try:
            if repos_changed:
                write_json_atomic(p, {"repos": repos, "updated_at": now})
            if checks_changed:
                write_json_atomic(_checks_path(p), {"repos": checks, "updated_at": now})
            return True
        except OSError:
            logger.warning("skill rows: %s is not writable; overlay not updated", p)
            return False


def _write(update: dict[str, dict[str, str] | None], path: Path | None) -> bool:
    """Apply ``{name: entry or None (remove)}`` to the overlay file (locked). Removing
    an entry also drops its bookkeeping."""
    def fn(repos: dict, checks: dict) -> tuple[bool, bool]:
        changed = checks_changed = False
        for name, entry in update.items():
            key = name.lower()
            if entry is None:
                changed |= repos.pop(key, None) is not None
                checks_changed |= checks.pop(key, None) is not None
            elif (repos.get(key) or {}).get("reason") != entry["reason"]:
                repos[key] = entry
                changed = True
        return changed, checks_changed
    return _mutate(fn, path)


def record(full_name: str, reason: str, path: Path | None = None) -> bool:
    if reason not in _REASONS or "/" not in full_name:
        return False
    return _write({full_name: {"reason": reason, "at": _now().isoformat()}}, path)


def clear(full_name: str, path: Path | None = None) -> bool:
    return _write({full_name: None}, path)


def note_404(full_name: str, path: Path | None = None, now: datetime | None = None) -> bool:
    """A GitHub 404 / 451 for ``full_name``. The first is only noted with its time; a
    later one at least ``GONE_CONFIRM_GAP`` after it records ``repo_gone``. True when the
    row is (now) recorded as gone."""
    if "/" not in full_name:
        return False
    key = full_name.lower()
    t = now or _now()
    gone = {"v": False}

    def fn(repos: dict, checks: dict) -> tuple[bool, bool]:
        if (repos.get(key) or {}).get("reason") == REPO_GONE:
            gone["v"] = True
            return False, False
        entry = checks.setdefault(key, {})
        first = _parse(entry.get("first_404_at"))
        if first is None or t < first:
            entry["first_404_at"] = t.isoformat()
            return False, True
        if t - first < GONE_CONFIRM_GAP:
            return False, False
        repos[key] = {"reason": REPO_GONE, "at": t.isoformat(),
                      "first_404_at": first.isoformat()}
        entry.pop("first_404_at", None)
        if not entry:
            checks.pop(key, None)
        gone["v"] = True
        return True, True
    _mutate(fn, path)
    return gone["v"]


def reset_404(full_name: str, path: Path | None = None) -> bool:
    """Any answer other than a 404 / 451: forget a pending first 404."""
    key = full_name.lower()

    def fn(repos: dict, checks: dict) -> tuple[bool, bool]:
        entry = checks.get(key)
        if not entry or "first_404_at" not in entry:
            return False, False
        entry.pop("first_404_at")
        if not entry:
            checks.pop(key)
        return False, True
    return _mutate(fn, path)


def mark_checked(full_name: str, path: Path | None = None,
                  now: datetime | None = None) -> bool:
    key = full_name.lower()
    t = (now or _now()).isoformat()

    def fn(repos: dict, checks: dict) -> tuple[bool, bool]:
        checks.setdefault(key, {})["checked_at"] = t
        return False, True
    return _mutate(fn, path)


def recheck_targets(limit: int, path: Path | None = None,
                    now: datetime | None = None) -> list[tuple[str, str]]:
    """``no_skill_md`` rows due for another skill scan (last check, or the record time,
    older than ``RECHECK_AFTER``), oldest first, as ``(owner, repo)``. The loop skill-scans
    these so a repo that gains a SKILL.md gets its skill row back."""
    if limit <= 0:
        return []
    from src.catalog_growth.state import read_json

    p = path or _default_path()
    t = now or _now()
    doc = read_json(p, {})
    repos = doc.get("repos") if isinstance(doc, dict) else None
    checks = _load_checks(p)
    due: list[tuple[datetime, str]] = []
    for name, entry in (repos or {}).items() if isinstance(repos, dict) else []:
        if not isinstance(entry, dict) or entry.get("reason") != NO_SKILL_MD or "/" not in name:
            continue
        last = _parse((checks.get(name) or {}).get("checked_at")) or _parse(entry.get("at")) \
            or datetime.min.replace(tzinfo=timezone.utc)
        if t - last >= RECHECK_AFTER:
            due.append((last, name))
    due.sort()
    return [tuple(name.split("/", 1)) for _last, name in due[:limit]]  # type: ignore[misc]


def is_corpus_skill_row(owner: str, repo: str) -> bool:
    """Whether owner/repo is a launch-corpus skill row: it opens a corpus skill page, or
    it already has an overlay entry (entries are only ever written for corpus skill rows,
    and a reclassified row no longer opens a skill page, so this keeps it eligible for
    recovery)."""
    if f"{owner}/{repo}".lower() in load_overlay():
        return True
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
    confirmed miss for a launch-corpus skill row, or clears its entry on success.
    Fail-open: never raises."""
    full = f"{owner}/{repo}"
    try:
        if error is None:
            if full.lower() in load_overlay():
                clear(full)
            else:
                reset_404(full)
            return
        kind = miss_kind(error)
        if kind is None or not is_corpus_skill_row(owner, repo):
            return
        if kind == REPO_GONE:
            if await github_repo_gone(owner, repo):
                note_404(full)
            else:
                reset_404(full)
            return
        # The repo answered, so any pending 404 is stale.
        reset_404(full)
        if full.lower() in load_overlay():
            return  # a recheck that is still a miss: the entry stays
        if await confirm_no_skill_md(owner, repo):
            record(full, NO_SKILL_MD)
    except Exception:
        logger.debug("skill rows: could not note %s/%s", owner, repo, exc_info=True)
