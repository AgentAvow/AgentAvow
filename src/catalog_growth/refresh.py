"""Daily version refresh: re-scan only the catalog tools whose version moved.

Which tools a run checks: the top ``top_n`` catalog pages by adoption every day; every
other page once a week (a stable seventh of them each day, by a hash of the page key,
so the weekly load is spread evenly).

How a tool's "latest" is read (one cheap metadata call each):

* npm   - ``registry.npmjs.org/<name>/latest`` -> version
* PyPI  - ``pypi.org/pypi/<name>/json``       -> info.version (+ its upload time)
* GitHub repos and OpenClaw skills - ``GET /repos/{o}/{r}/commits/HEAD`` with the sha
  media type and the last ETag: a 304 is free (does not count against the budget) and
  means "unchanged". Stops at ``github_calls`` per run or when the core budget left
  falls under ``github_min_budget``, so live user scans keep their budget.
* MCP registry rows with a live endpoint - one ``updated_since`` listing of the MCP
  Registry; a server published since the last refresh counts as changed.
* crates / Docker / Hugging Face / plain MCP endpoints: not checked here (counted as
  ``unsupported``); the scheduler's stalest-first re-scan loop still covers them.

"The version we scanned" is, in order: this job's baseline for the page (written after
each successful scan or check), else the version in the cached scan (the 7-day copy),
else unknown. With no reference, a PyPI release newer than the row's scan date counts
as changed; anything else is recorded as the baseline without a re-scan.
"""
from __future__ import annotations

import hashlib
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from src.catalog_growth.http import Fetcher
from src.catalog_growth.index import CatalogIndex, Entry

logger = logging.getLogger(__name__)

NPM_LATEST_URL = "https://registry.npmjs.org/{name}/latest"
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
GITHUB_HEAD_URL = "https://api.github.com/repos/{owner}/{repo}/commits/HEAD"
MCP_REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"

PRIORITY_CHANGED_TOP = 0
PRIORITY_CHANGED = 1


def weekly_bucket(key: str) -> int:
    return int(hashlib.sha1(key.encode()).hexdigest()[:8], 16) % 7


def day_index(now: datetime) -> int:
    return (now.date() - datetime(1970, 1, 1).date()).days % 7


def select_entries(index: CatalogIndex, *, top_n: int, today: int
                   ) -> tuple[list[Entry], set[str]]:
    """(entries to check this run, the keys of the daily top tier). Entries with no
    scan target (no page or a skipped row) are left out."""
    scannable = [e for e in index.entries.values() if e.target is not None]
    scannable.sort(key=lambda e: (-(e.adoption or 0), e.key))
    top = scannable[:max(0, top_n)]
    top_keys = {e.key for e in top}
    rest = [e for e in scannable[len(top):] if weekly_bucket(e.key) == today]
    return top + rest, top_keys


def detect_change(baseline: str | None, observed: str | None, *,
                  scanned_version: str | None = None, released_at: datetime | None = None,
                  last_scanned_at: datetime | None = None) -> str:
    """changed | same | baselined | unknown. ``observed`` is the registry's latest
    version (or HEAD sha); ``baseline`` this job's record; ``scanned_version`` the
    version in the cached scan."""
    if not observed:
        return "unknown"
    ref = baseline or scanned_version
    if ref:
        return "same" if str(ref) == str(observed) else "changed"
    if released_at and last_scanned_at:
        return "changed" if released_at > last_scanned_at else "baselined"
    return "baselined"


def _parse_time(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def npm_latest(f: Fetcher, name: str) -> tuple[str | None, datetime | None]:
    data = await f.get_json(NPM_LATEST_URL.format(name=quote(name, safe="@/")), policy="npm")
    v = data.get("version") if isinstance(data, dict) else None
    return (v if isinstance(v, str) else None), None


async def pypi_latest(f: Fetcher, name: str) -> tuple[str | None, datetime | None]:
    data = await f.get_json(PYPI_JSON_URL.format(name=quote(name, safe="")), policy="pypi")
    if not isinstance(data, dict):
        return None, None
    v = (data.get("info") or {}).get("version")
    times = [_parse_time(u.get("upload_time_iso_8601")) for u in data.get("urls") or []
             if isinstance(u, dict)]
    times = [t for t in times if t]
    return (v if isinstance(v, str) else None), (max(times) if times else None)


class GitHubBudget:
    """Stops HEAD checks at the per-run cap or the budget floor."""

    def __init__(self, calls: int, min_budget: int) -> None:
        self.calls_left = calls
        self.min_budget = min_budget
        self.stopped: str | None = None

    def ok(self, f: Fetcher) -> bool:
        if self.stopped:
            return False
        if self.calls_left <= 0:
            self.stopped = "github call cap for this run reached"
        elif f.github_remaining is not None and f.github_remaining < self.min_budget:
            self.stopped = f"github budget under {self.min_budget}"
        return self.stopped is None


async def github_head(f: Fetcher, owner: str, repo: str, token: str, etag: str | None
                      ) -> tuple[str, str | None, str | None]:
    """(state, sha, etag): state is "same" (304), "ok", or "error"."""
    headers = {"Accept": "application/vnd.github.sha", "Authorization": f"Bearer {token}"}
    if etag:
        headers["If-None-Match"] = etag
    resp = await f.get(GITHUB_HEAD_URL.format(owner=quote(owner, safe=""),
                                              repo=quote(repo, safe="")),
                       policy="github", headers=headers)
    if resp is None:
        return "error", None, None
    if resp.status_code == 304:
        return "same", None, etag
    if resp.status_code != 200:
        return "error", None, None
    sha = (resp.text or "").strip()
    new_etag = (resp.headers or {}).get("etag")
    return ("ok", sha, new_etag) if len(sha) >= 7 else ("error", None, None)


async def registry_updated_since(f: Fetcher, since: datetime, *, max_pages: int = 200
                                 ) -> dict[str, str]:
    """name -> latest version for MCP Registry servers updated since ``since``."""
    out: dict[str, str] = {}
    cursor: str | None = None
    for _ in range(max_pages):
        params: dict[str, Any] = {"limit": 100, "version": "latest",
                                  "updated_since": since.astimezone(timezone.utc)
                                  .strftime("%Y-%m-%dT%H:%M:%SZ")}
        if cursor:
            params["cursor"] = cursor
        data = await f.get_json(MCP_REGISTRY_URL, policy="mcp_registry", params=params)
        if not isinstance(data, dict):
            break
        for entry in data.get("servers") or []:
            s = entry.get("server") if isinstance(entry, dict) and "server" in entry else entry
            if isinstance(s, dict) and isinstance(s.get("name"), str):
                out[s["name"]] = str(s.get("version") or "")
        md = data.get("metadata") or {}
        cursor = md.get("nextCursor") or md.get("next_cursor")
        if not cursor or not data.get("servers"):
            break
    return out


ScannedVersionFn = Callable[[str, str, str], Awaitable[str | None]]


async def cached_version(surface: str, owner: str, repo: str) -> str | None:
    """The version in the cached scan of a coordinate (Redis, fresh or 7-day copy)."""
    from src.scanner.behavioral.trigger import cached_scan_data, change_signature

    data = await cached_scan_data(surface, owner, repo)
    return change_signature(data).get("version") if data else None


async def plan_refresh(
    f: Fetcher, index: CatalogIndex, state: dict, *, top_n: int, now: datetime,
    github_token: str | None, github_calls: int, github_min_budget: int,
    scanned_version: ScannedVersionFn = cached_version,
    retry_after_iso: str | None = None,
) -> tuple[list[dict], dict, dict]:
    """Returns (work items, report, baseline updates). Baseline updates are for pages
    whose latest equals (or first records) what we hold; a changed page's new baseline
    rides on its work item and is written only after its scan lands."""
    report: dict = {"by_source": {}}
    baselines: dict = state.get("baselines") or {}
    updates: dict[str, dict] = {}
    items: list[dict] = []
    entries, top_keys = select_entries(index, top_n=top_n, today=day_index(now))
    budget = GitHubBudget(github_calls, github_min_budget)

    last = (state.get("last_run") or {}).get("refresh_on")
    since = _parse_time(last) or (now - timedelta(days=7))
    updated: dict[str, str] = {}
    if any(e.target and e.target[0] == "mcp" for e in entries):
        updated = await registry_updated_since(f, since)
    key_to_registry = {k: n for n, k in index.mcp_registry_keys.items()}

    def count(src: str, field: str) -> None:
        b = report["by_source"].setdefault(src, {})
        b[field] = b.get(field, 0) + 1

    failed: dict = state.get("failed") or {}
    for e in entries:
        surf, owner, repo = e.target  # type: ignore[misc]
        src = surf
        if retry_after_iso and (failed.get(e.key) or "") > retry_after_iso:
            count(src, "retry_wait")  # its last re-scan failed recently
            continue
        base = baselines.get(e.key) or {}
        observed: str | None = None
        released: datetime | None = None
        etag: str | None = None
        result: str
        if surf == "npm":
            observed, released = await npm_latest(f, repo)
        elif surf == "pypi":
            observed, released = await pypi_latest(f, repo)
        elif surf in ("github", "openclaw"):
            if not github_token or not budget.ok(f):
                count(src, "deferred")
                continue
            budget.calls_left -= 1
            st, sha, etag = await github_head(f, owner, repo, github_token, base.get("etag"))
            if st == "same":
                count(src, "checked")
                count(src, "unchanged")
                continue
            observed = sha if st == "ok" else None
        elif surf == "mcp":
            reg = key_to_registry.get(e.key)
            if not reg:
                count(src, "unsupported")
                continue
            count(src, "checked")
            if reg in updated:
                observed = updated[reg] or "updated"
                result = "same" if base.get("v") == observed else "changed"
            else:
                count(src, "unchanged")
                continue
        else:
            count(src, "unsupported")
            continue
        if surf != "mcp":
            count(src, "checked")
            ref = base.get("v")
            sv = None
            if not ref and surf in ("npm", "pypi"):
                sv = await scanned_version(surf, owner, repo)
            result = detect_change(ref, observed, scanned_version=sv, released_at=released,
                                   last_scanned_at=e.last_scanned_at)
        if result == "unknown":
            count(src, "failed")
            continue
        if result in ("same", "baselined"):
            count(src, "unchanged" if result == "same" else "baselined")
            updates[e.key] = {"v": observed, **({"etag": etag} if etag else {}),
                              "checked_at": now.isoformat(timespec="seconds")}
            continue
        count(src, "changed")
        items.append({
            "key": e.key, "surface": surf, "owner": owner, "repo": repo,
            "reason": "changed", "source": src,
            "priority": PRIORITY_CHANGED_TOP if e.key in top_keys else PRIORITY_CHANGED,
            "adoption": e.adoption, "version": observed,
            **({"etag": etag} if etag else {}),
            "was": base.get("v"),
        })
        count(src, "queued")
    if budget.stopped:
        report["stopped"] = budget.stopped
    report["selected"] = len(entries)
    report["top_tier"] = len(top_keys)
    items.sort(key=lambda i: (i["priority"], -(i.get("adoption") or 0), i["key"]))
    return items, report, updates
