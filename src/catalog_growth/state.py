"""Switches, small on-disk state, the work queue and the per-run metrics.

Files under ``catalog_growth_data_dir`` (default data/catalog-growth, a host directory
mounted into the one-off container):

* ``state.json``   - version baselines per catalog page, failed tools, Smithery entries
                     already looked up. Written only by a run in ``on`` mode.
* ``pending.json`` - the work queue: tools to scan, carried across runs until scanned
                     (resumable: a killed run picks up where it stopped). ``on`` only.
* ``plan-<job>-<mode>.json`` - the latest work list and counts for each job and mode;
                     a dry run writes only this (plus runs.jsonl).
* ``dnc-review.jsonl`` - Do-not-connect answers these jobs produced, for a person to read
                     before any of them may be indexed. Never read by the site.
* ``runs.jsonl``   - one line of counts per run (the same record kept in Redis for
                     /admin/metrics/growth).
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MODES = ("off", "dry-run", "on")
JOBS = ("discover", "refresh")
_FLAG_FOR = {"discover": "catalog_discovery", "refresh": "catalog_refresh"}

RUNS_KEY = "ag:metrics:catalog_growth:runs"
RUNS_KEEP = 30
PENDING_MAX = 20_000  # bound the queue file; lowest-priority items fall off first


def mode_for(job: str, settings: Any | None = None) -> str:
    """The switch for ``job``: off | dry-run | on. Missing, empty or unknown = off."""
    if settings is None:
        from src.config import settings as _s
        settings = _s
    raw = getattr(settings, _FLAG_FOR.get(job, ""), "off")
    val = str(raw or "off").strip().lower().replace("_", "-")
    if val in ("dryrun", "dry"):
        val = "dry-run"
    return val if val in MODES else "off"


def data_dir(settings: Any | None = None) -> Path:
    if settings is None:
        from src.config import settings as _s
        settings = _s
    p = Path(getattr(settings, "catalog_growth_data_dir", "data/catalog-growth"))
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[2] / p
    return p


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, default=str, sort_keys=True))
    tmp.replace(path)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except Exception:
        logger.warning("catalog_growth: could not read %s; starting from empty", path)
        return default


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(record, default=str, sort_keys=True) + "\n")


class RunLock:
    """One run at a time per data dir (fcntl lock file). ``acquired`` is False when
    another run holds it; the caller exits without doing anything."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / ".lock"
        self._fh: Any = None
        self.acquired = False

    def __enter__(self) -> RunLock:
        import fcntl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fh.write(str(os.getpid()))
            self._fh.flush()
            self.acquired = True
        except OSError:
            self.acquired = False
        return self

    def __exit__(self, *exc: Any) -> None:
        import fcntl
        if self._fh is not None:
            if self.acquired:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()


@contextmanager
def run_lock(directory: Path):
    lock = RunLock(directory)
    with lock:
        yield lock


class Store:
    """The state and queue files of one data dir."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory

    # -- state -----------------------------------------------------------------
    def load_state(self) -> dict:
        st = read_json(self.dir / "state.json", {})
        if not isinstance(st, dict):
            st = {}
        for k in ("baselines", "failed", "smithery_seen", "last_run"):
            if not isinstance(st.get(k), dict):
                st[k] = {}
        return st

    def save_state(self, state: dict) -> None:
        write_json_atomic(self.dir / "state.json", state)

    # -- queue -----------------------------------------------------------------
    def load_pending(self) -> list[dict]:
        items = read_json(self.dir / "pending.json", [])
        return [i for i in items if isinstance(i, dict) and i.get("key")] if isinstance(
            items, list) else []

    def save_pending(self, items: list[dict]) -> None:
        write_json_atomic(self.dir / "pending.json", items[:PENDING_MAX])

    # -- outputs ---------------------------------------------------------------
    def write_plan(self, job: str, mode: str, plan: dict) -> Path:
        path = self.dir / f"plan-{job}-{mode}.json"
        write_json_atomic(path, plan)
        return path

    def add_dnc_review(self, record: dict) -> None:
        append_jsonl(self.dir / "dnc-review.jsonl", record)

    def add_run(self, record: dict) -> None:
        append_jsonl(self.dir / "runs.jsonl", record)


def merge_pending(pending: list[dict], items: list[dict]) -> list[dict]:
    """Add ``items`` to the queue, one entry per page key (the earlier, higher-priority
    entry wins), ordered by priority (lower first) then adoption."""
    by_key: dict[str, dict] = {}
    for it in [*pending, *items]:
        k = it.get("key")
        if not k:
            continue
        cur = by_key.get(k)
        if cur is None or it.get("priority", 9) < cur.get("priority", 9):
            by_key[k] = it
    return interleave_sources(by_key.values())


def interleave_sources(items) -> list[dict]:
    """Order the queue by priority (lower first); within one priority, take turns across
    sources (mcp_registry, npm, pypi, openclaw, ...), each source most-adopted first.

    Sorting by adoption alone put every npm package (which has download counts) ahead of
    every MCP Registry server (which mostly has none): the first live run (11-13) scanned
    492 npm packages and 0 MCP servers. Taking turns gives each source a fair share of
    every run, and of the PENDING_MAX slots when the queue is trimmed."""
    by_prio: dict[int, dict[str, list[dict]]] = {}
    for it in items:
        src = it.get("source") or it.get("surface") or ""
        by_prio.setdefault(it.get("priority", 9), {}).setdefault(src, []).append(it)
    out: list[dict] = []
    for prio in sorted(by_prio):
        buckets = [sorted(b, key=lambda i: (-(i.get("adoption") or 0), i["key"]))
                   for _, b in sorted(by_prio[prio].items())]
        for n in range(max(len(b) for b in buckets)):
            out.extend(b[n] for b in buckets if n < len(b))
    return out


# -- metrics (Redis, for /admin/metrics/growth) -----------------------------------
_COUNT_FIELDS = ("discovered", "new", "changed", "queued", "scanned", "failed",
                 "skipped", "skipped_with_url", "no_code_no_url", "deferred",
                 "dnc_held", "unchanged", "baselined", "checked", "already",
                 "retry_wait", "below_floor", "unsupported")


def clean_run(raw: object) -> dict | None:
    """The fields kept for one run, or None if it is not one. Counts are non-negative
    ints; per-source counts keep the same count names."""
    if not isinstance(raw, dict) or raw.get("job") not in JOBS or raw.get("mode") not in MODES:
        return None

    def counts(d: object) -> dict[str, int]:
        if not isinstance(d, dict):
            return {}
        return {k: int(v) for k, v in d.items()
                if k in _COUNT_FIELDS and isinstance(v, int) and not isinstance(v, bool)
                and v >= 0}

    by_source = raw.get("by_source") if isinstance(raw.get("by_source"), dict) else {}
    out = {
        "at": str(raw.get("at") or now_iso())[:32],
        "job": raw["job"],
        "mode": raw["mode"],
        "totals": counts(raw.get("totals")),
        "by_source": {str(s)[:32]: counts(c) for s, c in list(by_source.items())[:16]},
        "requests": {str(p)[:32]: int(n) for p, n in (raw.get("requests") or {}).items()
                     if isinstance(n, int) and n >= 0} if isinstance(
                         raw.get("requests"), dict) else {},
        "duration_s": int(raw["duration_s"]) if isinstance(raw.get("duration_s"), (int, float))
        else None,
        "stopped": str(raw["stopped"])[:120] if raw.get("stopped") else None,
    }
    return out


async def record_run(raw: object) -> bool:
    """Push one run's counts to Redis (newest first, RUNS_KEEP kept). Best-effort."""
    run = clean_run(raw)
    if run is None:
        return False
    try:
        from src.redis_client import get_redis
        r = get_redis()
        await r.lpush(RUNS_KEY, json.dumps(run))
        await r.ltrim(RUNS_KEY, 0, RUNS_KEEP - 1)
        return True
    except Exception:
        logger.debug("catalog_growth: run record not stored", exc_info=True)
        return False


async def recent_runs(limit: int = 10) -> list[dict]:
    """Newest runs first; [] when Redis is unavailable."""
    try:
        from src.redis_client import get_redis
        raw = await get_redis().lrange(RUNS_KEY, 0, max(0, limit - 1))
    except Exception:
        return []
    out: list[dict] = []
    for item in raw or []:
        try:
            run = clean_run(json.loads(item))
        except (TypeError, ValueError):
            continue
        if run:
            out.append(run)
    return out
