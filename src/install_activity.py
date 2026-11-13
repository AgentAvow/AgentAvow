"""Active Claude Code plugin installs, counted by the plugin's random install ID.

The plugin's session-start and install-time hooks (plugins/agentavow-trust/scripts/
agentavow_precheck.py) send ``X-AgentAvow-Install: <uuid4>`` on their scan requests: a
random ID made once per machine. Counting machines by IP address undercounts returning
users (an address changes, and many people share one), so this is what active-install
and D1/D7 retention numbers are read from.

What is stored, and nothing else:
  * ``ag:metrics:install:active:<YYYY-MM-DD>``: a Redis set of the install IDs seen that
    UTC day, each as a keyed one-way hash (HMAC-SHA256 under a server key, never the
    raw ID);
  * ``ag:metrics:install:new:<YYYY-MM-DD>``: the subset seen that day and in none of the
    previous ``LOOKBACK_DAYS`` days ("new installs").
  * from plugin 0.1.41, the once-a-day "active" request (see the section at the end):
    ``ag:metrics:install:ping:<YYYY-MM-DD>[:<app type>]`` sets of the same hashes, a
    per-day count of installs per plugin version, and the first day one arrived.
All of these (bar the first-day date) expire 40 days after their day ends
(``RETENTION_DAYS``). No IP address, User-Agent,
path, tool name or time of day is stored with a hash, and the ID is never logged: the
nginx log format names only fixed fields, the app's request log records no headers, and
Sentry events have the header removed (src/sentry_filters.py).

The header is read only from the plugin hooks' own User-Agents, and only in the
canonical lowercase UUIDv4 form the plugin writes; anything else is ignored. Recording is
fire-and-forget: it never delays or fails a scan.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
from datetime import date, datetime, timedelta, timezone

from fastapi import Request

logger = logging.getLogger(__name__)

INSTALL_HEADER = "x-agentavow-install"
# The plugin hooks that send the header (session start, install time). The per-call
# gate never talks to AgentAvow, so it never sends one.
HOOK_UA_PREFIXES = ("agentavow-precheck/", "agentavow-preinstall/")

RETENTION_DAYS = 40
LOOKBACK_DAYS = RETENTION_DAYS - 1  # "new" = not seen on any of the previous 39 days
ACTIVE_PREFIX = "ag:metrics:install:active:"
NEW_PREFIX = "ag:metrics:install:new:"

_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_HASH_LABEL = b"agentavow-install-id-v1\x00"
_pending: set[asyncio.Task] = set()  # strong refs so fire-and-forget tasks finish


def parse_install_id(value: object) -> str | None:
    """The header value if it is exactly a canonical lowercase UUIDv4, else None."""
    if not isinstance(value, str) or len(value) != 36:
        return None
    return value if _UUID4.fullmatch(value) else None


def _hash_key() -> bytes:
    from src.config import settings

    if settings.install_id_hash_key:
        return settings.install_id_hash_key.encode("utf-8")
    return hmac.new(settings.jwt_secret.encode("utf-8"), b"install-id-hash-key",
                    hashlib.sha256).digest()


def hash_install_id(install_id: str) -> str:
    """Keyed one-way hash of a validated install ID (128 bits, hex)."""
    mac = hmac.new(_hash_key(), _HASH_LABEL + install_id.encode("ascii"), hashlib.sha256)
    return mac.hexdigest()[:32]


def install_hash_from_headers(headers) -> str | None:
    """The hashed install ID for a plugin hook request, or None (wrong client, no header,
    or a value that is not a canonical UUIDv4)."""
    ua = (headers.get("user-agent") or "").lower()
    if not ua.startswith(HOOK_UA_PREFIXES):
        return None
    iid = parse_install_id(headers.get(INSTALL_HEADER))
    return hash_install_id(iid) if iid else None


def _day_start(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)


def _expire_at(day: date) -> int:
    """Unix time the day's keys expire: RETENTION_DAYS after the day ends."""
    return int((_day_start(day) + timedelta(days=RETENTION_DAYS + 1)).timestamp())


async def record_install_hash(hashed: str, today: date | None = None) -> None:
    """Add a hashed install ID to today's active set, and to today's new set when it was
    not seen in the previous LOOKBACK_DAYS days. Best-effort: never raises."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = today or datetime.now(timezone.utc).date()
        active_key = f"{ACTIVE_PREFIX}{day.isoformat()}"
        added = await r.sadd(active_key, hashed)
        await r.expireat(active_key, _expire_at(day))
        if not added:
            return  # already counted today (and already judged new or not)
        pipe = r.pipeline(transaction=False)
        for i in range(1, LOOKBACK_DAYS + 1):
            pipe.sismember(f"{ACTIVE_PREFIX}{(day - timedelta(days=i)).isoformat()}", hashed)
        seen_before = await pipe.execute()
        if not any(bool(x) for x in seen_before):
            new_key = f"{NEW_PREFIX}{day.isoformat()}"
            await r.sadd(new_key, hashed)
            await r.expireat(new_key, _expire_at(day))
    except Exception:
        logger.debug("install activity not recorded", exc_info=False)


async def install_activity(request: Request) -> None:
    """FastAPI dependency for the scan routes the plugin hooks call. Reads and hashes the
    header, then records it in the background; the request never waits on Redis."""
    try:
        hashed = install_hash_from_headers(request.headers)
    except Exception:
        return
    if not hashed:
        return
    task = asyncio.create_task(record_install_hash(hashed))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


# --------------------------------------------------------------------------- #
# Read side (admin metrics)
# --------------------------------------------------------------------------- #
INSTALL_COLUMNS = (
    "installs_active", "installs_new", "installs_active_7d",
    "installs_d1_cohort", "installs_d1_returned",
    "installs_d7_cohort", "installs_d7_returned", "installs_d7_returned_week",
)

INSTALL_NOTES = [
    "installs_* count Claude Code plugin installs by the plugin's random install ID "
    "(X-AgentAvow-Install, plugin 0.1.40 and later), not by IP address. Only a keyed hash "
    "of the ID is kept, per UTC day, for 40 days, never with an IP. installs_active = "
    "distinct installs whose session-start or install-time hook called the scan API that "
    "day; installs_active_7d = distinct installs over the 7 days ending that day. The "
    "session-start hook calls the API only when it has something new or stale to grade "
    "(a grade is kept up to 7 days), so a day's count is a floor; prefer the 7-day count.",
    "installs_new = installs seen that day and not in the previous 39 days (every install "
    "reads as new on its first day after 0.1.40 ships). installs_d1/d7_cohort = installs "
    "new 1 or 7 days before this day; installs_d1/d7_returned = how many of them were "
    "active on this day; installs_d7_returned_week = of the d7 cohort, how many were active "
    "on any of the 7 days after their first day. Days older than 40 days read empty; days "
    "before plugin 0.1.40 reached users read 0.",
]


async def _smembers(r, key: str) -> set[str]:
    raw = await r.smembers(key)
    return {m.decode() if isinstance(m, bytes) else str(m) for m in (raw or ())}


async def install_series(day_strs: list[str], today: date | None = None) -> dict:
    """``{column: [value per day]}`` for INSTALL_COLUMNS over ``day_strs`` (oldest
    first). A day outside the 40-day retention, or one whose inputs are partly expired,
    is None, never a made-up zero. Fail-open: every value None."""
    empty = {c: [None] * len(day_strs) for c in INSTALL_COLUMNS}
    try:
        from src.redis_client import get_redis

        r = get_redis()
        now = today or datetime.now(timezone.utc).date()
        oldest_kept = now - timedelta(days=RETENTION_DAYS)
        days = [date.fromisoformat(d) for d in day_strs]
        need = {d - timedelta(days=k) for d in days for k in range(0, 8)}
        need = {d for d in need if oldest_kept <= d <= now}
        active: dict[date, set[str]] = {}
        new: dict[date, set[str]] = {}
        for d in sorted(need):
            active[d] = await _smembers(r, f"{ACTIVE_PREFIX}{d.isoformat()}")
            new[d] = await _smembers(r, f"{NEW_PREFIX}{d.isoformat()}")
    except Exception:
        logger.exception("install series unavailable")
        return empty

    def kept(d: date) -> bool:
        return d in active

    out = {c: [] for c in INSTALL_COLUMNS}
    for d in days:
        if not kept(d):
            for c in INSTALL_COLUMNS:
                out[c].append(None)
            continue
        out["installs_active"].append(len(active[d]))
        out["installs_new"].append(len(new[d]))
        week = [d - timedelta(days=k) for k in range(7)]
        if all(kept(w) for w in week):
            out["installs_active_7d"].append(len(set().union(*(active[w] for w in week))))
        else:
            out["installs_active_7d"].append(None)
        for n in (1, 7):
            first = d - timedelta(days=n)
            if kept(first):
                cohort = new[first]
                out[f"installs_d{n}_cohort"].append(len(cohort))
                out[f"installs_d{n}_returned"].append(len(cohort & active[d]))
            else:
                out[f"installs_d{n}_cohort"].append(None)
                out[f"installs_d{n}_returned"].append(None)
        first = d - timedelta(days=7)
        if kept(first):
            later = set().union(*(active[first + timedelta(days=k)] for k in range(1, 8)))
            out["installs_d7_returned_week"].append(len(new[first] & later))
        else:
            out["installs_d7_returned_week"].append(None)
    return out


# --------------------------------------------------------------------------- #
# Once-a-day "active" request (plugin 0.1.41 and later)
# --------------------------------------------------------------------------- #
# Most session starts answer from the plugin's cache and send no scan request, so the
# scan-route counts above only see machines that scanned something that day. From
# 0.1.41 the session-start hook also sends, at most once per UTC day, one POST to
# /api/v1/public/plugin/active with the same install ID header, its own User-Agent
# (agentavow-active/<version>) and a JSON body of {"version", "app"}. Stored, and nothing
# else: the same keyed hash in a per-day set overall and per app type, plus a per-day
# count of distinct installs per plugin version, all expiring with the sets above; and
# the first day any was recorded. No IP, no time of day. Owner machines
# (settings.metrics_owner_ips) are not recorded.
ACTIVE_UA_PREFIX = "agentavow-active/"
APP_TYPES = ("desktop", "cli", "sdk", "cloud", "other")
PING_PREFIX = "ag:metrics:install:ping:"  # <day> and <day>:<app>
PING_VERSIONS_PREFIX = "ag:metrics:install:ping_versions:"  # <day> -> {version: installs}
PING_FIRST_DAY_KEY = "ag:metrics:install:ping_first_day"  # first day any was recorded
PING_MAX_BODY = 512
_VERSION = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")


def parse_app_type(value: object) -> str:
    return value if isinstance(value, str) and value in APP_TYPES else "other"


def parse_version(value: object) -> str | None:
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


async def record_active_ping(hashed: str, app: str, version: str | None,
                             today: date | None = None) -> None:
    """Add a hashed install ID to today's active sets (overall and for its app type) and
    count its version once a day. Best-effort: never raises."""
    try:
        from src.redis_client import get_redis

        r = get_redis()
        day = today or datetime.now(timezone.utc).date()
        ds = day.isoformat()
        when = _expire_at(day)
        key = f"{PING_PREFIX}{ds}"
        added = await r.sadd(key, hashed)
        await r.expireat(key, when)
        app_key = f"{PING_PREFIX}{ds}:{parse_app_type(app)}"
        await r.sadd(app_key, hashed)
        await r.expireat(app_key, when)
        if added and version:
            vkey = f"{PING_VERSIONS_PREFIX}{ds}"
            await r.hincrby(vkey, version, 1)
            await r.expireat(vkey, when)
        await r.setnx(PING_FIRST_DAY_KEY, ds)
    except Exception:
        logger.debug("active ping not recorded", exc_info=False)


def _is_owner_ip(ip: str | None) -> bool:
    try:
        from src.config import settings

        raw = getattr(settings, "metrics_owner_ips", "") or ""
        return bool(ip) and ip in {x.strip() for x in raw.split(",") if x.strip()}
    except Exception:
        return False


async def handle_active_ping(headers, body: bytes, client_ip: str | None) -> bool:
    """Validate and record one active request; True when recorded. The raw ID is only
    ever hashed; the IP is used only to leave owner machines out and is never stored."""
    ua = (headers.get("user-agent") or "").lower()
    if not ua.startswith(ACTIVE_UA_PREFIX):
        return False
    iid = parse_install_id(headers.get(INSTALL_HEADER))
    if not iid or _is_owner_ip(client_ip):
        return False
    data: object = {}
    if body and len(body) <= PING_MAX_BODY:
        try:
            data = json.loads(body)
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    await record_active_ping(hash_install_id(iid), parse_app_type(data.get("app")),
                             parse_version(data.get("version")))
    return True


ACTIVE_COLUMNS = ("active_installs", "active_installs_7d",
                  *(f"active_installs_{a}" for a in APP_TYPES))

ACTIVE_NOTES = [
    "active_installs = distinct Claude Code plugin installs that sent the plugin's "
    "once-a-day active request that UTC day (plugin 0.1.41 and later). The hook sends it "
    "on the first session start of the day even when it has nothing new to check, so this "
    "counts machines the plugin protected that day, not only the ones that scanned. It "
    "carries only the install ID (kept as a keyed hash for 40 days), the plugin version "
    "and the app type. active_installs_7d = distinct installs over the 7 days ending that "
    "day (fewer days until counting_from + 6). active_installs_<app> splits by app type: "
    "desktop, cli, sdk, cloud, other. Owner machines (METRICS_OWNER_IPS) are left out. "
    "Days before counting_from read empty. Installs still on 0.1.40 or earlier never send "
    "it, so the count grows as people update. A cloud session starts from a fresh machine "
    "and makes a new install ID, so cloud can count once per session.",
]


async def active_ping_series(day_strs: list[str], today: date | None = None) -> dict:
    """``{"counting_from", "seven_day_complete_from", "series": {column: [per day]}}``
    for ACTIVE_COLUMNS over ``day_strs`` (oldest first). A day before counting began or
    outside the 40-day retention is None, never a made-up zero. Fail-open: all None."""
    empty = {"counting_from": None, "seven_day_complete_from": None,
             "series": {c: [None] * len(day_strs) for c in ACTIVE_COLUMNS}}
    try:
        from src.redis_client import get_redis

        r = get_redis()
        raw_first = await r.get(PING_FIRST_DAY_KEY)
        if not raw_first:
            return empty
        first = date.fromisoformat(
            raw_first.decode() if isinstance(raw_first, bytes) else str(raw_first))
        now = today or datetime.now(timezone.utc).date()
        floor = max(first, now - timedelta(days=RETENTION_DAYS))
        days = [date.fromisoformat(d) for d in day_strs]
        need = {d - timedelta(days=k) for d in days for k in range(7)}
        overall: dict[date, set[str]] = {}
        for d in sorted(x for x in need if floor <= x <= now):
            overall[d] = await _smembers(r, f"{PING_PREFIX}{d.isoformat()}")
        per_app: dict[tuple[date, str], int] = {}
        for d in days:
            if d in overall:
                for a in APP_TYPES:
                    per_app[(d, a)] = int(await r.scard(f"{PING_PREFIX}{d.isoformat()}:{a}")
                                          or 0)
    except Exception:
        logger.exception("active ping series unavailable")
        return empty

    out: dict[str, list] = {c: [] for c in ACTIVE_COLUMNS}
    for d in days:
        if d not in overall:
            for c in ACTIVE_COLUMNS:
                out[c].append(None)
            continue
        out["active_installs"].append(len(overall[d]))
        week = [w for w in (d - timedelta(days=k) for k in range(7)) if w in overall]
        out["active_installs_7d"].append(len(set().union(*(overall[w] for w in week))))
        for a in APP_TYPES:
            out[f"active_installs_{a}"].append(per_app[(d, a)])
    return {"counting_from": first.isoformat(),
            "seven_day_complete_from": (first + timedelta(days=6)).isoformat(),
            "series": out}
