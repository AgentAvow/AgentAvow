"""Per-5-minute counters of what /mcp answered, for the passive reject-rate check.

From 2026-10-17 to 10-20 every first request from current Claude clients got HTTP 400
"Unsupported protocol version" and nothing noticed: the clients fell back quietly and
the request log was the only trace. The /mcp ASGI front (src/bridges/mcp_streamable)
now hands each answered POST to :func:`record_response`, which counts it here by status
and surface, and counts protocol-version rejections on their own along with the version
the client asked for. ``src/jobs/mcp_health`` reads the window back and emails the
admin when the reject share crosses its threshold.

Hot-path rules: :func:`record_response` is synchronous and only schedules a task; the
task's Redis writes swallow every exception (logged at debug). Nothing here can change
or delay a response. Health-probe requests (see ``src/jobs/mcp_health.is_probe_request``)
are never counted, so the probe cannot mask or fake a reject rate.

Keys (TTL 26 h):
  ``ag:mcp:resp:{slot}``      hash — ``total``, ``c:{2xx|3xx|4xx|5xx}``, ``s:{status}``,
                              ``upv`` (unsupported-version rejects), ``t:{surface}``,
                              ``e:{surface}`` (4xx/5xx per surface)
  ``ag:mcp:resp:upv:{slot}``  set — the protocol versions those rejects asked for
where ``slot = unix_time // 300``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import time

logger = logging.getLogger(__name__)

SLOT_SECONDS = 300
KEY_PREFIX = "ag:mcp:resp:"
VERSIONS_PREFIX = "ag:mcp:resp:upv:"
KEY_TTL = 26 * 3600
BODY_CAP = 4096          # bytes of an error body kept to classify it
MAX_VERSIONS_PER_SLOT = 20
UNSUPPORTED_PROTOCOL_VERSION = -32022  # mcp_types.jsonrpc.UNSUPPORTED_PROTOCOL_VERSION
_UPV_TEXT = b"unsupported protocol version"
_VERSION_RE = re.compile(r"[^A-Za-z0-9._-]")
_SURFACES = frozenset({"chatgpt", "claude-code", "cursor", "vscode", "claude", "other"})

# The health probe marks its requests with this header so they never count as usage
# or as client traffic. The value is an HMAC of MCP_INTERNAL_TOKEN (never the token
# itself), so it cannot be replayed as the bridge's X-AgentAvow-Internal proof, and a
# client without the token cannot hide its requests from the reject counter.
PROBE_HEADER = "x-agentavow-health-probe"
_PROBE_LABEL = b"agentavow-mcp-health-probe-v1"

# Strong refs so a fire-and-forget task is not garbage-collected mid-write.
_PENDING: set[asyncio.Task] = set()


def counting_enabled() -> bool:
    """The MCP health checks (and so these counters) are on: MCP_HEALTH_ENABLED, or by
    default whenever DEBUG is false (prod)."""
    try:
        from src.config import settings

        flag = settings.mcp_health_enabled
        return (not settings.debug) if flag is None else bool(flag)
    except Exception:
        return False


def probe_marker() -> str:
    """The probe header value, or "" when no MCP_INTERNAL_TOKEN is configured."""
    try:
        from src.config import settings

        token = settings.mcp_internal_token or ""
    except Exception:
        token = ""
    if not token:
        return ""
    return hmac.new(token.encode(), _PROBE_LABEL, hashlib.sha256).hexdigest()


def is_probe_marker(value: str | bytes | None) -> bool:
    if not value:
        return False
    expected = probe_marker()
    if not expected:
        return False
    given = value.decode("latin-1", "replace") if isinstance(value, bytes) else value
    return hmac.compare_digest(given, expected)


def slot_for(ts: float) -> int:
    return int(ts // SLOT_SECONDS)


def clean_version(v: object) -> str:
    """A client-sent version string made safe to store and to put in an email."""
    s = v if isinstance(v, str) else ("" if v is None else str(v))
    s = _VERSION_RE.sub("", s)[:32]
    return s or "(none)"


def classify(status: int, body_head: bytes, header_version: str | None) -> str | None:
    """The rejected protocol version when this response is an unsupported-version
    rejection, else None. SDK 2.x answers with JSON-RPC error -32022 whose
    ``data.requested`` names the version; SDK 1.x answered a plain-text 400."""
    if status < 400 or not body_head:
        return None
    if b"-32022" in body_head:
        try:
            err = (json.loads(body_head) or {}).get("error") or {}
            if err.get("code") == UNSUPPORTED_PROTOCOL_VERSION:
                return clean_version((err.get("data") or {}).get("requested")
                                     or header_version)
        except (ValueError, AttributeError, TypeError):
            pass
    if _UPV_TEXT in body_head.lower():
        return clean_version(header_version)
    return None


def record_response(status: int, body_head: bytes = b"", *, header_version: str | None,
                    surface: str, now: float | None = None) -> None:
    """Count one answered /mcp POST. Never raises, never awaits."""
    try:
        rejected = classify(status, body_head, header_version)
        task = asyncio.get_running_loop().create_task(
            _write(int(status), rejected, surface if surface in _SURFACES else "other",
                   now if now is not None else time.time()))
        _PENDING.add(task)
        task.add_done_callback(_PENDING.discard)
    except Exception:
        logger.debug("mcp response counter: could not schedule", exc_info=True)


async def _write(status: int, rejected: str | None, surface: str, now: float) -> None:
    try:
        from src.redis_client import get_redis

        r = get_redis()
        slot = slot_for(now)
        key = f"{KEY_PREFIX}{slot}"
        pipe = r.pipeline(transaction=False)
        pipe.hincrby(key, "total", 1)
        pipe.hincrby(key, f"c:{status // 100}xx", 1)
        pipe.hincrby(key, f"s:{status}", 1)
        pipe.hincrby(key, f"t:{surface}", 1)
        if status >= 400:
            pipe.hincrby(key, f"e:{surface}", 1)
        if rejected is not None:
            pipe.hincrby(key, "upv", 1)
        pipe.expire(key, KEY_TTL)
        await pipe.execute()
        if rejected is not None:
            vkey = f"{VERSIONS_PREFIX}{slot}"
            if int(await r.scard(vkey) or 0) < MAX_VERSIONS_PER_SLOT:
                await r.sadd(vkey, rejected)
                await r.expire(vkey, KEY_TTL)
    except Exception:
        logger.debug("mcp response counter: write failed", exc_info=True)


def _s(v: object) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


async def read_window(minutes: int, now: float | None = None) -> dict:
    """Sum the counters over the last ``minutes`` (whole 5-minute slots, current slot
    included). Returns ``{total, classes, statuses, upv, surfaces, versions}``."""
    from src.redis_client import get_redis

    r = get_redis()
    now = time.time() if now is None else now
    last = slot_for(now)
    n = max(1, -(-int(minutes * 60) // SLOT_SECONDS))
    out: dict = {"total": 0, "classes": {}, "statuses": {}, "upv": 0,
                 "surfaces": {}, "versions": []}
    versions: set[str] = set()
    for slot in range(last - n + 1, last + 1):
        h = await r.hgetall(f"{KEY_PREFIX}{slot}") or {}
        for k, v in h.items():
            k, cnt = _s(k), int(float(_s(v)))
            if k == "total":
                out["total"] += cnt
            elif k == "upv":
                out["upv"] += cnt
            elif k.startswith("c:"):
                out["classes"][k[2:]] = out["classes"].get(k[2:], 0) + cnt
            elif k.startswith("s:"):
                out["statuses"][k[2:]] = out["statuses"].get(k[2:], 0) + cnt
            elif k[:2] in ("t:", "e:"):
                s = out["surfaces"].setdefault(k[2:], {"total": 0, "errors": 0})
                s["total" if k[0] == "t" else "errors"] += cnt
        for v in await r.smembers(f"{VERSIONS_PREFIX}{slot}") or set():
            versions.add(_s(v))
    out["versions"] = sorted(versions)
    return out
