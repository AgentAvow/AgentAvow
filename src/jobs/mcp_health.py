"""MCP connector health: email the admin when the hosted /mcp endpoint breaks.

From 2026-10-17 to 10-20 every first request from current Claude clients (claude-code
2.1.29x+, claude.ai "Claude-User") got HTTP 400 "Unsupported protocol version": prod
ran mcp SDK 1.30 and the clients speak MCP 2026-07-28. They fell back quietly, our own
checks only spoke the old protocol, and ~4,000 rejects went unnoticed for days. Three
checks close that gap; each emails the admin (and posts the in-app notification + the
admin's HMAC alert webhook, like the sandbox watchdog):

``run_probe``      every 10 min: call the public URL (through nginx, as clients do) in
                   both protocol eras: 2026-07-28 ``server/discover`` + ``tools/list``
                   (per-request ``_meta`` envelope + routing headers), and 2025-11-25
                   ``initialize`` (no version header, like real clients) + ``tools/list``,
                   plus one read-only ``about_agentavow`` call per era. A check fails on a
                   non-200, a JSON-RPC error, a changed tool count, or a timeout.
``tools_list_drift``  part of the probe: the live 2025-11-25 ``tools/list`` bytes must
                   hash to the reviewed fixture (tests/fixtures/mcp_wire_2025_11_25/
                   tools_list.json, pinned below because tests/ is not in the image).
                   A mismatch needs an OpenAI portal Rescan.
``run_reject_check``  every 15 min: the reject share of real client POSTs over the last
                   30 min (src/bridges/mcp_response_counter), and any "Unsupported
                   protocol version" rejects with the version clients asked for.

Alerting: a check that fails emails once per distinct problem per 6 h; timeouts,
connection errors and 5xx must fail twice in a row first (a blip is not an outage).
When an alerted check passes twice in a row, one "recovered" email goes out. Probe
requests carry an HMAC marker so they bump no usage metric and are not counted as client
traffic. Nothing here raises into the scheduler.

Manual use (inside the backend container)::

    python -m src.jobs.mcp_health probe        # run the probe once, print results
    python -m src.jobs.mcp_health rejects      # print the reject window
    python -m src.jobs.mcp_health test-email   # send one test alert email
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.bridges import mcp_response_counter as counter

logger = logging.getLogger(__name__)

MODERN = "2026-07-28"
HANDSHAKE = "2025-11-25"
PROBE_UA = "agentavow-mcp-health/1.0 (+https://agentavow.com)"
ABOUT_TOOL = "about_agentavow"

# SHA-256 of tests/fixtures/mcp_wire_2025_11_25/tools_list.json, the exact 2025-11-25
# tools/list bytes (request id 1) the ChatGPT app review was done against, and its tool
# count. tests/test_mcp_health.py keeps both in sync with the fixture.
EXPECTED_TOOLS_LIST_SHA256 = "d673f85d019dd57a48a10bf696d3c8952b538bf4d32b440d55ae64b89e294847"
EXPECTED_TOOL_COUNT = 8

STATE_PREFIX = "ag:ops:mcp_health:state:"
DEDUPE_PREFIX = "ag:ops:mcp_health:alerted:"
STATE_TTL = 7 * 24 * 3600
RECOVERY_PASSES = 2
WEBHOOK_TYPE = "agentavow.ops.mcp_health"

_NEXT_PROBE = (
    "Run the probe by hand in the backend container (<code>python -m src.jobs.mcp_health "
    "probe</code>) and read <code>docker compose logs backend | grep 'POST /mcp'</code>. "
    "If a deploy just went out, compare the running mcp SDK (<code>pip show mcp</code>) "
    "with main and roll back if it differs.")
_NEXT_DRIFT = (
    "The live 2025-11-25 tools/list no longer matches the reviewed snapshot "
    "(tests/fixtures/mcp_wire_2025_11_25/tools_list.json). If the change was meant, "
    "Rescan the app in the OpenAI portal (docs/internal/chatgpt-plugin-release-runbook.md) "
    "and update the fixture and EXPECTED_TOOLS_LIST_SHA256; if not, roll back the deploy.")
_NEXT_UPV = (
    "Clients are sending a protocol version /mcp does not serve. Check which mcp SDK prod "
    "runs (<code>pip show mcp</code>) and whether a newer one serves that version (the "
    "10-20 fix was PR #205, SDK 2.3.0).")
_NEXT_REJECTS = (
    "Read <code>docker compose logs backend | grep 'POST /mcp'</code> for the failing "
    "status and run <code>python -m src.jobs.mcp_health probe</code> in the container.")


@dataclass
class Check:
    """One check's outcome. ``ok`` None means "could not judge" (no state change)."""

    key: str
    label: str
    ok: bool | None
    problem: str = ""
    detail: str = ""
    transient: bool = False
    next_step: str = _NEXT_PROBE
    facts: dict = field(default_factory=dict)


def _cfg(name: str, default):
    try:
        from src.config import settings

        v = getattr(settings, name)
        return default if v is None else v
    except Exception:
        return default


def enabled() -> bool:
    return counter.counting_enabled()


# --------------------------------------------------------------------------- #
# active probe
# --------------------------------------------------------------------------- #
def modern_envelope(**params) -> dict:
    """Request params with the 2026-07-28 per-request ``_meta`` envelope (the same
    shape as tests/mcp_wire.modern_envelope)."""
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "agentavow-mcp-health",
                                                    "version": "1.0"},
        },
        **params,
    }


def _headers(method: str, era: str, params: dict | None) -> dict:
    h = {"content-type": "application/json",
         "accept": "application/json, text/event-stream",
         "user-agent": PROBE_UA}
    marker = counter.probe_marker()
    if marker:
        h[counter.PROBE_HEADER] = marker
    if era == MODERN:
        h["mcp-protocol-version"] = MODERN
        h["mcp-method"] = method
        name = (params or {}).get("name")
        if isinstance(name, str):
            h["mcp-name"] = name
    elif method != "initialize":  # real clients send initialize without the header
        h["mcp-protocol-version"] = era
    return h


def _rpc_body(raw: bytes, content_type: str) -> dict | None:
    """The JSON-RPC message in a JSON or single-event SSE response."""
    try:
        if "text/event-stream" in content_type:
            for line in raw.decode("utf-8", "replace").splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return None
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def _snippet(raw: bytes, n: int = 300) -> str:
    return raw[:n].decode("utf-8", "replace")


async def _call(client, url: str, method: str, era: str, params: dict | None,
                request_id: int, label: str, key: str
                ) -> tuple[Check, dict | None, bytes]:
    """POST one JSON-RPC request; a Check for the transport/JSON-RPC outcome plus the
    parsed message and raw body for the caller's own assertions."""
    import httpx

    body: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    started = time.monotonic()
    try:
        resp = await client.post(url, headers=_headers(method, era, params),
                                 content=json.dumps(body))
    except httpx.TimeoutException:
        return Check(key, label, False, "timeout", f"No answer within "
                     f"{_cfg('mcp_health_probe_timeout_seconds', 20.0):g}s.",
                     transient=True), None, b""
    except Exception as exc:  # connection refused, DNS, TLS ...
        return Check(key, label, False, "connection error",
                     f"{type(exc).__name__} reaching {url}.", transient=True), None, b""
    ms = int((time.monotonic() - started) * 1000)
    raw = resp.content
    facts = {"status": resp.status_code, "ms": ms}
    if resp.status_code != 200:
        msg = _rpc_body(raw, resp.headers.get("content-type", "")) or {}
        err = msg.get("error") if isinstance(msg, dict) else None
        detail = f"HTTP {resp.status_code} after {ms} ms."
        if isinstance(err, dict):
            detail += f" JSON-RPC error {err.get('code')}: {err.get('message')}."
            data = err.get("data")
            if isinstance(data, dict) and data.get("requested"):
                facts["requested"] = counter.clean_version(data.get("requested"))
                facts["supported"] = [counter.clean_version(v)
                                      for v in (data.get("supported") or [])][:8]
        else:
            detail += f" Body starts: {_snippet(raw, 200)!r}."
        return Check(key, label, False, f"HTTP {resp.status_code}", detail,
                     transient=resp.status_code >= 500, facts=facts), None, raw
    msg = _rpc_body(raw, resp.headers.get("content-type", ""))
    if not isinstance(msg, dict):
        return Check(key, label, False, "unreadable response",
                     f"HTTP 200 but the body is not a JSON-RPC message: "
                     f"{_snippet(raw, 200)!r}.", facts=facts), None, raw
    if "error" in msg:
        err = msg.get("error") or {}
        return Check(key, label, False, f"JSON-RPC error {err.get('code')}",
                     f"HTTP 200 carrying JSON-RPC error {err.get('code')}: "
                     f"{err.get('message')}.", facts=facts), None, raw
    if not isinstance(msg.get("result"), dict):
        return Check(key, label, False, "no result", "HTTP 200 without a result object.",
                     facts=facts), None, raw
    return Check(key, label, True, facts=facts), msg["result"], raw


def _tool_count_check(c: Check, result: dict | None) -> Check:
    if not c.ok or result is None:
        return c
    tools = result.get("tools")
    n = len(tools) if isinstance(tools, list) else -1
    c.facts["tools"] = n
    if n != EXPECTED_TOOL_COUNT:
        return Check(c.key, c.label, False, f"{n} tools, expected {EXPECTED_TOOL_COUNT}",
                     f"tools/list returned {n} tools; the reviewed snapshot has "
                     f"{EXPECTED_TOOL_COUNT}.", facts=c.facts)
    return c


def _tool_call_check(c: Check, result: dict | None) -> Check:
    if not c.ok or result is None:
        return c
    if result.get("isError") is True or not result.get("content"):
        return Check(c.key, c.label, False, "tool error",
                     f"{ABOUT_TOOL} answered isError={result.get('isError')!r} "
                     f"with {len(result.get('content') or [])} content block(s).",
                     facts=c.facts)
    return c


async def run_probe(url: str | None = None, client=None) -> list[Check]:
    """Probe /mcp in both protocol eras. Never raises."""
    import httpx

    url = url or str(_cfg("mcp_health_probe_url", "https://agentavow.com/mcp"))
    own = client is None
    if own:
        client = httpx.AsyncClient(
            timeout=float(_cfg("mcp_health_probe_timeout_seconds", 20.0)),
            follow_redirects=False)
    # The tools/call needs the probe marker, or it would count as connector usage.
    marked = bool(counter.probe_marker())
    out: list[Check] = []
    try:
        # ── 2026-07-28 (current Claude clients) ──
        c, res, _ = await _call(client, url, "server/discover", MODERN, modern_envelope(),
                                1, f"{MODERN} server/discover", "modern_discover")
        if c.ok and MODERN not in (res.get("supportedVersions") or []):
            c = Check(c.key, c.label, False, f"{MODERN} not advertised",
                      f"supportedVersions is {res.get('supportedVersions')!r}.",
                      facts=c.facts)
        out.append(c)
        c, res, _ = await _call(client, url, "tools/list", MODERN, modern_envelope(), 2,
                                f"{MODERN} tools/list", "modern_tools_list")
        out.append(_tool_count_check(c, res))
        if marked:
            c, res, _ = await _call(
                client, url, "tools/call", MODERN,
                modern_envelope(name=ABOUT_TOOL, arguments={}), 3,
                f"{MODERN} tools/call {ABOUT_TOOL}", "modern_tool_call")
            out.append(_tool_call_check(c, res))

        # ── 2025-11-25 (ChatGPT, older clients; handshake era) ──
        c, res, _ = await _call(
            client, url, "initialize", HANDSHAKE,
            {"protocolVersion": HANDSHAKE, "capabilities": {},
             "clientInfo": {"name": "agentavow-mcp-health", "version": "1.0"}},
            0, f"{HANDSHAKE} initialize", "legacy_initialize")
        if c.ok and res.get("protocolVersion") != HANDSHAKE:
            c = Check(c.key, c.label, False, "wrong protocolVersion",
                      f"initialize answered protocolVersion "
                      f"{counter.clean_version(res.get('protocolVersion'))}.", facts=c.facts)
        out.append(c)
        # Request id 1 and no params: exactly the request the fixture was captured with.
        c, res, raw = await _call(client, url, "tools/list", HANDSHAKE, None, 1,
                                  f"{HANDSHAKE} tools/list", "legacy_tools_list")
        listed = c.ok
        out.append(_tool_count_check(c, res))
        out.append(drift_check(raw if listed else None))
        if marked:
            c, res, _ = await _call(client, url, "tools/call", HANDSHAKE,
                                    {"name": ABOUT_TOOL, "arguments": {}}, 3,
                                    f"{HANDSHAKE} tools/call {ABOUT_TOOL}",
                                    "legacy_tool_call")
            out.append(_tool_call_check(c, res))
    except Exception as exc:
        logger.debug("mcp health probe crashed", exc_info=True)
        out.append(Check("probe_crashed", "MCP health probe", False, "probe error",
                         f"{type(exc).__name__} inside the probe.", transient=True))
    finally:
        if own:
            await client.aclose()
    return out


def drift_check(raw: bytes | None) -> Check:
    """The live 2025-11-25 tools/list bytes vs the reviewed fixture's SHA-256."""
    label = f"{HANDSHAKE} tools/list vs reviewed snapshot"
    if raw is None:  # tools/list itself failed; that check already reports it
        return Check("tools_list_drift", label, None, next_step=_NEXT_DRIFT)
    got = hashlib.sha256(raw).hexdigest()
    if got == EXPECTED_TOOLS_LIST_SHA256:
        return Check("tools_list_drift", label, True, next_step=_NEXT_DRIFT)
    return Check("tools_list_drift", label, False, "bytes changed",
                 f"SHA-256 of the live body is {got[:16]}…, the reviewed snapshot is "
                 f"{EXPECTED_TOOLS_LIST_SHA256[:16]}… ({len(raw)} bytes live).",
                 next_step=_NEXT_DRIFT, facts={"sha256": got, "bytes": len(raw)})


# --------------------------------------------------------------------------- #
# passive reject-rate check
# --------------------------------------------------------------------------- #
def evaluate_rejects(window: dict, *, minutes: int | None = None) -> list[Check]:
    """Threshold logic over a ``mcp_response_counter.read_window`` result (pure)."""
    minutes = int(minutes or _cfg("mcp_health_reject_window_minutes", 30))
    min_req = int(_cfg("mcp_health_reject_min_requests", 30))
    ratio_at = float(_cfg("mcp_health_reject_error_ratio", 0.10))
    upv_min = int(_cfg("mcp_health_unsupported_version_min", 3))
    total = int(window.get("total") or 0)
    statuses = {str(k): int(v) for k, v in (window.get("statuses") or {}).items()}
    upv = int(window.get("upv") or 0)
    versions = list(window.get("versions") or [])
    # 404 is JSON-RPC "method not found": clients probe optional methods and get it
    # as a normal answer, so it is shown but does not count as a reject.
    errors = sum(n for s, n in statuses.items() if s[:1] in ("4", "5") and s != "404")
    facts = {"window_minutes": minutes, "total": total, "errors": errors,
             "statuses": statuses, "upv": upv, "versions": versions,
             "surfaces": window.get("surfaces") or {}}
    out: list[Check] = []

    label = "Unsupported protocol version rejects"
    if upv >= upv_min:
        vs = ", ".join(versions) or "unknown"
        out.append(Check("rejects_unsupported_version", label, False,
                         f"{upv} in {minutes} min, clients sent {vs}",
                         f"{upv} request(s) in the last {minutes} min were rejected with "
                         f"'Unsupported protocol version'. Versions clients asked for: {vs}.",
                         next_step=_NEXT_UPV, facts=facts))
    else:
        out.append(Check("rejects_unsupported_version", label, True, facts=facts))

    label = "Client reject rate"
    if total < min_req:
        out.append(Check("rejects_error_rate", label, None, facts=facts))
    else:
        share = errors / total if total else 0.0
        if share >= ratio_at:
            top = ", ".join(f"{s}×{n}" for s, n in sorted(statuses.items())
                            if s[:1] in ("4", "5"))
            out.append(Check("rejects_error_rate", label, False,
                             f"{share:.0%} of {total} requests",
                             f"{errors} of {total} client POSTs to /mcp in the last "
                             f"{minutes} min got a 4xx/5xx ({share:.0%}; alert at "
                             f"{ratio_at:.0%}). Statuses: {top}.",
                             next_step=_NEXT_REJECTS, facts=facts))
        else:
            out.append(Check("rejects_error_rate", label, True, facts=facts))
    return out


async def run_reject_check(now: float | None = None) -> list[Check]:
    try:
        minutes = int(_cfg("mcp_health_reject_window_minutes", 30))
        window = await counter.read_window(minutes, now=now)
        return evaluate_rejects(window, minutes=minutes)
    except Exception:
        logger.debug("mcp reject check failed", exc_info=True)
        return []


# --------------------------------------------------------------------------- #
# alert state machine: dedupe + recovery
# --------------------------------------------------------------------------- #
def _slug(problem: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in problem.lower())[:60]


def _now_iso(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat(timespec="minutes")


async def process(checks: list[Check], now: datetime | None = None
                  ) -> tuple[list[tuple[Check, dict]], list[tuple[Check, dict]]]:
    """Advance each check's state; return ``(to_alert, recovered)`` with each check's
    state. Dedupe: per check, one alert per distinct problem per the dedupe window."""
    from src.redis_client import get_redis

    r = get_redis()
    dedupe_ttl = int(float(_cfg("mcp_health_alert_dedupe_hours", 6)) * 3600)
    need = max(1, int(_cfg("mcp_health_transient_failures_before_alert", 2)))
    to_alert: list[tuple[Check, dict]] = []
    recovered: list[tuple[Check, dict]] = []
    for c in checks:
        if c.ok is None:
            continue
        skey = f"{STATE_PREFIX}{c.key}"
        raw = await r.get(skey)
        try:
            state = json.loads(raw) if raw else None
        except ValueError:
            state = None
        if c.ok:
            if not state:
                continue
            if not state.get("alerted"):  # an unalerted blip: forget it at once
                await r.delete(skey)
                continue
            state["passes"] = int(state.get("passes", 0)) + 1
            if state["passes"] < RECOVERY_PASSES:
                await r.set(skey, json.dumps(state), ex=STATE_TTL)
                continue
            await r.delete(skey)
            await r.delete(f"{DEDUPE_PREFIX}{c.key}")
            if state.get("alerted"):
                recovered.append((c, state))
            continue
        state = state or {"since": _now_iso(now), "fails": 0, "alerted": False}
        state["fails"] = int(state.get("fails", 0)) + 1
        state["passes"] = 0
        state["problem"] = c.problem
        state["last"] = _now_iso(now)
        if not c.transient or state["fails"] >= need:
            dkey = f"{DEDUPE_PREFIX}{c.key}"
            prev = await r.get(dkey)
            prev = prev.decode() if isinstance(prev, bytes) else prev
            if prev != _slug(c.problem):
                await r.set(dkey, _slug(c.problem), ex=dedupe_ttl)
                state["alerted"] = True
                to_alert.append((c, state))
        await r.set(skey, json.dumps(state), ex=STATE_TTL)
    return to_alert, recovered


def _subject(items: list[tuple[Check, dict]], recovered: bool) -> str:
    c = items[0][0]
    head = (f"AgentAvow MCP: {c.label} recovered" if recovered
            else f"AgentAvow MCP: {c.label} failing ({c.problem})")
    if len(items) > 1:
        head += f" +{len(items) - 1} more"
    return head[:180]


def _facts_html(c: Check) -> str:
    f = c.facts or {}
    rows = []
    if "status" in f:
        rows.append(f"HTTP {f['status']} in {f.get('ms', '?')} ms")
    if f.get("requested"):
        rows.append(f"client version {f['requested']}; server supports "
                    f"{', '.join(f.get('supported') or []) or 'unknown'}")
    if "tools" in f:
        rows.append(f"{f['tools']} tools")
    if "total" in f:
        rows.append(f"{f['total']} client POSTs, {f.get('errors', 0)} rejects, "
                    f"{f.get('upv', 0)} unsupported-version in {f.get('window_minutes')} min")
        if f.get("statuses"):
            rows.append("statuses " + ", ".join(f"{k}×{v}" for k, v in
                                                sorted(f["statuses"].items())))
        surf = f.get("surfaces") or {}
        if surf:
            rows.append("by client " + ", ".join(
                f"{k} {v.get('errors', 0)}/{v.get('total', 0)}" for k, v in sorted(surf.items())))
    return "".join(f"<li>{html.escape(str(x))}</li>" for x in rows)


def render_email(items: list[tuple[Check, dict]], *, recovered: bool,
                 url: str) -> tuple[str, str]:
    """(subject, html) for one alert or recovery email covering ``items``."""
    parts = []
    for c, state in items:
        since = html.escape(str(state.get("since", "")))
        if recovered:
            parts.append(
                f"<h3>{html.escape(c.label)}: passing again</h3>"
                f"<p>It had been failing since {since} UTC "
                f"({html.escape(str(state.get('problem', '')))}, "
                f"{int(state.get('fails', 0))} failed checks). Two checks in a row have "
                f"passed.</p>")
            continue
        facts = _facts_html(c)
        parts.append(
            f"<h3>{html.escape(c.label)}: {html.escape(c.problem)}</h3>"
            f"<p>{html.escape(c.detail)}</p>"
            f"<p>First failed {since} UTC; failed {int(state.get('fails', 1))} check(s) "
            f"in a row.</p>"
            + (f"<ul>{facts}</ul>" if facts else "")
            + f"<p><b>Next step:</b> {c.next_step}</p>")
    dedupe = _cfg("mcp_health_alert_dedupe_hours", 6)
    footer = (f"<p style=\"color:#64748b\">Endpoint: {html.escape(url)}. "
              f"One email per problem per {dedupe} h, plus one when it recovers. "
              "Sent by src/jobs/mcp_health.py.</p>")
    return _subject(items, recovered), "".join(parts) + footer


async def _deliver(subject: str, body_html: str, event: str, keys: list[str]) -> bool:
    from src.email import send_ops_alert_email

    to = str(_cfg("mcp_health_alert_email", "") or "") or None
    sent = await send_ops_alert_email(subject, body_html, to=to)
    try:
        from src.jobs.behavioral_eval import notify_admins

        await notify_admins(subject, html.unescape(_strip_tags(body_html))[:1500],
                            reference_id=f"mcp-health:{event}:{','.join(keys)}"[:200],
                            payload={"type": WEBHOOK_TYPE, "event": event,
                                     "checks": keys, "title": subject})
    except Exception:
        logger.debug("mcp health in-app notify failed", exc_info=True)
    return sent


def _strip_tags(s: str) -> str:
    import re

    return re.sub(r"<[^>]+>", " ", s)


async def alert(checks: list[Check], now: datetime | None = None) -> dict:
    """Run ``checks`` through the state machine and send what is due. Never raises."""
    out = {"alerted": [], "recovered": []}
    try:
        to_alert, recovered = await process(checks, now)
        url = str(_cfg("mcp_health_probe_url", ""))
        if to_alert:
            subject, body = render_email(to_alert, recovered=False, url=url)
            keys = [c.key for c, _ in to_alert]
            logger.warning("MCP health alert: %s", subject)
            if not await _deliver(subject, body, "failing", keys):
                # Not delivered: forget the dedupe so the next tick tries again, and do
                # not promise a "recovered" email for an alert that never arrived.
                from src.redis_client import get_redis

                r = get_redis()
                for k in keys:
                    await r.delete(f"{DEDUPE_PREFIX}{k}")
                    raw = await r.get(f"{STATE_PREFIX}{k}")
                    if raw:
                        st = json.loads(raw)
                        st["alerted"] = False
                        await r.set(f"{STATE_PREFIX}{k}", json.dumps(st), ex=STATE_TTL)
            out["alerted"] = keys
        if recovered:
            subject, body = render_email(recovered, recovered=True, url=url)
            keys = [c.key for c, _ in recovered]
            logger.warning("MCP health recovered: %s", subject)
            await _deliver(subject, body, "recovered", keys)
            out["recovered"] = keys
    except Exception:
        logger.debug("mcp health alerting failed", exc_info=True)
    return out


async def probe_and_alert() -> dict:
    checks = await run_probe()
    bad = [c.key for c in checks if c.ok is False]
    if bad:
        logger.info("MCP health probe: failing %s", bad)
    return await alert(checks)


async def rejects_and_alert(now: float | None = None) -> dict:
    return await alert(await run_reject_check(now))


async def send_test_email() -> bool:
    """One clearly-labelled test alert, bypassing state and dedupe."""
    c = Check("test", "test alert", False, "test only",
              "This is a test of the MCP health alert email. Nothing is broken.",
              next_step="None. If you can read this, MCP alerts reach this address.")
    subject, body = render_email([(c, {"since": _now_iso(None), "fails": 1})],
                                 recovered=False,
                                 url=str(_cfg("mcp_health_probe_url", "")))
    return await _deliver(subject.replace("failing (test only)", "(no action needed)"),
                          body, "test", ["test"])


# --------------------------------------------------------------------------- #
# scheduler loops (started from src/jobs/scheduler.start_scheduler, lock holder only)
# --------------------------------------------------------------------------- #
async def probe_loop(initial_delay: float = 90.0) -> None:
    import asyncio

    interval = int(_cfg("mcp_health_probe_interval_seconds", 600))
    logger.info("MCP health probe started (interval=%ds)", interval)
    await asyncio.sleep(initial_delay)
    while True:
        try:
            await probe_and_alert()
        except Exception:
            logger.exception("MCP health probe failed")
        await asyncio.sleep(interval)


async def reject_loop(initial_delay: float = 120.0) -> None:
    import asyncio

    interval = int(_cfg("mcp_health_reject_check_interval_seconds", 900))
    logger.info("MCP reject-rate check started (interval=%ds)", interval)
    await asyncio.sleep(initial_delay)
    while True:
        try:
            await rejects_and_alert()
        except Exception:
            logger.exception("MCP reject-rate check failed")
        await asyncio.sleep(interval)


def _main(argv: list[str]) -> int:  # pragma: no cover - manual operator entry point
    import asyncio

    cmd = argv[1] if len(argv) > 1 else "probe"

    async def go() -> int:
        if cmd == "probe":
            for c in await run_probe():
                state = "PASS" if c.ok else ("SKIP" if c.ok is None else "FAIL")
                print(f"{state:4} {c.label}: {c.problem or 'ok'} {c.detail}".rstrip())
            return 0
        if cmd == "rejects":
            minutes = int(_cfg("mcp_health_reject_window_minutes", 30))
            window = await counter.read_window(minutes)
            print(json.dumps(window, indent=2))
            for c in evaluate_rejects(window, minutes=minutes):
                print(c.key, c.ok, c.problem)
            return 0
        if cmd == "test-email":
            ok = await send_test_email()
            print("sent" if ok else "NOT sent (check RESEND_API_KEY / SMTP and the log)")
            return 0 if ok else 1
        print("usage: python -m src.jobs.mcp_health [probe|rejects|test-email]")
        return 2

    return asyncio.run(go())


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(_main(sys.argv))
