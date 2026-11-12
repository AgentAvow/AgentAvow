"""x402 phase 2: one polite, unpaid live check per listed endpoint.

Approved by Kenne 2026-11-11 (via agentgraph-83). The plan is in
docs/internal/x402-scan-design-2026-11-11.md, section "Phase 2: exact request, user
agent and rate plan".

* Only listings that declare GET, mainnet only. Never a body, never a payment header
  (X-PAYMENT / PAYMENT-SIGNATURE), no cookies, no auth.
* ``GET <listed URL>`` with ``User-Agent: AgentAvowBot/1.0 (+https://agentavow.com/docs/x402)``.
  https only, redirects not followed, 10 s timeout, 64 KB cap.
* 1 request every 2 s per host, at most 4 hosts at once, at most 50 endpoints per host
  per run (rotating across runs). Retry-After honoured; a host is skipped after 2
  429/503 replies or 3 timeouts in a row. robots.txt ``Disallow`` for AgentAvowBot is
  honoured. Opt-out: admin@agentavow.com.

What changes (``live_findings``, pure):
* the live 402 asks to pay a different address than the listing, on a network both
  name: HIGH, so the answer is Review. Never Do not connect from one read.
  Except when the live address is one the same site already lists on its other
  endpoints: then the listing is out of date, not redirected, and it is a LOW
  disclosure. Run 2 (11-12): 549 of the 646 payee findings were this case, one live
  payee per host, already in the host's other listings. "Same site" is the registrable
  domain (``payee_domain``: Public Suffix List, private section included), so one
  operator's subdomains count together while tenants of shared hosting (vercel.app,
  onrender.com, an account on workers.dev) stay apart. Run 3 (11-12): 44 of the 56
  HIGH payee rows were *.use.x402atlas.com, whose new Solana payee 95 other
  x402atlas.com listings already name.
* the live price is more than 10x the listing's: MEDIUM.
* terms match: no finding (``live_check.matches`` is True).
* no 402, a redirect, another status, a timeout or an unreadable 402: disclosure only.

The run itself (``run_live_checks``) takes an injectable fetch and clock, so CI uses
fixtures only and never touches a real endpoint.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

USER_AGENT = "AgentAvowBot/1.0 (+https://agentavow.com/docs/x402)"
ROBOTS_AGENT = "agentavowbot"
OPT_OUT_CONTACT = "admin@agentavow.com"
TIMEOUT_S = 10.0
MAX_BYTES = 64 * 1024
HOST_INTERVAL_S = 2.0
MAX_HOSTS_PARALLEL = 4
MAX_PER_HOST = 50
MAX_THROTTLES = 2      # 429 / 503 replies before a host is skipped for the run
MAX_TIMEOUTS = 3       # timeouts in a row before a host is skipped for the run
PRICE_JUMP = Decimal(10)
FORBIDDEN_HEADERS = frozenset({"x-payment", "payment-signature", "authorization", "cookie"})

WHERE_LIVE = "x402:live-402"


# ── which listings ─────────────────────────────────────────────────────────────

def declared_method(rec: dict) -> str:
    """The method the listing declares: v2 ``extensions.bazaar.info.input.method``,
    else v1 ``accepts[].outputSchema.input.method``. "" when none is declared."""
    ext = rec.get("extensions") if isinstance(rec.get("extensions"), dict) else {}
    baz = ext.get("bazaar") if isinstance(ext.get("bazaar"), dict) else {}
    info = baz.get("info") if isinstance(baz.get("info"), dict) else {}
    inp = info.get("input") if isinstance(info.get("input"), dict) else {}
    m = inp.get("method")
    if isinstance(m, str) and m.strip():
        return m.strip().upper()
    for a in rec.get("accepts") or []:
        if not isinstance(a, dict):
            continue
        os_ = a.get("outputSchema") if isinstance(a.get("outputSchema"), dict) else {}
        inp = os_.get("input") if isinstance(os_.get("input"), dict) else {}
        m = inp.get("method")
        if isinstance(m, str) and m.strip():
            return m.strip().upper()
    return ""


def eligible(rec: dict) -> bool:
    """GET-declared, https, and not testnet-only."""
    from src.scanner.x402_scan import TESTNETS, network_id
    url = str(rec.get("resource") or rec.get("endpoint_url") or "")
    if declared_method(rec) != "GET" or not url.lower().startswith("https://"):
        return False
    nets = {network_id(a.get("network")) for a in rec.get("accepts") or []
            if isinstance(a, dict)}
    return bool(nets - set(TESTNETS))


def plan(records: list[dict], run_index: int) -> dict[str, list[dict]]:
    """Per host, at most MAX_PER_HOST eligible listings, rotating with ``run_index`` so
    a big host is covered over successive runs."""
    by_host: dict[str, list[dict]] = {}
    for rec in records:
        if not eligible(rec):
            continue
        host = (urlsplit(str(rec.get("resource") or rec.get("endpoint_url"))).hostname
                or "").lower()
        if host:
            by_host.setdefault(host, []).append(rec)
    out: dict[str, list[dict]] = {}
    for host, recs in by_host.items():
        recs.sort(key=lambda r: str(r.get("resource") or r.get("endpoint_url")))
        n = len(recs)
        if n <= MAX_PER_HOST:
            out[host] = recs
            continue
        start = (run_index * MAX_PER_HOST) % n
        out[host] = [recs[(start + i) % n] for i in range(MAX_PER_HOST)]
    return out


# ── reading a reply (pure) ─────────────────────────────────────────────────────

def _decode_header(value: str) -> dict | None:
    v = (value or "").strip()
    if not v:
        return None
    for raw in (v, v + "=" * (-len(v) % 4)):
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                doc = json.loads(dec(raw))
                return doc if isinstance(doc, dict) else None
            except Exception:  # noqa: BLE001
                continue
    try:
        doc = json.loads(v)
        return doc if isinstance(doc, dict) else None
    except ValueError:
        return None


def read_reply(status: int | None, headers: dict[str, str], body: bytes,
               error: str | None = None) -> dict:
    """``{"state": ..., "accepts": [...], "status": n}``. States: ``paid`` (a readable
    402), ``unreadable_402``, ``redirect``, ``not_paid`` (any other status), ``timeout``,
    ``error``."""
    if error:
        return {"state": "timeout" if error == "timeout" else "error", "status": None,
                "accepts": []}
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if status is not None and 300 <= status < 400:
        return {"state": "redirect", "status": status, "accepts": []}
    if status != 402:
        return {"state": "not_paid", "status": status, "accepts": []}
    doc = _decode_header(h.get("payment-required", ""))
    if doc is None:
        try:
            doc = json.loads((body or b"")[:MAX_BYTES].decode("utf-8", "replace"))
        except ValueError:
            doc = None
    accepts = doc.get("accepts") if isinstance(doc, dict) else None
    if not isinstance(accepts, list) or not any(isinstance(a, dict) for a in accepts):
        return {"state": "unreadable_402", "status": 402, "accepts": []}
    return {"state": "paid", "status": 402,
            "accepts": [a for a in accepts if isinstance(a, dict)][:20]}


def _amount(a: dict) -> Decimal | None:
    raw = a.get("amount", a.get("maxAmountRequired"))
    try:
        return Decimal(str(raw)) if raw is not None and str(raw).strip() else None
    except (InvalidOperation, ValueError):
        return None


def _terms(accepts: list) -> dict[tuple[str, str], tuple[set[str], Decimal | None]]:
    """``(network, asset) -> ({payTo}, lowest amount)``; EVM addresses lower-cased."""
    from src.scanner.x402_scan import network_id
    out: dict[tuple[str, str], tuple[set[str], Decimal | None]] = {}
    for a in accepts or []:
        if not isinstance(a, dict):
            continue
        net = network_id(a.get("network"))
        evm = net.startswith("eip155")
        asset = str(a.get("asset") or "")
        asset = asset.lower() if evm else asset
        pt = str(a.get("payTo") or "").strip()
        pt = pt.lower() if evm else pt
        payees, amt = out.get((net, asset), (set(), None))
        if pt:
            payees.add(pt)
        a_amt = _amount(a)
        if a_amt is not None and (amt is None or a_amt < amt):
            amt = a_amt
        out[(net, asset)] = (payees, amt)
    return out


def _norm_payee(pt) -> str:
    """EVM addresses compare case-insensitively; other chains as written."""
    p = str(pt or "").strip()
    return p.lower() if p.startswith("0x") else p


_PSL = None


def payee_domain(host: str | None) -> str:
    """The site a host belongs to for payee comparison: its registrable domain under
    the Public Suffix List with the private section (``a.use.x402atlas.com`` ->
    ``x402atlas.com``; ``app.vercel.app`` stays itself, since vercel.app is a public
    suffix). An IP literal, a single label or anything the list can't place is
    compared as the host alone."""
    import ipaddress
    global _PSL
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h.strip("[]"))
        return h
    except ValueError:
        pass
    if _PSL is None:
        from publicsuffixlist import PublicSuffixList
        _PSL = PublicSuffixList()
    return _PSL.privatesuffix(h) or h


def host_payees(stubs) -> dict[str, set[str]]:
    """``payee_domain(host) -> every payTo its listings name`` (from the live stubs). An
    address the same site already lists elsewhere is not a redirect when an endpoint
    switches to it. Look a URL up with ``payees_for(known, url)``."""
    out: dict[str, set[str]] = {}
    for st in stubs or []:
        host = payee_domain(urlsplit(str(st.get("resource") or "")).hostname)
        if not host:
            continue
        for a in st.get("accepts") or []:
            if isinstance(a, dict) and a.get("payTo"):
                out.setdefault(host, set()).add(_norm_payee(a["payTo"]))
    return out


def payees_for(known: dict[str, set[str]], url: str) -> list[str]:
    """The payees ``url``'s site lists, sorted, from a ``host_payees`` map."""
    return sorted(known.get(payee_domain(urlsplit(url).hostname), ()))


LIVE_TERM_FIELDS = ("scheme", "network", "asset", "payTo", "amount", "maxAmountRequired")


def live_terms(accepts: list) -> list[dict]:
    """The live 402's payment terms as read, kept on ``live_check`` so a reviewer can
    compare them with the listing later (run 2 kept only the clipped finding text). At
    most 5 entries; each value is a string of at most 100 characters; ``extra`` is kept
    only as its key names."""
    out = []
    for a in (accepts or [])[:5]:
        if not isinstance(a, dict):
            continue
        t = {k: str(a[k])[:100] for k in LIVE_TERM_FIELDS if a.get(k) is not None}
        if isinstance(a.get("extra"), dict):
            t["extra_keys"] = sorted(str(k)[:40] for k in a["extra"])[:10]
        out.append(t)
    return out


def live_findings(listing: dict, reply: dict) -> tuple[list, dict]:
    """Findings from one live reply, and the ``live_check`` record to keep."""
    from src.scanner.x402_scan import _clip, _finding
    record: dict[str, Any] = {"state": reply.get("state"), "status": reply.get("status")}
    if reply.get("state") != "paid":
        return [], record
    record["live_terms"] = live_terms(reply.get("accepts") or [])
    want = _terms(listing.get("accepts") or [])
    got = _terms(reply.get("accepts") or [])
    out = []
    shared = [k for k in got if k in want]
    record["networks_compared"] = sorted({k[0] for k in shared})
    known = {_norm_payee(p) for p in reply.get("host_payees") or []}
    moved, unknown = [], []
    for k in shared:
        if got[k][0] and want[k][0] and not (got[k][0] & want[k][0]):
            m = (k[0], sorted(got[k][0])[0], sorted(want[k][0])[0])
            moved.append(m)
            if not {_norm_payee(p) for p in got[k][0]} <= known:
                unknown.append(m)
    if moved:
        record["payee_known_to_host"] = not unknown
    if unknown:
        net, live_pt, listed_pt = unknown[0]
        out.append(_finding(
            "payment_terms",
            f"the endpoint asks to pay a different address than its listing says on {net} "
            f"({_clip(live_pt, 20)}, listing: {_clip(listed_pt, 20)})",
            "high", WHERE_LIVE,
            "Check the live payment terms before you pay. The listing is reviewed once; "
            "the endpoint chooses whom it collects for on every call."))
    elif moved:
        net, live_pt, listed_pt = moved[0]
        out.append(_finding(
            "payment_terms",
            f"the listing's pay-to address is out of date on {net}: the endpoint now asks "
            f"to pay {_clip(live_pt, 20)}, an address this site lists on its other "
            f"endpoints (listing: {_clip(listed_pt, 20)})",
            "low", WHERE_LIVE,
            "Pay the address in the live request, which the site already uses elsewhere; "
            "the listing has not been refreshed."))
    jumps = []
    for k in shared:
        g, w = got[k][1], want[k][1]
        if g is not None and w is not None and w > 0 and g > w * PRICE_JUMP:
            jumps.append((k[0], g, w))
    if jumps:
        net, g, w = jumps[0]
        out.append(_finding(
            "payment_terms",
            f"the live price on {net} is {int(g / w)}x the listing's",
            "medium", WHERE_LIVE,
            "An agent that budgets from the listing will be asked for much more. Set a "
            "spending cap per call."))
    record["matches"] = bool(shared) and not moved and not jumps
    return out, record


# ── robots.txt (pure) ──────────────────────────────────────────────────────────

def robots_disallows(robots_txt: str, path: str) -> bool:
    """True when robots.txt disallows ``path`` for AgentAvowBot (or for ``*`` when it
    has no group of its own). Longest-match ``Allow`` wins over ``Disallow``."""
    groups: dict[str, list[tuple[str, str]]] = {}
    agents: list[str] = []
    last_was_agent = False
    for raw in (robots_txt or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k == "user-agent":
            if not last_was_agent:
                agents = []
            agents.append(v.lower())
            groups.setdefault(v.lower(), [])
            last_was_agent = True
        elif k in ("allow", "disallow"):
            for a in agents:
                groups.setdefault(a, []).append((k, v))
            last_was_agent = False
    rules = groups.get(ROBOTS_AGENT)
    if rules is None:
        rules = groups.get("*", [])
    best: tuple[int, str] | None = None
    for kind, pat in rules:
        if pat and path.startswith(pat) and (best is None or len(pat) > best[0]):
            best = (len(pat), kind)
    return best is not None and best[1] == "disallow"


# ── the run ────────────────────────────────────────────────────────────────────

Fetch = Callable[[str], Awaitable[tuple[int | None, dict, bytes, str | None]]]


@dataclass
class HostLog:
    sent: int = 0
    skipped_reason: str | None = None
    throttles: int = 0
    timeouts_in_row: int = 0


@dataclass
class RunReport:
    results: dict[str, dict] = field(default_factory=dict)   # resource -> reply
    hosts: dict[str, HostLog] = field(default_factory=dict)


def request_headers() -> dict[str, str]:
    """The only headers we send. Asserted in tests: no payment or auth header."""
    return {"User-Agent": USER_AGENT, "Accept": "application/json"}


async def _run_host(host: str, recs: list[dict], fetch: Fetch, report: RunReport,
                    sleep: Callable[[float], Awaitable[None]],
                    clock: Callable[[], float]) -> None:
    log = report.hosts.setdefault(host, HostLog())
    status, _h, body, err = await fetch(f"https://{host}/robots.txt")
    robots = body.decode("utf-8", "replace") if status == 200 and not err else ""
    last = None
    for rec in recs:
        url = str(rec.get("resource") or rec.get("endpoint_url"))
        parts = urlsplit(url)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        if robots and robots_disallows(robots, path):
            report.results[url] = {"state": "robots_disallowed", "status": None,
                                   "accepts": []}
            continue
        if last is not None:
            wait = HOST_INTERVAL_S - (clock() - last)
            if wait > 0:
                await sleep(wait)
        last = clock()
        status, headers, body, err = await fetch(url)
        log.sent += 1
        reply = read_reply(status, headers, body, err)
        report.results[url] = reply
        if reply["state"] == "timeout":
            log.timeouts_in_row += 1
            if log.timeouts_in_row >= MAX_TIMEOUTS:
                log.skipped_reason = "timeouts"
                return
            continue
        log.timeouts_in_row = 0
        if status in (429, 503):
            log.throttles += 1
            if log.throttles >= MAX_THROTTLES:
                log.skipped_reason = f"throttled ({status})"
                return
            ra = {k.lower(): v for k, v in (headers or {}).items()}.get("retry-after", "")
            try:
                delay = min(float(ra), 300.0)
            except ValueError:
                delay = 30.0
            await sleep(delay)


async def run_live_checks(plan_by_host: dict[str, list[dict]], fetch: Fetch, *,
                          sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                          clock: Callable[[], float] = time.monotonic) -> RunReport:
    """Run the plan: hosts in parallel (at most MAX_HOSTS_PARALLEL), each paced."""
    report = RunReport()
    sem = asyncio.Semaphore(MAX_HOSTS_PARALLEL)

    async def one(host, recs):
        async with sem:
            try:
                await _run_host(host, recs, fetch, report, sleep, clock)
            except Exception:  # noqa: BLE001 — one host never stops the run
                logger.warning("x402 live: host %s failed", host, exc_info=True)
                report.hosts.setdefault(host, HostLog()).skipped_reason = "error"

    await asyncio.gather(*(one(h, r) for h, r in plan_by_host.items()))
    return report


def make_fetch(client) -> Fetch:
    """A real fetch over an ``ssrf_safe_async_client``: GET, our two headers only, no
    redirects followed, 10 s timeout, the first 64 KB read."""
    import httpx

    async def fetch(url: str):
        if not url.lower().startswith("https://"):
            return None, {}, b"", "error"
        try:
            async with client.stream("GET", url, headers=request_headers(),
                                     follow_redirects=False, timeout=TIMEOUT_S) as r:
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) >= MAX_BYTES:
                        break
                return r.status_code, dict(r.headers), bytes(buf[:MAX_BYTES]), None
        except httpx.TimeoutException:
            return None, {}, b"", "timeout"
        except Exception:  # noqa: BLE001 — SSRF refusal, DNS, TLS: one error row
            return None, {}, b"", "error"
    return fetch
