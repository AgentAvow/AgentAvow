"""x402 phase 2: one polite, unpaid live check per listed endpoint (approved by Kenne
2026-11-11). Fixtures only: nothing here touches a real endpoint."""
from __future__ import annotations

import base64
import json

import pytest

from src.scanner import x402_live as xl
from src.scanner.x402_scan import scan_result_from_listing

PAYTO = "0x0E84dDEdAaE6A779c462C22a59F301EC31B6b808"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _listing(url="https://api.example.com/news", method="GET", net="eip155:8453",
             pay_to=PAYTO, amount="1000"):
    return {"resource": url, "description": "Crypto headlines",
            "accepts": [{"scheme": "exact", "network": net, "asset": USDC,
                         "payTo": pay_to, "amount": amount}],
            "extensions": {"bazaar": {"info": {"input": {"method": method,
                                                         "type": "http"}}}}}


def _v2_reply(pay_to=PAYTO, amount="1000", net="eip155:8453"):
    doc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": net,
                                          "asset": USDC, "payTo": pay_to,
                                          "amount": amount}]}
    return 402, {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(doc).encode()).decode()}, b""


# ── which listings ─────────────────────────────────────────────────────────────

def test_only_get_https_mainnet_listings():
    assert xl.eligible(_listing())
    assert not xl.eligible(_listing(method="POST"))
    assert not xl.eligible(_listing(method=""))
    assert not xl.eligible(_listing(url="http://api.example.com/x"))
    assert not xl.eligible(_listing(net="eip155:84532"))      # Base Sepolia only
    v1 = {"resource": "https://a.example/x", "accepts": [{
        "network": "base", "payTo": PAYTO, "maxAmountRequired": "1",
        "outputSchema": {"input": {"method": "GET"}}}]}
    assert xl.declared_method(v1) == "GET" and xl.eligible(v1)


def test_plan_caps_and_rotates_per_host():
    recs = [_listing(url=f"https://big.example/r{i:03d}") for i in range(120)]
    recs += [_listing(url="https://small.example/a")]
    p0, p1, p2 = (xl.plan(recs, k) for k in (0, 1, 2))
    assert len(p0["big.example"]) == xl.MAX_PER_HOST and len(p0["small.example"]) == 1
    seen = {r["resource"] for p in (p0, p1, p2) for r in p["big.example"]}
    assert len(seen) == 120          # three runs cover the whole host
    assert p0["big.example"] != p1["big.example"]


# ── reading a reply ────────────────────────────────────────────────────────────

def test_read_v2_header_and_v1_body():
    s, h, b = _v2_reply()
    assert xl.read_reply(s, h, b)["state"] == "paid"
    body = json.dumps({"x402Version": 1, "accepts": [{"payTo": PAYTO}]}).encode()
    assert xl.read_reply(402, {}, body)["accepts"][0]["payTo"] == PAYTO


@pytest.mark.parametrize("status,headers,body,err,state", [
    (402, {}, b"<html>pay</html>", None, "unreadable_402"),
    (200, {}, b"{}", None, "not_paid"),
    (302, {"Location": "https://elsewhere"}, b"", None, "redirect"),
    (500, {}, b"", None, "not_paid"),
    (None, {}, b"", "timeout", "timeout"),
    (None, {}, b"", "error", "error"),
])
def test_other_replies_are_disclosure_only(status, headers, body, err, state):
    reply = xl.read_reply(status, headers, body, err)
    assert reply["state"] == state
    findings, rec = xl.live_findings(_listing(), reply)
    assert findings == [] and rec["state"] == state


# ── what changes ───────────────────────────────────────────────────────────────

def test_matching_terms_add_nothing():
    f, rec = xl.live_findings(_listing(), xl.read_reply(*_v2_reply(pay_to=PAYTO.lower())))
    assert f == [] and rec["matches"] is True


def test_moved_payee_is_high_and_reads_review():
    reply = xl.read_reply(*_v2_reply(pay_to="0x" + "9" * 40))
    f, rec = xl.live_findings(_listing(), reply)
    assert [x.severity for x in f] == ["high"] and rec["matches"] is False
    assert "different address" in f[0].name and f[0].file_path == xl.WHERE_LIVE
    r = scan_result_from_listing(_listing(), {**reply, "checked_at": "2026-11-18T00:00:00Z"})
    assert r.artifact_scan["live_check"]["checked_at"] == "2026-11-18T00:00:00Z"
    from src.scanner.verdict import decide
    items = [{"category": x.category, "name": x.name, "severity": x.severity,
              "file_path": x.file_path} for x in r.findings]
    d = decide({"trust_score": r.trust_score, "findings": {"items": items},
                "metadata": {"files_scanned": 1}, "coverage": r.coverage,
                "coverage_gaps": r.coverage_gaps})
    assert d.decision == "review"            # never Do not connect from one read
    assert "in its live payment request" in d.reason


def test_payee_on_another_network_only_is_not_compared():
    reply = xl.read_reply(*_v2_reply(pay_to="So1anaWa11et", net="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"))
    f, rec = xl.live_findings(_listing(), reply)
    assert f == [] and rec["matches"] is False and rec["networks_compared"] == []


def test_price_jump_over_10x_is_medium():
    f, _ = xl.live_findings(_listing(amount="1000"), xl.read_reply(*_v2_reply(amount="20000")))
    assert [x.severity for x in f] == ["medium"]
    f, _ = xl.live_findings(_listing(amount="1000"), xl.read_reply(*_v2_reply(amount="9000")))
    assert f == []


# ── robots.txt ─────────────────────────────────────────────────────────────────

def test_robots():
    assert xl.robots_disallows("User-agent: *\nDisallow: /", "/news")
    assert not xl.robots_disallows("User-agent: *\nDisallow: /private", "/news")
    own = "User-agent: AgentAvowBot\nDisallow: /news\n\nUser-agent: *\nDisallow:"
    assert xl.robots_disallows(own, "/news?x=1")
    assert not xl.robots_disallows("User-agent: AgentAvowBot\nAllow: /\n\nUser-agent: *\n"
                                   "Disallow: /", "/news")
    assert not xl.robots_disallows("User-agent: *\nDisallow: /\nAllow: /news", "/news")


# ── the run (fake fetch and clock) ─────────────────────────────────────────────

class _Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def now(self):
        return self.t

    async def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def _fetcher(replies, sent):
    async def fetch(url):
        sent.append(url)
        if url.endswith("/robots.txt"):
            return 404, {}, b"", None
        return replies(url)
    return fetch


async def test_requests_are_paced_per_host_and_carry_no_payment_header():
    assert not {k.lower() for k in xl.request_headers()} & xl.FORBIDDEN_HEADERS
    assert xl.request_headers()["User-Agent"] == xl.USER_AGENT
    clock, sent = _Clock(), []
    recs = [_listing(url=f"https://a.example/r{i}") for i in range(3)]
    rep = await xl.run_live_checks(xl.plan(recs, 0), _fetcher(lambda u: (*_v2_reply(), None), sent),
                                   sleep=clock.sleep, clock=clock.now)
    assert sent[0] == "https://a.example/robots.txt" and len(sent) == 4
    assert clock.sleeps == [xl.HOST_INTERVAL_S, xl.HOST_INTERVAL_S]
    assert all(v["state"] == "paid" for v in rep.results.values())


async def test_throttled_host_is_skipped_after_two():
    clock, sent = _Clock(), []
    recs = [_listing(url=f"https://a.example/r{i}") for i in range(5)]
    rep = await xl.run_live_checks(
        xl.plan(recs, 0), _fetcher(lambda u: (429, {"Retry-After": "5"}, b"", None), sent),
        sleep=clock.sleep, clock=clock.now)
    assert rep.hosts["a.example"].sent == 2
    assert rep.hosts["a.example"].skipped_reason == "throttled (429)"
    assert 5.0 in clock.sleeps


async def test_timeouts_skip_the_host_after_three_in_a_row():
    clock, sent = _Clock(), []
    recs = [_listing(url=f"https://a.example/r{i}") for i in range(6)]
    rep = await xl.run_live_checks(
        xl.plan(recs, 0), _fetcher(lambda u: (None, {}, b"", "timeout"), sent),
        sleep=clock.sleep, clock=clock.now)
    assert rep.hosts["a.example"].sent == 3 and rep.hosts["a.example"].skipped_reason


async def test_robots_disallow_sends_nothing_to_that_path():
    sent = []

    async def fetch(url):
        sent.append(url)
        if url.endswith("/robots.txt"):
            return 200, {}, b"User-agent: AgentAvowBot\nDisallow: /", None
        return (*_v2_reply(), None)
    clock = _Clock()
    rep = await xl.run_live_checks(xl.plan([_listing(url="https://a.example/x")], 0), fetch,
                                   sleep=clock.sleep, clock=clock.now)
    assert sent == ["https://a.example/robots.txt"]
    assert rep.results["https://a.example/x"]["state"] == "robots_disallowed"


async def test_at_most_four_hosts_at_once():
    import asyncio
    live, peak = [0], [0]

    async def fetch(url):
        live[0] += 1
        peak[0] = max(peak[0], live[0])
        await asyncio.sleep(0)
        live[0] -= 1
        return (404, {}, b"", None) if url.endswith("robots.txt") else (*_v2_reply(), None)
    recs = [_listing(url=f"https://h{i}.example/x") for i in range(10)]
    rep = await xl.run_live_checks(xl.plan(recs, 0), fetch)
    assert peak[0] <= xl.MAX_HOSTS_PARALLEL
    assert len(rep.results) == 10 and not any(h.skipped_reason for h in rep.hosts.values())


def test_docs_page_states_the_approved_plan():
    from pathlib import Path
    doc = (Path(__file__).resolve().parent.parent / "web/src/rebrand/docs/x402.md").read_text()
    assert xl.USER_AGENT in doc and xl.OPT_OUT_CONTACT in doc
    assert "User-agent: AgentAvowBot" in doc and "every 2 seconds per host" in doc
    assert "50" in doc and "never a payment" in doc
