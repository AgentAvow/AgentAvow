"""MCP connector health alerting (src/jobs/mcp_health.py, src/bridges/mcp_response_counter.py).

The probe is run against the real /mcp ASGI front in-process (so the exact 2026-07-28
envelope and the reviewed 2025-11-25 bytes are exercised), and against mocked HTTP for
the failure modes. Redis is faked; email and the in-app notification are captured.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone

import httpx
import pytest
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from src.bridges import mcp_response_counter as counter
from src.bridges import mcp_streamable as m
from src.config import settings
from src.jobs import mcp_health as h
from tests import mcp_wire as wire

FIXTURE = (pathlib.Path(__file__).parent / "fixtures" / "mcp_wire_2025_11_25"
           / "tools_list.json")
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
TOKEN = "unit-test-internal-token"


# ── fakes ─────────────────────────────────────────────────────────────────────────
class _Pipe:
    def __init__(self, r):
        self.r, self.ops = r, []

    def hincrby(self, *a):
        self.ops.append(("hincrby", a))

    def expire(self, *a):
        self.ops.append(("expire", a))

    async def execute(self):
        for name, a in self.ops:
            await getattr(self.r, name)(*a)


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.hashes: dict[str, dict[str, int]] = {}
        self.sets: dict[str, set[str]] = {}
        self.ttl: dict[str, int] = {}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return None
        self.kv[k] = str(v)
        if ex:
            self.ttl[k] = ex
        return True

    async def delete(self, k):
        self.kv.pop(k, None)
        return 1

    async def hincrby(self, k, f, n):
        d = self.hashes.setdefault(k, {})
        d[f] = d.get(f, 0) + n

    async def hgetall(self, k):
        return {f: str(v) for f, v in self.hashes.get(k, {}).items()}

    async def expire(self, k, s):
        self.ttl[k] = s

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def scard(self, k):
        return len(self.sets.get(k, set()))

    async def sadd(self, k, v):
        self.sets.setdefault(k, set()).add(v)

    async def smembers(self, k):
        return set(self.sets.get(k, set()))


@pytest.fixture
def redis(monkeypatch):
    r = FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    return r


@pytest.fixture
def mail(monkeypatch):
    sent: list[dict] = []
    notified: list[dict] = []

    async def fake_send(to, subject, html_body):
        sent.append({"to": to, "subject": subject, "html": html_body})
        return True

    async def fake_notify(title, body, *, reference_id, payload):
        notified.append({"title": title, "body": body, **payload})
        return {"notified": 1, "webhooks": 0}

    monkeypatch.setattr("src.email.send_email", fake_send)
    monkeypatch.setattr("src.jobs.behavioral_eval.notify_admins", fake_notify)
    monkeypatch.setattr(settings, "admin_email", "kenne@agentavow.com")
    monkeypatch.setattr(settings, "mcp_health_alert_email", "")
    return {"sent": sent, "notified": notified}


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(settings, "mcp_internal_token", TOKEN)


@pytest.fixture
def offline(monkeypatch):
    """No API, no adoption lookup; usage bumps recorded."""
    bumps: list[str] = []

    async def _scan(path, params=None):
        return {"trust_score": 88, "findings": {"total": 0, "items": []}}

    async def _none(*a, **k):
        return None

    async def _bump_metric(name, *a, **k):
        bumps.append(name)

    async def _record_unique(name, *a, **k):
        bumps.append(name)

    monkeypatch.setattr(m, "_get", _scan)
    monkeypatch.setattr(m, "_adoption", _none)
    monkeypatch.setattr("src.api.metrics_dashboard_router.bump_metric", _bump_metric)
    monkeypatch.setattr("src.api.metrics_dashboard_router.record_unique", _record_unique)
    return bumps


async def _probe_in_process(monkeypatch) -> list[h.Check]:
    sm = StreamableHTTPSessionManager(app=m.server, json_response=True, stateless=True)
    monkeypatch.setattr(m, "session_manager", sm)
    async with sm.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.mcp_asgi_app),
                                     base_url="http://testserver") as c:
            return await h.run_probe("http://testserver/mcp", client=c)


def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _ok(result: dict, rid: int = 1) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})


GOOD_TOOLS = {"tools": [{"name": f"t{i}"} for i in range(h.EXPECTED_TOOL_COUNT)]}


def _healthy_handler(overrides=None):
    """A fake /mcp that answers like prod, with per-(era, method) overrides."""
    overrides = overrides or {}
    fixture = FIXTURE.read_bytes()

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        era = "modern" if req.headers.get("mcp-method") else "legacy"
        key = (era, body["method"])
        if key in overrides:
            o = overrides[key]
            return o(req) if callable(o) else o
        if body["method"] == "server/discover":
            return _ok({"supportedVersions": [h.MODERN]})
        if body["method"] == "initialize":
            return _ok({"protocolVersion": h.HANDSHAKE}, 0)
        if body["method"] == "tools/list":
            if era == "legacy":
                return httpx.Response(200, content=fixture,
                                      headers={"content-type": "application/json"})
            return _ok(GOOD_TOOLS)
        if body["method"] == "tools/call":
            return _ok({"content": [{"type": "text", "text": "hi"}], "isError": False})
        return httpx.Response(404)
    return handler


# ── the pinned digest stays in sync with the reviewed fixture ─────────────────────
def test_expected_digest_and_tool_count_match_the_fixture():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == h.EXPECTED_TOOLS_LIST_SHA256
    assert len(json.loads(raw)["result"]["tools"]) == h.EXPECTED_TOOL_COUNT


def test_probe_envelope_matches_the_wire_helper():
    ours, theirs = h.modern_envelope(name="x"), wire.modern_envelope(name="x")
    assert set(ours["_meta"]) == set(theirs["_meta"])
    assert ours["_meta"]["io.modelcontextprotocol/protocolVersion"] == wire.MODERN
    hd = h._headers("tools/call", h.MODERN, {"name": "about_agentavow"})
    for k, v in wire.modern_headers("tools/call", {"name": "about_agentavow"}).items():
        assert hd[k] == v
    # handshake era: initialize carries no version header, like real clients
    assert "mcp-protocol-version" not in h._headers("initialize", h.HANDSHAKE, None)
    assert h._headers("tools/list", h.HANDSHAKE, None)["mcp-protocol-version"] == h.HANDSHAKE


# ── probe against the real /mcp front ─────────────────────────────────────────────
async def test_probe_passes_against_the_real_server_and_bumps_no_usage(
        monkeypatch, offline, token):
    checks = await _probe_in_process(monkeypatch)
    assert [c.key for c in checks] == [
        "modern_discover", "modern_tools_list", "modern_tool_call",
        "legacy_initialize", "legacy_tools_list", "tools_list_drift", "legacy_tool_call"]
    assert all(c.ok for c in checks), [(c.key, c.problem, c.detail) for c in checks]
    assert offline == []  # the marked probe's tools/call counted as no usage


async def test_unmarked_tool_call_still_counts_as_usage(monkeypatch, offline, token):
    resp = await wire.post("tools/call", {"name": "about_agentavow", "arguments": {}})
    assert resp.status_code == 200
    assert "mcp:calls:total" in offline


async def test_probe_skips_tool_calls_without_a_token(monkeypatch, offline):
    monkeypatch.setattr(settings, "mcp_internal_token", "")
    checks = await _probe_in_process(monkeypatch)
    assert "modern_tool_call" not in [c.key for c in checks]
    assert all(c.ok for c in checks)


def test_probe_marker_is_an_hmac_not_the_token(token):
    marker = counter.probe_marker()
    assert marker and TOKEN not in marker
    assert counter.is_probe_marker(marker)
    assert counter.is_probe_marker(marker.encode())
    assert not counter.is_probe_marker("forged")
    assert not counter.is_probe_marker("")


def test_no_marker_without_a_token(monkeypatch):
    monkeypatch.setattr(settings, "mcp_internal_token", "")
    assert counter.probe_marker() == ""
    assert not counter.is_probe_marker("anything")


# ── probe failure modes (mocked HTTP) ─────────────────────────────────────────────
def _by_key(checks):
    return {c.key: c for c in checks}


async def test_modern_unsupported_version_400_fails_discover(token):
    reject = httpx.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32022, "message": "Unsupported protocol version",
        "data": {"supported": ["2025-11-25"], "requested": "2026-07-28"}}})
    async with _mock_client(_healthy_handler({("modern", "server/discover"): reject,
                                              ("modern", "tools/list"): reject,
                                              ("modern", "tools/call"): reject})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    d = checks["modern_discover"]
    assert d.ok is False and d.problem == "HTTP 400" and not d.transient
    assert d.facts["requested"] == "2026-07-28"
    assert "-32022" in d.detail
    assert checks["legacy_initialize"].ok and checks["tools_list_drift"].ok


async def test_timeout_is_transient(token):
    def boom(req):
        raise httpx.ReadTimeout("slow", request=req)
    async with _mock_client(_healthy_handler({("legacy", "initialize"): boom})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["legacy_initialize"].problem == "timeout"
    assert checks["legacy_initialize"].transient is True


async def test_5xx_is_transient_and_4xx_is_not(token):
    async with _mock_client(_healthy_handler({
            ("modern", "server/discover"): httpx.Response(502, text="bad gateway"),
            ("legacy", "initialize"): httpx.Response(406, text="nope")})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["modern_discover"].transient is True
    assert checks["legacy_initialize"].transient is False


async def test_jsonrpc_error_in_a_200_fails(token):
    err = httpx.Response(200, json={"jsonrpc": "2.0", "id": 2,
                                    "error": {"code": -32603, "message": "boom"}})
    async with _mock_client(_healthy_handler({("modern", "tools/list"): err})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["modern_tools_list"].ok is False
    assert checks["modern_tools_list"].problem == "JSON-RPC error -32603"


async def test_tool_count_change_fails(token):
    fewer = _ok({"tools": [{"name": "only"}]}, 2)
    async with _mock_client(_healthy_handler({("modern", "tools/list"): fewer})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["modern_tools_list"].ok is False
    assert checks["modern_tools_list"].problem.startswith("1 tools")


async def test_tool_call_iserror_fails(token):
    bad = _ok({"content": [{"type": "text", "text": "x"}], "isError": True}, 3)
    async with _mock_client(_healthy_handler({("legacy", "tools/call"): bad})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["legacy_tool_call"].ok is False


async def test_discover_must_advertise_2026_07_28(token):
    old = _ok({"supportedVersions": ["2025-11-25"]})
    async with _mock_client(_healthy_handler({("modern", "server/discover"): old})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["modern_discover"].ok is False


async def test_tools_list_drift_is_detected(token):
    raw = FIXTURE.read_bytes().replace(b"AgentAvow", b"AgentAvoW", 1)
    changed = httpx.Response(200, content=raw, headers={"content-type": "application/json"})
    async with _mock_client(_healthy_handler({("legacy", "tools/list"): changed})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["legacy_tools_list"].ok is True  # same count, still a valid listing
    drift = checks["tools_list_drift"]
    assert drift.ok is False and drift.problem == "bytes changed"
    assert "Rescan" in drift.next_step


async def test_drift_not_judged_when_tools_list_failed(token):
    async with _mock_client(_healthy_handler({
            ("legacy", "tools/list"): httpx.Response(500)})) as c:
        checks = _by_key(await h.run_probe("https://x.test/mcp", client=c))
    assert checks["tools_list_drift"].ok is None


# ── reject counter ────────────────────────────────────────────────────────────────
def test_classify_sdk2_rejection_reads_the_requested_version():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32022, "message": "Unsupported protocol version",
        "data": {"supported": ["2026-07-28"], "requested": "2099-01-01"}}}).encode()
    assert counter.classify(400, body, None) == "2099-01-01"


def test_classify_sdk1_plaintext_rejection_uses_the_header():
    body = b'{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,' \
           b'"message":"Bad Request: Unsupported protocol version: 2026-07-28"}}'
    assert counter.classify(400, body, "2026-07-28") == "2026-07-28"


def test_classify_other_errors_and_successes_are_not_upv():
    assert counter.classify(200, b"Unsupported protocol version", "x") is None
    assert counter.classify(400, b'{"error":{"code":-32602}}', "x") is None


def test_clean_version_strips_junk():
    assert counter.clean_version("2026-07-28<script>") == "2026-07-28script"
    assert counter.clean_version(None) == "(none)"
    assert len(counter.clean_version("9" * 100)) == 32


async def _drain():
    import asyncio

    while counter._PENDING:
        await asyncio.gather(*list(counter._PENDING))


async def test_record_and_read_window(redis):
    t = 1_800_000_000.0
    upv = json.dumps({"error": {"code": -32022,
                                "data": {"requested": "2026-07-28"}}}).encode()
    for _ in range(3):
        counter.record_response(400, upv, header_version="2026-07-28", surface="claude",
                                now=t)
    counter.record_response(200, b"", header_version=None, surface="chatgpt", now=t - 600)
    counter.record_response(404, b"{}", header_version=None, surface="bogus", now=t)
    counter.record_response(200, b"", header_version=None, surface="claude", now=t - 7200)
    await _drain()
    w = await counter.read_window(30, now=t)
    assert w["total"] == 5  # the 2 h-old one is outside the window
    assert w["upv"] == 3 and w["versions"] == ["2026-07-28"]
    assert w["statuses"] == {"400": 3, "200": 1, "404": 1}
    assert w["classes"] == {"4xx": 4, "2xx": 1}
    assert w["surfaces"]["claude"] == {"total": 3, "errors": 3}
    assert w["surfaces"]["other"] == {"total": 1, "errors": 1}  # unknown surface bucketed
    assert all(v == counter.KEY_TTL for v in redis.ttl.values())


async def test_counter_write_failure_is_swallowed(monkeypatch):
    def broken():
        raise RuntimeError("redis down")
    monkeypatch.setattr("src.redis_client.get_redis", broken)
    counter.record_response(500, b"", header_version=None, surface="claude")
    await _drain()  # no exception


async def test_versions_set_is_capped(redis):
    t = 1_800_000_000.0
    for i in range(counter.MAX_VERSIONS_PER_SLOT + 10):
        body = json.dumps({"error": {"code": -32022,
                                     "data": {"requested": f"v{i}"}}}).encode()
        counter.record_response(400, body, header_version=None, surface="other", now=t)
        await _drain()
    assert len((await counter.read_window(5, now=t))["versions"]) == \
        counter.MAX_VERSIONS_PER_SLOT


def test_counting_follows_debug_unless_set(monkeypatch):
    monkeypatch.setattr(settings, "mcp_health_enabled", None)
    monkeypatch.setattr(settings, "debug", False)
    assert counter.counting_enabled() is True
    monkeypatch.setattr(settings, "debug", True)
    assert counter.counting_enabled() is False
    monkeypatch.setattr(settings, "mcp_health_enabled", True)
    assert counter.counting_enabled() is True


async def test_asgi_front_counts_client_rejects_but_not_probes(
        monkeypatch, redis, offline, token):
    monkeypatch.setattr(settings, "mcp_health_enabled", True)
    env = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2099-01-01",
                     "io.modelcontextprotocol/clientCapabilities": {},
                     "io.modelcontextprotocol/clientInfo": {"name": "c", "version": "1"}}}
    resp = await wire.post("server/discover", env, ua=wire.UA_CLAUDE_CODE,
                           protocol_version="2099-01-01",
                           headers={"mcp-method": "server/discover"})
    assert resp.status_code == 400
    ok = await wire.post("tools/list", None, ua=wire.UA_CLAUDE)
    assert ok.status_code == 200
    # the probe's own (marked) failing request is not client traffic
    await wire.post("server/discover", env, protocol_version="2099-01-01",
                    headers={"mcp-method": "server/discover",
                             counter.PROBE_HEADER: counter.probe_marker()})
    await _drain()
    w = await counter.read_window(5)
    assert w["total"] == 2 and w["upv"] == 1
    assert w["versions"] == ["2099-01-01"]
    assert w["surfaces"]["claude-code"] == {"total": 1, "errors": 1}
    assert w["surfaces"]["claude"] == {"total": 1, "errors": 0}


async def test_asgi_front_counts_nothing_when_disabled(monkeypatch, redis, offline):
    monkeypatch.setattr(settings, "mcp_health_enabled", False)
    await wire.post("tools/list", None)
    await _drain()
    assert redis.hashes == {}


# ── threshold logic ───────────────────────────────────────────────────────────────
def _window(total=0, statuses=None, upv=0, versions=()):
    return {"total": total, "statuses": statuses or {}, "upv": upv,
            "versions": list(versions), "surfaces": {}}


def test_too_few_requests_is_not_judged():
    checks = _by_key(h.evaluate_rejects(_window(29, {"400": 29}), minutes=30))
    assert checks["rejects_error_rate"].ok is None


def test_error_rate_at_threshold_fails():
    checks = _by_key(h.evaluate_rejects(_window(30, {"200": 27, "429": 3}), minutes=30))
    c = checks["rejects_error_rate"]
    assert c.ok is False and "10%" in c.problem


def test_error_rate_below_threshold_passes():
    checks = _by_key(h.evaluate_rejects(_window(100, {"200": 91, "500": 9}), minutes=30))
    assert checks["rejects_error_rate"].ok is True


def test_404_method_not_found_does_not_count_as_a_reject():
    checks = _by_key(h.evaluate_rejects(_window(40, {"200": 20, "404": 20}), minutes=30))
    assert checks["rejects_error_rate"].ok is True


def test_unsupported_version_rejects_alert_on_their_own():
    checks = _by_key(h.evaluate_rejects(
        _window(5, {"400": 3, "200": 2}, upv=3, versions=["2026-07-28"]), minutes=30))
    c = checks["rejects_unsupported_version"]
    assert c.ok is False and "2026-07-28" in c.problem
    assert checks["rejects_error_rate"].ok is None  # too few requests for the ratio
    two = _by_key(h.evaluate_rejects(_window(5, {"400": 2}, upv=2), minutes=30))
    assert two["rejects_unsupported_version"].ok is True


async def test_run_reject_check_reads_the_counters(redis, monkeypatch):
    t = 1_800_000_000.0
    body = json.dumps({"error": {"code": -32022,
                                 "data": {"requested": "2026-07-28"}}}).encode()
    for _ in range(40):
        counter.record_response(400, body, header_version=None, surface="claude", now=t)
    await _drain()
    checks = _by_key(await h.run_reject_check(now=t))
    assert checks["rejects_unsupported_version"].ok is False
    assert checks["rejects_error_rate"].ok is False


# ── dedupe, recovery, email ───────────────────────────────────────────────────────
def _fail(key="modern_discover", problem="HTTP 400", transient=False):
    return h.Check(key, f"{h.MODERN} server/discover", False, problem,
                   "HTTP 400 after 12 ms. JSON-RPC error -32022: Unsupported protocol "
                   "version.", transient=transient,
                   facts={"status": 400, "ms": 12, "requested": "2026-07-28",
                          "supported": ["2025-11-25"]})


def _pass(key="modern_discover"):
    return h.Check(key, f"{h.MODERN} server/discover", True)


async def test_failure_emails_once_then_dedupes(redis, mail):
    out = await h.alert([_fail()], NOW)
    assert out["alerted"] == ["modern_discover"]
    assert len(mail["sent"]) == 1
    msg = mail["sent"][0]
    assert msg["to"] == "kenne@agentavow.com"
    assert msg["subject"] == "AgentAvow MCP: 2026-07-28 server/discover failing (HTTP 400)"
    assert "2026-07-28" in msg["html"] and "Next step" in msg["html"]
    assert mail["notified"][0]["type"] == h.WEBHOOK_TYPE
    for _ in range(3):
        await h.alert([_fail()], NOW)
    assert len(mail["sent"]) == 1  # still the same problem inside the window
    assert redis.ttl[f"{h.DEDUPE_PREFIX}modern_discover"] == 6 * 3600


async def test_a_different_problem_emails_again(redis, mail):
    await h.alert([_fail()], NOW)
    await h.alert([_fail(problem="HTTP 500")], NOW)
    assert len(mail["sent"]) == 2


async def test_dedupe_expiry_renags(redis, mail):
    await h.alert([_fail()], NOW)
    del redis.kv[f"{h.DEDUPE_PREFIX}modern_discover"]  # the 6 h TTL passed
    await h.alert([_fail()], NOW)
    assert len(mail["sent"]) == 2


async def test_transient_failure_needs_two_in_a_row(redis, mail):
    await h.alert([_fail(problem="timeout", transient=True)], NOW)
    assert mail["sent"] == []
    await h.alert([_fail(problem="timeout", transient=True)], NOW)
    assert len(mail["sent"]) == 1


async def test_a_single_blip_then_pass_is_forgotten(redis, mail):
    await h.alert([_fail(problem="timeout", transient=True)], NOW)
    await h.alert([_pass()], NOW)
    await h.alert([_fail(problem="timeout", transient=True)], NOW)
    assert mail["sent"] == []  # never two in a row


async def test_recovery_emails_once_after_two_passes(redis, mail):
    await h.alert([_fail()], NOW)
    out = await h.alert([_pass()], NOW)
    assert out["recovered"] == [] and len(mail["sent"]) == 1
    out = await h.alert([_pass()], NOW)
    assert out["recovered"] == ["modern_discover"]
    assert len(mail["sent"]) == 2
    assert mail["sent"][1]["subject"] == "AgentAvow MCP: 2026-07-28 server/discover recovered"
    await h.alert([_pass()], NOW)
    assert len(mail["sent"]) == 2  # only one recovery email
    # after recovery a new break is a new problem
    await h.alert([_fail()], NOW)
    assert len(mail["sent"]) == 3


async def test_several_failures_go_in_one_email(redis, mail):
    await h.alert([_fail(), _fail("legacy_initialize"), _pass("legacy_tools_list")], NOW)
    assert len(mail["sent"]) == 1
    assert mail["sent"][0]["subject"].endswith("+1 more")


async def test_undelivered_alert_is_retried_and_promises_no_recovery(redis, mail,
                                                                     monkeypatch):
    async def fail_send(to, subject, html_body):
        return False
    monkeypatch.setattr("src.email.send_email", fail_send)
    await h.alert([_fail()], NOW)
    assert f"{h.DEDUPE_PREFIX}modern_discover" not in redis.kv
    state = json.loads(redis.kv[f"{h.STATE_PREFIX}modern_discover"])
    assert state["alerted"] is False


async def test_unjudged_checks_change_nothing(redis, mail):
    await h.alert([h.Check("rejects_error_rate", "x", None)], NOW)
    assert redis.kv == {} and mail["sent"] == []


async def test_alert_email_setting_overrides_admin(redis, mail, monkeypatch):
    monkeypatch.setattr(settings, "mcp_health_alert_email", "ops@agentavow.com")
    await h.alert([_fail()], NOW)
    assert mail["sent"][0]["to"] == "ops@agentavow.com"


async def test_email_escapes_and_carries_no_secrets(redis, mail, token):
    c = _fail()
    c.detail = "<script>alert(1)</script>"
    await h.alert([c], NOW)
    body = mail["sent"][0]["html"]
    assert "<script>" not in body
    assert TOKEN not in body and counter.probe_marker() not in body


async def test_test_email(mail):
    assert await h.send_test_email() is True
    assert mail["sent"][0]["subject"] == "AgentAvow MCP: test alert (no action needed)"


async def test_alert_never_raises(monkeypatch, mail):
    def broken():
        raise RuntimeError("redis down")
    monkeypatch.setattr("src.redis_client.get_redis", broken)
    assert await h.alert([_fail()], NOW) == {"alerted": [], "recovered": []}


async def test_probe_and_alert_end_to_end(redis, mail, token, monkeypatch):
    reject = httpx.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32022, "message": "Unsupported protocol version",
        "data": {"supported": ["2025-11-25"], "requested": "2026-07-28"}}})
    client = _mock_client(_healthy_handler({("modern", "server/discover"): reject}))
    real = h.run_probe

    async def probe():
        return await real("https://agentavow.com/mcp", client=client)
    monkeypatch.setattr(h, "run_probe", probe)
    out = await h.probe_and_alert()
    assert out["alerted"] == ["modern_discover"]
    assert "client version 2026-07-28" in mail["sent"][0]["html"]
    await client.aclose()


# ── scheduling ────────────────────────────────────────────────────────────────────
async def test_scheduler_starts_the_loops_only_when_enabled(monkeypatch):
    import asyncio

    from src.jobs import scheduler

    started: list[str] = []

    async def fake_loop(*a, **k):
        started.append("x")
        await asyncio.sleep(3600)

    monkeypatch.setattr(h, "probe_loop", fake_loop)
    monkeypatch.setattr(h, "reject_loop", fake_loop)
    for name in ("_scheduler_loop", "_api_health_loop", "_github_budget_loop",
                 "_security_scan_loop", "_auto_follow_loop", "_marketing_sync_loop",
                 "_developer_radar_loop", "_watch_rescan_loop", "_app_rescan_loop",
                 "_catalog_rescan_loop", "_behavioral_eval_loop", "_starter_pack_loop",
                 "_reply_monitor_loop", "_reply_drafter_loop", "_reply_poster_loop",
                 "_lock_refresh_loop"):
        monkeypatch.setattr(scheduler, name, lambda *a, **k: asyncio.sleep(3600))
    monkeypatch.setattr(settings, "behavioral_backfill_enabled", False)
    r = FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)

    monkeypatch.setattr(settings, "mcp_health_enabled", True)
    await scheduler.start_scheduler(interval=999999)
    await asyncio.sleep(0)
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert {"mcp-health-probe", "mcp-health-rejects"} <= names
    scheduler.stop_scheduler()
    await asyncio.sleep(0)
    assert scheduler._mcp_probe_task is None

    r.kv.clear()
    monkeypatch.setattr(settings, "mcp_health_enabled", False)
    await scheduler.start_scheduler(interval=999999)
    await asyncio.sleep(0)
    names = {t.get_name() for t in asyncio.all_tasks() if not t.done()}
    assert "mcp-health-probe" not in names
    scheduler.stop_scheduler()
    for t in asyncio.all_tasks():
        if t is not asyncio.current_task() and not t.done():
            t.cancel()
    await asyncio.sleep(0)
