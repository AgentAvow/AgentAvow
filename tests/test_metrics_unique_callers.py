"""Distinct callers per day — "how many machines used it", not "how many calls".

Pins three things the adoption trend lines rest on:
  * record_unique / _read_unique_by_day: a salted per-day HLL per metric name with
    the same privacy properties as unique_humans (nothing identifying stored).
  * The MCP server records the calling machine per surface on every tool call,
    from the IP uvicorn resolved and the User-Agent it bucketed.
  * The Claude Code plugin's session-start hook (User-Agent agentavow-precheck)
    is counted by the request middleware on every public scan request — cached
    or not — as scans + distinct machines, and nothing else is mistaken for it.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from httpx import ASGITransport, AsyncClient

import src.api.metrics_dashboard_router as md
from src import usage_scope as us
from src.bridges import mcp_streamable as ms

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
SALT = f"ag:metrics:unique_humans:salt:{TODAY}"
CC = "claude-code/2.1.287 (cli)"
HOOK = "agentavow-precheck/0.1.9 (plugin)"
BROWSER = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36"
)


class _FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.hll: dict[str, set[str]] = {}
        self.counters: dict[str, int] = {}
        self.fail = False

    def _check(self):
        if self.fail:
            raise ConnectionError("redis down")

    async def get(self, key):
        self._check()
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        if ex:
            self.ttl[key] = ex
        return True

    async def pfadd(self, key, *members):
        self._check()
        before = len(self.hll.setdefault(key, set()))
        self.hll[key].update(members)
        return int(len(self.hll[key]) != before)

    async def pfcount(self, *keys):
        self._check()
        return len(set().union(*(self.hll.get(k, set()) for k in keys)))

    async def expire(self, key, ttl):
        self._check()
        self.ttl[key] = ttl
        return True

    async def incr(self, key):
        self._check()
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def mget(self, keys):
        self._check()
        return [self.counters.get(k) for k in keys]


@pytest.fixture
def redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    md._salt_cache.clear()
    yield fake
    md._salt_cache.clear()


# --- record_unique / _read_unique_by_day -------------------------------------

@pytest.mark.asyncio
async def test_same_machine_counts_once_per_name_and_names_are_independent(redis):
    await md.record_unique("mcp:callers:claude-code", "203.0.113.7", CC)
    await md.record_unique("mcp:callers:claude-code", "203.0.113.7", CC)
    await md.record_unique("mcp:callers:claude-code", "203.0.113.8", CC)
    await md.record_unique("hook:machines", "203.0.113.7", HOOK)
    assert await md._read_unique_by_day("mcp:callers:claude-code", [TODAY]) == {TODAY: 2}
    assert await md._read_unique_by_day("hook:machines", [TODAY]) == {TODAY: 1}
    assert await md._read_unique_by_day("mcp:callers:cursor", [TODAY]) == {TODAY: 0}


@pytest.mark.asyncio
async def test_member_is_salted_sha256_sharing_the_daily_salt(redis):
    await md.record_unique("mcp:callers", "203.0.113.7", CC)
    (member,) = redis.hll[f"ag:metrics:uniq:mcp:callers:{TODAY}"]
    salt = redis.kv[SALT]
    assert member == hashlib.sha256(f"{salt}|203.0.113.7|{CC}".encode()).hexdigest()
    assert "203.0.113.7" not in member and "claude" not in member
    assert redis.ttl[f"ag:metrics:uniq:mcp:callers:{TODAY}"] == md._COUNTER_TTL


@pytest.mark.asyncio
async def test_read_is_per_day_and_missing_days_are_zero(redis):
    await md.record_unique("mcp:callers", "203.0.113.7", CC)
    out = await md._read_unique_by_day("mcp:callers", ["2000-01-01", TODAY])
    assert out == {"2000-01-01": 0, TODAY: 1}
    assert await md._read_unique_by_day("mcp:callers", []) == {}


@pytest.mark.asyncio
async def test_redis_outage_is_silent_on_write_and_empty_on_read(redis):
    redis.fail = True
    await md.record_unique("mcp:callers", "203.0.113.7", CC)  # must not raise
    assert await md._read_unique_by_day("mcp:callers", [TODAY]) == {}


# --- MCP server: caller per surface on every tool call ------------------------

@pytest.mark.asyncio
async def test_tool_call_records_the_machine_overall_and_per_surface(redis, monkeypatch):
    seen: list[tuple[str, str, str]] = []

    async def _rec(name, ip, ua):
        seen.append((name, ip, ua))

    monkeypatch.setattr(md, "record_unique", _rec)
    ms._SURFACE.set("claude-code")
    ms._CLIENT_IP.set("203.0.113.7")
    ms._CLIENT_UA.set(CC)
    await ms._call_tool("about_agentavow", {})
    assert seen == [
        ("mcp:callers", "203.0.113.7", CC),
        ("mcp:callers:claude-code", "203.0.113.7", CC),
    ]


@pytest.mark.asyncio
async def test_asgi_entry_captures_client_ip_and_ua_for_the_tool_handler(monkeypatch):
    captured = {}

    async def _handle(scope, receive, send):
        captured["ip"] = ms._CLIENT_IP.get()
        captured["ua"] = ms._CLIENT_UA.get()
        captured["surface"] = ms._SURFACE.get()

    monkeypatch.setattr(ms.session_manager, "handle_request", _handle)
    scope = {
        "type": "http", "method": "POST", "path": "/mcp",
        "headers": [(b"user-agent", CC.encode())], "client": ("198.51.100.4", 51234),
    }
    await ms.mcp_asgi_app(scope, None, None)
    assert captured == {"ip": "198.51.100.4", "ua": CC, "surface": "claude-code"}


@pytest.mark.asyncio
async def test_asgi_entry_without_a_client_fails_open(monkeypatch):
    captured = {}

    async def _handle(scope, receive, send):
        captured["ip"] = ms._CLIENT_IP.get()

    monkeypatch.setattr(ms.session_manager, "handle_request", _handle)
    await ms.mcp_asgi_app({"type": "http", "headers": []}, None, None)
    assert captured["ip"] == ""


@pytest.mark.asyncio
async def test_recording_failure_never_breaks_a_tool_call(monkeypatch):
    async def _boom(name, ip, ua):
        raise RuntimeError("redis exploded")

    monkeypatch.setattr(md, "record_unique", _boom)
    out = await ms._call_tool("about_agentavow", {})
    items = out[0] if isinstance(out, tuple) else out
    assert "AgentAvow" in items[0].text


# --- The session-start hook, counted by the request middleware -------------------
# It must count on EVERY scan request (cached or not), never on other paths, and
# never on a redirect or legacy-host request.

def _app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def _scope(request, call_next):
        return await us.usage_scope_middleware(request, call_next)

    @app.get("/api/v1/public/scan/package/npm/chalk")
    async def scan():
        return {"cached": True}

    @app.get("/api/v1/public/scan/moved")
    async def moved():
        return RedirectResponse(url="/api/v1/public/scan/package/npm/chalk", status_code=301)

    @app.get("/docs/auto-scan")
    async def docs():
        return {"ok": True}

    return app


async def _get(path: str, ua: str, ip: str = "203.0.113.9", host: str = "agentavow.com"):
    async with AsyncClient(
        transport=ASGITransport(app=_app(), client=(ip, 40000)), base_url="http://t",
        headers={"host": host, "user-agent": ua},
    ) as c:
        return await c.get(path)


def test_is_hook_request_is_path_and_ua_specific():
    assert md.is_hook_request("/api/v1/public/scan/mcp", HOOK)
    assert md.is_hook_request("/api/v1/public/scan/package/npm/x", "AgentAvow-Precheck/0.1.2 (manual)")
    assert not md.is_hook_request("/api/v1/public/scan/mcp", CC)
    assert not md.is_hook_request("/api/v1/public/scan/mcp", BROWSER)
    assert not md.is_hook_request("/docs/auto-scan", HOOK)
    assert not md.is_hook_request(None, HOOK) and not md.is_hook_request("/x", None)


@pytest.mark.asyncio
async def test_hook_scan_counts_a_scan_and_a_machine_even_when_cached(redis):
    assert (await _get("/api/v1/public/scan/package/npm/chalk", HOOK)).status_code == 200
    assert (await _get("/api/v1/public/scan/package/npm/chalk", HOOK)).status_code == 200
    assert (await _get("/api/v1/public/scan/package/npm/chalk", HOOK, ip="203.0.113.10")).status_code == 200
    assert redis.counters[f"ag:metrics:hook_scan:{TODAY}"] == 3
    assert await md._read_unique_by_day("hook:machines", [TODAY]) == {TODAY: 2}


@pytest.mark.asyncio
@pytest.mark.parametrize("ua", [BROWSER, CC, "Claude-User", "curl/8.4", ""])
async def test_other_callers_never_count_as_the_hook(redis, ua):
    assert (await _get("/api/v1/public/scan/package/npm/chalk", ua)).status_code == 200
    assert f"ag:metrics:hook_scan:{TODAY}" not in redis.counters
    assert await md._read_unique_by_day("hook:machines", [TODAY]) == {TODAY: 0}


@pytest.mark.asyncio
async def test_hook_on_a_non_scan_path_or_a_redirect_or_legacy_host_does_not_count(redis):
    assert (await _get("/docs/auto-scan", HOOK)).status_code == 200
    assert (await _get("/api/v1/public/scan/moved", HOOK)).status_code == 301
    assert (await _get("/api/v1/public/scan/package/npm/chalk", HOOK, host="agentgraph.co")).status_code == 200
    assert f"ag:metrics:hook_scan:{TODAY}" not in redis.counters
    assert await md._read_unique_by_day("hook:machines", [TODAY]) == {TODAY: 0}


@pytest.mark.asyncio
async def test_hook_tracking_is_best_effort(redis):
    redis.fail = True
    await md.record_hook_checkin("203.0.113.9", HOOK)  # must not raise
    assert (await _get("/api/v1/public/scan/package/npm/chalk", HOOK)).status_code == 200


# --- The aggregate carries the trend lines ------------------------------------

@pytest.mark.asyncio
async def test_aggregate_exposes_daily_adoption_series_and_callers(db, redis):
    await md.record_unique("mcp:callers", "203.0.113.7", CC)
    await md.record_unique("mcp:callers:claude-code", "203.0.113.7", CC)
    await md.record_unique("hook:machines", "203.0.113.7", HOOK)
    await md.bump_metric("hook_scan")
    out = await md._aggregate(db, "7d")
    s = out["series"]
    for key in ("mcp_calls", "mcp_callers", "hook_scans", "hook_machines",
                "mcp_calls:claude-code", "mcp_callers:claude-code", "mcp_callers:claude",
                "scan_requests:human", "scan_requests:agent", "scan_requests:automated"):
        assert len(s[key]) == 7, key
    assert s["mcp_callers"][-1] == 1
    assert s["mcp_callers:claude-code"][-1] == 1
    assert s["hook_machines"][-1] == 1 and s["hook_scans"][-1] == 1
    assert out["headline"]["mcp_callers"] == 1
    assert out["headline"]["hook_machines"] == 1 and out["headline"]["hook_scans"] == 1
    assert out["mcp"]["callers_window"] == 1
    assert out["mcp"]["by_surface"]["claude-code"]["callers"] == 1
    assert out["mcp"]["by_surface"]["cursor"]["callers"] == 0
    assert out["hook"] == {"scans_window": 1, "machines_window": 1}
    assert any("mcp_callers" in n and "hook_machines" in n for n in out["notes"])
