"""Tests for the registry fetchers' shared client: deadlines, retries, breaker, SSRF (#406).

No real network: requests stop at a patched ``httpx.AsyncHTTPTransport``, DNS is a
patched ``socket.getaddrinfo``, and time is a fake clock.
"""
from __future__ import annotations

import json
import logging
import socket
from unittest.mock import patch

import httpx
import pytest

from src.source_import import http as fh
from tests import fetcher_fixture_net as net

PUBLIC = "93.184.216.34"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def _isolate():
    fh.breakers.clear()
    yield
    fh.breakers.clear()


@pytest.fixture
def clock():
    c = FakeClock()
    with patch.object(fh, "_monotonic", c.monotonic), patch.object(fh, "_sleep", c.sleep), \
            patch.object(fh, "_random", lambda: 0.5):
        yield c


class Network:
    """Scripted transport: each entry is a status code, a (status, headers) pair or an
    exception, consumed one per request that reaches the network."""

    def __init__(self, script, *, dns=None) -> None:
        self.script = list(script)
        self.requests: list[httpx.Request] = []
        self.timeouts: list[dict] = []
        self.dns_lookups: list[str] = []
        self._dns = dns or (lambda host, n: PUBLIC)

    async def handle(self, transport, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.timeouts.append(request.extensions.get("timeout", {}))
        step = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(step, BaseException):
            raise step
        if callable(step):
            return await step(request)
        status, headers = step if isinstance(step, tuple) else (step, {})
        return httpx.Response(status, json={}, headers=headers, request=request)

    def getaddrinfo(self, host, *args, **kwargs):
        self.dns_lookups.append(host)
        ip = self._dns(host, len(self.dns_lookups))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    def __enter__(self):
        async def handle(transport, request):
            return await self.handle(transport, request)

        self._patches = [
            patch.object(httpx.AsyncHTTPTransport, "handle_async_request", handle),
            patch("socket.getaddrinfo", self.getaddrinfo),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()


async def _get(url="https://registry.npmjs.org/x", *, total=20.0, attempt_timeout=10.0):
    async with fh.fetch_client(total=total, attempt_timeout=attempt_timeout) as c:
        return await c.get(url)


# ---------------------------------------------------------------------------
# Deadlines
# ---------------------------------------------------------------------------

class TestDeadline:
    async def test_every_attempt_has_connect_and_total_timeouts(self, clock):
        with Network([200]) as n:
            await _get(total=20.0, attempt_timeout=10.0)
        t = n.timeouts[0]
        assert t["connect"] == fh.CONNECT_TIMEOUT_S
        assert t["read"] == 10.0

    async def test_attempt_timeout_is_capped_by_ambient_deadline(self, clock):
        # A request with 2 s left: the call's timeout is at most 2 s.
        with Network([200]) as n, fh.deadline_scope(2.0):
            await _get(total=20.0, attempt_timeout=10.0)
        t = n.timeouts[0]
        assert t["read"] <= 2.0 and t["connect"] <= 2.0

    async def test_deadline_spans_calls_in_one_fetch(self, clock):
        with Network([200]) as n:
            async with fh.fetch_client(total=12.0, attempt_timeout=10.0) as c:
                await c.get("https://pypi.org/a")
                clock.now += 9.0
                await c.get("https://pypi.org/b")
        assert n.timeouts[1]["read"] == pytest.approx(3.0)

    async def test_spent_deadline_raises_without_network(self, clock):
        with Network([200]) as n:
            async with fh.fetch_client(total=5.0) as c:
                clock.now += 6.0
                with pytest.raises(fh.DeadlineExceeded) as ei:
                    await c.get("https://pypi.org/a")
        assert n.requests == []
        # Fetchers catch httpx.TimeoutException / HTTPError: messages stay theirs.
        assert isinstance(ei.value, httpx.TimeoutException)

    async def test_hanging_server_is_cut_off_at_the_deadline(self):
        # Real clock: a server that never answers is cut off at the deadline.
        import asyncio

        async def hang(request):
            await asyncio.sleep(30)

        with Network([hang]):
            with pytest.raises(fh.DeadlineExceeded):
                await _get(total=0.2)

    async def test_no_retry_wait_runs_past_the_deadline(self, clock):
        with Network([(503, {"retry-after": "4"})]) as n:
            resp = await _get(total=3.0)
        assert resp.status_code == 503
        assert len(n.requests) == 1 and clock.sleeps == []


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------

class TestRetries:
    @pytest.mark.parametrize("status", [502, 503, 504])
    async def test_transient_status_is_retried_then_succeeds(self, clock, status):
        with Network([status, 200]) as n:
            resp = await _get()
        assert resp.status_code == 200
        assert len(n.requests) == 2

    async def test_retry_budget_is_bounded_and_last_response_returned(self, clock):
        with Network([503]) as n:
            resp = await _get()
        assert resp.status_code == 503
        assert len(n.requests) == fh.MAX_ATTEMPTS
        assert len(clock.sleeps) == fh.MAX_ATTEMPTS - 1

    async def test_full_jitter_backoff(self, clock):
        with Network([503]):
            await _get()
        # _random() == 0.5 → half of min(cap, base * 2**attempt)
        assert clock.sleeps == [0.5 * fh.BACKOFF_BASE_S * 2, 0.5 * fh.BACKOFF_BASE_S * 4]

    async def test_connect_error_is_retried_then_raised(self, clock):
        with Network([httpx.ConnectError("refused")]) as n:
            with pytest.raises(httpx.ConnectError, match="refused"):
                await _get()
        assert len(n.requests) == fh.MAX_ATTEMPTS

    async def test_read_timeout_is_not_retried(self, clock):
        with Network([httpx.ReadTimeout("slow")]) as n:
            with pytest.raises(httpx.ReadTimeout):
                await _get()
        assert len(n.requests) == 1

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 422])
    async def test_4xx_is_not_retried(self, clock, status):
        with Network([status, 200]) as n:
            resp = await _get()
        assert resp.status_code == status
        assert len(n.requests) == 1

    async def test_500_is_not_retried(self, clock):
        with Network([500, 200]) as n:
            resp = await _get()
        assert resp.status_code == 500 and len(n.requests) == 1

    async def test_429_honours_retry_after(self, clock):
        with Network([(429, {"retry-after": "3"}), 200]) as n:
            resp = await _get()
        assert resp.status_code == 200
        assert clock.sleeps == [3.0]
        assert len(n.requests) == 2

    async def test_429_retry_after_over_cap_is_not_waited_out(self, clock):
        with Network([(429, {"retry-after": "120"}), 200]) as n:
            resp = await _get()
        assert resp.status_code == 429
        assert len(n.requests) == 1 and clock.sleeps == []

    async def test_429_without_retry_after_uses_backoff(self, clock):
        with Network([429, 200]) as n:
            resp = await _get()
        assert resp.status_code == 200 and len(n.requests) == 2
        assert clock.sleeps == [0.5 * fh.BACKOFF_BASE_S * 2]

    def test_retry_after_http_date(self):
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime

        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
        resp = httpx.Response(429, headers={"retry-after": when})
        assert 25 <= fh._retry_after(resp) <= 31
        assert fh._retry_after(httpx.Response(429, headers={"retry-after": "junk"})) is None

    async def test_unsafe_method_is_never_retried(self, clock):
        with Network([503, 200]) as n:
            async with fh.fetch_client(total=20.0) as c:
                resp = await c.request("POST", "https://registry.npmjs.org/x")
        assert resp.status_code == 503 and len(n.requests) == 1

    async def test_unsafe_method_connect_error_not_retried(self, clock):
        with Network([httpx.ConnectError("refused"), 200]) as n:
            async with fh.fetch_client(total=20.0) as c:
                with pytest.raises(httpx.ConnectError):
                    await c.request("POST", "https://registry.npmjs.org/x")
        assert len(n.requests) == 1

    async def test_httpx_transport_retries_are_off(self):
        captured = {}
        real = fh.httpx.AsyncClient

        def spy(*args, **kwargs):
            captured["transport"] = kwargs["transport"]
            return real(*args, **kwargs)

        with patch.object(fh.httpx, "AsyncClient", spy):
            async with fh.fetch_client(total=1.0):
                pass
        pool = captured["transport"]._pool
        assert pool._retries == 0
        assert captured["transport"].__class__.__name__ == "_SsrfSafeTransport"


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class TestBreaker:
    async def test_opens_after_threshold_and_fails_fast(self, clock, caplog):
        caplog.set_level(logging.INFO, logger="src.source_import.http")
        with Network([500]) as n:
            for _ in range(fh.BREAKER_THRESHOLD):
                await _get()
            sent = len(n.requests)
            with pytest.raises(fh.CircuitOpenError):
                await _get()
        assert len(n.requests) == sent  # no network attempt while open
        assert "circuit opened for registry.npmjs.org" in caplog.text
        # It's an httpx.TransportError, so fetchers wrap it in their usual message.
        assert issubclass(fh.CircuitOpenError, httpx.HTTPError)

    async def test_other_hosts_unaffected(self, clock):
        with Network([500]):
            for _ in range(fh.BREAKER_THRESHOLD):
                await _get()
        with Network([200]):
            assert (await _get("https://pypi.org/pypi/x/json")).status_code == 200

    async def test_success_resets_the_count(self, clock):
        with Network([500] * (fh.BREAKER_THRESHOLD - 1) + [200, 500]):
            for _ in range(fh.BREAKER_THRESHOLD + 1):
                await _get()
        assert fh.breakers.get("registry.npmjs.org").state == fh.CircuitBreaker.CLOSED

    async def test_4xx_counts_as_healthy(self, clock):
        with Network([404]):
            for _ in range(fh.BREAKER_THRESHOLD + 2):
                await _get()
        assert fh.breakers.get("registry.npmjs.org").state == fh.CircuitBreaker.CLOSED

    async def test_half_open_success_closes(self, clock, caplog):
        caplog.set_level(logging.INFO, logger="src.source_import.http")
        with Network([500]):
            for _ in range(fh.BREAKER_THRESHOLD):
                await _get()
        clock.now += fh.BREAKER_COOLOFF_S + 1
        with Network([200]) as n:
            assert (await _get()).status_code == 200
            assert (await _get()).status_code == 200
        assert len(n.requests) == 2
        assert "circuit closed for registry.npmjs.org" in caplog.text

    async def test_half_open_failure_reopens(self, clock):
        with Network([500]):
            for _ in range(fh.BREAKER_THRESHOLD):
                await _get()
        clock.now += fh.BREAKER_COOLOFF_S + 1
        with Network([500]) as n:
            await _get()  # the one trial call
            with pytest.raises(fh.CircuitOpenError):
                await _get()
        assert len(n.requests) == 1

    def test_half_open_allows_one_probe_at_a_time(self, clock):
        b = fh.CircuitBreaker("h", threshold=1, cooloff=10)
        b.record_failure()
        clock.now += 11
        b.before_call()  # the probe
        with pytest.raises(fh.CircuitOpenError):
            b.before_call()

    async def test_connect_failures_after_retries_count_once_per_call(self, clock):
        with Network([httpx.ConnectError("refused")]):
            for _ in range(fh.BREAKER_THRESHOLD - 1):
                with pytest.raises(httpx.ConnectError):
                    await _get()
        assert fh.breakers.get("registry.npmjs.org").state == fh.CircuitBreaker.CLOSED

    def test_registry_is_bounded(self):
        reg = fh._BreakerRegistry(max_hosts=3)
        for h in ("a", "b", "c", "d"):
            reg.get(h)
        assert len(reg) == 3
        assert "a" not in reg._breakers


# ---------------------------------------------------------------------------
# SSRF guard on every attempt
# ---------------------------------------------------------------------------

class TestSsrfOnEveryAttempt:
    async def test_guard_resolves_and_validates_on_each_retry(self, clock):
        with Network([503, 503, 200]) as n:
            resp = await _get()
        assert resp.status_code == 200
        assert n.dns_lookups == ["registry.npmjs.org"] * 3
        # Each attempt connected to the pinned, validated IP.
        assert all(r.url.host == PUBLIC for r in n.requests)

    async def test_retry_that_rebinds_to_internal_address_is_blocked(self, clock):
        # First lookup is public and the server answers 503; the retry's lookup now
        # points at the metadata service. The guard must refuse it before connecting.
        def dns(host, n):
            return PUBLIC if n == 1 else "169.254.169.254"

        with Network([503, 200], dns=dns) as n:
            with pytest.raises(ValueError, match="blocked internal address"):
                await _get()
        assert len(n.requests) == 1
        # A refused address says nothing about the host's health.
        assert fh.breakers.get("registry.npmjs.org").failures == 0

    async def test_connect_error_retry_also_goes_through_guard(self, clock):
        def dns(host, n):
            return PUBLIC if n == 1 else "127.0.0.1"

        with Network([httpx.ConnectError("refused"), 200], dns=dns) as n:
            with pytest.raises(ValueError, match="blocked internal address"):
                await _get()
        assert len(n.requests) == 1
        assert n.dns_lookups == ["registry.npmjs.org"] * 2

    async def test_redirects_are_not_followed(self, clock):
        with Network([(302, {"location": "http://169.254.169.254/"})]) as n:
            resp = await _get()
        assert resp.status_code == 302
        assert len(n.requests) == 1


# ---------------------------------------------------------------------------
# False-negative check: fetchers give the same results and messages as before
# ---------------------------------------------------------------------------

class TestFetchersUnchanged:
    """``tests/fixtures/source_import_fetch_results.json`` was generated from the
    fetchers before they moved to the shared client (``python -m
    tests.fetcher_fixture_net`` on main). Same network, same output."""

    async def test_results_identical_to_before(self, clock):
        expected = json.loads(net.FIXTURE_PATH.read_text())
        assert await net.run_all_fetchers() == expected["results"]

    async def test_error_messages_identical_to_before(self, clock):
        expected = json.loads(net.FIXTURE_PATH.read_text())
        assert await net.run_error_cases() == expected["errors"]

    async def test_fetchers_recover_from_a_transient_503(self, clock):
        from src.source_import.npm_fetcher import fetch_npm

        calls = {"n": 0}

        async def flaky(transport, request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(503, request=request)
            return await net.fake_handle(transport, request)

        with net.patched_network(), patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", flaky
        ):
            result = await fetch_npm("demo-pkg", "https://www.npmjs.com/package/demo-pkg")
        expected = json.loads(net.FIXTURE_PATH.read_text())["results"]["npm"]
        assert result.display_name == expected["display_name"]
        assert result.community_signals == expected["community_signals"]

    async def test_open_breaker_surfaces_as_the_usual_network_error(self, clock):
        from src.source_import.errors import SourceFetchError
        from src.source_import.pypi_fetcher import fetch_pypi

        for _ in range(fh.BREAKER_THRESHOLD):
            fh.breakers.get("pypi.org").record_failure()
        with net.patched_network():
            with pytest.raises(SourceFetchError, match="^Network error fetching PyPI package"):
                await fetch_pypi("demo-pkg", "https://pypi.org/project/demo-pkg/")


class TestBreakerCancellation:
    async def test_cancelled_trial_call_frees_the_half_open_slot(self, clock):
        import asyncio

        for _ in range(fh.BREAKER_THRESHOLD):
            fh.breakers.get("registry.npmjs.org").record_failure()
        clock.now += fh.BREAKER_COOLOFF_S + 1

        async def cancelled(request):
            raise asyncio.CancelledError

        with Network([cancelled]):
            with pytest.raises(asyncio.CancelledError):
                await _get()
        with Network([200]) as n:
            assert (await _get()).status_code == 200
        assert len(n.requests) == 1


# ---------------------------------------------------------------------------
# Pinned transport: next validated address on a connect failure (src/ssrf.py)
# ---------------------------------------------------------------------------

V6 = "2606:4700::6810:1"
V4 = PUBLIC


class MultiAddr:
    """DNS answers several addresses; connects to the addresses in ``down`` fail."""

    def __init__(self, answer, *, down=(), exc=None) -> None:
        self.answer = answer
        self.down = set(down)
        self.exc = exc or httpx.ConnectError
        self.connects: list[str] = []
        self.dns_lookups = 0
        self.seen: list[httpx.Request] = []

    def getaddrinfo(self, host, *args, **kwargs):
        self.dns_lookups += 1
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "",
             (ip, 0)) for ip in self.answer
        ]

    def __enter__(self):
        async def handle(transport, request):
            ip = request.url.host
            self.connects.append(ip)
            self.seen.append(request)
            if ip in self.down:
                raise self.exc(f"connect to {ip} failed")
            return httpx.Response(200, json={}, request=request)

        self._patches = [
            patch.object(httpx.AsyncHTTPTransport, "handle_async_request", handle),
            patch("socket.getaddrinfo", self.getaddrinfo),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()


class TestPinnedTransportAddressFallback:
    async def test_aaaa_first_v6_fails_v4_succeeds(self, clock):
        with MultiAddr([V6, V4], down={V6}) as m:
            resp = await _get("https://registry.npmjs.org/x")
        assert resp.status_code == 200
        assert m.connects == [V6, V4]
        assert m.dns_lookups == 1  # no second resolution inside the loop
        last = m.seen[-1]
        assert last.headers["host"] == "registry.npmjs.org"
        assert last.extensions["sni_hostname"] == "registry.npmjs.org"

    async def test_connect_timeout_also_falls_through(self, clock):
        with MultiAddr([V6, V4], down={V6}, exc=httpx.ConnectTimeout) as m:
            assert (await _get()).status_code == 200
        assert m.connects == [V6, V4]

    async def test_all_addresses_failing_raises_connect_error(self, clock):
        from src.source_import.errors import SourceFetchError
        from src.source_import.pypi_fetcher import fetch_pypi

        with MultiAddr([V6, V4], down={V6, V4}) as m:
            with pytest.raises(SourceFetchError) as ei:
                await fetch_pypi("demo-pkg", "https://pypi.org/project/demo-pkg/")
        assert str(ei.value) == (
            f"Network error fetching PyPI package demo-pkg: connect to {V4} failed"
        )
        assert isinstance(ei.value.__cause__, httpx.ConnectError)
        # One http.py attempt = one pass over the addresses; each attempt resolves
        # (and validates) once.
        assert m.connects == [V6, V4] * fh.MAX_ATTEMPTS
        assert m.dns_lookups == fh.MAX_ATTEMPTS

    async def test_blocked_address_anywhere_refuses_before_connecting(self, clock):
        with MultiAddr([V6, V4, "10.0.0.5"]) as m:
            with pytest.raises(ValueError, match="blocked internal address"):
                await _get()
        assert m.connects == []

    async def test_read_error_does_not_try_next_address(self, clock):
        with MultiAddr([V6, V4], down={V6}, exc=httpx.ReadError) as m:
            with pytest.raises(httpx.ReadError):
                await _get()
        assert m.connects == [V6]

    async def test_response_does_not_try_next_address(self, clock):
        with MultiAddr([V6, V4]) as m:
            assert (await _get()).status_code == 200
        assert m.connects == [V6]

    async def test_mcp_client_post_falls_through_only_on_connect(self):
        # The live MCP path shares this transport. A failed connect sent nothing, so
        # trying the next address doesn't repeat the POST.
        from src.ssrf import ssrf_safe_async_client

        with MultiAddr([V6, V4], down={V6}) as m:
            async with ssrf_safe_async_client(timeout=5) as c:
                resp = await c.post("https://mcp.example.com/mcp", json={"x": 1})
        assert resp.status_code == 200
        assert m.connects == [V6, V4]
