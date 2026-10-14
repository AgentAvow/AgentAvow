"""Jetstream resume cursor, replay yielding, stale-cursor guard and host rotation.

Incident 2026-10-14: the cursor was saved only when a MATCHED post landed on the
1000th processed event, so it sat hours stale; every reconnect replayed the same
backlog, the replay never yielded to the keepalive, the server closed the socket at
ping_interval + ping_timeout (40 s), and the loop repeated with the cursor unmoved.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from src.feeds.bluesky import subscriber as sub


class FakeRedis:
    def __init__(self, cursor=None):
        self.kv = {}
        if cursor is not None:
            self.kv[sub.CURSOR_KEY] = cursor
        self.z = {}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v):
        self.kv[k] = v

    async def zadd(self, k, mapping):
        self.z.setdefault(k, {}).update(mapping)

    async def zcard(self, k):
        return len(self.z.get(k, {}))

    async def zremrangebyrank(self, k, a, b):
        pass


class FakeWS:
    """Async iterator over pre-buffered messages that never awaits (like a full
    socket buffer during replay); optionally raises at the end."""

    def __init__(self, messages, end_exc=None):
        self._it = iter(messages)
        self._end = end_exc

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._it)
        except StopIteration:
            if self._end is not None:
                raise self._end from None
            raise StopAsyncIteration from None


class FakeConnect:
    def __init__(self, ws, seen):
        self.ws, self.seen = ws, seen

    def __call__(self, url, **kw):
        self.seen.append(url)
        return self

    async def __aenter__(self):
        return self.ws

    async def __aexit__(self, *a):
        return False


def _post(i, text="hello world", t0=1_791_970_000_000_000):
    import json
    return json.dumps({
        "did": "did:plc:x", "time_us": t0 + i, "kind": "commit",
        "commit": {"operation": "create", "collection": "app.bsky.feed.post",
                   "rkey": f"r{i}", "record": {"text": text}},
    })


def _patch(monkeypatch, redis, ws, seen):
    import src.redis_client as rc
    monkeypatch.setattr(rc, "get_redis", lambda: redis)
    monkeypatch.setattr(sub.websockets, "connect", FakeConnect(ws, seen))


@pytest.mark.asyncio
async def test_cursor_advances_on_non_matching_posts(monkeypatch):
    """No post matches a keyword, yet the cursor must end at the last event seen."""
    monkeypatch.setattr(sub, "matches_keywords", lambda text: [])
    r, seen = FakeRedis(), []
    msgs = [_post(i) for i in range(2500)]
    _patch(monkeypatch, r, FakeWS(msgs), seen)
    await sub._subscribe(url_base="wss://h/subscribe?x")
    assert r.kv[sub.CURSOR_KEY] == str(1_791_970_000_000_000 + 2499)


@pytest.mark.asyncio
async def test_cursor_saved_when_the_session_ends_in_a_close(monkeypatch):
    monkeypatch.setattr(sub, "matches_keywords", lambda text: [])
    r, seen = FakeRedis(), []
    boom = ConnectionResetError("closed")
    _patch(monkeypatch, r, FakeWS([_post(i) for i in range(10)], end_exc=boom), seen)
    with pytest.raises(ConnectionResetError):
        await sub._subscribe(url_base="wss://h/subscribe?x")
    assert r.kv[sub.CURSOR_KEY] == str(1_791_970_000_000_000 + 9)


@pytest.mark.asyncio
async def test_replay_yields_so_other_tasks_run(monkeypatch):
    """A fully buffered replay must still let the keepalive (any other task) run."""
    monkeypatch.setattr(sub, "matches_keywords", lambda text: [])
    r, seen = FakeRedis(), []
    _patch(monkeypatch, r, FakeWS([_post(i) for i in range(5 * sub.YIELD_EVERY)]), seen)
    ticks = {"n": 0}

    async def keepalive():
        while True:
            ticks["n"] += 1
            await asyncio.sleep(0)

    task = asyncio.create_task(keepalive())
    await asyncio.sleep(0)
    start = ticks["n"]
    await sub._subscribe(url_base="wss://h/subscribe?x")
    task.cancel()
    assert ticks["n"] - start >= 4


@pytest.mark.asyncio
async def test_matches_still_land_in_the_feed(monkeypatch):
    monkeypatch.setattr(sub, "matches_keywords", lambda text: ["agent"] if "agent" in text else [])
    r, seen = FakeRedis(), []
    msgs = [_post(0, "an AI agent shipped"), _post(1, "lunch")]
    _patch(monkeypatch, r, FakeWS(msgs), seen)
    await sub._subscribe(url_base="wss://h/subscribe?x")
    assert list(r.z[sub.FEED_KEY]) == ["at://did:plc:x/app.bsky.feed.post/r0"]


def test_resume_cursor_rules():
    now = int(time.time() * 1_000_000)
    assert sub._resume_cursor(None, now) is None
    assert sub._resume_cursor(b"not-a-number", now) is None
    recent = now - 60 * 1_000_000
    assert sub._resume_cursor(str(recent).encode(), now) == str(recent)
    stale = now - (sub.MAX_REPLAY_SECONDS + 60) * 1_000_000
    assert sub._resume_cursor(str(stale), now) is None


@pytest.mark.asyncio
async def test_stale_cursor_starts_live(monkeypatch):
    stale = int(time.time() * 1_000_000) - (sub.MAX_REPLAY_SECONDS + 3600) * 1_000_000
    r, seen = FakeRedis(cursor=str(stale)), []
    _patch(monkeypatch, r, FakeWS([]), seen)
    await sub._subscribe(url_base="wss://h/subscribe?x")
    assert "cursor=" not in seen[0]


@pytest.mark.asyncio
async def test_recent_cursor_is_resumed(monkeypatch):
    recent = int(time.time() * 1_000_000) - 60 * 1_000_000
    r, seen = FakeRedis(cursor=str(recent)), []
    _patch(monkeypatch, r, FakeWS([]), seen)
    await sub._subscribe(url_base="wss://h/subscribe?x")
    assert seen[0].endswith(f"&cursor={recent}")


@pytest.mark.asyncio
async def test_failed_connect_rotates_to_next_host(monkeypatch):
    urls = []

    async def fake_subscribe(on_connect=None, url_base=None):
        urls.append(url_base)
        if len(urls) < 3:
            raise OSError("handshake timeout")
        raise asyncio.CancelledError

    async def no_sleep(_):
        return None

    monkeypatch.setattr(sub, "_subscribe", fake_subscribe)
    monkeypatch.setattr(sub.asyncio, "sleep", no_sleep)
    await sub.run_subscriber()
    hosts = [u.split("/")[2] for u in urls]
    assert hosts == list(sub.JETSTREAM_HOSTS[:3])


def test_hosts_are_the_four_public_jetstreams():
    assert len(sub.JETSTREAM_HOSTS) == 4
    assert all(h.endswith(".bsky.network") for h in sub.JETSTREAM_HOSTS)
    assert sub.JETSTREAM_URL.startswith(f"wss://{sub.JETSTREAM_HOSTS[0]}/subscribe")
