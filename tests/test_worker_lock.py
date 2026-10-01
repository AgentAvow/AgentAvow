"""src.worker_lock: one worker runs a background task, the others wait and take over.

Production runs four uvicorn workers. Before this, the Bluesky Jetstream subscriber
and the startup trust recompute ran in every worker (four firehose consumers on a
two-vCPU box). These tests pin the lock semantics with a fake Redis.
"""
from __future__ import annotations

import asyncio

import pytest

from src import worker_lock


class FakeRedis:
    """Just enough of redis.asyncio for SET NX EX / EXPIRE / DEL."""

    def __init__(self):
        self.store: dict[str, str] = {}
        self.expires: dict[str, int] = {}
        self.expire_calls = 0

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        self.expires[key] = ex
        return True

    async def expire(self, key, ttl):
        self.expire_calls += 1
        self.expires[key] = ttl
        return key in self.store

    def release(self, key):
        self.store.pop(key, None)


@pytest.fixture
def redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: fake)
    return fake


@pytest.mark.asyncio
async def test_first_worker_wins_and_the_rest_do_not(redis):
    assert await worker_lock.try_acquire("ag:lock:x", 60) is True
    assert await worker_lock.try_acquire("ag:lock:x", 60) is False
    assert redis.expires["ag:lock:x"] == 60  # the lock expires on its own if we die


@pytest.mark.asyncio
async def test_redis_down_means_run_anyway(monkeypatch):
    def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr("src.redis_client.get_redis", _boom)
    assert await worker_lock.try_acquire("ag:lock:x", 60) is True


@pytest.mark.asyncio
async def test_run_exclusively_runs_work_in_the_holder_and_refreshes(redis):
    ran = asyncio.Event()

    async def work():
        ran.set()
        await asyncio.sleep(1.1)  # long enough for one refresh (ttl 3 → every 1s)

    await asyncio.wait_for(worker_lock.run_exclusively("ag:lock:x", 3, work), 3)
    assert ran.is_set()
    assert redis.expire_calls >= 1


@pytest.mark.asyncio
async def test_loser_waits_then_takes_over_when_the_lock_lapses(redis):
    redis.store["ag:lock:x"] = "1"  # another worker holds it
    ran = asyncio.Event()

    async def work():
        ran.set()

    task = asyncio.create_task(worker_lock.run_exclusively("ag:lock:x", 60, work, retry=0.01))
    await asyncio.sleep(0.03)
    assert not ran.is_set()  # still waiting while the holder is alive
    redis.release("ag:lock:x")  # holder died, key expired
    await asyncio.wait_for(task, 1)
    assert ran.is_set()


@pytest.mark.asyncio
async def test_refresh_loop_stops_when_work_finishes(redis):
    async def work():
        return None

    await asyncio.wait_for(worker_lock.run_exclusively("ag:lock:x", 60, work), 1)
    await asyncio.sleep(0)
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert "lock-refresh:ag:lock:x" not in names
