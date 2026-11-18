"""The test session flushes a Redis db, so it must be a db no other process uses."""
from __future__ import annotations

import pytest

from tests.service_guards import TEST_REDIS_DB, flushable_redis_db


def test_dedicated_db_is_accepted():
    assert flushable_redis_db(f"redis://localhost:6379/{TEST_REDIS_DB}") == TEST_REDIS_DB
    assert flushable_redis_db(f"redis://:pw@cache:6380/{TEST_REDIS_DB}?ssl=false") == TEST_REDIS_DB
    assert flushable_redis_db(f"redis://localhost:6379/1?db={TEST_REDIS_DB}") == TEST_REDIS_DB


@pytest.mark.parametrize("url", [
    "redis://localhost:6379/0",      # .env.example's dev db
    "redis://localhost:6379/1",      # staging's db
    "redis://localhost:6379",        # no db number means db 0
    "redis://localhost:6379/x",
    "redis://localhost:6379/15?db=1",  # redis-py lets ?db= override the path
    "redis://localhost:6379/15?db=x",  # redis-py rejects it; so do we
    "unix:///tmp/redis.sock?db=1",
])
def test_any_other_db_is_refused(url):
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        flushable_redis_db(url)


# --- Parallel runs (pytest -n): one database and one Redis db per worker ------

from tests.service_guards import MAX_WORKERS, worker_database_url, worker_redis_url  # noqa: E402


def test_worker_database_name_goes_in_the_path_not_the_query():
    url = worker_database_url(
        "postgresql+asyncpg://u:p@h:5432/agentgraph_test?ssl=disable", "gw3")
    assert url.endswith("/agentgraph_test_gw3?ssl=disable")


@pytest.mark.parametrize("base", [
    "postgresql+asyncpg://u:p@h:5432/agentgraph",
    "postgresql+asyncpg://u:p@h:5432/agentgraph_staging?ssl=disable",
    "postgresql+asyncpg://u:p@h:5432/",
])
def test_worker_database_needs_a_test_database_as_base(base):
    with pytest.raises(RuntimeError, match="test"):
        worker_database_url(base, "gw0")


def test_workers_count_down_from_the_test_redis_db():
    base = f"redis://localhost:6379/{TEST_REDIS_DB}"
    assert worker_redis_url(base, "gw0") == f"redis://localhost:6379/{TEST_REDIS_DB}"
    last = worker_redis_url(base, f"gw{MAX_WORKERS - 1}")
    assert last == f"redis://localhost:6379/{TEST_REDIS_DB - MAX_WORKERS + 1}"
    assert TEST_REDIS_DB - MAX_WORKERS + 1 > 1  # never reaches staging (1) or dev (0)
    flushable_redis_db(last, worker=f"gw{MAX_WORKERS - 1}")


def test_too_many_workers_is_refused():
    with pytest.raises(RuntimeError, match="workers"):
        worker_redis_url(f"redis://localhost:6379/{TEST_REDIS_DB}", f"gw{MAX_WORKERS}")


def test_a_worker_may_flush_only_its_own_db():
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        flushable_redis_db(f"redis://localhost:6379/{TEST_REDIS_DB}", worker="gw2")
