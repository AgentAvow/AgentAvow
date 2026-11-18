"""The test session flushes a Redis db, so it must be a db no other process uses."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.service_guards import (
    MAX_WORKERS,
    TEST_REDIS_DB,
    flushable_redis_db,
    run_token,
    worker_database_url,
    worker_redis_url,
)


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

_BASE = "postgresql+asyncpg://u:p@h:5432/agentgraph_test"


def test_worker_database_name_goes_in_the_path_not_the_query():
    url = worker_database_url(f"{_BASE}?ssl=disable", "gw3", "ab12cd34")
    assert url.endswith("/agentgraph_test_ab12cd34_gw3?ssl=disable")


def test_two_runs_from_one_base_get_different_copies():
    a = worker_database_url(_BASE, "gw0", run_token("0123456789abcdef0123456789abcdef"))
    b = worker_database_url(_BASE, "gw0", run_token("fedcba9876543210fedcba9876543210"))
    assert a.endswith("/agentgraph_test_01234567_gw0")
    assert b.endswith("/agentgraph_test_fedcba98_gw0")


@pytest.mark.parametrize("base", [
    "postgresql+asyncpg://u:p@h:5432/agentgraph",
    "postgresql+asyncpg://u:p@h:5432/agentgraph_staging?ssl=disable",
    "postgresql+asyncpg://u:p@h:5432/agentgraph_latest",  # "test" only inside a word
    "postgresql+asyncpg://u:p@h:5432/contest",
    "postgresql+asyncpg://u:p@h:5432/",
])
def test_worker_database_needs_a_test_database_as_base(base):
    with pytest.raises(RuntimeError, match="test database"):
        worker_database_url(base, "gw0", "ab12cd34")


@pytest.mark.parametrize("name", ["test", "agentgraph_test", "agentgraph_test_alice", "test_x"])
def test_test_as_a_whole_word_is_accepted(name):
    url = worker_database_url(f"postgresql+asyncpg://h/{name}", "gw1", "ab12cd34")
    assert url.endswith(f"/{name}_ab12cd34_gw1")


@pytest.mark.parametrize("worker", ["gw", "x1", "gw1;drop", "../gw1"])
def test_odd_worker_ids_are_refused(worker):
    with pytest.raises(RuntimeError, match="worker"):
        worker_database_url(_BASE, worker, "ab12cd34")


@pytest.mark.parametrize("token", ["", "AB12", "ab-12", 'a"b'])
def test_odd_run_tokens_are_refused(token):
    with pytest.raises(RuntimeError, match="token"):
        worker_database_url(_BASE, "gw0", token)


def test_run_token_keeps_letters_and_digits_only():
    assert run_token("AB-12_cd/34ef") == "ab12cd34"
    with pytest.raises(RuntimeError):
        run_token("--")


def test_overlong_worker_database_name_is_refused():
    with pytest.raises(RuntimeError, match="longer"):
        worker_database_url(f"postgresql+asyncpg://h/{'x' * 50}_test", "gw0", "ab12cd34")


def test_workers_count_down_from_the_test_redis_db():
    base = f"redis://localhost:6379/{TEST_REDIS_DB}"
    assert worker_redis_url(base, "gw0") == f"redis://localhost:6379/{TEST_REDIS_DB}"
    last = worker_redis_url(base, f"gw{MAX_WORKERS - 1}")
    assert last == f"redis://localhost:6379/{TEST_REDIS_DB - MAX_WORKERS + 1}"
    assert TEST_REDIS_DB - MAX_WORKERS + 1 > 1  # never reaches staging (1) or dev (0)
    flushable_redis_db(last, worker=f"gw{MAX_WORKERS - 1}")


def test_a_db_query_cannot_override_the_worker_db():
    # The base passes the guard (redis-py connects to db 15), but its ?db= must
    # not carry over and point every worker at the same db.
    url = worker_redis_url(f"redis://:pw@cache:6380/1?db={TEST_REDIS_DB}&ssl=false", "gw2")
    assert url == f"redis://:pw@cache:6380/{TEST_REDIS_DB - 2}?ssl=false"
    flushable_redis_db(url, worker="gw2")


def test_unix_socket_worker_db_goes_in_the_query():
    url = worker_redis_url(f"unix:///tmp/redis.sock?db={TEST_REDIS_DB}", "gw3")
    assert url == f"unix:///tmp/redis.sock?db={TEST_REDIS_DB - 3}"


def test_too_many_workers_is_refused():
    with pytest.raises(RuntimeError, match="workers"):
        worker_redis_url(f"redis://localhost:6379/{TEST_REDIS_DB}", f"gw{MAX_WORKERS}")


def test_a_worker_may_flush_only_its_own_db():
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        flushable_redis_db(f"redis://localhost:6379/{TEST_REDIS_DB}", worker="gw2")


def test_conftest_loads_without_pytest_xdist():
    """Plain pytest must work without xdist installed; -p no:xdist stands in for that."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_XDIST")}
    env.pop("PYTEST_ADDOPTS", None)
    env["REDIS_URL"] = f"redis://localhost:6379/{TEST_REDIS_DB}"
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:xdist", "-p", "no:cacheprovider",
         "--collect-only", "-q", "tests/test_service_guards.py"],
        cwd=root, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
