"""The test session flushes a Redis db, so it must be a db no other process uses."""
from __future__ import annotations

import pytest

from tests.service_guards import TEST_REDIS_DB, flushable_redis_db


def test_dedicated_db_is_accepted():
    assert flushable_redis_db(f"redis://localhost:6379/{TEST_REDIS_DB}") == TEST_REDIS_DB
    assert flushable_redis_db(f"redis://:pw@cache:6380/{TEST_REDIS_DB}?ssl=false") == TEST_REDIS_DB


@pytest.mark.parametrize("url", [
    "redis://localhost:6379/0",      # .env.example's dev db
    "redis://localhost:6379/1",      # staging's db
    "redis://localhost:6379",        # no db number means db 0
    "redis://localhost:6379/x",
])
def test_any_other_db_is_refused(url):
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        flushable_redis_db(url)
