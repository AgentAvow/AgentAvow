"""Guards for the services the test session wipes."""
from __future__ import annotations

from redis.connection import parse_url

# The only Redis db the test session may flush. Dev uses db 0 (.env.example) and
# staging db 1, so the tests keep to the other end of the range.
TEST_REDIS_DB = 15


def flushable_redis_db(url: str) -> int:
    """The db number in ``url`` if the test session may flush it; else raise.

    The db comes from redis-py's own URL parser, the one the client connects
    with, so a ``?db=`` query that overrides the path is read the same way here.
    """
    try:
        db = parse_url(url).get("db", 0)
    except ValueError:
        db = None
    if db != TEST_REDIS_DB:
        raise RuntimeError(
            f"REDIS_URL must point at Redis db {TEST_REDIS_DB}, which the test "
            f"session flushes; got {url!r}. Unset it or end it in /{TEST_REDIS_DB}."
        )
    return db
