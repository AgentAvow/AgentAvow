"""Guards for the services the test session wipes."""
from __future__ import annotations

from urllib.parse import urlsplit

# The only Redis db the test session may flush. Dev uses db 0 (.env.example) and
# staging db 1, so the tests keep to the other end of the range.
TEST_REDIS_DB = 15


def flushable_redis_db(url: str) -> int:
    """The db number in ``url`` if the test session may flush it; else raise."""
    path = urlsplit(url).path.strip("/") or "0"
    if not path.isdigit() or int(path) != TEST_REDIS_DB:
        raise RuntimeError(
            f"REDIS_URL must point at Redis db {TEST_REDIS_DB}, which the test "
            f"session flushes; got {url!r}. Unset it or end it in /{TEST_REDIS_DB}."
        )
    return int(path)
