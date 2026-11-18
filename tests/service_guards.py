"""Guards for the services the test session wipes.

The session truncates the database in DATABASE_URL and flushes the Redis db in
REDIS_URL. Under pytest -n each xdist worker (gw0, gw1, ...) gets its own copy
of both, named here.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from redis.connection import parse_url

# The test session's Redis db. Dev uses db 0 (.env.example) and staging db 1, so
# the tests keep to the other end of the range: worker N uses db TEST_REDIS_DB - N.
TEST_REDIS_DB = 15
MAX_WORKERS = 8


def _worker_number(worker: str | None) -> int:
    if not worker:
        return 0
    n = int(worker.removeprefix("gw"))
    if n >= MAX_WORKERS:
        raise RuntimeError(
            f"at most {MAX_WORKERS} workers (one Redis db each); got {worker}. "
            f"Use -n {MAX_WORKERS} or fewer."
        )
    return n


def flushable_redis_db(url: str, worker: str | None = None) -> int:
    """The db number in ``url`` if this session (or worker) may flush it; else raise."""
    expected = TEST_REDIS_DB - _worker_number(worker)
    # redis-py's own parser, so a ?db= query that overrides the path counts.
    try:
        db = parse_url(url).get("db", 0)
    except ValueError:
        db = None
    if db != expected:
        raise RuntimeError(
            f"REDIS_URL must point at Redis db {expected}, which the test session "
            f"flushes; got {url!r}. Unset it or end it in /{TEST_REDIS_DB}."
        )
    return db


def worker_redis_url(url: str, worker: str) -> str:
    """``url`` with the worker's own db: TEST_REDIS_DB - N."""
    flushable_redis_db(url)
    parts = urlsplit(url)
    db = TEST_REDIS_DB - _worker_number(worker)
    return urlunsplit(parts._replace(path=f"/{db}"))


def worker_database_url(url: str, worker: str) -> str:
    """``url`` with the worker's database, ``<base>_<worker>``. The base must be a
    test database: the worker's copy is dropped and recreated every run."""
    from sqlalchemy.engine import make_url

    base = make_url(url)
    if not base.database or "test" not in base.database:
        raise RuntimeError(
            f"DATABASE_URL must name a test database (with 'test' in its name) for "
            f"parallel runs; got {base.database!r}"
        )
    name = f"{base.database}_{worker}"
    out = base.set(database=name)
    assert out.database == name != base.database and name.endswith(f"_{worker}")
    return out.render_as_string(hide_password=False)
