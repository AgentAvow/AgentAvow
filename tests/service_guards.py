"""Guards for the services the test session wipes.

The session truncates the database in DATABASE_URL and flushes the Redis db in
REDIS_URL. Under pytest -n each xdist worker (gw0, gw1, ...) gets its own copy
of both, named here.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from redis.connection import parse_url

# The test session's Redis db. Dev uses db 0 (.env.example) and staging db 1, so
# the tests keep to the other end of the range: worker N uses db TEST_REDIS_DB - N.
TEST_REDIS_DB = 15
MAX_WORKERS = 8

# A base database is a test database when "test" is a whole word of its name:
# agentgraph_test and agentgraph_test_alice are, agentgraph_latest is not.
_TEST_DB_NAME = re.compile(r"(^|_)test(_|$)")
_WORKER_ID = re.compile(r"gw(\d+)")
_PG_MAX_NAME = 63  # Postgres silently truncates longer identifiers


def _worker_number(worker: str | None) -> int:
    if not worker:
        return 0
    m = _WORKER_ID.fullmatch(worker)
    if not m:
        raise RuntimeError(f"unexpected xdist worker id {worker!r}; expected gw<N>")
    n = int(m.group(1))
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
    """``url`` with the worker's own db: TEST_REDIS_DB - N.

    Any ``db`` in the query is dropped, so it cannot override the worker's db.
    Other query options are kept.
    """
    flushable_redis_db(url)
    db = TEST_REDIS_DB - _worker_number(worker)
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "db"]
    if parts.scheme == "unix":  # the path is the socket; the db goes in the query
        query.append(("db", str(db)))
        # Built by hand: urlunsplit drops the empty authority ("unix:/path").
        rebuilt = f"unix://{parts.netloc}{parts.path}?{urlencode(query)}"
    else:
        rebuilt = urlunsplit(parts._replace(path=f"/{db}", query=urlencode(query)))
    flushable_redis_db(rebuilt, worker)  # what redis-py will connect to
    return rebuilt


def run_token(testrunuid: str) -> str:
    """A short token that tells one parallel run's database copies from another's.

    ``testrunuid`` is the id xdist gives every worker of one run
    (PYTEST_XDIST_TESTRUNUID).
    """
    token = re.sub(r"[^0-9a-z]", "", testrunuid.lower())[:8]
    if not token:
        raise RuntimeError(f"cannot build a run token from testrunuid {testrunuid!r}")
    return token


def worker_database_url(url: str, worker: str, token: str) -> str:
    """``url`` with the worker's database, ``<base>_<token>_<worker>``.

    The base must be a test database. ``token`` is this run's (see run_token), so
    two runs from the same base never touch each other's copies. The copy is
    dropped when the worker finishes.
    """
    from sqlalchemy.engine import make_url

    base = make_url(url)
    if not base.database or not _TEST_DB_NAME.search(base.database):
        raise RuntimeError(
            f"DATABASE_URL must name a test database ('test' as a word of its "
            f"name, e.g. agentgraph_test) for parallel runs; got {base.database!r}"
        )
    _worker_number(worker)  # gw<N>, below MAX_WORKERS
    if not re.fullmatch(r"[0-9a-z]+", token):
        raise RuntimeError(f"run token must be lowercase letters and digits; got {token!r}")
    name = f"{base.database}_{token}_{worker}"
    if len(name.encode()) > _PG_MAX_NAME:
        raise RuntimeError(
            f"worker database name {name!r} is longer than Postgres allows "
            f"({_PG_MAX_NAME} bytes); use a shorter base name"
        )
    out = base.set(database=name)
    # Raise rather than assert: these checks guard a DROP DATABASE, and asserts
    # vanish under python -O.
    if (out.database != name or name == base.database
            or not name.endswith(f"_{token}_{worker}")
            or out.query != base.query):
        raise RuntimeError(f"refusing worker database {out.database!r} for base {url!r}")
    return out.render_as_string(hide_password=False)
