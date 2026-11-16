"""/livez and /readyz beside /health (#404), the nginx routes for them, and the prod
backend's graceful-shutdown settings."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml
from httpx import ASGITransport, AsyncClient

import src.database
import src.main as main_mod
import src.redis_client
from src.main import app

ROOT = Path(__file__).resolve().parent.parent
SECRET_DSN = "postgresql+asyncpg://agentgraph:hunter2@db.internal:5432/agentgraph"


async def _get(path: str):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


class _FakeRedis:
    def __init__(self, ok: bool = True, exc: Exception | None = None) -> None:
        self._ok = ok
        self._exc = exc

    async def ping(self) -> bool:
        if self._exc is not None:
            raise self._exc
        return self._ok


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *_a, **_kw):
        return None


def _db_down(*_a, **_kw):
    # The exception text carries a connection string: it must never reach the body.
    raise ConnectionRefusedError(f"could not connect to {SECRET_DSN}")


@pytest.fixture
def db_up(monkeypatch):
    monkeypatch.setattr(src.database, "async_session", lambda: _FakeSession())


@pytest.fixture
def db_down(monkeypatch):
    monkeypatch.setattr(src.database, "async_session", _db_down)


@pytest.fixture
def redis_up(monkeypatch):
    monkeypatch.setattr(src.redis_client, "get_redis", lambda: _FakeRedis(ok=True))


@pytest.fixture
def redis_down(monkeypatch):
    monkeypatch.setattr(
        src.redis_client, "get_redis",
        lambda: _FakeRedis(exc=ConnectionError("redis://:s3cret@redis:6379/0 refused")),
    )


# --- /livez ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_livez_ok():
    resp = await _get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_livez_ok_when_db_and_redis_are_down(db_down, redis_down):
    resp = await _get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_livez_makes_no_dependency_calls(monkeypatch):
    def boom(*_a, **_kw):
        raise AssertionError("livez must not call a dependency")

    monkeypatch.setattr(src.database, "async_session", boom)
    monkeypatch.setattr(src.redis_client, "get_redis", boom)
    resp = await _get("/livez")
    assert resp.status_code == 200


# --- /readyz --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_readyz_ok_when_both_up(db_up, redis_up):
    resp = await _get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready", "checks": {"database": "ok", "redis": "ok"}}
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_readyz_503_when_db_unreachable(db_down, redis_up):
    resp = await _get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body == {
        "status": "not_ready",
        "checks": {"database": "error", "redis": "ok"},
        "failed": ["database"],
    }
    # No secrets or connection strings in the body.
    assert "hunter2" not in resp.text
    assert "db.internal" not in resp.text
    assert "postgresql" not in resp.text


@pytest.mark.asyncio
async def test_readyz_503_when_redis_down(db_up, redis_down):
    resp = await _get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"] == {"database": "ok", "redis": "error"}
    assert body["failed"] == ["redis"]
    assert "s3cret" not in resp.text


@pytest.mark.asyncio
async def test_readyz_503_when_redis_ping_false(db_up, monkeypatch):
    monkeypatch.setattr(src.redis_client, "get_redis", lambda: _FakeRedis(ok=False))
    resp = await _get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["failed"] == ["redis"]


@pytest.mark.asyncio
async def test_readyz_503_when_both_down(db_down, redis_down):
    resp = await _get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["failed"] == ["database", "redis"]


@pytest.mark.asyncio
async def test_readyz_times_out_a_hung_dependency(monkeypatch, redis_up):
    class _HangingSession(_FakeSession):
        async def execute(self, *_a, **_kw):
            await asyncio.sleep(30)

    monkeypatch.setattr(main_mod, "_READYZ_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(src.database, "async_session", lambda: _HangingSession())
    loop = asyncio.get_running_loop()
    started = loop.time()
    resp = await _get("/readyz")
    assert loop.time() - started < 5
    assert resp.status_code == 503
    assert resp.json()["checks"] == {"database": "timeout", "redis": "ok"}
    assert resp.json()["failed"] == ["database"]


# --- /health is unchanged -------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_shape_unchanged_when_up(db_up, redis_up):
    resp = await _get("/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "service": "AgentAvow",
        "checks": {"database": "ok", "redis": "ok"},
    }


@pytest.mark.asyncio
async def test_health_shape_unchanged_when_db_down(db_down, redis_up):
    resp = await _get("/health")
    assert resp.status_code == 503
    assert resp.json() == {
        "status": "degraded",
        "service": "AgentAvow",
        "checks": {"database": "error", "redis": "ok"},
    }


# --- not rate limited, not in OpenAPI -------------------------------------------------

@pytest.mark.asyncio
async def test_probes_have_no_rate_limit(db_up, redis_up):
    for _ in range(3):
        for path in ("/livez", "/readyz"):
            resp = await _get(path)
            assert resp.status_code == 200
            assert "x-ratelimit-limit" not in resp.headers


@pytest.mark.asyncio
async def test_probes_not_in_openapi():
    paths = app.openapi()["paths"]
    assert "/livez" not in paths
    assert "/readyz" not in paths
    assert "/health" in paths  # unchanged


def test_probes_skipped_by_request_logging():
    assert {"/health", "/livez", "/readyz"} <= main_mod._PROBE_PATHS


# --- nginx ----------------------------------------------------------------------------

def _location_blocks(conf: str, path: str) -> list[str]:
    pattern = re.compile(r"location\s+=\s+" + re.escape(path) + r"\s*\{([^}]*)\}")
    return pattern.findall(conf)


@pytest.mark.parametrize("path", ["/livez", "/readyz"])
def test_nginx_proxies_probes_like_health(path: str):
    conf = (ROOT / "nginx" / "nginx.conf").read_text()
    health_count = len(re.findall(r"location\s+/health\s*\{", conf))
    blocks = _location_blocks(conf, path)
    # One per server block that has /health (agentavow.com and the legacy host).
    assert len(blocks) == health_count >= 1
    for body in blocks:
        assert "proxy_pass $backend;" in body
        assert "limit_req" not in body
        assert "return 301" not in body


@pytest.mark.parametrize("path", ["/livez", "/readyz"])
def test_nginx_ssl_proxies_probes(path: str):
    conf = (ROOT / "nginx" / "nginx-ssl.conf").read_text()
    blocks = _location_blocks(conf, path)
    assert len(blocks) == 1
    assert "proxy_pass http://backend:8000;" in blocks[0]
    assert "limit_req" not in blocks[0]


# --- prod compose: graceful shutdown --------------------------------------------------

def _grace_seconds(value: str) -> int:
    m = re.fullmatch(r"(\d+)s", str(value).strip())
    assert m, f"unexpected stop_grace_period {value!r}"
    return int(m.group(1))


def test_prod_backend_has_graceful_shutdown():
    compose = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())
    backend = compose["services"]["backend"]
    m = re.search(r"--timeout-graceful-shutdown\s+(\d+)", backend["command"])
    assert m, "uvicorn needs --timeout-graceful-shutdown"
    uvicorn_grace = int(m.group(1))
    docker_grace = _grace_seconds(backend["stop_grace_period"])
    # Long enough for the longest held scan request (`wait` is capped at 60 s)...
    assert uvicorn_grace >= 60
    # ...and docker waits longer than uvicorn, so lifespan shutdown runs before SIGKILL.
    assert docker_grace > uvicorn_grace
    # /health stays the backend healthcheck (deploy and rollback read it).
    assert "http://localhost:8000/health" in backend["healthcheck"]["test"]


def test_entrypoint_execs_the_server():
    # SIGTERM from docker reaches uvicorn only if the entrypoint execs it (PID 1).
    script = (ROOT / "scripts" / "docker-entrypoint.sh").read_text()
    assert 'exec "$@"' in script
