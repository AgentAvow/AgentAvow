from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    """All responses include standard security headers."""
    resp = await client.get("/health")
    assert resp.status_code in (200, 503)  # 503 if Redis/DB pool stale in test suite

    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-XSS-Protection"] == "0"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in resp.headers["Permissions-Policy"]


@pytest.mark.asyncio
async def test_security_headers_on_api(client: AsyncClient):
    """Security headers are present on API endpoints too."""
    resp = await client.get("/api/v1/ping")
    assert resp.status_code == 200

    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


@pytest.mark.asyncio
async def test_security_headers_on_error(client: AsyncClient):
    """Security headers are present even on error responses."""
    import uuid

    resp = await client.get(f"/api/v1/profiles/{uuid.uuid4()}")
    assert resp.status_code == 404

    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


@pytest.mark.asyncio
async def test_security_headers_suppressed_behind_proxy(client: AsyncClient):
    """B15: behind nginx (X-Forwarded-For present) the backend must NOT emit the
    security headers — nginx owns them, and emitting here too produced duplicate
    Content-Security-Policy / X-Frame-Options / etc. headers.
    """
    resp = await client.get("/api/v1/ping", headers={"X-Forwarded-For": "203.0.113.7"})
    assert resp.status_code == 200

    # None of the nginx-owned headers should be set by the backend now.
    for header in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Content-Security-Policy",
    ):
        assert header not in resp.headers, f"{header} should be left to nginx behind a proxy"
