"""Smoke test: the FULL middleware stack (incl. the prod-only Prometheus metrics
instrumentator) must not 500 on included-router routes.

Regression guard for the 2026-08-27 prod outage: FastAPI 0.130+ introduced
`_IncludedRouter` route objects with no `.path`; `prometheus-fastapi-instrumentator`
<8 called `route.path` on every request, so ALL `/api/v1/*` routes 500'd. The 3093-test
suite did not catch it because the instrumentator is a prod-only dependency and CI
installed only `.[dev]`. CI now installs `.[prod,dev]`, and this test exercises the
metrics middleware against an included-router route so this class of gap can't recur.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_metrics_middleware_no_500_on_included_route():
    """An included-router route must return 200 through the full middleware stack —
    the exact path (`/api/v1/*`) and route class that the outage 500'd on."""
    from src.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/ping")
    assert resp.status_code == 200, (
        f"included-router route 500'd through the middleware stack: "
        f"{resp.status_code} {resp.text[:200]}"
    )
    assert resp.json() == {"ping": "pong"}


@pytest.mark.asyncio
async def test_metrics_endpoint_does_not_500():
    """`/metrics` (present only when the prod instrumentator is installed) must serve,
    never 500. 404 is acceptable when the instrumentator isn't installed (bare dev)."""
    from src.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
    assert resp.status_code in (200, 404), f"/metrics 500'd: {resp.status_code} {resp.text[:200]}"
