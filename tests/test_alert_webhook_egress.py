"""Alert webhook egress — the account holder supplies the URL, so the backend must
never POST to it with a plain client.

Without a guard, any logged-in account could point its webhook at an internal
address, press "test", and read the status code back: a probe of the network the
backend sits in. The URL must be a public https:// address when it is saved and
again when it is delivered to, and the connection goes through the rebind-safe
client with redirects off.
"""
from __future__ import annotations

import socket

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api import account_webhook_router
from src.api.account_webhook_router import deliver_alert_webhook
from src.database import get_db
from src.main import app
from src.models import AlertWebhook


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


WEBHOOK_URL = "/api/v1/account/alert-webhook"
USER = {"email": "hook@test.com", "password": "Str0ngP@ss", "display_name": "HookUser"}
# A public IP literal: passes the guard without a DNS lookup.
PUBLIC_URL = "https://93.184.216.34/hook"


async def _auth(client: AsyncClient) -> dict:
    await client.post("/api/v1/auth/register", json=USER)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": USER["email"], "password": USER["password"]},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class _FakeClient:
    """Stands in for the rebind-safe client; records what was asked of it."""

    def __init__(self, calls: list, status: int = 204):
        self._calls, self._status = calls, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None):
        self._calls.append(("post", url, json))

        class _Resp:
            status_code = self._status

        return _Resp()


@pytest.fixture
def egress(monkeypatch):
    """Replace the outbound client. ``calls`` stays empty unless a request is made."""
    calls: list = []
    created: list = []

    def fake_factory(**kwargs):
        created.append(kwargs)
        return _FakeClient(calls)

    monkeypatch.setattr("src.ssrf.ssrf_safe_async_client", fake_factory)
    return calls, created


# ── saving the URL ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://93.184.216.34/hook",                 # not https
    "https://localhost/hook",
    "https://127.0.0.1/hook",
    "https://10.0.0.5/hook",
    "https://192.168.1.10/hook",
    "https://169.254.169.254/latest/meta-data/",  # cloud metadata
    "https://[::1]/hook",
])
async def test_internal_or_plain_http_url_is_refused(client, url):
    headers = await _auth(client)
    resp = await client.put(WEBHOOK_URL, json={"url": url}, headers=headers)
    assert resp.status_code == 422
    assert (await client.get(WEBHOOK_URL, headers=headers)).json()["url"] is None


@pytest.mark.asyncio
async def test_hostname_that_resolves_internally_is_refused(client, monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    headers = await _auth(client)
    resp = await client.put(
        WEBHOOK_URL, json={"url": "https://rebind.example.com/hook"}, headers=headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_public_https_url_is_saved(client):
    headers = await _auth(client)
    resp = await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["url"] == PUBLIC_URL


# ── delivery ─────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_delivery_uses_the_rebind_safe_client_without_redirects(egress):
    calls, created = egress
    status = await deliver_alert_webhook(PUBLIC_URL, {"type": "agentavow.alert.test"})
    assert status == 204
    assert calls == [("post", PUBLIC_URL, {"type": "agentavow.alert.test"})]
    assert created[0]["follow_redirects"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8000/api/v1/admin",
    "https://169.254.169.254/latest/meta-data/",
    "http://93.184.216.34/hook",
])
async def test_delivery_refuses_a_blocked_url_without_sending(egress, url):
    calls, created = egress
    assert await deliver_alert_webhook(url, {"x": 1}) == 0
    assert calls == [] and created == []


@pytest.mark.asyncio
async def test_delivery_failure_is_status_zero(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("connect failed")

    monkeypatch.setattr("src.ssrf.ssrf_safe_async_client", boom)
    assert await deliver_alert_webhook(PUBLIC_URL, {"x": 1}) == 0


@pytest.mark.asyncio
async def test_test_endpoint_does_not_probe_an_internal_url_saved_before_the_guard(
    client, db, egress,
):
    """A row written before the guard existed may hold an internal URL. "Test" must
    not send to it, and must not report a status that came from the network."""
    calls, created = egress
    headers = await _auth(client)
    me = (await client.get("/api/v1/auth/me", headers=headers)).json()
    db.add(AlertWebhook(
        entity_id=me["id"], url="https://127.0.0.1:8000/api/v1/admin", active=True))
    await db.flush()

    resp = await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"delivered": False, "status": 0}
    assert calls == [] and created == []


@pytest.mark.asyncio
async def test_test_endpoint_delivers_to_a_public_url(client, egress):
    calls, _ = egress
    headers = await _auth(client)
    await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)
    resp = await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert resp.json() == {"delivered": True, "status": 204}
    assert len(calls) == 1 and calls[0][1] == PUBLIC_URL


def test_watch_loop_delivers_through_the_guarded_helper():
    """The re-scan loop must not build its own client for the account's URL."""
    import inspect

    from src.jobs import scheduler

    src = inspect.getsource(scheduler._run_watch_rescan)
    assert "deliver_alert_webhook" in src
    assert "httpx" not in src
    assert account_webhook_router.deliver_alert_webhook is deliver_alert_webhook
